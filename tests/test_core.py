import asyncio
import base64
import hashlib
import inspect
import json
import os
import subprocess
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from xconn._client.async_ import _setup, register_async
from xconn.exception import ApplicationError
from xconn.quic import AsyncQUICConnection
from xconn.requests import RegisterRequest
from xconn.types import Invocation

from main import app
from deskconn import helpers, uris
from deskconn.api import auth, desktop


def test_password_hash_preserves_existing_credentials():
    password = "test-password"
    salt = "test-salt"
    expected = base64.b64encode(hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 1000, 32)).decode()
    assert helpers.hash_password(password, salt) == expected
    assert helpers.verify_password(password, salt, expected)
    assert not helpers.verify_password("incorrect", salt, expected)


class RegistrationSession:
    def __init__(self):
        self.handlers = {}

    def register(self, uri, handler):
        return RegisterRequest(uri, handler, session=self)

    async def _execute_register(self, request):
        self.handlers[request.procedure] = request.handler


@pytest.mark.asyncio
async def test_all_account_procedures_register_with_core():
    session = RegistrationSession()
    for uri, handler in app.procedures.items():
        await register_async(session, uri, handler)

    assert session.handlers.keys() == app.procedures.keys()
    assert "com.deskconn.account.login.verify" in session.handlers
    assert "com.deskconn.desktop.attach" in session.handlers


@pytest.mark.asyncio
async def test_router_realm_inventory_requires_router_role(monkeypatch):
    database = AsyncMock()
    database.execute.return_value = [("realm-a", "machine-a"), ("realm-b", "machine-b")]

    @asynccontextmanager
    async def dependency():
        yield database

    uri = "com.deskconn.realm.list"
    handler = desktop.component.procedures[uri]
    default = inspect.signature(handler).parameters["db"].default
    monkeypatch.setattr(default, "dependency", dependency)
    session = RegistrationSession()
    await register_async(session, uri, handler)

    with pytest.raises(ApplicationError, match="authrole") as error:
        await session.handlers[uri](Invocation([], {}, {}))
    assert error.value.uri == "wamp.error.internal_error"
    for role in ("user:cryptosign", "trusted"):
        with pytest.raises(ApplicationError) as error:
            await session.handlers[uri](Invocation([], {}, {"caller_authrole": role}))
        assert error.value.uri == "wamp.error.not_authorized"
    database.execute.assert_not_awaited()

    invocation = Invocation([], {}, {"caller_authrole": desktop.ROUTER_AUTHROLE})
    result = await session.handlers[uri](invocation)
    assert result.args == [[{"realm": "realm-a", "authid": "machine-a"}, {"realm": "realm-b", "authid": "machine-b"}]]
    assert list(database.execute.call_args.args[0].selected_columns.keys()) == ["realm", "authid"]

    database.execute.return_value = []
    result = await session.handlers[uri](invocation)
    assert result.args == [[]]


@pytest.mark.asyncio
async def test_login_invocation_resolves_dependencies_and_preserves_errors(monkeypatch):
    database = object()

    @asynccontextmanager
    async def dependency():
        yield database

    uri = "com.deskconn.account.login"
    handler = auth.component.procedures[uri]
    default = inspect.signature(handler).parameters["db"].default
    monkeypatch.setattr(default, "dependency", dependency)
    user = SimpleNamespace(is_verified=True)
    lookup = AsyncMock(return_value=user)
    otp = AsyncMock()
    monkeypatch.setattr(auth.user_backend, "get_user_by_email", lookup)
    monkeypatch.setattr(auth.user_backend, "generate_and_save_otp", otp)
    session = RegistrationSession()
    await register_async(session, uri, handler)

    await session.handlers[uri](Invocation(["test@example.com"], {}, {"caller_authid": "test@example.com"}))
    lookup.assert_awaited_once_with(database, "test@example.com", for_update=True)
    otp.assert_awaited_once_with(database, user, helpers.OTP_PURPOSE_LOGIN)

    lookup.return_value = None
    with pytest.raises(ApplicationError) as error:
        await session.handlers[uri](Invocation(["missing@example.com"], {}, {"caller_authid": "missing@example.com"}))
    assert error.value.uri == uris.ERROR_USER_NOT_FOUND

    # a CRA session for one account cannot drive another account's login OTP
    lookup.reset_mock()
    with pytest.raises(ApplicationError) as error:
        await session.handlers[uri](Invocation(["victim@example.com"], {}, {"caller_authid": "test@example.com"}))
    assert error.value.uri == uris.ERROR_USER_NOT_AUTHORIZED
    lookup.assert_not_awaited()


@pytest.mark.asyncio
async def test_core_router_registration_rpc_and_publication():
    binary = os.environ.get("XCONN_TRANSPORT_PEER")
    if not binary:
        pytest.skip("Set XCONN_TRANSPORT_PEER to the Core transport_peer binary")

    process = subprocess.Popen([binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        peer = json.loads(process.stdout.readline())
        async with await AsyncQUICConnection.connect(
            peer["quic"], server_name="localhost", certificate=bytes.fromhex(peer["quic_certificate"])
        ) as connection:
            session = await connection.open_session("realm")
            try:
                await _setup(app, session)
                await helpers.call_cloud_router_rpc(session, "echo", ["value", 42], "RPC failed")
                received = asyncio.Queue()
                subscription = await session.subscribe("account.test", received.put).execute()
                await (
                    session.publish("account.test")
                    .args("key", "role")
                    .options(acknowledge=True, exclude_me=False)
                    .execute()
                )
                event = await asyncio.wait_for(received.get(), 5)
                assert event.args == ["key", "role"]
                await subscription.unsubscribe()
            finally:
                await session.close()
    finally:
        process.stdin.close()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def test_service_launcher_uses_cryptosign(monkeypatch):
    import xconn
    from main import run

    monkeypatch.setenv("ROUTER_URL", "ws://127.0.0.1:1/ws")
    monkeypatch.setenv("DESKCONN_ACCOUNT_AUTHID", "test-account-service")
    monkeypatch.setenv("DESKCONN_ACCOUNT_PRIVATE_KEY", "01" * 32)
    captured = []
    monkeypatch.setattr(xconn, "connect", lambda app, config: captured.append((app, config)))
    run()

    target, config = captured[0]
    assert target == "main:app"
    assert config.realm == "com.deskconn"
    assert config.authmethod == "cryptosign"
    assert config.authid == "test-account-service"
    assert config.private_key == "01" * 32


@pytest.mark.asyncio
async def test_account_get_preserves_caller_identity_and_response(monkeypatch):
    from uuid import UUID
    from deskconn.api import user

    uri = "com.deskconn.account.get"
    handler = user.component.procedures[uri]
    database = object()

    @asynccontextmanager
    async def dependency():
        yield database

    default = inspect.signature(handler).parameters["db"].default
    monkeypatch.setattr(default, "dependency", dependency)
    user_id = "b7f1a8b5-59d2-42a2-b55b-77a26505ad13"
    record = SimpleNamespace(id=UUID(user_id), email="test@example.com", name="Test User")
    lookup = AsyncMock(return_value=record)
    monkeypatch.setattr(user.user_backend, "get_user_by_email", lookup)
    session = RegistrationSession()
    await register_async(session, uri, handler)

    result = await session.handlers[uri](Invocation([], {}, {"caller_authid": "test@example.com"}))
    lookup.assert_awaited_once_with(database, "test@example.com")
    assert result.args == [{"email": "test@example.com", "name": "Test User", "id": user_id}]


@pytest.mark.asyncio
async def test_otp_is_consumed_after_successful_verification():
    from deskconn.database.backend import user as user_backend

    db = SimpleNamespace(commit=AsyncMock())
    record = SimpleNamespace(
        id=1,
        otp_hash=helpers.hash_otp("123456"),
        otp_expires_at=helpers.otp_expiry_time(),
        otp_purpose=helpers.OTP_PURPOSE_LOGIN,
        otp_verify_attempts=0,
    )
    await user_backend.verify_otp(db, record, "123456", helpers.OTP_PURPOSE_LOGIN)
    assert record.otp_hash is None and record.otp_expires_at is None and record.otp_purpose is None
    assert record.otp_send_count == 0 and record.otp_window_started_at is None
    db.commit.assert_awaited()

    # replaying the same code is rejected
    db.execute = AsyncMock(return_value=SimpleNamespace(scalar_one=lambda: 1))
    with pytest.raises(ApplicationError) as error:
        await user_backend.verify_otp(db, record, "123456", helpers.OTP_PURPOSE_LOGIN)
    assert error.value.uri == uris.ERROR_USER_OTP_INVALID


def test_otp_user_lookup_locks_the_row():
    from sqlalchemy.dialects import postgresql
    from deskconn.database.backend import user as user_backend

    captured = []

    class DB:
        async def execute(self, stmt):
            captured.append(str(stmt.compile(dialect=postgresql.dialect())))
            return SimpleNamespace(scalar=lambda: None)

    asyncio.run(user_backend.get_user_by_email(DB(), "a@b.c", for_update=True))
    asyncio.run(user_backend.get_user_by_email(DB(), "a@b.c"))
    assert captured[0].endswith("FOR UPDATE")
    assert "FOR UPDATE" not in captured[1]


@pytest.mark.asyncio
async def test_desktop_access_keys_carry_login_key_expiry():
    from datetime import datetime, timezone
    from deskconn.database.backend import desktop as desktop_backend

    expires = datetime(2027, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    later = datetime(2027, 2, 1, tzinfo=timezone.utc)
    rows = [
        ("owner@example.com", "login", "owner", expires),
        ("owner@example.com", "phone", "owner", None),
        # a key that is both a login key and a device key doesn't expire
        ("member@example.com", "shared", "member", expires),
        ("member@example.com", "shared", "member", None),
        ("member@example.com", "login", "member", expires),
        ("member@example.com", "login", "member", later),
        ("machine-1", "desktop", "owner", None),
    ]
    db = SimpleNamespace(execute=AsyncMock(return_value=SimpleNamespace(all=lambda: rows)))

    result = await desktop_backend.get_desktop_access_public_keys(db, None)
    assert result == [
        {
            "authid": "owner@example.com",
            "authorized_keys": ["login", "phone"],
            "authrole": "owner",
            "key_expires_at": {"login": int(expires.timestamp())},
        },
        {
            "authid": "member@example.com",
            "authorized_keys": ["shared", "login"],
            "authrole": "member",
            "key_expires_at": {"login": int(later.timestamp())},
        },
        {"authid": "machine-1", "authorized_keys": ["desktop"], "authrole": "owner", "key_expires_at": {}},
    ]


@pytest.mark.asyncio
async def test_new_login_key_is_announced_with_its_expiry(monkeypatch):
    from datetime import datetime, timezone
    from deskconn import schemas
    from deskconn.api import principal

    expires = datetime(2027, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    record = SimpleNamespace(public_key="ab" * 32, expires_at=expires)
    monkeypatch.setattr(principal.principal_backend, "principal_exists_by_public_key", AsyncMock(return_value=False))
    monkeypatch.setattr(principal.principal_backend, "create_principal", AsyncMock(return_value=record))
    monkeypatch.setattr(
        principal.desktop_backend,
        "get_user_desktops_authid_with_authrole",
        AsyncMock(return_value=[("machine-1", "owner")]),
    )
    published = []

    class Publication:
        def __init__(self, topic):
            self.topic = topic

        def args(self, *args):
            published.append((self.topic, list(args)))
            return self

        def options(self, **_):
            return self

        async def execute(self):
            return None

    monkeypatch.setattr(principal.component, "_session", SimpleNamespace(publish=Publication))

    user = SimpleNamespace(id=1, email="owner@example.com")
    await principal.create_and_notify_principal(object(), schemas.PrincipalCreate(public_key="ab" * 32), user)
    assert published == [
        (
            helpers.TOPIC_KEY_ADD.format(machine_id="machine-1"),
            ["owner@example.com", "ab" * 32, "owner", int(expires.timestamp())],
        )
    ]


def cli_login_handler(name):
    return auth.component.procedures[f"com.deskconn.account.login.cli.{name}"]


def test_cli_login_purpose_defaults_to_login_for_older_clis():
    from deskconn import schemas

    assert schemas.CLILoginStart(public_key="ab" * 32, hostname="laptop").purpose == "login"
    with pytest.raises(ValueError):
        schemas.CLILoginStart(public_key="ab" * 32, hostname="laptop", purpose="other")


def test_user_code_is_typed_back_in_any_case():
    code = helpers.generate_user_code()
    assert len(code) == 9 and code[4] == "-"
    assert helpers.normalize_user_code(f" {code.replace('-', '').lower()} ") == code


@pytest.mark.asyncio
async def test_cli_login_start_keeps_the_code_out_of_the_link(monkeypatch):
    from deskconn import schemas

    created = []

    async def create_cli_login(_, data):
        created.append(data)
        return SimpleNamespace(user_code=data.user_code)

    monkeypatch.setattr(auth.principal_backend, "principal_exists_by_public_key", AsyncMock(return_value=False))
    monkeypatch.setattr(auth.cli_login_backend, "delete_expired_cli_logins", AsyncMock())
    monkeypatch.setattr(auth.cli_login_backend, "create_cli_login", create_cli_login)

    rs = schemas.CLILoginStart(public_key="ab" * 32, hostname="laptop", purpose="attach")
    started = await cli_login_handler("start")(rs, SimpleNamespace(session_id=7), db=object())

    [data] = created
    assert data.session_id == 7 and data.public_key == "ab" * 32 and data.purpose == "attach"
    assert data.device_code_hash == helpers.hash_device_code(started.device_code)
    assert started.user_code == data.user_code
    assert started.user_code not in started.verification_uri


@pytest.mark.asyncio
async def test_cli_login_start_rejects_a_registered_key(monkeypatch):
    from deskconn import schemas

    monkeypatch.setattr(auth.principal_backend, "principal_exists_by_public_key", AsyncMock(return_value=True))
    rs = schemas.CLILoginStart(public_key="ab" * 32, hostname="laptop")
    with pytest.raises(ApplicationError) as e:
        await cli_login_handler("start")(rs, SimpleNamespace(session_id=7), db=object())
    assert e.value.uri == uris.ERROR_PRINCIPAL_EXISTS


@pytest.mark.asyncio
@pytest.mark.parametrize("procedure", ["get", "approve", "deny"])
async def test_cli_login_answering_needs_a_verified_user(monkeypatch, procedure):
    user = SimpleNamespace(email="owner@example.com", is_verified=False)
    monkeypatch.setattr(auth.user_backend, "get_user_by_email", AsyncMock(return_value=user))
    with pytest.raises(ApplicationError) as e:
        await cli_login_handler(procedure)("abcd-efgh", SimpleNamespace(authid=user.email), db=object())
    assert e.value.uri == uris.ERROR_USER_NOT_VERIFIED


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status, expires_in, key_exists, answer",
    [
        ("pending", 60, True, {"status": "pending"}),
        ("pending", -1, True, {"status": "expired"}),
        ("denied", 60, True, {"status": "denied"}),
        ("approved", 60, True, {"status": "approved", "authid": "owner@example.com"}),
        # the key was removed between approval and this poll
        ("approved", 60, False, {"status": "expired"}),
    ],
)
async def test_cli_login_poll(monkeypatch, status, expires_in, key_exists, answer):
    from datetime import timedelta
    from deskconn import models

    db_login = SimpleNamespace(
        status=models.CLILoginStatus(status),
        expires_at=helpers.utcnow() + timedelta(seconds=expires_in),
        public_key="ab" * 32,
        user=SimpleNamespace(email="owner@example.com"),
    )
    monkeypatch.setattr(auth.cli_login_backend, "get_cli_login_by_device_code", AsyncMock(return_value=db_login))
    principal = SimpleNamespace(expires_at=None) if key_exists else None
    monkeypatch.setattr(auth.principal_backend, "get_user_principal", AsyncMock(return_value=principal))

    for _ in range(2):  # asking again, after a lost reply, gets the same answer
        result = await cli_login_handler("poll")("device-code", db=object())
        assert result.model_dump(exclude_none=True) == answer


@pytest.mark.asyncio
async def test_cli_login_unknown_device_code_is_expired(monkeypatch):
    monkeypatch.setattr(auth.cli_login_backend, "get_cli_login_by_device_code", AsyncMock(return_value=None))
    assert (await cli_login_handler("poll")("unknown", db=object())).status == "expired"


@pytest.mark.asyncio
async def test_cli_login_approve_registers_the_started_key(monkeypatch):
    user = SimpleNamespace(id=1, email="owner@example.com", is_verified=True)
    db_login = SimpleNamespace(public_key="ab" * 32)
    approve = AsyncMock()
    register = AsyncMock()
    monkeypatch.setattr(auth.user_backend, "get_user_by_email", AsyncMock(return_value=user))
    monkeypatch.setattr(auth.cli_login_backend, "get_pending_cli_login_by_user_code", AsyncMock(return_value=db_login))
    monkeypatch.setattr(auth.cli_login_backend, "approve_cli_login", approve)
    monkeypatch.setattr(auth, "create_and_notify_principal", register)

    await cli_login_handler("approve")("abcd-efgh", SimpleNamespace(authid=user.email), db=object())

    principal = register.await_args.args[1]
    assert principal.public_key == "ab" * 32 and register.await_args.args[2] is user
    assert approve.await_args.args[1:] == (db_login, user)


@pytest.mark.asyncio
@pytest.mark.parametrize("answer", ["approve_cli_login", "deny_cli_login"])
async def test_cli_login_answer_restarts_the_expiry(answer):
    """The CLI gets a full window to collect an answer, even one given at the last moment."""
    from deskconn.database.backend import cli_login

    statements = []

    class DB:
        async def execute(self, stmt):
            statements.append(stmt)

        async def commit(self):
            pass

    args = (SimpleNamespace(id=1, email="x"),) if answer == "approve_cli_login" else ()
    await getattr(cli_login, answer)(DB(), SimpleNamespace(id=1), *args)

    [stmt] = statements
    assert stmt.compile().params["expires_at"] > helpers.utcnow()
