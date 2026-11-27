from xconn import Component
from xconn.exception import ApplicationError
from sqlalchemy.ext.asyncio import AsyncSession
from xconn.types import Depends, Result, CallDetails

from deskconn import schemas, uris, helpers, models
from deskconn.database.database import get_database
from deskconn.database.backend import user as user_backend
from deskconn.database.backend import device as device_backend
from deskconn.database.backend import desktop as desktop_backend
from deskconn.database.backend import principal as principal_backend
from deskconn.database.backend import cli_login as cli_login_backend
from deskconn.api.principal import create_and_notify_principal

component = Component()


@component.register("com.deskconn.account.cra.verify", response_model=schemas.CRAUser)
async def verify_cra(authid: str, realm: str, db: AsyncSession = Depends(get_database)):
    db_user = await user_backend.get_user_by_email(db, authid)
    if db_user is None:
        raise ApplicationError(uris.ERROR_USER_NOT_FOUND, f"User with authid '{authid}' not found")

    if not db_user.is_verified:
        raise ApplicationError(uris.ERROR_USER_NOT_VERIFIED, f"User with authid '{authid}' is not verified")

    await validate_user_connect_to_desktop(db, authid, realm, db_user)

    return db_user


@component.register("com.deskconn.account.login")
async def login(email: str, details: CallDetails, db: AsyncSession = Depends(get_database)):
    ensure_login_email_matches_caller(details, email)
    db_user = await user_backend.get_user_by_email(db, email, for_update=True)
    if db_user is None:
        raise ApplicationError(uris.ERROR_USER_NOT_FOUND, f"User with email '{email}' not found")

    if not db_user.is_verified:
        raise ApplicationError(uris.ERROR_USER_NOT_VERIFIED, f"User with email '{email}' is not verified")

    await user_backend.generate_and_save_otp(db, db_user, helpers.OTP_PURPOSE_LOGIN)


@component.register("com.deskconn.account.login.verify", response_model=schemas.PrincipalGet)
async def verify_login(rs: schemas.UserVerify, details: CallDetails, db: AsyncSession = Depends(get_database)):
    ensure_login_email_matches_caller(details, rs.email)
    db_user = await user_backend.get_user_by_email(db, rs.email, for_update=True)
    if db_user is None:
        raise ApplicationError(uris.ERROR_USER_NOT_FOUND, f"User with email '{rs.email}' not found")

    await user_backend.verify_otp(db, db_user, rs.code, helpers.OTP_PURPOSE_LOGIN)

    return await create_and_notify_principal(db, schemas.PrincipalCreate(public_key=rs.public_key), db_user)


@component.register("com.deskconn.account.cryptosign.verify")
async def verify_cryptosign(authid: str, public_key: str, realm: str, db: AsyncSession = Depends(get_database)):
    db_user = await user_backend.get_user_by_email(db, authid)
    if db_user is not None:
        if not db_user.is_verified:
            raise ApplicationError(uris.ERROR_USER_NOT_VERIFIED, f"User with authid '{authid}' is not verified")

        if not await principal_backend.user_principal_exists(db, public_key, db_user):
            db_device = await device_backend.get_device_by_public_key(db, public_key, db_user.id)
            if db_device is None:
                raise ApplicationError(
                    uris.ERROR_NOT_FOUND, f"Device/Principal with public key '{public_key}' not found"
                )

        await validate_user_connect_to_desktop(db, authid, realm, db_user)

        authrole = helpers.ROLE_CRYPTOSIGN_USER
        if realm != helpers.CLOUD_REALM:
            authrole = await desktop_access_role(db, realm, db_user)
    else:
        db_desktop = await desktop_backend.get_desktop_by_public_key(db, authid, public_key)
        if db_desktop is None:
            raise ApplicationError(
                uris.ERROR_DEVICE_NOT_FOUND, f"Desktop with authid '{authid}' public key '{public_key}' not found"
            )

        if realm not in (db_desktop.realm, helpers.CLOUD_REALM):
            raise ApplicationError(
                uris.ERROR_AUTHENTICATION_FAILED, f"Desktop is not authorized to access realm '{realm}'"
            )

        authrole = helpers.ROLE_DESKTOP.format(authid=db_desktop.authid)

    return Result(args=[{"authid": authid, "authrole": authrole}])


@component.register("com.deskconn.desktop.access")
async def desktop_access(authid: str, desktop_authid: str, db: AsyncSession = Depends(get_database)):
    db_user = await user_backend.get_user_by_email(db, authid)
    if db_user is None:
        raise ApplicationError(uris.ERROR_USER_NOT_FOUND, f"User with authid '{authid}' not found")

    if not db_user.is_verified:
        raise ApplicationError(uris.ERROR_USER_NOT_VERIFIED, f"User with authid '{authid}' is not verified")

    db_desktop = await desktop_backend.get_desktop_by_authid(db, desktop_authid)
    if db_desktop is None:
        raise ApplicationError(uris.ERROR_DEVICE_NOT_FOUND, f"Desktop with authid '{desktop_authid}' not found")

    if not await desktop_backend.has_desktop_access(db, db_desktop.id, db_user.id):
        raise ApplicationError(
            uris.ERROR_USER_NOT_AUTHORIZED, f"User with authid '{authid}' is not authorized to access desktop"
        )

    return None


def ensure_login_email_matches_caller(details: CallDetails, email: str) -> None:
    # The login OTP flow runs on a password (CRA) session; it may only act on that account.
    if details.authid != email:
        raise ApplicationError(uris.ERROR_USER_NOT_AUTHORIZED, "Cannot act on another user's login")


async def validate_user_connect_to_desktop(db: AsyncSession, authid: str, realm: str, user: models.User):
    if realm == helpers.CLOUD_REALM:
        return

    db_desktop = await desktop_backend.get_desktop_by_realm(db, realm)
    if db_desktop is None:
        raise ApplicationError(uris.ERROR_DEVICE_NOT_FOUND, f"Desktop with realm '{realm}' not found")

    if not await desktop_backend.has_desktop_access(db, db_desktop.id, user.id):
        raise ApplicationError(
            uris.ERROR_USER_NOT_AUTHORIZED, f"User with authid '{authid}' is not authorized to access desktop"
        )


async def desktop_access_role(db: AsyncSession, realm: str, user: models.User) -> str:
    """Returns user:owner, user:admin or user:member: the user's best access role on the desktop."""
    role = models.DesktopAccessRole.member
    for desktop in await desktop_backend.get_user_desktops_with_role(db, user.id):
        if desktop.realm == realm:
            role = desktop.role
    return helpers.ROLE_USER_DESKTOP.format(role=role.value)


@component.register("com.deskconn.account.login.cli.start", response_model=schemas.CLILoginStartGet)
async def start_cli_login(rs: schemas.CLILoginStart, details: CallDetails, db: AsyncSession = Depends(get_database)):
    # Approving would fail on it: fail now rather than leave the login pending until it expires.
    if await principal_backend.principal_exists_by_public_key(db, rs.public_key):
        raise ApplicationError(uris.ERROR_PRINCIPAL_EXISTS, "This key is already registered")

    await cli_login_backend.delete_expired_cli_logins(db)

    device_code = helpers.generate_device_code()
    data = schemas.CLILoginCreate(
        public_key=rs.public_key,
        hostname=rs.hostname,
        purpose=rs.purpose,
        device_code_hash=helpers.hash_device_code(device_code),
        user_code=helpers.generate_user_code(),
        session_id=details.session_id,
        expires_at=helpers.cli_login_expires_at(),
    )
    db_login = await cli_login_backend.create_cli_login(db, data)

    return schemas.CLILoginStartGet(
        device_code=device_code,
        user_code=db_login.user_code,
        # No code in the link: the user types it from their terminal, so a forwarded link can't be approved.
        verification_uri=helpers.CLI_LOGIN_URL,
        expires_in=helpers.CLI_LOGIN_TTL_SECONDS,
        interval=helpers.CLI_LOGIN_POLL_INTERVAL_SECONDS,
    )


async def verified_user(db: AsyncSession, authid: str) -> models.User:
    db_user = await user_backend.get_user_by_email(db, authid)
    if db_user is None:
        raise ApplicationError(uris.ERROR_USER_NOT_FOUND, f"User with authid '{authid}' not found")

    if not db_user.is_verified:
        raise ApplicationError(uris.ERROR_USER_NOT_VERIFIED, f"User with authid '{authid}' is not verified")

    return db_user


@component.register("com.deskconn.account.login.cli.get", response_model=schemas.CLILoginGet)
async def get_cli_login(user_code: str, details: CallDetails, db: AsyncSession = Depends(get_database)):
    await verified_user(db, details.authid)
    db_login = await cli_login_backend.get_pending_cli_login_by_user_code(db, user_code)
    if db_login is None:
        raise ApplicationError(uris.ERROR_CLI_LOGIN_NOT_FOUND, "This login request has expired or was already used")

    return db_login


@component.register("com.deskconn.account.login.cli.approve")
async def approve_cli_login(user_code: str, details: CallDetails, db: AsyncSession = Depends(get_database)):
    db_user = await verified_user(db, details.authid)

    # Locked until the commit in create_and_notify_principal, which commits the approval and
    # the key together: a second approval waits, then finds it no longer pending.
    db_login = await cli_login_backend.get_pending_cli_login_by_user_code(db, user_code, for_update=True)
    if db_login is None:
        raise ApplicationError(uris.ERROR_CLI_LOGIN_NOT_FOUND, "This login request has expired or was already used")

    principal = schemas.PrincipalCreate(public_key=db_login.public_key)
    await cli_login_backend.approve_cli_login(db, db_login, db_user)
    await create_and_notify_principal(db, principal, db_user)


@component.register("com.deskconn.account.login.cli.deny")
async def deny_cli_login(user_code: str, details: CallDetails, db: AsyncSession = Depends(get_database)):
    await verified_user(db, details.authid)
    db_login = await cli_login_backend.get_pending_cli_login_by_user_code(db, user_code, for_update=True)
    if db_login is None:
        raise ApplicationError(uris.ERROR_CLI_LOGIN_NOT_FOUND, "This login request has expired or was already used")

    await cli_login_backend.deny_cli_login(db, db_login)


@component.register("com.deskconn.account.login.cli.poll", response_model=schemas.CLILoginPoll)
async def poll_cli_login(device_code: str, db: AsyncSession = Depends(get_database)):
    db_login = await cli_login_backend.get_cli_login_by_device_code(db, device_code)
    # start_cli_login deletes expired logins, so one left here just answers expired.
    if db_login is None or helpers.utcnow() >= db_login.expires_at:
        return schemas.CLILoginPoll(status="expired")

    if db_login.status == models.CLILoginStatus.pending:
        return schemas.CLILoginPoll(status="pending")

    # Approved or denied: answered until it expires, so a CLI whose poll reply got lost can ask again.
    if db_login.status == models.CLILoginStatus.denied:
        return schemas.CLILoginPoll(status="denied")

    principal = await principal_backend.get_user_principal(db, db_login.public_key, db_login.user)
    # Removed since it was approved: there is nothing left to sign in with.
    if principal is None:
        return schemas.CLILoginPoll(status="expired")

    return schemas.CLILoginPoll(status="approved", authid=db_login.user.email, expires_at=principal.expires_at)
