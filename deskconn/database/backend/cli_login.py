from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from deskconn import helpers, models, schemas


async def delete_expired_cli_logins(db: AsyncSession) -> None:
    stmt = delete(models.CLILogin).where(models.CLILogin.expires_at <= helpers.utcnow())
    await db.execute(stmt)
    await db.commit()


async def create_cli_login(db: AsyncSession, data: schemas.CLILoginCreate) -> models.CLILogin:
    # One login per WAMP session: starting another replaces it. Each CLI has a session of its
    # own; anything calling start for several people over one shared session would need another key.
    stmt = delete(models.CLILogin).where(models.CLILogin.session_id == data.session_id)
    await db.execute(stmt)

    db_login = models.CLILogin(**data.model_dump())
    db.add(db_login)
    await db.commit()

    return db_login


async def get_pending_cli_login_by_user_code(
    db: AsyncSession, user_code: str, for_update: bool = False
) -> models.CLILogin | None:
    stmt = (
        select(models.CLILogin)
        .where(models.CLILogin.user_code == helpers.normalize_user_code(user_code))
        .where(models.CLILogin.status == models.CLILoginStatus.pending)
        .where(models.CLILogin.expires_at > helpers.utcnow())
    )
    if for_update:
        stmt = stmt.with_for_update()
    result = await db.execute(stmt)

    return result.scalar()


async def get_cli_login_by_device_code(db: AsyncSession, device_code: str) -> models.CLILogin | None:
    stmt = (
        select(models.CLILogin)
        .where(models.CLILogin.device_code_hash == helpers.hash_device_code(device_code))
        .options(selectinload(models.CLILogin.user))
    )
    result = await db.execute(stmt)

    return result.scalar()


async def approve_cli_login(db: AsyncSession, db_login: models.CLILogin, user: models.User) -> None:
    # Not committed here: the approval is committed together with the key it registers. The
    # expiry restarts so the CLI gets a full window to collect the answer.
    stmt = (
        update(models.CLILogin)
        .where(models.CLILogin.id == db_login.id)
        .values(
            status=models.CLILoginStatus.approved,
            user_id=user.id,
            expires_at=helpers.cli_login_expires_at(),
        )
    )
    await db.execute(stmt)


async def deny_cli_login(db: AsyncSession, db_login: models.CLILogin) -> None:
    # The expiry restarts so the CLI gets a full window to collect the answer.
    stmt = (
        update(models.CLILogin)
        .where(models.CLILogin.id == db_login.id)
        .values(status=models.CLILoginStatus.denied, expires_at=helpers.cli_login_expires_at())
    )
    await db.execute(stmt)
    await db.commit()
