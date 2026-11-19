from xconn import Component
from xconn.exception import ApplicationError
from sqlalchemy.ext.asyncio import AsyncSession
from xconn.types import Depends, CallDetails

from deskconn import schemas, uris, helpers
from deskconn.database.database import get_database
from deskconn.database.backend import user as user_backend
from deskconn.database.backend import desktop as desktop_backend
from deskconn.api.principal import create_and_notify_principal

component = Component()


@component.register("com.deskconn.account.create", response_model=schemas.UserGet)
async def create(rs: schemas.UserCreate, db: AsyncSession = Depends(get_database)):
    if await user_backend.get_user_by_email(db, rs.email) is not None:
        raise ApplicationError(uris.ERROR_USER_EXISTS, f"User with email '{rs.email}' already exists")

    return await user_backend.create_user(db, rs)


@component.register("com.deskconn.account.get", response_model=schemas.UserGet)
async def get(details: CallDetails, db: AsyncSession = Depends(get_database)):
    db_user = await user_backend.get_user_by_email(db, details.authid)
    if db_user is None:
        raise ApplicationError(uris.ERROR_USER_NOT_FOUND, f"User with authid '{details.authid}' not found")

    return db_user


@component.register("com.deskconn.account.update", response_model=schemas.UserGet)
async def update(rs: schemas.UserUpdate, details: CallDetails, db: AsyncSession = Depends(get_database)):
    db_user = await user_backend.get_user_by_email(db, details.authid)
    if db_user is None:
        raise ApplicationError(uris.ERROR_USER_NOT_FOUND, f"User with authid '{details.authid}' not found")

    data = rs.model_dump(exclude_none=True)
    if len(data) == 0:
        raise ApplicationError("wamp.error.invalid_argument", "No field to update")

    return await user_backend.update_user(db, db_user, data)


@component.register("com.deskconn.account.delete")
async def delete(details: CallDetails, db: AsyncSession = Depends(get_database)):
    db_user = await user_backend.get_user_by_email(db, details.authid)
    if db_user is None:
        raise ApplicationError(uris.ERROR_USER_NOT_FOUND, f"User with authid '{details.authid}' not found")

    # publish keys removal to desktops
    db_desktops = await desktop_backend.get_user_desktops(db, db_user.id)
    authorized_keys = await user_backend.get_user_public_keys(db, db_user.id)

    await user_backend.delete_user(db, db_user)

    for desktop in db_desktops:
        await (
            component.session.publish(helpers.TOPIC_KEY_REMOVE.format(machine_id=desktop.authid))
            .args(authorized_keys)
            .options(acknowledge=True)
            .execute()
        )


@component.register("com.deskconn.account.verify", response_model=schemas.PrincipalGet)
async def account_verification(rs: schemas.UserVerify, db: AsyncSession = Depends(get_database)):
    db_user = await user_backend.get_user_by_email(db, rs.email, for_update=True)
    if db_user is None:
        raise ApplicationError(uris.ERROR_USER_NOT_FOUND, f"User with email '{rs.email}' not found")

    if db_user.is_verified:
        raise ApplicationError(uris.ERROR_USER_ALREADY_VERIFIED, "User is already verified")

    await user_backend.verify_otp(db, db_user, rs.code, helpers.OTP_PURPOSE_VERIFY)

    principal = await create_and_notify_principal(db, schemas.PrincipalCreate(public_key=rs.public_key), db_user)

    await user_backend.verify_user(db, db_user)

    return principal


@component.register("com.deskconn.account.otp.resend")
async def otp_resend(email: str, db: AsyncSession = Depends(get_database)):
    db_user = await user_backend.get_user_by_email(db, email, for_update=True)
    if db_user is None:
        raise ApplicationError(uris.ERROR_USER_NOT_FOUND, f"User with email '{email}' not found")

    await user_backend.generate_and_save_otp(db, db_user, helpers.OTP_PURPOSE_VERIFY)


@component.register("com.deskconn.account.password.forget")
async def forget_password(email: str, db: AsyncSession = Depends(get_database)):
    db_user = await user_backend.get_user_by_email(db, email, for_update=True)
    if db_user is None:
        return None

    await user_backend.generate_and_save_otp(db, db_user, helpers.OTP_PURPOSE_PASSWORD_RESET)


@component.register("com.deskconn.account.password.reset")
async def reset_password(rs: schemas.PasswordReset, db: AsyncSession = Depends(get_database)):
    db_user = await user_backend.get_user_by_email(db, rs.email, for_update=True)
    if db_user is None:
        raise ApplicationError(uris.ERROR_USER_NOT_FOUND, f"User with email '{rs.email}' not found")

    await user_backend.verify_otp(db, db_user, rs.code, helpers.OTP_PURPOSE_PASSWORD_RESET)

    await user_backend.reset_password(db, db_user, rs.password)

    if not db_user.is_verified:
        await user_backend.verify_user(db, db_user)
