
import os
import uuid

from datetime import (
    datetime,
    timedelta,
    timezone
)

from dotenv import load_dotenv
from jose import JWTError, jwt
from sqlalchemy import text

from backend.database import engine


load_dotenv(
    dotenv_path="/root/cyber-digital-twin/.env",
    override=True
)


SECRET_KEY = os.getenv("JWT_SECRET_KEY")

if not SECRET_KEY:
    raise RuntimeError(
        "JWT_SECRET_KEY is not configured."
    )


ALGORITHM = "HS256"

ACCESS_TOKEN_EXPIRE_MINUTES = 60

JWT_ISSUER = "cyber-digital-twin"

JWT_AUDIENCE = "cyber-digital-twin-dashboard"


def create_access_token(data):

    to_encode = data.copy()

    now = datetime.now(timezone.utc)

    expire = now + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )

    to_encode.update({
        "exp": expire,
        "iat": now,
        "jti": str(uuid.uuid4()),
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE
    })

    encoded_jwt = jwt.encode(
        to_encode,
        SECRET_KEY,
        algorithm=ALGORITHM
    )

    return encoded_jwt


def verify_access_token(token):

    try:

        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            issuer=JWT_ISSUER,
            audience=JWT_AUDIENCE,
            options={
                "require_exp": True,
                "require_sub": True,
                "require_iat": True,
                "require_jti": True,
                "require_iss": True,
                "require_aud": True
            }
        )

        username = payload.get("sub")
        token_id = payload.get("jti")

        if not username or not token_id:
            return None

        with engine.connect() as connection:

            revoked = connection.execute(
                text("""
                    SELECT 1
                    FROM revoked_tokens
                    WHERE jti = :jti
                    LIMIT 1
                """),
                {"jti": token_id}
            ).first()

        if revoked:
            return None

        return payload

    except JWTError:
        return None


def revoke_access_token(payload):

    token_id = payload["jti"]

    expires_at = datetime.fromtimestamp(
        payload["exp"],
        timezone.utc
    )

    with engine.begin() as connection:

        connection.execute(
            text("""
                INSERT INTO revoked_tokens (
                    jti,
                    expires_at
                )
                VALUES (
                    :jti,
                    :expires_at
                )
            """),
            {
                "jti": token_id,
                "expires_at": expires_at
            }
        )
