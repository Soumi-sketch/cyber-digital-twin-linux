import os

from datetime import (
    datetime,
    timedelta,
    timezone
)

from dotenv import (
    load_dotenv
)

from jose import (
    JWTError,
    jwt
)


load_dotenv(
    dotenv_path="/root/cyber-digital-twin/.env",
    override=True
)


SECRET_KEY = os.getenv(
    "JWT_SECRET_KEY"
)


if not SECRET_KEY:

    raise RuntimeError(
        "JWT_SECRET_KEY is not configured."
    )


ALGORITHM = "HS256"


ACCESS_TOKEN_EXPIRE_MINUTES = 60


def create_access_token(
    data
):

    to_encode = data.copy()


    expire = datetime.now(
        timezone.utc
    ) + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )


    to_encode.update(
        {
            "exp": expire
        }
    )


    encoded_jwt = jwt.encode(
        to_encode,
        SECRET_KEY,
        algorithm=ALGORITHM
    )


    return encoded_jwt


def verify_access_token(
    token
):

    try:

        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[
                ALGORITHM
            ]
        )


        username = payload.get(
            "sub"
        )


        if username is None:

            return None


        return payload


    except JWTError:

        return None

