from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from sqlalchemy import text

from backend.auth.password import (
    verify_password
)

from backend.auth.jwt_handler import (
    create_access_token
)

from backend.database import engine


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"]
)


class LoginRequest(
    BaseModel
):

    username: str

    password: str


@router.post("/login")
def login(
    credentials: LoginRequest
):

    with engine.connect() as connection:

        user = connection.execute(
            text("""
                SELECT
                    id,
                    username,
                    password_hash,
                    role,
                    is_active
                FROM users
                WHERE username = :username
            """),
            {
                "username": credentials.username
            }
        ).mappings().first()


    if not user:

        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )


    if not user["is_active"]:

        raise HTTPException(
            status_code=403,
            detail="User account is inactive"
        )


    password_valid = verify_password(
        credentials.password,
        user["password_hash"]
    )


    if not password_valid:

        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )


    access_token = create_access_token(
        {
            "sub": user["username"],
            "role": user["role"],
            "user_id": user["id"]
        }
    )


    return {
        "access_token": access_token,
        "token_type": "bearer",
        "username": user["username"],
        "role": user["role"]
    }
