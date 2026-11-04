import getpass

from sqlalchemy import text

from backend.auth.password import (
    hash_password
)

from backend.database import engine


def create_user():

    username = input(
        "Enter username: "
    ).strip()


    if not username:

        print(
            "❌ Username cannot be empty."
        )

        return


    role = input(
        "Enter role (admin/analyst/viewer): "
    ).strip().lower()


    valid_roles = {
        "admin",
        "analyst",
        "viewer"
    }


    if role not in valid_roles:

        print(
            "❌ Invalid role."
        )

        return


    password = getpass.getpass(
        "Enter password: "
    )


    confirm_password = getpass.getpass(
        "Confirm password: "
    )


    if password != confirm_password:

        print(
            "❌ Passwords do not match."
        )

        return


    if len(password) < 8:

        print(
            "❌ Password must contain at least 8 characters."
        )

        return


    password_hash = hash_password(
        password
    )


    with engine.begin() as connection:

        existing_user = connection.execute(
            text("""
                SELECT id
                FROM users
                WHERE username = :username
            """),
            {
                "username": username
            }
        ).first()


        if existing_user:

            print(
                "❌ Username already exists."
            )

            return


        connection.execute(
            text("""
                INSERT INTO users
                (
                    username,
                    password_hash,
                    role,
                    is_active
                )
                VALUES
                (
                    :username,
                    :password_hash,
                    :role,
                    TRUE
                )
            """),
            {
                "username": username,
                "password_hash": password_hash,
                "role": role
            }
        )


    print(
        f"✅ User '{username}' "
        f"with role '{role}' created successfully."
    )


if __name__ == "__main__":

    create_user()
