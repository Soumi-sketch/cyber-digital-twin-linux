import getpass

from sqlalchemy import text

from backend.auth.password import (
    hash_password
)

from backend.database import engine


def create_admin_user():

    username = input(
        "Enter admin username: "
    ).strip()

    if not username:

        print(
            "❌ Username cannot be empty."
        )

        return


    password = getpass.getpass(
        "Enter admin password: "
    )

    confirm_password = getpass.getpass(
        "Confirm admin password: "
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
                    'admin',
                    TRUE
                )
            """),
            {
                "username": username,
                "password_hash": password_hash
            }
        )


    print(
        f"✅ Admin user '{username}' created successfully."
    )


if __name__ == "__main__":

    create_admin_user()
