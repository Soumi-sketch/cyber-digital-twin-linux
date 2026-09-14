import bcrypt


def hash_password(
    password
):

    password_bytes = password.encode(
        "utf-8"
    )

    salt = bcrypt.gensalt()

    password_hash = bcrypt.hashpw(
        password_bytes,
        salt
    )

    return password_hash.decode(
        "utf-8"
    )


def verify_password(
    password,
    password_hash
):

    password_bytes = password.encode(
        "utf-8"
    )

    hash_bytes = password_hash.encode(
        "utf-8"
    )

    return bcrypt.checkpw(
        password_bytes,
        hash_bytes
    )
