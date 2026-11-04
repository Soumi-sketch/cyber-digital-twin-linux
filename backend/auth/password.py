
import bcrypt


def validate_password(password):
    errors = []

    if len(password) < 12:
        errors.append("Password must contain at least 12 characters.")

    if not any(char.isupper() for char in password):
        errors.append("Password must contain an uppercase letter.")

    if not any(char.islower() for char in password):
        errors.append("Password must contain a lowercase letter.")

    if not any(char.isdigit() for char in password):
        errors.append("Password must contain a number.")

    if not any(not char.isalnum() for char in password):
        errors.append("Password must contain a special character.")

    if len(password.encode("utf-8")) > 72:
        errors.append("Password must not exceed 72 UTF-8 bytes.")

    return errors


def hash_password(password):
    password_bytes = password.encode("utf-8")

    if len(password_bytes) > 72:
        raise ValueError("Password exceeds bcrypt's 72-byte limit.")

    salt = bcrypt.gensalt()

    password_hash = bcrypt.hashpw(
        password_bytes,
        salt
    )

    return password_hash.decode("utf-8")


def verify_password(password, password_hash):
    password_bytes = password.encode("utf-8")
    hash_bytes = password_hash.encode("utf-8")

    return bcrypt.checkpw(
        password_bytes,
        hash_bytes
    )
