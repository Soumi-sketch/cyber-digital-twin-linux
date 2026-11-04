from fastapi import (
    Depends,
    HTTPException
)

from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBearer
)

from backend.auth.jwt_handler import (
    verify_access_token
)


security = HTTPBearer()


ADMIN_ROLE = "admin"

ANALYST_ROLE = "analyst"

VIEWER_ROLE = "viewer"


VALID_ROLES = {
    ADMIN_ROLE,
    ANALYST_ROLE,
    VIEWER_ROLE
}


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(
        security
    )
):

    token = credentials.credentials

    payload = verify_access_token(
        token
    )

    if payload is None:

        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )

    return payload


def require_roles(
    allowed_roles
):

    def role_checker(
        current_user = Depends(
            get_current_user
        )
    ):

        user_role = current_user.get(
            "role"
        )

        if user_role not in VALID_ROLES:

            raise HTTPException(
                status_code=403,
                detail="Invalid user role"
            )

        if user_role not in allowed_roles:

            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions"
            )

        return current_user


    return role_checker
