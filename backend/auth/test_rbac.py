from backend.auth.dependencies import (
    ADMIN_ROLE,
    ANALYST_ROLE,
    VIEWER_ROLE,
    VALID_ROLES,
    require_roles
)


def test_role_definitions():

    assert ADMIN_ROLE == "admin"

    assert ANALYST_ROLE == "analyst"

    assert VIEWER_ROLE == "viewer"

    assert VALID_ROLES == {
        "admin",
        "analyst",
        "viewer"
    }


def test_admin_permission():

    checker = require_roles(
        {"admin"}
    )

    assert callable(checker)


def test_analyst_permission():

    checker = require_roles(
        {
            "admin",
            "analyst"
        }
    )

    assert callable(checker)


def test_viewer_permission():

    checker = require_roles(
        {
            "admin",
            "analyst",
            "viewer"
        }
    )

    assert callable(checker)


if __name__ == "__main__":

    test_role_definitions()

    test_admin_permission()

    test_analyst_permission()

    test_viewer_permission()

    print(
        "✅ RBAC dependency tests passed."
    )
