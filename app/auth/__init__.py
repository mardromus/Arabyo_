"""Firebase Auth integration — token verification, role resolution, session handling."""
from app.auth.firebase_auth import (
    init_firebase,
    verify_token,
    get_user_role,
    current_user_required,
    login_required,
    admin_required,
)

__all__ = [
    "init_firebase",
    "verify_token",
    "get_user_role",
    "current_user_required",
    "login_required",
    "admin_required",
]
