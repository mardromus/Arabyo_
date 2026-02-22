"""Firebase Auth backend — verify ID tokens, resolve roles from email whitelists."""
import os
import logging
import json
import urllib.error
import urllib.parse
import urllib.request
from functools import wraps

from app.config import (
    FIREBASE_SERVICE_ACCOUNT_PATH,
    FIREBASE_CONFIG,
    ADMIN_EMAILS,
    RISK_MANAGER_EMAILS,
    AUDITOR_EMAILS,
)

logger = logging.getLogger(__name__)

_firebase_initialized = False
TOKENINFO_URL = "https://oauth2.googleapis.com/tokeninfo?id_token="


def _verify_token_via_http(id_token: str) -> tuple[dict | None, str | None]:
    """
    Verify Firebase/Google ID token using Google's tokeninfo endpoint.
    No firebase-admin or grpcio required. Returns (claims, error_code) like verify_token().
    """
    token = id_token.strip()
    if not token:
        return None, "invalid"
    project_id = (FIREBASE_CONFIG or {}).get("projectId") or ""
    try:
        req = urllib.request.Request(TOKENINFO_URL + urllib.parse.quote(token, safe=""))
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 400:
            body = {}
            try:
                body = json.loads(e.read().decode()) if e.fp else {}
            except Exception:
                pass
            err = (body.get("error_description") or body.get("error") or str(e)).lower()
            if "expired" in err or "exp" in err:
                return None, "expired"
            return None, "invalid"
        return None, "unavailable"
    except Exception as e:
        logger.warning("[Auth] Tokeninfo request failed: %s", e)
        return None, "unavailable"
    aud = data.get("aud") or ""
    if project_id and aud != project_id:
        try:
            if not aud.startswith(project_id):
                return None, "invalid"
        except Exception:
            return None, "invalid"
    email = (data.get("email") or "").strip().lower()
    return (
        {
            "uid": data.get("sub", ""),
            "email": email,
            "name": (data.get("name") or email.split("@")[0] if email else ""),
        },
        None,
    )


def init_firebase():
    """
    Initialize Firebase Admin SDK. Safe to call multiple times.
    Returns (True, None) on success, (False, reason_code) on failure.
    reason_code: 'firebase_not_installed' | 'service_account_not_found' | 'service_account_invalid' | 'init_error'
    """
    global _firebase_initialized
    if _firebase_initialized:
        return True, None
    path = os.path.abspath(os.path.expanduser(FIREBASE_SERVICE_ACCOUNT_PATH))
    try:
        import firebase_admin
        from firebase_admin import credentials
    except ImportError as e:
        logger.warning("[Auth] Firebase Admin SDK not installed: %s", e)
        return False, "firebase_not_installed"
    if not os.path.exists(path):
        logger.warning("[Auth] Service account file not found: %s", path)
        return False, "service_account_not_found"
    try:
        cred = credentials.Certificate(path)
        firebase_admin.initialize_app(cred)
        _firebase_initialized = True
        logger.info("[Auth] Firebase Admin SDK initialized")
        return True, None
    except Exception as e:
        logger.error("[Auth] Firebase init failed: %s", e)
        return False, "service_account_invalid" if "Certificate" in type(e).__name__ or "JSON" in str(e) else "init_error"


def verify_token(id_token: str) -> tuple[dict | None, str | None]:
    """
    Verify Firebase ID token and return (claims, error_code).
    Uses Firebase Admin SDK if available; otherwise falls back to Google tokeninfo HTTP API
    (no grpcio/firebase-admin required).
    """
    if not id_token or not id_token.strip():
        return None, "invalid"
    ok, init_reason = init_firebase()
    if ok:
        try:
            from firebase_admin import auth
            decoded = auth.verify_id_token(id_token.strip())
            return (
                {
                    "uid": decoded.get("uid"),
                    "email": (decoded.get("email") or "").strip().lower(),
                    "name": decoded.get("name") or (decoded.get("email") or "").split("@")[0],
                },
                None,
            )
        except Exception as e:
            err_str = str(e).lower()
            if "expired" in err_str or "expiredidtokenerror" in type(e).__name__.lower():
                logger.info("[Auth] Token expired")
                return None, "expired"
            logger.warning("[Auth] Token verification failed: %s", e)
            return None, "invalid" if "signature" in err_str or "invalid" in err_str else "unavailable"
    # Fallback: verify via Google tokeninfo (no firebase-admin/grpcio needed)
    logger.info("[Auth] Using HTTP tokeninfo (Firebase Admin SDK not available)")
    return _verify_token_via_http(id_token)


def get_user_role(email: str) -> str:
    """
    Resolve role: check user_roles table first, then env whitelists.
    Order: admin > risk_manager > auditor > analyst (default).
    """
    if not email:
        return "analyst"
    email = email.strip().lower()
    try:
        from app.db import query
        rows = query("SELECT role FROM user_roles WHERE email = %s", [email])
        if rows:
            return rows[0].get("role", "analyst")
    except Exception:
        pass
    if email in ADMIN_EMAILS:
        return "admin"
    if email in RISK_MANAGER_EMAILS:
        return "risk_manager"
    if email in AUDITOR_EMAILS:
        return "auditor"
    return "analyst"


def _get_current_user_from_session(session):
    """Get current user dict from Flask session."""
    return session.get("user")


def current_user_required(f):
    """
    Decorator that requires a logged-in user.
    Injects current_user via g.current_user. Redirects to /login if not authenticated.
    """

    @wraps(f)
    def inner(*args, **kwargs):
        from flask import session, redirect, url_for, request, g

        user = _get_current_user_from_session(session)
        if not user:
            session["next"] = request.url
            return redirect(url_for("login"))
        g.current_user = user
        return f(*args, **kwargs)

    return inner


def login_required(f):
    """
    Decorator that requires a logged-in user.
    Stores current_user in g.current_user and redirects to /login if not authenticated.
    """

    @wraps(f)
    def inner(*args, **kwargs):
        from flask import session, redirect, url_for, request, g

        user = _get_current_user_from_session(session)
        if not user:
            session["next"] = request.url
            return redirect(url_for("login"))
        g.current_user = user
        return f(*args, **kwargs)

    return inner


def admin_required(f):
    """Decorator that requires admin role. Returns 403 if not admin."""

    @wraps(f)
    def inner(*args, **kwargs):
        from flask import session, jsonify, redirect, url_for, request

        user = _get_current_user_from_session(session)
        if not user:
            if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify({"error": "Unauthorized"}), 401
            session["next"] = request.url
            return redirect(url_for("login"))
        if user.get("role") != "admin":
            if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify({"error": "Admin role required"}), 403
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)

    return inner
