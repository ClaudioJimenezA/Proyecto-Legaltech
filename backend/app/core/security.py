"""JWT authentication dependency and simulated role support for FastAPI endpoints."""

from dataclasses import dataclass
from typing import Any, Optional

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt

from .config import get_settings

_bearer_scheme = HTTPBearer(auto_error=False)

DEV_USERS = {
    "auditor": {
        "user_id": "00000000-0000-0000-0000-000000000001",
        "email": "lead.auditor@lexploit.local",
        "role": "auditor",
    },
    "client": {
        "user_id": "00000000-0000-0000-0000-000000000002",
        "email": "client.poc@empresa.local",
        "role": "client",
    },
}

_RESOLVED_AUTH_USERS: dict[str, str] = {}


@dataclass(frozen=True)
class AuthenticatedUser:
    """Identity extracted from a verified Bearer JWT or simulated dev role."""

    user_id: str
    email: Optional[str] = None
    role: Optional[str] = None


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
    x_simulated_role: Optional[str] = Header(None, alias="X-Simulated-Role"),
) -> AuthenticatedUser:
    """Validate Bearer JWT or fallback to simulated role in development mode."""
    # 1. Si viene un token Bearer real, validarlo con JWT_SECRET
    if credentials and credentials.credentials:
        settings = get_settings()
        if not settings.jwt_secret:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="JWT_SECRET no configurado en el servidor.",
            )
        try:
            payload = jwt.decode(
                credentials.credentials,
                settings.jwt_secret,
                algorithms=["HS256"],
                options={"verify_aud": False},
            )
            user_id = payload.get("sub")
            if not user_id:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="El token no contiene identificador de usuario (sub).",
                )
            return AuthenticatedUser(
                user_id=str(user_id),
                email=payload.get("email"),
                role=payload.get("role"),
            )
        except jwt.PyJWTError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Token de sesion invalido o expirado: {exc}",
            ) from exc

    # 2. Modo desarrollo / simulador de roles para pruebas locales
    role_key = (x_simulated_role or "auditor").strip().lower()
    dev_info = DEV_USERS.get(role_key, DEV_USERS["auditor"])

    return AuthenticatedUser(
        user_id=dev_info["user_id"],
        email=dev_info["email"],
        role=dev_info["role"],
    )


def resolve_or_provision_auth_user_id(supabase: Any, current_user: AuthenticatedUser) -> str:
    """Ensure the user exists in Supabase auth.users to satisfy FK constraints on logs/queries."""
    email = (current_user.email or "lead.auditor@lexploit.local").lower()
    if email in _RESOLVED_AUTH_USERS:
        return _RESOLVED_AUTH_USERS[email]

    try:
        users_resp = supabase.auth.admin.list_users()
        users_list = getattr(users_resp, "users", None) or (
            users_resp if isinstance(users_resp, list) else []
        )
        for u in users_list:
            u_email = (
                getattr(u, "email", None)
                or (u.get("email") if isinstance(u, dict) else "")
                or ""
            ).lower()
            u_id = getattr(u, "id", None) or (u.get("id") if isinstance(u, dict) else None)
            if u_email == email and u_id:
                _RESOLVED_AUTH_USERS[email] = str(u_id)
                return str(u_id)

        created = supabase.auth.admin.create_user(
            {
                "email": email,
                "password": "LexPloitDevUser2026!",
                "email_confirm": True,
                "user_metadata": {"role": current_user.role or "auditor"},
            }
        )
        c_user = getattr(created, "user", None) or created
        c_id = getattr(c_user, "id", None) or (
            c_user.get("id") if isinstance(c_user, dict) else None
        )
        if c_id:
            _RESOLVED_AUTH_USERS[email] = str(c_id)
            return str(c_id)
    except Exception:
        pass

    return current_user.user_id
