from collections.abc import Callable

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.models import RefreshSession, User, utcnow
from app.security import decode_access_token

ACCESS_COOKIE = "access_token"
REFRESH_COOKIE = "refresh_token"


def trusted_origin(request: Request) -> None:
    """CSRF belt-and-braces on top of SameSite=strict: browsers always send Origin on cross-site POSTs."""
    origin = request.headers.get("origin")
    if origin and origin not in get_settings().CORS_ORIGINS:
        raise HTTPException(403, "Origem não permitida.")


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    token = request.cookies.get(ACCESS_COOKIE)
    auth = request.headers.get("authorization", "")
    if not token and auth.lower().startswith("bearer "):
        token = auth[7:]
    ids = decode_access_token(token) if token else None
    user = db.get(User, ids[0]) if ids else None
    sess = db.get(RefreshSession, ids[1]) if ids else None
    # the JWT is only good while its session is alive: logout / refresh-rotation revoke it immediately
    if not user or not user.is_active or not sess or sess.user_id != user.id or sess.revoked_at or sess.expires_at < utcnow():
        raise HTTPException(401, "Autenticação necessária.")
    return user


def require_roles(*roles: str) -> Callable[[User], User]:
    def dep(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(403, "Sem permissão.")
        return user

    return dep
