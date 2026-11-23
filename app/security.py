import hashlib
import re
import secrets
from datetime import UTC, datetime, timedelta

import jwt
from pwdlib import PasswordHash

from app.config import get_settings

_ph = PasswordHash.recommended()  # argon2
_DUMMY = _ph.hash("not-a-real-password")  # verified when the e-mail is unknown, so timing doesn't reveal which accounts exist


def hash_password(p: str) -> str:
    return _ph.hash(p)


def verify_password(p: str, hashed: str | None) -> bool:
    return _ph.verify(p, hashed or _DUMMY) and hashed is not None


def check_password_strength(p: str) -> str:
    if len(p) < 8 or not re.search(r"[A-Z]", p) or not re.search(r"[a-z]", p) or not re.search(r"\d", p):
        raise ValueError("A palavra-passe deve ter 8+ caracteres, com maiúscula, minúscula e número.")
    return p


def create_access_token(user_id: int, sid: int) -> str:
    """JWT HS256. sid = the refresh session it belongs to, so revoking the session (logout/rotation) kills this token too."""
    s = get_settings()
    now = datetime.now(UTC)
    return jwt.encode(
        {"iss": s.JWT_ISSUER, "aud": s.JWT_AUDIENCE, "sub": str(user_id), "sid": sid, "type": "access",
         "iat": now, "exp": now + timedelta(minutes=s.ACCESS_TOKEN_MINUTES)},
        s.SECRET_KEY, algorithm="HS256",
    )


def decode_access_token(token: str) -> tuple[int, int] | None:
    """-> (user_id, session_id), or None for anything invalid: bad signature, expired, wrong iss/aud, missing claims."""
    s = get_settings()
    try:
        p = jwt.decode(
            token, s.SECRET_KEY, algorithms=["HS256"], issuer=s.JWT_ISSUER, audience=s.JWT_AUDIENCE,
            options={"require": ["exp", "iat", "iss", "aud", "sub", "sid"]},
        )
        return (int(p["sub"]), int(p["sid"])) if p.get("type") == "access" else None
    except (jwt.PyJWTError, ValueError, TypeError):
        return None


def hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def new_refresh_token() -> tuple[str, str]:
    raw = secrets.token_urlsafe(48)
    return raw, hash_token(raw)
