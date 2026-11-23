from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.deps import ACCESS_COOKIE, REFRESH_COOKIE, get_current_user, require_roles, trusted_origin
from app.models import RefreshSession, User, utcnow
from app.schemas import LoginRequest, UserCreate, UserOut
from app.security import (
    create_access_token, hash_password, hash_token, new_refresh_token, verify_password,
)

router = APIRouter(prefix="/auth", tags=["auth"])


def _set_cookies(resp: Response, user_id: int, db: Session) -> None:
    s = get_settings()
    raw, hashed = new_refresh_token()
    sess = RefreshSession(user_id=user_id, token_hash=hashed, expires_at=utcnow() + timedelta(days=s.REFRESH_TOKEN_DAYS))
    db.add(sess)
    db.commit()
    common = dict(httponly=True, secure=s.PRODUCTION, samesite="strict")
    resp.set_cookie(ACCESS_COOKIE, create_access_token(user_id, sess.id), max_age=s.ACCESS_TOKEN_MINUTES * 60, path="/", **common)
    # refresh cookie only travels to /auth/*
    resp.set_cookie(REFRESH_COOKIE, raw, max_age=s.REFRESH_TOKEN_DAYS * 86400, path="/auth", **common)


def _clear_cookies(resp: Response) -> None:
    resp.delete_cookie(ACCESS_COOKIE, path="/")
    resp.delete_cookie(REFRESH_COOKIE, path="/auth")


@router.post("/login", dependencies=[Depends(trusted_origin)])
def login(data: LoginRequest, response: Response, db: Session = Depends(get_db)):
    s = get_settings()
    user = db.scalar(select(User).where(User.email == data.email.lower()))
    if user and user.locked_until and user.locked_until > utcnow():
        raise HTTPException(429, "Demasiadas tentativas. Tenta mais tarde.", headers={"Retry-After": str(s.LOCKOUT_MINUTES * 60)})

    if not (verify_password(data.password, user.password_hash if user else None) and user and user.is_active):
        if user:
            user.failed_logins += 1
            if user.failed_logins >= s.MAX_FAILED_LOGINS:
                user.failed_logins, user.locked_until = 0, utcnow() + timedelta(minutes=s.LOCKOUT_MINUTES)
            db.commit()
        raise HTTPException(401, "E-mail ou palavra-passe incorretos.")

    user.failed_logins, user.locked_until = 0, None
    _set_cookies(response, user.id, db)
    return {"user": UserOut.model_validate(user)}


@router.get("/getUserAuth", response_model=UserOut)
def get_user_auth(user: User = Depends(get_current_user)):
    return user


@router.post("/refresh", dependencies=[Depends(trusted_origin)])
def refresh(request: Request, response: Response, db: Session = Depends(get_db)):
    raw = request.cookies.get(REFRESH_COOKIE)
    sess = db.scalar(select(RefreshSession).where(RefreshSession.token_hash == hash_token(raw))) if raw else None
    user = db.get(User, sess.user_id) if sess else None
    if not sess or sess.revoked_at or sess.expires_at < utcnow() or not user or not user.is_active:
        _clear_cookies(response)
        raise HTTPException(401, "Sessão inválida ou expirada.")
    sess.revoked_at = utcnow()  # rotation: each refresh token works once
    _set_cookies(response, user.id, db)
    return {"user": UserOut.model_validate(user)}


@router.post("/logout", dependencies=[Depends(trusted_origin)])
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    raw = request.cookies.get(REFRESH_COOKIE)
    if raw:
        db.execute(update(RefreshSession).where(RefreshSession.token_hash == hash_token(raw)).values(revoked_at=utcnow()))
        db.commit()
    _clear_cookies(response)
    return {"message": "Sessão encerrada."}


@router.post("/createUser", response_model=UserOut, status_code=201, dependencies=[Depends(trusted_origin)])
def create_user(data: UserCreate, actor: User = Depends(require_roles("admin", "superuser")), db: Session = Depends(get_db)):
    if data.role != "user" and actor.role != "superuser":
        raise HTTPException(403, "Só um superuser cria admins ou superusers.")
    user = User(name=data.name.strip(), email=data.email.lower(), password_hash=hash_password(data.password), role=data.role)
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Já existe um utilizador com esse e-mail.")
    return user
