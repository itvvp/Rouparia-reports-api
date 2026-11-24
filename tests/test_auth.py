import os

# Settings are required at import time; fake values so the tests never touch the real SQL Server.
for k, v in {"SQLSRV_HOST": "x,1433", "SQLSRV_USER": "x", "SQLSRV_PASS": "x", "SQLSRV_DB": "x",
             "SECRET_KEY": "test-secret-key-test-secret-key-0123456789"}.items():
    os.environ[k] = v

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import get_db
from app.main import app
from app.models import Base, User
from app.security import hash_password

ORIGIN = {"Origin": "http://localhost:3040"}
PW = "Certa1234"


@pytest.fixture
def client():
    engine = create_engine("sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(engine, expire_on_commit=False)
    with Session() as db:
        db.add_all([
            User(name="Su", email="su@x.pt", password_hash=hash_password(PW), role="superuser"),
            User(name="Ad", email="ad@x.pt", password_hash=hash_password(PW), role="admin"),
            User(name="Us", email="us@x.pt", password_hash=hash_password(PW), role="user"),
        ])
        db.commit()

    def override():
        with Session() as db:
            yield db

    app.dependency_overrides[get_db] = override
    with TestClient(app, base_url="http://localhost:8025") as c:
        yield c
    app.dependency_overrides.clear()


def login(c, email="us@x.pt", pw=PW):
    return c.post("/auth/login", json={"email": email, "password": pw}, headers=ORIGIN)


def test_login_session_refresh_logout(client):
    assert client.get("/auth/getUserAuth").status_code == 401
    assert login(client, pw="errada").status_code == 401

    r = login(client, "US@x.pt")  # e-mail is case-insensitive
    assert r.status_code == 200 and r.json()["user"]["email"] == "us@x.pt" and isinstance(r.json()["user"]["id"], str)
    assert "password" not in r.text
    assert client.get("/auth/getUserAuth").json()["name"] == "Us"

    old = client.cookies.get("refresh_token", path="/auth")
    assert client.post("/auth/refresh", headers=ORIGIN).status_code == 200
    assert client.cookies.get("refresh_token", path="/auth") != old  # rotated
    client.cookies.set("refresh_token", old, path="/auth")
    assert client.post("/auth/refresh", headers=ORIGIN).status_code == 401  # a used refresh token is dead

    login(client)
    assert client.post("/auth/logout", headers=ORIGIN).status_code == 200
    assert client.get("/auth/getUserAuth").status_code == 401
    assert client.post("/auth/refresh", headers=ORIGIN).status_code == 401


def test_lockout_after_5_failures(client):
    for _ in range(5):
        assert login(client, pw="errada").status_code == 401
    assert login(client).status_code == 429  # even the right password is refused while locked


def test_foreign_origin_is_rejected(client):
    r = client.post("/auth/login", json={"email": "us@x.pt", "password": PW}, headers={"Origin": "http://evil.example"})
    assert r.status_code == 403


def test_create_user_rules(client):
    new = {"name": "N", "email": "n@x.pt", "password": PW}
    login(client, "us@x.pt")
    assert client.post("/auth/createUser", json=new, headers=ORIGIN).status_code == 403  # plain user

    login(client, "ad@x.pt")
    assert client.post("/auth/createUser", json={**new, "password": "fraca"}, headers=ORIGIN).status_code == 422
    assert client.post("/auth/createUser", json={**new, "role": "admin"}, headers=ORIGIN).status_code == 403
    assert client.post("/auth/createUser", json=new, headers=ORIGIN).status_code == 201
    assert client.post("/auth/createUser", json=new, headers=ORIGIN).status_code == 409  # duplicate

    login(client, "su@x.pt")
    assert client.post("/auth/createUser", json={**new, "email": "a2@x.pt", "role": "admin"}, headers=ORIGIN).status_code == 201


def test_only_superuser_lists_users(client):
    for email in ("us@x.pt", "ad@x.pt"):
        login(client, email)
        assert client.get("/auth/users").status_code == 403
    login(client, "su@x.pt")
    r = client.get("/auth/users")
    assert r.status_code == 200 and {"us@x.pt", "ad@x.pt", "su@x.pt"} <= {u["email"] for u in r.json()}


def test_access_token_dies_with_its_session(client):
    login(client)
    token = client.cookies.get("access_token")
    assert client.get("/auth/getUserAuth").status_code == 200
    client.post("/auth/logout", headers=ORIGIN)
    client.cookies.set("access_token", token, path="/")  # replay the stolen JWT: still unexpired, but its session is revoked
    assert client.get("/auth/getUserAuth").status_code == 401


def test_jwt_must_have_right_signature_issuer_audience_and_claims(client):
    import jwt
    from datetime import UTC, datetime, timedelta
    from app.config import get_settings

    s = get_settings()
    login(client)
    good = client.cookies.get("access_token")
    claims = jwt.decode(good, s.SECRET_KEY, algorithms=["HS256"], audience=s.JWT_AUDIENCE)
    assert (claims["iss"], claims["aud"]) == (s.JWT_ISSUER, s.JWT_AUDIENCE) and {"sid", "sub", "exp", "iat"} <= claims.keys()

    def status(tok):
        client.cookies.set("access_token", tok, path="/")
        return client.get("/auth/getUserAuth").status_code

    assert status(good) == 200
    assert status(jwt.encode(claims, "outra-chave-outra-chave-outra-chave-12345", algorithm="HS256")) == 401  # wrong secret
    assert status(jwt.encode({**claims, "aud": "outra-app"}, s.SECRET_KEY, algorithm="HS256")) == 401
    assert status(jwt.encode({**claims, "iss": "outro"}, s.SECRET_KEY, algorithm="HS256")) == 401
    assert status(jwt.encode({k: v for k, v in claims.items() if k != "sid"}, s.SECRET_KEY, algorithm="HS256")) == 401
    assert status(jwt.encode({**claims, "exp": datetime.now(UTC) - timedelta(minutes=1)}, s.SECRET_KEY, algorithm="HS256")) == 401
    assert status(jwt.encode(claims, key="", algorithm="none")) == 401  # alg=none is refused
