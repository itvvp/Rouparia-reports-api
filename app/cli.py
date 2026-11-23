"""Uso: python -m app.cli create-superuser --email a@b.pt --name "Nome"  (pede a palavra-passe; não fica em logs)"""
import argparse
import getpass
import sys

from sqlalchemy import select

from app.database import SessionLocal
from app.models import User
from app.security import check_password_strength, hash_password


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["create-superuser"])
    ap.add_argument("--email", required=True)
    ap.add_argument("--name", required=True)
    a = ap.parse_args()
    pw = getpass.getpass("Palavra-passe: ")
    if pw != getpass.getpass("Repetir: "):
        sys.exit("As palavras-passe não coincidem.")
    try:
        check_password_strength(pw)
    except ValueError as e:
        sys.exit(str(e))
    with SessionLocal() as db:
        if db.scalar(select(User).where(User.email == a.email.lower())):
            sys.exit("Já existe um utilizador com esse e-mail.")
        db.add(User(name=a.name, email=a.email.lower(), password_hash=hash_password(pw), role="superuser"))
        db.commit()
    print(f"Superuser {a.email} criado.")


if __name__ == "__main__":
    main()
