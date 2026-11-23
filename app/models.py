from datetime import UTC, datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Unicode
from sqlalchemy.dialects.mssql import DATETIME2
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

DT = DateTime().with_variant(DATETIME2(), "mssql")
# e-mail is unique case-insensitively on SQL Server; we also store it lower-cased, so SQLite (tests) behaves the same
EMAIL = String(255).with_variant(String(255, collation="Latin1_General_CI_AS"), "mssql")
ROLES = ("user", "admin", "superuser")


def utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)  # naive UTC, matches DATETIME2


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        Index("ux_users_email", "email", unique=True),
        CheckConstraint("role IN ('user', 'admin', 'superuser')", name="ck_users_role"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(Unicode(255))
    email: Mapped[str] = mapped_column(EMAIL)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(10), default="user")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DT, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DT, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DT, default=utcnow, onupdate=utcnow)


class RefreshSession(Base):
    """One row per issued refresh token (only its SHA-256 is stored). Rotated on every refresh."""

    __tablename__ = "refresh_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime] = mapped_column(DT)
    revoked_at: Mapped[datetime | None] = mapped_column(DT, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DT, default=utcnow)
