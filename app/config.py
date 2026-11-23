from functools import lru_cache
from typing import Literal
from urllib.parse import quote_plus

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _esc(v: str) -> str:
    """ODBC connection-string value: brace-quote so ';' or '}' in a password can't break the string."""
    return "{" + v.replace("}", "}}") + "}"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    PRODUCTION: bool = False

    SQLSRV_HOST: str  # "host,port"
    SQLSRV_USER: str
    SQLSRV_PASS: str
    SQLSRV_DB: str
    ODBC_DRIVER: str = "ODBC Driver 17 for SQL Server"
    SQLSRV_TRUST_CERT: Literal["yes", "no"] = "yes"

    SECRET_KEY: str = Field(min_length=32)
    JWT_ISSUER: str = "rouparia-api"
    JWT_AUDIENCE: str = "rouparia"
    ACCESS_TOKEN_MINUTES: int = 15
    REFRESH_TOKEN_DAYS: int = 7
    MAX_FAILED_LOGINS: int = 5
    LOCKOUT_MINUTES: int = 15

    CORS_ORIGINS: list[str] = ["http://localhost:3040"]

    @model_validator(mode="after")
    def no_trusted_cert_in_production(self):
        if self.PRODUCTION and self.SQLSRV_TRUST_CERT != "no":
            raise ValueError("SQLSRV_TRUST_CERT=yes is forbidden when PRODUCTION=true")
        return self

    @property
    def database_url(self) -> str:
        odbc = (
            f"DRIVER={_esc(self.ODBC_DRIVER)};SERVER={self.SQLSRV_HOST};DATABASE={_esc(self.SQLSRV_DB)};"
            f"UID={_esc(self.SQLSRV_USER)};PWD={_esc(self.SQLSRV_PASS)};"
            f"Encrypt=yes;TrustServerCertificate={self.SQLSRV_TRUST_CERT};Connection Timeout=10"
        )
        return f"mssql+pyodbc:///?odbc_connect={quote_plus(odbc)}"


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]  # values come from .env / environment
