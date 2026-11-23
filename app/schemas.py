from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.security import check_password_strength


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class UserCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    email: EmailStr
    password: str
    role: Literal["user", "admin", "superuser"] = "user"

    _strength = field_validator("password")(check_password_strength)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str  # the frontend types ids as strings
    name: str
    email: str
    role: str

    @field_validator("id", mode="before")
    @classmethod
    def _id_str(cls, v):
        return str(v)
