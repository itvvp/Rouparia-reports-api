from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.routers import auth

s = get_settings()
app = FastAPI(
    title="Rouparia API",
    docs_url=None if s.PRODUCTION else "/docs",
    redoc_url=None,
    openapi_url=None if s.PRODUCTION else "/openapi.json",
)
app.add_middleware(
    CORSMiddleware, allow_origins=s.CORS_ORIGINS, allow_credentials=True,
    allow_methods=["GET", "POST"], allow_headers=["Content-Type"],
)
app.include_router(auth.router)


@app.get("/health")
def health(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        raise HTTPException(503, "Base de dados indisponível.")
    return {"status": "ok"}
