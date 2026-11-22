"""Centralized application configuration loaded from environment variables."""

from dataclasses import dataclass
from functools import lru_cache
import os
from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Settings:
    """Application settings sourced from .env / environment variables."""

    supabase_url: str
    supabase_secret_key: str
    jwt_secret: str
    allowed_origins: list[str]


@lru_cache
def get_settings() -> Settings:
    """Return cached Settings instance."""
    raw_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
    origins = [o.strip() for o in raw_origins.split(",") if o.strip()]
    return Settings(
        supabase_url=os.getenv("SUPABASE_URL", ""),
        supabase_secret_key=os.getenv("SUPABASE_SECRET_KEY", ""),
        jwt_secret=os.getenv("JWT_SECRET", ""),
        allowed_origins=origins,
    )
