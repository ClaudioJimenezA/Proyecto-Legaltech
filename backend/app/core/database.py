"""Supabase client factory for backend persistence."""

from functools import lru_cache
from supabase import Client, create_client

from .config import get_settings


@lru_cache
def get_supabase_client() -> Client:
    """Return a cached Supabase client initialized with the backend secret key."""
    settings = get_settings()
    if not settings.supabase_url or not settings.supabase_secret_key:
        raise RuntimeError("SUPABASE_URL y SUPABASE_SECRET_KEY deben estar configurados en backend/.env")
    return create_client(settings.supabase_url, settings.supabase_secret_key)
