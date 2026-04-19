import os
import logging
import threading
from typing import Optional, Any, Dict

try:
    # SQLAlchemy is already used in this repo
    from sqlalchemy import create_engine, text
    from sqlalchemy.engine import Engine
except Exception:  # pragma: no cover
    create_engine = None  # type: ignore
    Engine = Any  # type: ignore
    text = None  # type: ignore


_ENGINE_LOCK = threading.Lock()
_ENGINE: Optional["Engine"] = None
_TABLE_ENSURED = False


def _get_dsn() -> Optional[str]:
    """
    Resolve a PostgreSQL DSN from environment.
    Prefers POSTGRES_DSN, falls back to DATABASE_URL.
    """
    dsn = os.getenv("POSTGRES_DSN") or os.getenv("DATABASE_URL")
    return dsn


def _ensure_engine(dsn: Optional[str] = None) -> Optional["Engine"]:
    """
    Lazily create a shared SQLAlchemy engine.
    """
    global _ENGINE
    if _ENGINE is not None:
        return _ENGINE
    if create_engine is None:
        return None
    with _ENGINE_LOCK:
        if _ENGINE is not None:
            return _ENGINE
        _dsn = dsn or _get_dsn()
        if not _dsn:
            return None
        try:
            _ENGINE = create_engine(_dsn, pool_pre_ping=True)
            return _ENGINE
        except Exception:
            return None