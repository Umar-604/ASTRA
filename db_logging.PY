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


def _ensure_table(engine: "Engine") -> None:
    """
    Create the logs table if it does not exist.
    """
    global _TABLE_ENSURED
    if _TABLE_ENSURED:
        return
    if text is None:
        return
    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS app_logs (
                        id BIGSERIAL PRIMARY KEY,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        level TEXT NOT NULL,
                        logger_name TEXT NOT NULL,
                        message TEXT NOT NULL,
                        pathname TEXT,
                        func_name TEXT,
                        line_no INTEGER,
                        process INTEGER,
                        thread INTEGER,
                        agent_id TEXT,
                        extra JSONB
                    );
                    """
                )
            )
        _TABLE_ENSURED = True
    except Exception:
        # Non-fatal: skip table ensure
        pass


class PostgresLogHandler(logging.Handler):
    """
    Logging handler that writes log records to a PostgreSQL table (app_logs).
    Safe-fails if DB is unavailable.
    """

    def __init__(self, dsn: Optional[str] = None, level: int = logging.INFO) -> None:
        super().__init__(level=level)
        self._engine = _ensure_engine(dsn)
        if self._engine is not None:
            _ensure_table(self._engine)
        self._local = threading.local()

    def emit(self, record: logging.LogRecord) -> None:
        try:
            # If engine not ready, try once to initialize
            if self._engine is None:
                self._engine = _ensure_engine()
                if self._engine is None:
                    return
                _ensure_table(self._engine)