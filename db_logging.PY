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