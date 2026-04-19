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