import joblib
import orjson
from fastapi import FastAPI, HTTPException, Depends, Request, Query
from fastapi.responses import JSONResponse, Response
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel
from typing import List, Dict, Any, Tuple
from collections import deque
from src.config import settings
from src.response_engine import ResponseEngine, EngineConfig
import json
from datetime import datetime

try:
    # Optional aggregator (may not be present)
    from src.aggregator import create_flow_aggregator, extract_cicids_features, normalize_cicids_features  # type: ignore
    _AGG_AVAILABLE = True
except Exception:
    _AGG_AVAILABLE = False
    # Fallback no-ops to keep server booting without aggregator
    def create_flow_aggregator(*args, **kwargs):  # type: ignore
        return None
    def extract_cicids_features(*args, **kwargs):  # type: ignore
        return {}
    def normalize_cicids_features(*args, **kwargs):  # type: ignore
        return {}
    

from src.endpoint_predictor import create_endpoint_predictor
from src.process_predictor import create_process_predictor
from src.pipeline import Pipeline
import os
import warnings
import warnings
import sys
import asyncio
import json as _json
import logging
import os
from datetime import datetime, timedelta, timezone
import hmac
import hashlib as _hashlib
import base64
import time
import uuid
from pathlib import Path
from fastapi.middleware.cors import CORSMiddleware
try:
    from db_logging import attach_postgres_handler
except Exception:
    attach_postgres_handler = None
# Load environment variables from .env if present (to get POSTGRES_DSN/DATABASE_URL)
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

try:
    from nats.aio.client import Client as NATS
    from nats.js.api import StreamConfig
    _NATS_AVAILABLE = True
except Exception:
    _NATS_AVAILABLE = False

_INGEST_SUBJECT = os.getenv("INGEST_SUBJECT", "astra.events.ingest")
_RESPONSE_CMD_SUBJECT_PREFIX = os.getenv("RESPONSE_CMD_SUBJECT_PREFIX", "astra.response.commands.agent")
_RESPONSE_ACK_SUBJECT = os.getenv("RESPONSE_ACK_SUBJECT", "astra.response.acks")
_RESPONSE_DELIVERY_MODE = os.getenv("RESPONSE_DELIVERY_MODE", "hybrid").strip().lower()  # server | agent | hybrid


# Ensure all server output is also written to logs/logs.txt
try:
    os.makedirs("logs", exist_ok=True)
    _log_file_path = os.path.join("logs", "logs.txt")

    class _Tee:
        def __init__(self, stream, fh):
            self._stream = stream
            self._fh = fh

        def write(self, data):
            try:
                self._stream.write(data)
            except Exception:
                pass
            try:
                self._fh.write(data)
                self._fh.flush()
            except Exception:
                pass

            def flush(self):
            try:
                self._stream.flush()
            except Exception:
                pass
            try:
                self._fh.flush()
            except Exception:
                pass

        _log_fh = open(_log_file_path, "a", buffering=1, encoding="utf-8", errors="replace")
    sys.stdout = _Tee(sys.stdout, _log_fh)
    sys.stderr = _Tee(sys.stderr, _log_fh)
    print(f"📝 Logging to {_log_file_path}")
except Exception as _e:
    # If logging setup fails, continue without file logging
    pass

# Also send logs to PostgreSQL when configured
def _wire_postgres_logging() -> None:
    if not attach_postgres_handler:
        return
    # Resolve DSN from env or settings

    dsn = os.getenv("POSTGRES_DSN") or os.getenv("DATABASE_URL") or getattr(settings, "DATABASE_URL", None)
    try:
        targets = [
            logging.getLogger(),  # root
            logging.getLogger("uvicorn"),
            logging.getLogger("uvicorn.error"),
            logging.getLogger("uvicorn.access"),
            logging.getLogger(__name__),
        ]
        for lg in targets:
            try:
                attach_postgres_handler(lg, dsn=dsn)
            except Exception:
                # Never break logging due to handler issues
                pass
        # Emit one line to ensure table exists and first insert happens
        logging.getLogger(__name__).info("Startup: PostgreSQL logging wired")
    except Exception:
        pass

_wire_postgres_logging()

# Suppress XGBoost mutex warnings
os.environ['OMP_NUM_THREADS'] = '1'
os.environ['OPENBLAS_NUM_THREADS'] = '1'
os.environ['MKL_NUM_THREADS'] = '1'
os.environ['NUMEXPR_NUM_THREADS'] = '1'

# Suppress specific warnings
warnings.filterwarnings('ignore', category=UserWarning, module='xgboost')


app = FastAPI(title="ASTRA-ML")

# -------------------- Security: CORS, Allowlist, Rate limit, JWT/RBAC --------------------
_ALLOWED_ORIGINS = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "").split(",") if o.strip()]
_STRICT_CORS = os.getenv("STRICT_CORS", "1") == "1"
if not _ALLOWED_ORIGINS and _STRICT_CORS:
    raise RuntimeError("CORS is strict and ALLOWED_ORIGINS is empty. Set ALLOWED_ORIGINS for production.")
app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS if _ALLOWED_ORIGINS else ["https://127.0.0.1:5173", "https://localhost:5173"],  # minimal fallback in dev
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

@app.exception_handler(RequestValidationError)
async def _hide_validation_details(request: Request, exc: RequestValidationError):
    # Reduce attack surface: never leak validation structure/details
    return JSONResponse({"detail": "Invalid request"}, status_code=400)


_ALLOWLIST_PATHS = [p.strip() for p in os.getenv("ALLOWLIST_PATHS", "/health,/alerts,/events/,/audit/verify,/ui,/ui/alerts,/ui/threats/summary,/ui/integrity/,/auth/login,/auth/signup,/auth/refresh,/agents,/agents/").split(",") if p.strip()]
_RATE_LIMIT_PER_MIN = int(os.getenv("RATE_LIMIT_PER_MIN", "600"))
_JWT_SECRET = os.getenv("JWT_SECRET", "")
_ACCESS_TTL_MIN = int(os.getenv("ACCESS_TOKEN_TTL_MIN", "15"))
_REFRESH_TTL_DAYS = int(os.getenv("REFRESH_TOKEN_TTL_DAYS", "7"))
_AGENT_TOKEN_TTL_DAYS = int(os.getenv("AGENT_TOKEN_TTL_DAYS", "90"))
_SERVICE_TOKENS = {t.strip() for t in os.getenv("SERVICE_TOKENS", "").split(",") if t.strip()}
_LOGIN_RATE_LIMIT_PER_MIN = int(os.getenv("LOGIN_RATE_LIMIT_PER_MIN", "30"))
_LOGIN_MAX_FAILURES = int(os.getenv("LOGIN_MAX_FAILURES", "5"))
_LOGIN_LOCKOUT_MIN = int(os.getenv("LOGIN_LOCKOUT_MIN", "15"))
_PASSWORD_MIN_LEN = int(os.getenv("PASSWORD_MIN_LEN", "12"))


_rl_state: dict[str, tuple[int, int]] = {}  # ip -> (window_start_ts, count)
_login_rl: dict[str, tuple[int, int]] = {}  # ip -> (window_start_ts, count)

def _path_allowed(path: str) -> bool:
    for p in _ALLOWLIST_PATHS:
        if p.endswith("/"):
            if path.startswith(p.rstrip("/")):
                return True
        else:
            if path == p:
                return True
    return False


@app.middleware("http")
async def _allowlist_and_rate_limit(request: Request, call_next):
    path = request.url.path
    # Let CORSMiddleware handle preflight and attach proper CORS headers
    if request.method == "OPTIONS":
        return await call_next(request)
    # Always allow authentication endpoints (defensive default)
    if path.startswith("/auth/"):
        return await call_next(request)
    # Allow agent provisioning endpoints (admin-protected at route level)
    if path.startswith("/agents"):
        return await call_next(request)
    # Allow UI summary endpoints (read-only, still RBAC'd at route level)
    if path.startswith("/ui/"):
        return await call_next(request)
    # Allow OpenAPI/docs endpoints (useful for dev/testing)
    if path in ("/openapi.json", "/docs", "/redoc") or path.startswith("/docs/") or path.startswith("/redoc/"):
        return await call_next(request)
    # Allow audit verify endpoint (RBAC at route level)
    if path.startswith("/audit/verify"):
        return await call_next(request)
    # Allow audit listing endpoint for UI
    if path == "/audit":
        return await call_next(request)
    # Allow audit logs endpoint for UI
    if path.startswith("/audit/logs"):
        return await call_next(request)
    # Allow hosts list and per-host alerts (RBAC at route level)
    if path.startswith("/hosts"):
        return await call_next(request)
    # Allow observability endpoints (read-only, for dashboard charts)
    if path.startswith("/observability"):
        return await call_next(request)
    # Allow event detail and other UI/API paths (RBAC at route level)
    if path.startswith("/events") or path.startswith("/alerts"):
        return await call_next(request)
    # Admin settings (RBAC at route level; admin only)
    if path.startswith("/admin"):
        return await call_next(request)
    # Allow response endpoints (RBAC at route level)
    if path.startswith("/response"):
        return await call_next(request)
    # Allowlist
    if not _path_allowed(path):
        return JSONResponse({"detail": "Not found"}, status_code=404)
    # Rate limit (simple fixed window per IP)
    try:
        ip = request.client.host if request.client else "unknown"
        now = int(time.time())
        window = now // 60
        win, cnt = _rl_state.get(ip, (window, 0))
        if win != window:
            _rl_state[ip] = (window, 1)