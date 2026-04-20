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