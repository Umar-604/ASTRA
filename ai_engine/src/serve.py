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