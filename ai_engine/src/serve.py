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