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