"""
Shared evaluation figures for Astra training scripts (ROC, PR, metrics bars, learning curves).
Uses matplotlib Agg backend; safe for headless runs.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

import numpy as np

import matplotlib
