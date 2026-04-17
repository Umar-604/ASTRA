#!/usr/bin/env python3
"""
Behavioral detection from real Windows events (JSONL).

- Attack rows: explicit label 1 from --attack file(s) (e.g. Execution2.json).
- Benign rows: explicit label 0 from --benign file(s); required (no heuristic labels,
  no synthetic attack samples).

Trains LightGBM (supervised) and Isolation Forest (fit on benign-only, same features).

Features are process-behavior only (no EventID / channel / user / logon frequency) to reduce
dataset memorization. Stratified K-fold CV reports generalization; holdout test for final check.
"""


from __future__ import annotations

import argparse
import json
import math
import random
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import lightgbm as lgb
from lightgbm import LGBMClassifier

from src.eval_plots import (
    save_cv_metrics_bar_png,
    save_iforest_score_distribution,
    save_lightgbm_eval_plot,
    save_metrics_bar_png,
    save_pr_curve_png,
    save_roc_curve_png,
)

from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    accuracy_score,
    classification_report,
    confusion_matrix,
    matthews_corrcoef,
    precision_recall_fscore_support,
    roc_auc_score,
)

from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.preprocessing import StandardScaler

try:
    from imblearn.over_sampling import SMOTE as _SMOTE
    _HAS_SMOTE = True
except ImportError:
    _HAS_SMOTE = False

# ---------------------------------------------------------------------------
# IO
# ---------------------------------------------------------------------------


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for ln in f:
            ln = ln.strip()
            if not ln:
                continue
            try:
                rows.append(json.loads(ln))
            except json.JSONDecodeError:
                continue
    return rows


# ---------------------------------------------------------------------------
# Field helpers (missing → "unknown" or 0; never drop rows)
# ---------------------------------------------------------------------------

def _to_int(val: Any, default: int = 0) -> int:
    if val is None or val == "":
        return default
    if isinstance(val, str) and val.lower().startswith("0x"):
        try:
            return int(val, 16)
        except ValueError:
            return default
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def _first_str(rec: Mapping[str, Any], *keys: str) -> Optional[str]:
    for key in keys:
        if key not in rec:
            continue
        v = rec.get(key)
        if v is None:
            continue
        s = str(v).strip()
        if s:
            return s
    return None


def primary_process_path(rec: Mapping[str, Any]) -> str:
    v = _first_str(
        rec,
        "ProcessName",
        "Image",
        "image",
        "SourceImage",
        "source_image",
        "TargetImage",
        "target_image",
        "Application",
        "application",
    )
    return v if v is not None else "unknown"


def parent_process_path(rec: Mapping[str, Any]) -> str:
    v = _first_str(rec, "ParentImage", "parent_image", "ParentProcessName")
    return v if v is not None else "unknown"


def basename_lower(path: str) -> str:
    if path == "unknown":
        return "unknown"
    p = path.replace("\\", "/").strip().lower()
    name = p.split("/")[-1] if p else "unknown"
    return name if name else "unknown"

# ---------------------------------------------------------------------------
# Process-behavior features only (no EventID / channel / account / logon leakage)
# ---------------------------------------------------------------------------

FREQ_BASENAME_KEYS = ("process_basename", "parent_basename")

# Fixed column order for LightGBM / IF / disk artifacts
BEHAVIORAL_FEATURE_COLUMNS: List[str] = [
    # ── original process-behavior features ──
    "freq_process_basename",
    "freq_parent_basename",
    "granted_access",
    "process_is_wmiprvse",
    "process_spawns_cmd_or_powershell",
    "indicator_unc_process",
    "indicator_unc_parent",
    "indicator_psexec_remote",
    "indicator_wmic",
    "indicator_winrm_winrs",
    # ── expanded features (v2) ──
    "event_id_risk_tier",
    "granted_access_risk_tier",
    "target_is_sensitive",
    "source_target_same",
    "calltrace_dll_count",
    "process_in_system_dir",
    "process_path_depth",
    "channel_is_sysmon",
    "account_is_system",
    "has_script_content",
    "has_file_hash",
    "log_granted_access",
    "has_parent_process",
    "is_remote_logon",
]


_SENSITIVE_TARGETS = frozenset([
    "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe",
    "smss.exe", "wininit.exe",
])

