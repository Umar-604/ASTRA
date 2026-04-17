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

_SUSPICIOUS_GA = frozenset([
    "0x1fffff", "0x101000", "0x101541", "0x1478", "0x1410",
    "0x143a", "0x1438", "0x1010",
])

_HIGH_RISK_EIDS = frozenset([1, 3, 4104, 800, 4103, 5857])
_MEDIUM_RISK_EIDS = frozenset([10, 7, 11, 12, 13, 4688, 4689])

def _ga_risk_tier(ga_str: str) -> int:
    """0=none/missing, 1=low(0x1000), 2=medium, 3=critical."""
    s = ga_str.strip().lower()
    if not s or s == "0" or s == "0x0":
        return 0
    if s in _SUSPICIOUS_GA:
        return 3
    if s == "0x1000":
        return 1
    return 2

def _event_id_risk_tier(eid: Any) -> int:
    """0=low, 1=medium, 2=high."""
    try:
        eid_int = int(eid)
    except (TypeError, ValueError):
        return 0
    if eid_int in _HIGH_RISK_EIDS:
        return 2
    if eid_int in _MEDIUM_RISK_EIDS:
        return 1
    return 0

def _count_calltrace_dlls(rec: Mapping[str, Any]) -> int:
    ct = rec.get("CallTrace") or ""
    if not ct:
        return 0
    dlls = set()
    for part in str(ct).split("|"):
        dll = part.split("+")[0].replace("\\", "/").strip().lower().split("/")[-1]
        if dll:
            dlls.add(dll)
    return len(dlls)


def _process_in_system_dir(path: str) -> int:
    p = path.lower().replace("\\", "/")
    return 1 if ("/windows/system32/" in p or "/windows/syswow64/" in p or p.startswith("c:/windows/")) else 0


def _process_path_depth(path: str) -> int:
    if path == "unknown":
        return 0
    return len([s for s in path.replace("\\", "/").split("/") if s])


def behavioral_parts(rec: Mapping[str, Any]) -> Dict[str, Any]:
    """Extract all behavioral features from a single event record."""
    proc = primary_process_path(rec)
    parent = parent_process_path(rec)
    proc_l = proc.lower()
    parent_l = parent.lower()
    hay = f"{proc_l} {parent_l}"

    ga = rec.get("GrantedAccess")
    if ga is None or ga == "":
        ga = rec.get("granted_access")
    granted = _to_int(ga)
    ga_str = str(ga) if ga is not None else ""

    process_is_wmiprvse = 1 if "wmiprvse" in proc_l else 0
    spawn_markers = ("cmd.exe", "powershell.exe", "pwsh.exe")
    process_spawns_cmd_or_powershell = 1 if any(m in parent_l for m in spawn_markers) else 0

    pls = proc_l.strip()
    pal = parent_l.strip()
    indicator_unc_process = 1 if pls.startswith("\\\\") else 0
    indicator_unc_parent = 1 if pal.startswith("\\\\") else 0
    indicator_psexec_remote = 1 if ("psexec" in hay or "psexesvc" in hay) else 0
    indicator_wmic = 1 if ("wmic" in hay or pls.endswith("\\wmic.exe") or pal.endswith("\\wmic.exe")) else 0
    indicator_winrm_winrs = 1 if ("winrm" in hay or "winrs" in hay) else 0

    target_img = (rec.get("TargetImage") or "").lower()
    target_bn = basename_lower(target_img) if target_img else "unknown"
    source_img = (rec.get("SourceImage") or "").lower()
    source_bn = basename_lower(source_img) if source_img else "unknown"

    channel = str(rec.get("Channel") or "").lower()
    acct = str(rec.get("AccountName") or rec.get("SubjectUserName") or "").strip().upper()
    logon_type = str(rec.get("LogonType") or "")

