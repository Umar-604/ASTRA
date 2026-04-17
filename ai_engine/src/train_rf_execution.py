#!/usr/bin/env python3
"""
Train a Random Forest classifier on properly labeled endpoint event data.

Uses the re-labeled attack/benign JSONL files produced by
scripts/prepare_behavioral_data.py instead of the unreliable weak-supervision
heuristic.  Features are richer than the behavioral LightGBM pipeline — they
include DictVectorizer-expanded categorical fields (image basenames, EventID
categories) alongside numeric and binary indicator features.

Usage (from ai_engine/):
  python -m src.train_rf_execution
  python -m src.train_rf_execution --attack ../dataset/MachineLearningCVE/attack_relabeled.jsonl \
                                    --benign ../dataset/MachineLearningCVE/benign_combined.jsonl
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any, Dict, List

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import DictVectorizer
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

from src.eval_plots import save_metrics_bar_png, save_pr_curve_png, save_roc_curve_png


# ────────────────────────────────────────────────────────────────────
# Feature engineering
# ────────────────────────────────────────────────────────────────────

SUSPICIOUS_TOKENS = (
    "mimikatz", "psexec", "rundll32", "regsvr32", "powershell -enc",
    "encodedcommand", "downloadstring", "invoke-expression", "certutil",
    "mshta", "wmic", "procdump", "vssadmin", "shadowcopy",
)

SENSITIVE_TARGETS = frozenset([
    "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe",
    "smss.exe", "wininit.exe",
])

SUSPICIOUS_GA = frozenset([
    "0x1fffff", "0x101000", "0x101541", "0x1478", "0x1410",
    "0x143a", "0x1438", "0x1010",
])


def _to_int(v: Any, default: int = 0) -> int:
    try:
        if isinstance(v, str) and v.lower().startswith("0x"):
            return int(v, 16)
        return int(v)
    except Exception:
        return default


def _basename(path: str) -> str:
    return path.replace("\\", "/").strip().lower().split("/")[-1] if path else ""


def _in_system_dir(path: str) -> int:
    p = path.lower().replace("\\", "/")
    return 1 if ("/windows/system32/" in p or "/windows/syswow64/" in p) else 0


def extract_features(rec: Dict[str, Any]) -> Dict[str, Any]:
    """Extract rich features from a single Sysmon/Security event."""
    event_id = _to_int(rec.get("EventID"))
    granted_access = _to_int(rec.get("GrantedAccess"))
    ga_str = str(rec.get("GrantedAccess") or "").strip().lower()

    img = str(rec.get("Image") or rec.get("SourceImage") or rec.get("ProcessName") or rec.get("Application") or "").lower()
    tgt = str(rec.get("TargetImage") or rec.get("TargetFilename") or "").lower()
    parent = str(rec.get("ParentImage") or "").lower()
    cmd = str(rec.get("CommandLine") or rec.get("Message") or rec.get("Payload") or "").lower()
    channel = str(rec.get("Channel") or "").lower()
    acct = str(rec.get("AccountName") or rec.get("SubjectUserName") or "").strip().upper()
    calltrace = str(rec.get("CallTrace") or "")

    img_bn = _basename(img)
    tgt_bn = _basename(tgt)
    parent_bn = _basename(parent)

    hay = f"{img} {tgt} {parent} {cmd}"
    suspicious_token_count = sum(1 for tok in SUSPICIOUS_TOKENS if tok in hay)

    ct_dlls = set()
    if calltrace:
        for part in calltrace.split("|"):
            dll = part.split("+")[0].replace("\\", "/").strip().lower().split("/")[-1]
            if dll:
                ct_dlls.add(dll)