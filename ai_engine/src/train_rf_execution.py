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

    return {
        # ── Numeric features ──
        "event_id": event_id,
        "granted_access": granted_access,
        "log_granted_access": math.log1p(granted_access),
        "source_pid": _to_int(rec.get("SourceProcessId") or rec.get("ProcessId")),
        # ── Risk tier features ──
        "event_id_risk": 2 if event_id in {1, 3, 4104, 800, 4103, 5857} else (1 if event_id in {10, 7, 11, 12, 13, 4688} else 0),
        "ga_risk_tier": 3 if ga_str in SUSPICIOUS_GA else (1 if ga_str == "0x1000" else (2 if granted_access > 0 else 0)),
        # ── Binary indicators ──
        "has_powershell": 1 if "powershell" in hay else 0,
        "has_cmd_exe": 1 if "cmd.exe" in hay else 0,
        "has_encoded_command": 1 if ("encodedcommand" in cmd or " -enc " in cmd) else 0,
        "has_download_exec": 1 if ("downloadstring" in cmd or "invoke-expression" in cmd) else 0,
        "targets_lsass": 1 if "lsass" in tgt else 0,
        "target_is_sensitive": 1 if tgt_bn in SENSITIVE_TARGETS else 0,
        "suspicious_token_count": suspicious_token_count,
        "is_sysmon": 1 if "sysmon" in channel else 0,
        "account_is_system": 1 if acct in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE") else 0,
        "process_in_system_dir": _in_system_dir(img),
        "has_parent": 1 if parent and parent != "unknown" else 0,
        "has_calltrace": 1 if calltrace else 0,
        "calltrace_dll_count": len(ct_dlls),
        "has_script_content": 1 if (rec.get("Payload") or rec.get("ScriptBlockText")) else 0,
        "has_file_hash": 1 if rec.get("Hashes") else 0,
        "source_target_same": 1 if (img_bn and img_bn == tgt_bn) else 0,
        "is_remote_logon": 1 if str(rec.get("LogonType") or "") in ("3", "10") else 0,
        # ── Categorical features (DictVectorizer will one-hot encode) ──
        "image_bin": img_bn or "unknown",
        "target_bin": tgt_bn or "unknown",
        "parent_bin": parent_bn or "unknown",
        "channel": channel or "unknown",
        "category": str(rec.get("Category") or "unknown").lower()[:60],
    }


# ────────────────────────────────────────────────────────────────────
# IO
# ────────────────────────────────────────────────────────────────────

def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for ln in f:
            ln = ln.strip()
            if not ln:
                continue
            try:
                rows.append(json.loads(ln))
            except Exception:
                continue
    return rows


# ────────────────────────────────────────────────────────────────────
# Training
# ────────────────────────────────────────────────────────────────────

def _save_confusion_matrix_png(cm: np.ndarray, path: Path, title: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(5.5, 4.5))
    disp = ConfusionMatrixDisplay(
        confusion_matrix=cm,
        display_labels=["Normal (0)", "Attack (1)"],
    )
    disp.plot(ax=ax, cmap="Blues", colorbar=True, values_format="d")
    ax.set_title(title)
    fig.tight_layout()
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)


def save_feature_importance_png(
    importances: np.ndarray,
    feature_names: List[str],
    path: Path,
    top_k: int = 25,
    title: str = "Feature Importance",
) -> None:
    indices = np.argsort(importances)[::-1][:top_k]
    fig, ax = plt.subplots(figsize=(10, 7))
    names = [feature_names[i] for i in indices]
    vals = importances[indices]
    ax.barh(range(len(names)), vals[::-1], color="#4C72B0")
    ax.set_yticks(range(len(names)))
    ax.set_yticklabels(names[::-1], fontsize=9)
    ax.set_xlabel("Importance (Gini)")
    ax.set_title(title)
    fig.tight_layout()
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)


def train(
    attack_rows: List[Dict[str, Any]],
    benign_rows: List[Dict[str, Any]],
    out_dir: Path,
    seed: int = 42,
    cv_splits: int = 5,
) -> Dict[str, Any]:
    import random
    rng = random.Random(seed)
    combined = [(r, 1) for r in attack_rows] + [(r, 0) for r in benign_rows]
    rng.shuffle(combined)
    all_rows = [t[0] for t in combined]
    y = np.array([t[1] for t in combined], dtype=np.int32)

    n_attack = int((y == 1).sum())
    n_benign = int((y == 0).sum())
    print(f"  Dataset: {len(y)} rows (attack={n_attack}, benign={n_benign})")

    feat_dicts = [extract_features(r) for r in all_rows]
    vec = DictVectorizer(sparse=True)
    X = vec.fit_transform(feat_dicts)
    feature_names = list(vec.get_feature_names_out())
    print(f"  Features after DictVectorizer: {X.shape[1]}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=seed, stratify=y
    )

    # ── Cross-validation ──
    n_splits = min(cv_splits, int((y_train == 0).sum()), int((y_train == 1).sum()))
    if n_splits < 2:
        n_splits = 2
    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=seed)
    cv_results: List[Dict[str, float]] = []

    print(f"\n=== Stratified {n_splits}-fold CV ===")
    for fold_i, (tr_idx, va_idx) in enumerate(skf.split(X_train, y_train)):
        X_f_tr, X_f_va = X_train[tr_idx], X_train[va_idx]
        y_f_tr, y_f_va = y_train[tr_idx], y_train[va_idx]
        clf_f = RandomForestClassifier(
            n_estimators=300, random_state=seed + fold_i,
            class_weight="balanced_subsample", n_jobs=-1, min_samples_leaf=2,
        )