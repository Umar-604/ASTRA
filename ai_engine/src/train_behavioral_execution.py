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

    return {
        "process_basename": basename_lower(proc),
        "parent_basename": basename_lower(parent),
        "granted_access": granted,
        "process_is_wmiprvse": process_is_wmiprvse,
        "process_spawns_cmd_or_powershell": process_spawns_cmd_or_powershell,
        "indicator_unc_process": indicator_unc_process,
        "indicator_unc_parent": indicator_unc_parent,
        "indicator_psexec_remote": indicator_psexec_remote,
        "indicator_wmic": indicator_wmic,
        "indicator_winrm_winrs": indicator_winrm_winrs,
        # ── v2 features ──
        "event_id_risk_tier": _event_id_risk_tier(rec.get("EventID")),
        "granted_access_risk_tier": _ga_risk_tier(ga_str),
        "target_is_sensitive": 1 if target_bn in _SENSITIVE_TARGETS else 0,
        "source_target_same": 1 if (source_bn != "unknown" and source_bn == target_bn) else 0,
        "calltrace_dll_count": _count_calltrace_dlls(rec),
        "process_in_system_dir": _process_in_system_dir(proc),
        "process_path_depth": _process_path_depth(proc),
        "channel_is_sysmon": 1 if "sysmon" in channel else 0,
        "account_is_system": 1 if acct in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE") else 0,
        "has_script_content": 1 if (rec.get("Payload") or rec.get("ScriptBlockText")) else 0,
        "has_file_hash": 1 if rec.get("Hashes") else 0,
        "log_granted_access": math.log1p(granted),
        "has_parent_process": 0 if parent == "unknown" else 1,
        "is_remote_logon": 1 if logon_type in ("3", "10") else 0,
    }


class BehavioralEncoders:
    """Frequency encoding for process/parent basenames only (fit on training data per split)."""

    def __init__(self) -> None:
        self.freq_maps: Dict[str, Dict[str, float]] = {}
        self.feature_columns: List[str] = list(BEHAVIORAL_FEATURE_COLUMNS)

    def fit(self, raw_rows: Sequence[Mapping[str, Any]]) -> None:
        self.freq_maps = {}
        for key in FREQ_BASENAME_KEYS:
            counts: Counter[str] = Counter()
            for r in raw_rows:
                bp = behavioral_parts(r)
                counts[str(bp[key])] += 1
            total = max(len(raw_rows), 1)
            self.freq_maps[key] = {k: math.log1p(c) / math.log1p(total) for k, c in counts.items()}

    def _freq(self, col: str, value: str) -> float:
        m = self.freq_maps.get(col) or {}
        return float(m.get(value, 0.0))

    def transform_row(self, rec: Mapping[str, Any]) -> Dict[str, float]:
        bp = behavioral_parts(rec)
        row: Dict[str, float] = {
            "freq_process_basename": self._freq("process_basename", str(bp["process_basename"])),
            "freq_parent_basename": self._freq("parent_basename", str(bp["parent_basename"])),
        }
        for key in self.feature_columns:
            if key in row:
                continue
            if key in bp:
                row[key] = float(bp[key])
            else:
                row[key] = 0.0
        return row

    def transform_matrix(self, records: Sequence[Mapping[str, Any]]) -> Tuple[np.ndarray, List[str]]:
        cols = self.feature_columns
        rows = [self.transform_row(r) for r in records]
        X = np.array([[rows[i][c] for c in cols] for i in range(len(rows))], dtype=np.float64)
        return X, cols


def combine_attack_benign_shuffle(
    attack: List[Dict[str, Any]],
    benign: List[Dict[str, Any]],
    seed: int,
) -> Tuple[List[Dict[str, Any]], List[int]]:
    """Full attack + benign, one list, shuffled before any train/test split."""
    if not attack or not benign:
        raise RuntimeError("Need non-empty attack and benign JSONL inputs.")
    rng = random.Random(seed)
    combined: List[Tuple[Dict[str, Any], int]] = [(r, 1) for r in attack] + [(r, 0) for r in benign]
    rng.shuffle(combined)
    rows_out = [t[0] for t in combined]
    y_out = [t[1] for t in combined]
    return rows_out, y_out

def lgbm_scale_pos_weight(y: np.ndarray) -> float:
    neg = int((y == 0).sum())
    pos = int((y == 1).sum())
    if pos == 0:
        return 1.0
    return neg / pos

def build_behavioral_lgbm(seed: int, scale_pos_weight: float) -> LGBMClassifier:
    """Regularized model; tuned for generalization rather than peak train accuracy."""
    return LGBMClassifier(
        n_estimators=220,
        num_leaves=31,
        max_depth=6,
        learning_rate=0.05,
        min_child_samples=40,
        subsample=0.8,
        colsample_bytree=0.8,
        reg_alpha=0.15,
        reg_lambda=0.15,
        scale_pos_weight=scale_pos_weight,
        random_state=seed,
        n_jobs=-1,
        verbose=-1,
    )


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

def _fold_metrics(y_true: np.ndarray, y_pred: np.ndarray, proba: np.ndarray) -> Dict[str, float]:
    acc = float(accuracy_score(y_true, y_pred))
    prec, rec, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average="binary", pos_label=1, zero_division=0
    )
    prec_m, rec_m, f1_m, _ = precision_recall_fscore_support(
        y_true, y_pred, average="macro", zero_division=0
    )
    mcc = float(matthews_corrcoef(y_true, y_pred))
    try:
        auc = float(roc_auc_score(y_true, proba))
    except ValueError:
        auc = float("nan")
    return {
        "accuracy": acc,
        "precision_attack": float(prec),
        "recall_attack": float(rec),
        "f1_attack": float(f1),
        "f1_macro": float(f1_m),
        "mcc": mcc,
        "roc_auc": auc,
    }


def train_pipeline(
    attack_rows: List[Dict[str, Any]],
    benign_rows: List[Dict[str, Any]],
    out_dir: Path,
    test_size: float,
    seed: int,
    cv_splits: int = 5,
    use_smote: bool = False,
) -> Dict[str, Any]:
    rows, y_list = combine_attack_benign_shuffle(attack_rows, benign_rows, seed)
    y = np.array(y_list, dtype=np.int32)
    n_attack = int((y == 1).sum())
    n_benign = int((y == 0).sum())

    idx = np.arange(len(rows))
    idx_train, idx_test = train_test_split(
        idx, test_size=test_size, random_state=seed, stratify=y
    )
    train_rows = [rows[i] for i in idx_train]
    test_rows = [rows[i] for i in idx_test]
    y_train, y_test = y[idx_train], y[idx_test]

    pos_tr = int((y_train == 1).sum())
    neg_tr = int((y_train == 0).sum())
    n_splits = min(cv_splits, pos_tr, neg_tr)
    if n_splits < 2:
        raise RuntimeError(
            "Stratified CV needs at least 2 samples per class in the training split; "
            f"got attack={pos_tr}, benign={neg_tr}. Add more data or reduce --test-size."
        )

    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=seed)
    cv_fold_rows: List[Dict[str, Any]] = []
    for fold_i, (tr_idx, va_idx) in enumerate(skf.split(np.zeros(len(y_train)), y_train)):
        fold_train = [train_rows[i] for i in tr_idx]
        fold_val = [train_rows[i] for i in va_idx]
        y_ft, y_fv = y_train[tr_idx], y_train[va_idx]

        enc_fold = BehavioralEncoders()
        enc_fold.fit(fold_train)
        X_ft, fn = enc_fold.transform_matrix(fold_train)
        X_fv, _ = enc_fold.transform_matrix(fold_val)

        spw_f = lgbm_scale_pos_weight(y_ft)
        clf_f = build_behavioral_lgbm(seed + fold_i, spw_f)
        clf_f.fit(pd.DataFrame(X_ft, columns=fn), y_ft)
        proba_f = clf_f.predict_proba(pd.DataFrame(X_fv, columns=fn))[:, 1]
        pred_f = (proba_f >= 0.5).astype(np.int32)
        m = _fold_metrics(y_fv, pred_f, proba_f)
        m["fold"] = fold_i + 1
        cv_fold_rows.append(m)

    def _agg(key: str) -> Tuple[float, float]:
        vals = [r[key] for r in cv_fold_rows if not (key == "roc_auc" and math.isnan(r[key]))]
        if not vals:
            return float("nan"), float("nan")
        return float(np.mean(vals)), float(np.std(vals))

    cv_mean_acc, cv_std_acc = _agg("accuracy")
    cv_mean_prec, cv_std_prec = _agg("precision_attack")
    cv_mean_rec, cv_std_rec = _agg("recall_attack")
    cv_mean_f1, cv_std_f1 = _agg("f1_attack")
    cv_mean_auc, cv_std_auc = _agg("roc_auc")

    cv_mean_f1m, cv_std_f1m = _agg("f1_macro")
    cv_mean_mcc, cv_std_mcc = _agg("mcc")

    print("\n=== Stratified K-fold CV (training split only; behavioral features) ===")
    print(f"Folds: {n_splits} (requested up to {cv_splits})")
    for r in cv_fold_rows:
        auc_s = "n/a" if math.isnan(r["roc_auc"]) else f"{r['roc_auc']:.4f}"
        print(
            f"  Fold {int(r['fold'])}: acc={r['accuracy']:.4f} "
            f"P={r['precision_attack']:.4f} R={r['recall_attack']:.4f} "
            f"F1={r['f1_attack']:.4f} F1m={r['f1_macro']:.4f} MCC={r['mcc']:.4f} AUC={auc_s}"
        )
    print(
        f"Mean ± std  acc={cv_mean_acc:.4f}±{cv_std_acc:.4f}  "
        f"P={cv_mean_prec:.4f}±{cv_std_prec:.4f}  R={cv_mean_rec:.4f}±{cv_std_rec:.4f}  "
        f"F1={cv_mean_f1:.4f}±{cv_std_f1:.4f}  "
        f"F1m={cv_mean_f1m:.4f}±{cv_std_f1m:.4f}  "
        f"MCC={cv_mean_mcc:.4f}±{cv_std_mcc:.4f}  "
        f"AUC={cv_mean_auc:.4f}±{cv_std_auc:.4f}"
    )

    out_dir.mkdir(parents=True, exist_ok=True)
    cv_plot_path = out_dir / "behavioral_cv_metrics_by_fold.png"
    save_cv_metrics_bar_png(
        cv_fold_rows,
        cv_plot_path,
        title="Behavioral LightGBM — CV metrics by fold",
    )

    enc = BehavioralEncoders()
    enc.fit(train_rows)
    X_train, feat_names = enc.transform_matrix(train_rows)
    X_test, _ = enc.transform_matrix(test_rows)

    smote_applied = False
    if use_smote and _HAS_SMOTE:
        minority_count = min(int((y_train == 0).sum()), int((y_train == 1).sum()))
        k = min(5, minority_count - 1) if minority_count > 1 else 1
        if minority_count >= 2:
            smote = _SMOTE(random_state=seed, k_neighbors=k)
            X_train, y_train = smote.fit_resample(X_train, y_train)
            smote_applied = True
            print(f"\n  SMOTE applied: {len(y_train)} samples (attack={int((y_train==1).sum())}, benign={int((y_train==0).sum())})")
    elif use_smote and not _HAS_SMOTE:
        print("  WARNING: --smote requested but imblearn not installed; skipping.")

    X_train_df = pd.DataFrame(X_train, columns=feat_names)
    X_test_df = pd.DataFrame(X_test, columns=feat_names)

    spw = lgbm_scale_pos_weight(y_train)
    clf = build_behavioral_lgbm(seed, spw)
    clf.fit(X_train_df, y_train)

    proba = clf.predict_proba(X_test_df)[:, 1]
    pred = (proba >= 0.5).astype(np.int32)

    benign_mask_train = y_train == 0
    n_benign_train = int(benign_mask_train.sum())
    if n_benign_train < 2:
        raise RuntimeError("Need at least 2 benign training rows for IsolationForest + scaler.")
    scaler = StandardScaler()
    if n_benign_train >= 200:
        X_if_fit = scaler.fit_transform(X_train[benign_mask_train])
        if_trained_on = "benign_train_only"
        contamination_val: Any = "auto"
    else:
        X_if_fit = scaler.fit_transform(X_train)
        n_attack_train = int((y_train == 1).sum())
        contamination_val = max(0.01, min(0.5, n_attack_train / max(1, len(y_train))))
        if_trained_on = "all_train_semi_supervised"
    ifor = IsolationForest(
        n_estimators=300,
        max_samples=min(512, X_if_fit.shape[0]),
        max_features=min(1.0, max(0.5, 8 / max(1, X_if_fit.shape[1]))),
        random_state=seed,
        contamination=contamination_val,
        n_jobs=-1,
    )
    ifor.fit(X_if_fit)
    print(f"\n  Isolation Forest trained on: {if_trained_on} ({X_if_fit.shape[0]} samples, contamination={contamination_val})")

    def anomaly_scores(X: np.ndarray) -> np.ndarray:
        Xs = scaler.transform(X)
        raw = ifor.score_samples(Xs)
        return -raw.astype(np.float64)

    X_test_np, _ = enc.transform_matrix(test_rows)
    ano_test = anomaly_scores(X_test_np)

    importance = dict(zip(feat_names, clf.feature_importances_.astype(float).tolist()))
    top_features = sorted(importance.items(), key=lambda kv: kv[1], reverse=True)[:15]

    cm_arr = confusion_matrix(y_test, pred, labels=[0, 1])
    cm_list = cm_arr.tolist()
    acc = float(accuracy_score(y_test, pred))
    prec, rec, f1, _ = precision_recall_fscore_support(
        y_test, pred, average="binary", pos_label=1, zero_division=0
    )
    try:
        auc = float(roc_auc_score(y_test, proba))
    except ValueError:
        auc = float("nan")
    auc_json: Any = auc
    if isinstance(auc, float) and math.isnan(auc):
        auc_json = None
    report_dict = classification_report(
        y_test, pred, digits=4, zero_division=0, output_dict=True
    )
    report_txt = classification_report(y_test, pred, digits=4, zero_division=0)

    tn, fp, fn, tp = int(cm_arr[0, 0]), int(cm_arr[0, 1]), int(cm_arr[1, 0]), int(cm_arr[1, 1])
    if auc_json is None:
        auc_line = "n/a"
    else:
        auc_line = f"{float(auc):.4f}"
    prec_m, rec_m, f1_m, _ = precision_recall_fscore_support(
        y_test, pred, average="macro", zero_division=0
    )
    mcc = float(matthews_corrcoef(y_test, pred))

    print("\n=== LightGBM — held-out test (not used in CV) ===")
    print(f"Accuracy:                     {acc:.4f}")
    print(f"Precision (attack, class 1):  {float(prec):.4f}")
    print(f"Recall (attack, class 1):     {float(rec):.4f}")
    print(f"F1 (attack, class 1):         {float(f1):.4f}")
    print(f"F1 (macro, both classes):     {float(f1_m):.4f}")
    print(f"MCC (Matthews):               {mcc:.4f}")
    print(f"ROC-AUC:                      {auc_line}")
    if smote_applied:
        print(f"SMOTE:                        applied")
    print("\nConfusion matrix  rows=true label, cols=predicted")
    print("                  Pred normal(0)  Pred attack(1)")
    print(f"  True normal(0)       {tn:>6}           {fp:>6}")
    print(f"  True attack(1)       {fn:>6}           {tp:>6}")
    print("  (TN, FP / FN, TP)")
    print("\nClassification report:")
    print(report_txt)

    out_dir.mkdir(parents=True, exist_ok=True)
    enc_path = out_dir / "encoders.pkl"
    lgbm_path = out_dir / "lightgbm_model.pkl"
    if_path = out_dir / "isolation_forest.pkl"
    meta_path = out_dir / "behavioral_training_meta.json"
    results_json_path = out_dir / "behavioral_training_results.json"
    cm_png_path = out_dir / "behavioral_confusion_matrix.png"
    roc_png_path = out_dir / "behavioral_roc_curve.png"
    pr_png_path = out_dir / "behavioral_precision_recall_curve.png"
    metrics_bar_path = out_dir / "behavioral_holdout_metrics_bar.png"
    iforest_dist_path = out_dir / "behavioral_iforest_score_distribution.png"
    lgbm_learning_path = out_dir / "behavioral_lgbm_learning_curve.png"

    if len(np.unique(y_test)) > 1:
        save_roc_curve_png(
            y_test, proba, roc_png_path, title="Behavioral LightGBM — ROC (hold-out)"
        )
        save_pr_curve_png(
            y_test, proba, pr_png_path, title="Behavioral LightGBM — Precision–Recall (hold-out)"
        )
    holdout_metrics = {
        "Accuracy": acc,
        "Precision": float(prec),
        "Recall": float(rec),
        "F1": float(f1),
    }
    if auc_json is not None:
        holdout_metrics["ROC-AUC"] = float(auc)
    save_metrics_bar_png(
        holdout_metrics,
        metrics_bar_path,
        title="Behavioral LightGBM — hold-out metrics",
        y_max=1.15 if auc_json is not None else 1.05,
    )

    ano_normal = ano_test[y_test == 0]
    ano_attack = ano_test[y_test == 1]
    if len(ano_normal) and len(ano_attack):
        save_iforest_score_distribution(
            ano_normal,
            ano_attack,
            iforest_dist_path,
            title="Isolation Forest — anomaly scores (hold-out test)",
        )

    # Learning curve: extra fit on a train/val split from training data only (does not change saved model).
    try:
        ix_sub = np.arange(len(X_train_df))
        ix_tr, ix_va, _, _ = train_test_split(
            ix_sub, y_train, test_size=0.12, random_state=seed, stratify=y_train
        )
        X_tr_c = X_train_df.iloc[ix_tr]
        X_va_c = X_train_df.iloc[ix_va]
        y_tr_c = y_train[ix_tr]
        y_va_c = y_train[ix_va]
        spw_c = lgbm_scale_pos_weight(y_tr_c)
        clf_curve = build_behavioral_lgbm(seed + 777, spw_c)
        eval_hist: Dict[str, Any] = {}
        clf_curve.fit(
            X_tr_c,
            y_tr_c,
            eval_set=[(X_va_c, y_va_c)],
            eval_metric=["binary_logloss", "auc"],
            callbacks=[
                lgb.early_stopping(stopping_rounds=100, verbose=False),
                lgb.record_evaluation(eval_hist),
            ],
        )
        save_lightgbm_eval_plot(
            eval_hist,
            lgbm_learning_path,
            title="LightGBM — validation metrics vs iteration (train subset)",
        )
    except Exception as e:
        print(f"⚠️  Skipped LGBM learning curve plot: {e}")

    cv_summary = {
        "n_splits": n_splits,
        "requested_splits": cv_splits,
        "folds": cv_fold_rows,
        "mean": {
            "accuracy": cv_mean_acc,
            "precision_attack": cv_mean_prec,
            "recall_attack": cv_mean_rec,
            "f1_attack": cv_mean_f1,
            "f1_macro": cv_mean_f1m,
            "mcc": cv_mean_mcc,
            "roc_auc": cv_mean_auc,
        },
        "std": {
            "accuracy": cv_std_acc,
            "precision_attack": cv_std_prec,
            "recall_attack": cv_std_rec,
            "f1_attack": cv_std_f1,
            "f1_macro": cv_std_f1m,
            "mcc": cv_std_mcc,
            "roc_auc": cv_std_auc,
        },
    }

    results_payload: Dict[str, Any] = {
        "model": "LightGBM behavioral v2 (expanded features)",
        "feature_columns": list(BEHAVIORAL_FEATURE_COLUMNS),
        "smote_applied": smote_applied,
        "test_size": float(test_size),
        "random_seed": seed,
        "data": {
            "n_attack_loaded": len(attack_rows),
            "n_benign_loaded": len(benign_rows),
            "n_attack_combined": n_attack,
            "n_benign_combined": n_benign,
            "train_rows": int(len(y_train)),
            "test_rows": int(len(y_test)),
        },
        "cross_validation": cv_summary,
        "lightgbm_holdout": {
            "scale_pos_weight": spw,
            "accuracy": acc,
            "precision_binary_attack": float(prec),
            "recall_binary_attack": float(rec),
            "f1_binary_attack": float(f1),
            "roc_auc": auc_json,
            "f1_macro": float(f1_m),
            "mcc": mcc,
            "confusion_matrix": cm_list,
            "confusion_matrix_note": "rows=true [normal, attack], cols=pred [normal, attack]; [[TN, FP], [FN, TP]]",
            "classification_report": report_dict,
            "top_feature_importance": [{"feature": k, "importance": v} for k, v in top_features],
        },
        "isolation_forest": {
            "trained_on": if_trained_on,
            "test_anomaly_score_summary": {
                "mean": float(np.mean(ano_test)),
                "std": float(np.std(ano_test)),
                "min": float(np.min(ano_test)),
                "max": float(np.max(ano_test)),
                "mean_attack_class": float(np.mean(ano_test[y_test == 1])),
                "mean_normal_class": float(np.mean(ano_test[y_test == 0])),
            },
        },
        "artifacts": {
            "results_json": str(results_json_path.resolve()),
            "confusion_matrix_png": str(cm_png_path.resolve()),
            "roc_curve_png": str(roc_png_path.resolve()) if len(np.unique(y_test)) > 1 else None,
            "precision_recall_png": str(pr_png_path.resolve()) if len(np.unique(y_test)) > 1 else None,
            "holdout_metrics_bar_png": str(metrics_bar_path.resolve()),
            "cv_metrics_png": str(cv_plot_path.resolve()),
            "iforest_score_distribution_png": str(iforest_dist_path.resolve())
            if len(ano_normal) and len(ano_attack)
            else None,
            "lgbm_learning_curve_png": str(lgbm_learning_path.resolve()),
        },
    }
    with results_json_path.open("w", encoding="utf-8") as f:
        json.dump(results_payload, f, indent=2, default=str)

    _save_confusion_matrix_png(
        cm_arr,
        cm_png_path,
        "Behavioral LightGBM — held-out test confusion matrix",
    )

    encoder_state = {
        "freq_maps": enc.freq_maps,
        "feature_columns": feat_names,
    }
    joblib.dump(encoder_state, enc_path)
    joblib.dump(
        {
            "model": clf,
            "model_type": "lgbm",
            "feature_names": feat_names,
            "scale_pos_weight": spw,
            "feature_importance": importance,
            "encoder": encoder_state,
            "training_stats": {
                "cv_mean_accuracy": cv_mean_acc,
                "cv_mean_f1_attack": cv_mean_f1,
                "holdout_accuracy": acc,
                "holdout_roc_auc": auc_json,
            },
        },
        lgbm_path,
    )
    joblib.dump(
        {
            "model": ifor,
            "scaler": scaler,
            "feature_names": feat_names,
            "trained_on": if_trained_on,
        },
        if_path,
    )

    meta = {
        "n_attack_loaded": len(attack_rows),
        "n_benign_loaded": len(benign_rows),
        "n_attack_combined": n_attack,
        "n_benign_combined": n_benign,
        "train_size": int(len(y_train)),
        "test_size": int(len(y_test)),
        "cv_splits": n_splits,
        "cv_mean_accuracy": cv_mean_acc,
        "cv_std_accuracy": cv_std_acc,
        "scale_pos_weight": spw,
        "feature_names": feat_names,
        "top_feature_importance": top_features,
        "lgbm_holdout_accuracy": acc,
        "lgbm_holdout_roc_auc": auc_json,
        "confusion_matrix": cm_list,
        "artifacts": {
            "encoders": str(enc_path.resolve()),
            "lightgbm": str(lgbm_path.resolve()),
            "isolation_forest": str(if_path.resolve()),
            "results_json": str(results_json_path.resolve()),
            "confusion_matrix_png": str(cm_png_path.resolve()),
        },
    }
    with meta_path.open("w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, default=str)

    return {
        "meta_path": str(meta_path),
        "results_json_path": str(results_json_path),
        "confusion_matrix_png": str(cm_png_path),
        "encoders_path": str(enc_path),
        "lightgbm_path": str(lgbm_path),
        "isolation_forest_path": str(if_path),
        "top_feature_importance": top_features,
        "cv_mean_accuracy": cv_mean_acc,
    }


def encode_with_state(records: Sequence[Mapping[str, Any]], encoder_state: Mapping[str, Any]) -> Tuple[np.ndarray, List[str]]:
    """Transform rows using plain encoder state dict (pickle-safe across runtimes)."""
    freq_maps = encoder_state.get("freq_maps") or {}
    cols = list(encoder_state.get("feature_columns") or BEHAVIORAL_FEATURE_COLUMNS)

    def _freq(col: str, value: str) -> float:
        m = freq_maps.get(col) or {}
        return float(m.get(value, 0.0))

    rows = []
    for rec in records:
        bp = behavioral_parts(rec)
        row: Dict[str, float] = {
            "freq_process_basename": _freq("process_basename", str(bp["process_basename"])),
            "freq_parent_basename": _freq("parent_basename", str(bp["parent_basename"])),
        }
        for key in cols:
            if key in row:
                continue
            if key in bp:
                row[key] = float(bp[key])
            else:
                row[key] = 0.0
        rows.append(row)

    X = np.array([[rows[i][c] for c in cols] for i in range(len(rows))], dtype=np.float64)
    return X, cols


# ---------------------------------------------------------------------------
# Astra-facing inference (load once, score many)
# ---------------------------------------------------------------------------


class BehavioralDetector:
    """Loads saved artifacts; returns verdict, LGBM confidence, IF anomaly score, top features."""

    def __init__(self, out_dir: Path) -> None:
        out_dir = Path(out_dir)
        self.encoder_state: Mapping[str, Any] = joblib.load(out_dir / "encoders.pkl")
        lgbm_bundle = joblib.load(out_dir / "lightgbm_model.pkl")
        if_bundle = joblib.load(out_dir / "isolation_forest.pkl")
        self.clf: LGBMClassifier = lgbm_bundle["model"]
        self.feature_names: List[str] = lgbm_bundle["feature_names"]
        self.importance: Dict[str, float] = lgbm_bundle.get("feature_importance", {})
        self.iforest: IsolationForest = if_bundle["model"]
        self.scaler: StandardScaler = if_bundle["scaler"]

