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
        clf_f.fit(X_f_tr, y_f_tr)
        proba_f = clf_f.predict_proba(X_f_va)[:, 1]
        pred_f = (proba_f >= 0.5).astype(int)
        acc_f = float(accuracy_score(y_f_va, pred_f))
        p_f, r_f, f1_f, _ = precision_recall_fscore_support(y_f_va, pred_f, average="binary", pos_label=1, zero_division=0)
        _, _, f1m_f, _ = precision_recall_fscore_support(y_f_va, pred_f, average="macro", zero_division=0)
        mcc_f = float(matthews_corrcoef(y_f_va, pred_f))
        try:
            auc_f = float(roc_auc_score(y_f_va, proba_f))
        except ValueError:
            auc_f = float("nan")
        cv_results.append({"fold": fold_i + 1, "acc": acc_f, "prec": float(p_f), "rec": float(r_f),
                           "f1": float(f1_f), "f1_macro": float(f1m_f), "mcc": mcc_f, "auc": auc_f})
        auc_s = f"{auc_f:.4f}" if not np.isnan(auc_f) else "n/a"
        print(f"  Fold {fold_i+1}: acc={acc_f:.4f} P={p_f:.4f} R={r_f:.4f} F1={f1_f:.4f} F1m={f1m_f:.4f} MCC={mcc_f:.4f} AUC={auc_s}")

    def _mean_std(key: str):
        vals = [r[key] for r in cv_results if not (isinstance(r[key], float) and np.isnan(r[key]))]
        return (float(np.mean(vals)), float(np.std(vals))) if vals else (float("nan"), float("nan"))

    cv_acc_m, cv_acc_s = _mean_std("acc")
    cv_f1_m, cv_f1_s = _mean_std("f1")
    cv_f1m_m, cv_f1m_s = _mean_std("f1_macro")
    cv_mcc_m, cv_mcc_s = _mean_std("mcc")
    cv_auc_m, cv_auc_s = _mean_std("auc")
    print(f"  Mean: acc={cv_acc_m:.4f}±{cv_acc_s:.4f} F1={cv_f1_m:.4f}±{cv_f1_s:.4f} "
          f"F1m={cv_f1m_m:.4f}±{cv_f1m_s:.4f} MCC={cv_mcc_m:.4f}±{cv_mcc_s:.4f} AUC={cv_auc_m:.4f}±{cv_auc_s:.4f}")

    # ── Final model on full training data ──
    model = RandomForestClassifier(
        n_estimators=300, random_state=seed,
        class_weight="balanced_subsample", n_jobs=-1, min_samples_leaf=2,
    )
    model.fit(X_train, y_train)

    proba = model.predict_proba(X_test)[:, 1]
    pred = (proba >= 0.5).astype(int)
    acc = float(accuracy_score(y_test, pred))
    prec, rec, f1, _ = precision_recall_fscore_support(y_test, pred, average="binary", pos_label=1, zero_division=0)
    prec_m, rec_m, f1_m, _ = precision_recall_fscore_support(y_test, pred, average="macro", zero_division=0)
    mcc = float(matthews_corrcoef(y_test, pred))
    try:
        auc = float(roc_auc_score(y_test, proba))
    except ValueError:
        auc = float("nan")
    cm_arr = confusion_matrix(y_test, pred, labels=[0, 1])
    report_txt = classification_report(y_test, pred, digits=4, zero_division=0)
    report_dict = classification_report(y_test, pred, digits=4, zero_division=0, output_dict=True)

    print(f"\n=== Random Forest — hold-out test ===")
    print(f"Accuracy:        {acc:.4f}")
    print(f"F1 (attack):     {float(f1):.4f}")
    print(f"F1 (macro):      {float(f1_m):.4f}")
    print(f"MCC:             {mcc:.4f}")
    print(f"ROC-AUC:         {auc:.4f}" if not np.isnan(auc) else "ROC-AUC: n/a")
    tn, fp, fn, tp = int(cm_arr[0, 0]), int(cm_arr[0, 1]), int(cm_arr[1, 0]), int(cm_arr[1, 1])
    print(f"\nConfusion matrix:")
    print(f"  True normal(0)       {tn:>6}           {fp:>6}")
    print(f"  True attack(1)       {fn:>6}           {tp:>6}")
    print(f"\n{report_txt}")

    # ── Feature importance ──
    importances = model.feature_importances_
    top_idx = np.argsort(importances)[::-1][:15]
    print("Top 15 features:")
    for rank, idx in enumerate(top_idx, 1):
        print(f"  {rank:>2}. {feature_names[idx]:>40s}  {importances[idx]:.4f}")

    # ── Save plots ──
    out_dir.mkdir(parents=True, exist_ok=True)
    cm_png = out_dir / "endpoint_model_rf_confusion_matrix.png"
    roc_png = out_dir / "endpoint_model_rf_roc_curve.png"
    pr_png = out_dir / "endpoint_model_rf_pr_curve.png"
    bar_png = out_dir / "endpoint_model_rf_metrics_bar.png"
    imp_png = out_dir / "endpoint_model_rf_feature_importance.png"
    results_json_path = out_dir / "endpoint_model_rf_results.json"

    _save_confusion_matrix_png(cm_arr, cm_png, "Random Forest — hold-out confusion matrix")
    if len(np.unique(y_test)) > 1:
        save_roc_curve_png(y_test, proba, roc_png, title="Random Forest — ROC (hold-out)")
        save_pr_curve_png(y_test, proba, pr_png, title="Random Forest — Precision–Recall (hold-out)")

    bar_m = {"Accuracy": acc, "F1 (attack)": float(f1), "F1 (macro)": float(f1_m), "MCC": mcc}
    if not np.isnan(auc):
        bar_m["ROC-AUC"] = auc
    save_metrics_bar_png(bar_m, bar_png, title="Random Forest — hold-out metrics")
    save_feature_importance_png(importances, feature_names, imp_png,
                                title="Random Forest — top 25 feature importances")

    results_payload = {
        "model_type": "RandomForestClassifier (v2 — proper labels)",
        "labeling": "heuristic_relabeling (prepare_behavioral_data.py)",
        "data": {
            "n_attack": n_attack, "n_benign": n_benign,
            "features": int(X.shape[1]),
            "train_size": int(len(y_train)), "test_size": int(len(y_test)),
        },
        "cross_validation": {
            "n_splits": n_splits, "folds": cv_results,
            "mean_f1_macro": cv_f1m_m, "mean_mcc": cv_mcc_m, "mean_auc": cv_auc_m,
        },
        "holdout": {
            "accuracy": acc, "precision_attack": float(prec), "recall_attack": float(rec),
            "f1_attack": float(f1), "f1_macro": float(f1_m), "mcc": mcc, "auc": auc if not np.isnan(auc) else None,
            "confusion_matrix": cm_arr.tolist(),
            "classification_report": report_dict,
        },
        "top_features": [{"feature": feature_names[i], "importance": float(importances[i])} for i in top_idx],
    }
    with results_json_path.open("w", encoding="utf-8") as f:
        json.dump(results_payload, f, indent=2, default=str)

    model_obj = {
        "model": model, "vectorizer": vec, "feature_names": feature_names,
        "model_type": "rf_v2",
        "training_stats": {
            "n_attack": n_attack, "n_benign": n_benign,
            "accuracy": acc, "f1_macro": float(f1_m), "mcc": mcc, "auc": auc,
        },
    }
    pkl_path = out_dir / "endpoint_model_rf.pkl"
    joblib.dump(model_obj, pkl_path)
    print(f"\nSaved model: {pkl_path}")
    print(f"Saved results: {results_json_path}")
    return {"accuracy": acc, "f1_macro": float(f1_m), "mcc": mcc, "auc": auc}


# ────────────────────────────────────────────────────────────────────
# CLI
# ────────────────────────────────────────────────────────────────────

def main() -> None:
    root = Path(__file__).resolve().parents[2]
    default_attack = root / "dataset" / "MachineLearningCVE" / "attack_relabeled.jsonl"
    default_benign = root / "dataset" / "MachineLearningCVE" / "benign_combined.jsonl"
    default_out = Path(__file__).resolve().parents[1] / "saved_models"

    # Fall back to old defaults if re-labeled data doesn't exist
    if not default_attack.exists():
        default_attack = root / "dataset" / "MachineLearningCVE" / "Execution2.json"
    if not default_benign.exists():
        default_benign = root / "dataset" / "MachineLearningCVE" / "benign.jsonl"

    p = argparse.ArgumentParser(description="Train Random Forest on endpoint event data (v2)")
    p.add_argument("--attack", action="append", default=[], help="JSONL attack file(s)")
    p.add_argument("--benign", action="append", default=[], help="JSONL benign file(s)")
    p.add_argument("--outdir", default=str(default_out))
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--cv-splits", type=int, default=5, dest="cv_splits")
    args = p.parse_args()

    attack_paths = [Path(x) for x in args.attack] if args.attack else [default_attack]
    benign_paths = [Path(x) for x in args.benign] if args.benign else [default_benign]

    print("Training Random Forest endpoint model (v2 — proper labels)")
    print("=" * 60)

    attack_rows: List[Dict[str, Any]] = []
    for path in attack_paths:
        if not path.is_file():
            raise SystemExit(f"Attack file not found: {path}")
        rows = load_jsonl(path)
        attack_rows.extend(rows)
        print(f"  Loaded {len(rows)} attack rows from {path.name}")

    benign_rows: List[Dict[str, Any]] = []
    for path in benign_paths:
        if not path.is_file():
            raise SystemExit(f"Benign file not found: {path}")
        rows = load_jsonl(path)
        benign_rows.extend(rows)
        print(f"  Loaded {len(rows)} benign rows from {path.name}")

    result = train(attack_rows, benign_rows, Path(args.outdir), seed=args.seed, cv_splits=args.cv_splits)
    print("\nDone.")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
