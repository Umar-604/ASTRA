"""
Train XGBoost on CICIDS-2017 merged netflow CSV.

Improvements over the original pipeline:
  - Stratified sampling that guarantees minimum samples per class
    (rare attacks like Heartbleed/Infiltration are kept in full).
  - Class-balanced sample weights via compute_sample_weight.
  - Optional Destination Port removal (--drop-port) to test model
    reliance on the known-leaky port feature.
  - Per-class evaluation, MCC, macro/weighted metrics.
  - Feature importance analysis.
  - Proper train-vs-validation loss comparison.
"""

import argparse
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    matthews_corrcoef,
    precision_recall_fscore_support,
    roc_auc_score,
)

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.utils import compute_sample_weight
from xgboost import XGBClassifier

from src.eval_plots import (
    save_confusion_matrix_predictions_png,
    save_learning_curve_png,
    save_metrics_bar_png,
    save_pr_curve_png,
    save_roc_curve_png,
    save_xgboost_evals_plot,
)

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def load_stratified_csv(
    path: str,
    label_col: str,
    min_per_class: int = 500,
    max_majority: int = 50_000,
    sample_frac_medium: float = 0.15,
    chunksize: int = 300_000,
    drop_port: bool = False,
) -> Tuple[pd.DataFrame, np.ndarray, LabelEncoder]:
    
        """
    Load CICIDS CSV with stratified sampling that guarantees rare classes
    are fully represented while capping the majority class.

    Strategy:
      - Classes with fewer than min_per_class samples: keep ALL rows
      - Classes with min_per_class..max_majority: sample sample_frac_medium
        but guarantee at least min_per_class rows
      - Classes above max_majority: cap at max_majority
    """
    label_chunks: List[pd.DataFrame] = []
    for chunk in pd.read_csv(path, chunksize=chunksize, low_memory=False):
        if label_col not in chunk.columns:
            raise ValueError(f"Label column '{label_col}' not found in CSV")
        label_chunks.append(chunk)

    df = pd.concat(label_chunks, axis=0, ignore_index=True)
feature_cols = [
        c for c in df.columns
        if c != label_col and pd.api.types.is_numeric_dtype(df[c])
    ]
if drop_port:
        port_cols = [c for c in feature_cols if "port" in c.lower()]
        if port_cols:
            print(f"  Dropping leaky port feature(s): {port_cols}")
            feature_cols = [c for c in feature_cols if c not in port_cols]

    
    
     class_counts = df[label_col].value_counts()
    print(f"\n  Raw class distribution ({len(class_counts)} classes, {len(df):,} total):")
    for cls, cnt in class_counts.items():
        print(f"    {cls:40s}: {cnt:>10,}")

        sampled_indices: List[int] = []
    for cls, cnt in class_counts.items():
        cls_idx = df.index[df[label_col] == cls].tolist()
        if cnt <= min_per_class:
            sampled_indices.extend(cls_idx)
        elif cnt <= max_majority:
            target = max(min_per_class, int(cnt * sample_frac_medium))
            target = min(target, cnt)
            rng = np.random.RandomState(42)
            sampled_indices.extend(rng.choice(cls_idx, size=target, replace=False).tolist())
        else:
             rng = np.random.RandomState(42)
            sampled_indices.extend(rng.choice(cls_idx, size=max_majority, replace=False).tolist())

    df_sampled = df.loc[sampled_indices].reset_index(drop=True)

    X = df_sampled[feature_cols].replace([np.inf, -np.inf], np.nan).fillna(0.0)
    y_raw = df_sampled[label_col]

    encoder = LabelEncoder()
    y_enc = encoder.fit_transform(y_raw.values)

    sampled_counts = df_sampled[label_col].value_counts()
    print(f"\n  Stratified sample ({len(df_sampled):,} rows):")
    for cls in class_counts.index:
        cnt = sampled_counts.get(cls, 0)
        print(f"    {cls:40s}: {cnt:>8,}")

    return X, y_enc, encoder

def load_sampled_csv(
    path: str,
    label_col: str,
    sample_frac: float = 0.02,
    max_rows: Optional[int] = 300_000,
    chunksize: int = 150_000,
) -> Tuple[pd.DataFrame, np.ndarray]:
    X_parts: list[pd.DataFrame] = []
    y_parts: list[pd.Series] = []
    total_kept = 0

    for chunk in pd.read_csv(path, chunksize=chunksize, low_memory=False):
        if label_col not in chunk.columns:
            raise ValueError(f"Label column '{label_col}' not found in CSV")
        if 0.0 < sample_frac < 1.0:
            chunk = chunk.sample(frac=sample_frac, random_state=42)
        y_chunk = chunk[label_col]

        feature_cols = [
            c for c in chunk.columns
            if c != label_col and pd.api.types.is_numeric_dtype(chunk[c])
        ]
        X_chunk = chunk[feature_cols].replace([np.inf, -np.inf], np.nan).fillna(0.0)
        X_parts.append(X_chunk)
        y_parts.append(y_chunk)
        total_kept += len(X_chunk)
        if max_rows is not None and total_kept >= max_rows:
            break
        \
        if not X_parts:
        raise ValueError("No data loaded from CSV - adjust sampling parameters")
    X = pd.concat(X_parts, axis=0, ignore_index=True)
    y = pd.concat(y_parts, axis=0, ignore_index=True).iloc[: len(X)]
    if max_rows is not None and len(X) > max_rows:
        X = X.iloc[:max_rows].reset_index(drop=True)
        y = y.iloc[:max_rows].reset_index(drop=True)
    if y.dtype == object or isinstance(y.iloc[0], str):

        encoder = LabelEncoder()
        y_enc = encoder.fit_transform(y.values)
    else:
        y_enc = y.values
    return X, y_enc


def train_xgboost_classifier(
    X_train: pd.DataFrame,
    y_train: np.ndarray,
    X_val: pd.DataFrame,
    y_val: np.ndarray,
    sample_weights: Optional[np.ndarray] = None,

     n_labels = len(np.unique(y_train))
    eval_metrics = ["mlogloss", "merror"] if n_labels > 2 else ["logloss", "error"]
    model = XGBClassifier(
        n_estimators=400,
        max_depth=6,
        learning_rate=0.07,
        subsample=0.9,
        colsample_bytree=0.9,
        tree_method="hist",
        eval_metric=eval_metrics,
        n_jobs=-1,
        min_child_weight=5,
        gamma=0.1,
        reg_alpha=0.05,
        reg_lambda=1.0,
    )

    fit_params: Dict[str, Any] = {
        "eval_set": [(X_train, y_train), (X_val, y_val)],
        "verbose": False,
    }

    if sample_weights is not None:
        fit_params["sample_weight"] = sample_weights
    model.fit(X_train, y_train, **fit_params)
    return model


    def save_feature_importance_png(
    model: XGBClassifier,
    feature_names: List[str],
    path: Path,
    top_k: int = 25,
    title: str = "Feature Importance",
) -> None:

importances = model.feature_importances_
    indices = np.argsort(importances)[::-1][:top_k]

    fig, ax = plt.subplots(figsize=(10, 7))
    names = [feature_names[i].strip() for i in indices]
    vals = importances[indices]
    ax.barh(range(len(names)), vals[::-1], color="#4C72B0")
    ax.set_yticks(range(len(names)))
    ax.set_yticklabels(names[::-1], fontsize=9)
    ax.set_xlabel("Importance (gain)")
    ax.set_title(title)
    fig.tight_layout()
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)


def main():
    ap = argparse.ArgumentParser(description="Train XGBoost on cicids_merged.csv (improved pipeline)")
    ap.add_argument("--data", default="dataset/MachineLearningCVE/cicids_merged.csv")
    ap.add_argument("--label-col", default=" Label")
    ap.add_argument("--out", default="ai_engine/saved_models/xgboost_model.pkl")
    ap.add_argument("--drop-port", action="store_true", default=False,
                    help="Remove Destination Port feature to test leakage impact")
    ap.add_argument("--min-per-class", type=int, default=500, dest="min_per_class",
                    help="Minimum samples per class (rare classes kept in full)")
    ap.add_argument("--max-majority", type=int, default=50_000, dest="max_majority",
                    help="Cap for the largest class (BENIGN)")
    ap.add_argument("--sample-frac-medium", type=float, default=0.15, dest="sample_frac_medium",
                    help="Sampling fraction for medium-size classes")
    ap.add_argument("--no-class-weight", action="store_true", default=False, dest="no_class_weight",
                    help="Disable balanced class weights")
    # Legacy arguments (kept for backward compatibility)
    ap.add_argument("--sample-frac", type=float, default=0.02)
    ap.add_argument("--max-rows", type=int, default=300_000)
    ap.add_argument("--chunksize", type=int, default=150_000)
    ap.add_argument("--legacy", action="store_true", default=False,
                    help="Use the original 2%% random sampling (for comparison)")
    args = ap.parse_args()

    print("Training XGBoost on CICIDS merged CSV (improved pipeline)")
    print("=" * 60)
    print(f"  Data:           {args.data}")
    print(f"  Label column:   {args.label_col}")
    print(f"  Drop port:      {args.drop_port}")
    print(f"  Class weights:  {'disabled' if args.no_class_weight else 'balanced'}")
    if args.legacy:
        print(f"  Mode:           LEGACY (random {args.sample_frac*100:.0f}% sampling)")
    else:
        print(f"  Mode:           STRATIFIED (min={args.min_per_class}, max={args.max_majority})")
    print()

    plot_dir = Path(args.out).parent / "xgboost_training_plots"
    plot_dir.mkdir(parents=True, exist_ok=True)

    label_encoder: Optional[LabelEncoder] = None

    if args.legacy:
        print("Loading data (legacy random sampling)...")
        X, y = load_sampled_csv(
            path=args.data,
            label_col=args.label_col,
            sample_frac=args.sample_frac,
            max_rows=args.max_rows,
            chunksize=args.chunksize,
        )

        else:
        print("Loading data (stratified min-guarantee sampling)...")
        X, y, label_encoder = load_stratified_csv(
            path=args.data,
            label_col=args.label_col,
            min_per_class=args.min_per_class,
            max_majority=args.max_majority,
            sample_frac_medium=args.sample_frac_medium,
            drop_port=args.drop_port,
        )

        print(f"\n  Loaded {len(X):,} rows with {X.shape[1]} features")
    feature_names = list(X.columns)

    try:
        X_model, X_hold, y_model, y_hold = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        except ValueError:
        X_model, X_hold, y_model, y_hold = train_test_split(
            X, y, test_size=0.2, random_state=42
        )
    try:
        X_tr, X_val, y_tr, y_val = train_test_split(
            X_model, y_model, test_size=0.12, random_state=42, stratify=y_model
        )
        except ValueError:
        X_tr, X_val, y_tr, y_val = train_test_split(
            X_model, y_model, test_size=0.12, random_state=42
        )

    sample_weights = None
    if not args.no_class_weight:
        sample_weights = compute_sample_weight("balanced", y_tr)
        print(f"  Balanced sample weights applied (range: {sample_weights.min():.3f} – {sample_weights.max():.3f})")

    print("\nTraining XGBoost model (with train + validation eval sets)...")
    model = train_xgboost_classifier(X_tr, y_tr, X_val, y_val, sample_weights=sample_weights)

    # ── Evaluation ────────────────────────────────────────────────
    proba = model.predict_proba(X_hold)
    n_classes = int(proba.shape[1])
    pred = model.predict(X_hold)

    acc = float(accuracy_score(y_hold, pred))
    prec_mac, rec_mac, f1_mac, _ = precision_recall_fscore_support(
        y_hold, pred, average="macro", zero_division=0
    )
    prec_wt, rec_wt, f1_wt, _ = precision_recall_fscore_support(
        y_hold, pred, average="weighted", zero_division=0
    )

    mcc = float(matthews_corrcoef(y_hold, pred))
    try:
        if n_classes == 2:
            auc_v = float(roc_auc_score(y_hold, proba[:, 1]))
        else:
            auc_v = float(roc_auc_score(y_hold, proba, multi_class="ovr", average="weighted"))
    except ValueError:
        auc_v = float("nan")

        print("\n=== Hold-out evaluation (20% stratified) ===")
    if label_encoder is not None:
        target_names = [str(c) for c in label_encoder.classes_]
        print(classification_report(y_hold, pred, target_names=target_names, digits=4, zero_division=0))
    else:
        print(classification_report(y_hold, pred, digits=4, zero_division=0))

    
    print(f"Accuracy:       {acc:.4f}")
    print(f"Macro F1:       {float(f1_mac):.4f}")
    print(f"Weighted F1:    {float(f1_wt):.4f}")
    print(f"MCC:            {mcc:.4f}")
    print(f"ROC-AUC (wt):   {auc_v:.4f}" if not np.isnan(auc_v) else "ROC-AUC: n/a")

    # ── Feature importance ────────────────────────────────────────
    imp = model.feature_importances_
    top_idx = np.argsort(imp)[::-1][:15]
    print("\nTop 15 features by importance:")
    for rank, idx in enumerate(top_idx, 1):
        print(f"  {rank:>2}. {feature_names[idx]:>35s}  {imp[idx]:.4f}")

    save_feature_importance_png(
        model, feature_names,
        plot_dir / "netflow_xgboost_feature_importance.png",
        title="XGBoost (netflow) — top 25 feature importances",
    )

    # ── Plots ─────────────────────────────────────────────────────
    evals = model.evals_result()
    train_key = "validation_0"
    val_key = "validation_1"

    save_xgboost_evals_plot(
        evals, plot_dir / "netflow_xgboost_learning_curve.png",
        title="XGBoost (netflow) — validation metrics per boosting round",
    )

    save_confusion_matrix_predictions_png(
        y_hold, pred,
        plot_dir / "netflow_xgboost_confusion_matrix.png",
        title="XGBoost (netflow) — hold-out confusion matrix",
    )
    bar_m: Dict[str, float] = {
        "Accuracy": acc,
        "Macro F1": float(f1_mac),
        "Weighted F1": float(f1_wt),
        "MCC": mcc,
    }

    if not np.isnan(auc_v):
        bar_m["ROC-AUC"] = auc_v
    save_metrics_bar_png(bar_m, plot_dir / "netflow_xgboost_metrics_bar.png",
                         title="XGBoost — hold-out metrics")


    for loss_key in ("mlogloss", "logloss"):
        train_series = (evals.get(train_key) or {}).get(loss_key)
        val_series = (evals.get(val_key) or {}).get(loss_key)
        if train_series and val_series:
            save_learning_curve_png(
                list(range(1, len(train_series) + 1)),
                train_series,
                val_series,
                plot_dir / "netflow_xgboost_loss_curve.png",
                y_label=loss_key,
                title="XGBoost — train vs validation loss",
            )
            break
            
            elif train_series:
            save_learning_curve_png(
                list(range(1, len(train_series) + 1)),
                train_series, None,
                plot_dir / "netflow_xgboost_loss_curve.png",
                y_label=loss_key,
                title="XGBoost — training loss per round",
            )
            break
            
            for err_key in ("merror", "error"):
        train_series = (evals.get(train_key) or {}).get(err_key)
        val_series = (evals.get(val_key) or {}).get(err_key)
        if train_series and val_series:
            save_learning_curve_png(
                list(range(1, len(train_series) + 1)),
                train_series,
                val_series,
                plot_dir / "netflow_xgboost_error_rate_curve.png",
                y_label="Classification error",
                title="XGBoost — train vs validation error rate",
            )
            break
        elif train_series:
            save_learning_curve_png(
                list(range(1, len(train_series) + 1)),
                train_series, None,
                plot_dir / "netflow_xgboost_error_rate_curve.png",
                y_label="Classification error",
                title="XGBoost — validation error per round",
            )
            break