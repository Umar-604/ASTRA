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
