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