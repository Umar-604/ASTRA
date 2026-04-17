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


