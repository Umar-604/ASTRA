"""
Shared evaluation figures for Astra training scripts (ROC, PR, metrics bars, learning curves).
Uses matplotlib Agg backend; safe for headless runs.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

import numpy as np

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    PrecisionRecallDisplay,
    RocCurveDisplay,
    auc,
    precision_recall_curve,
    roc_curve,
)

def save_confusion_matrix_png(
    cm: np.ndarray,
    path: Path,
    title: str,
    display_labels: Tuple[str, str] = ("Negative (0)", "Positive (1)"),
) -> None:
path.parent.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(5.5, 4.5))
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=list(display_labels))
    disp.plot(ax=ax, cmap="Blues", colorbar=True, values_format="d")
    ax.set_title(title)
    fig.tight_layout()
fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
def save_confusion_matrix_predictions_png(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    path: Path,
    title: str,
) -> None:
    """Confusion matrix for any number of classes (e.g. multiclass CICIDS)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(min(14, 4 + 0.35 * len(np.unique(y_true))), 6))
    disp = ConfusionMatrixDisplay.from_predictions(
        y_true, y_pred, ax=ax, cmap="Blues", colorbar=True, xticks_rotation=45
 )
    ax.set_title(title)
    fig.tight_layout()
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
