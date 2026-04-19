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
def save_roc_curve_png(
    y_true: np.ndarray,
    y_score: np.ndarray,
    path: Path,
 title: str = "ROC curve",
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(6, 5))
    fpr, tpr, _ = roc_curve(y_true, y_score)
    roc_auc = auc(fpr, tpr)
    disp = RocCurveDisplay(fpr=fpr, tpr=tpr, roc_auc=roc_auc, estimator_name="Model")
    disp.plot(ax=ax)
 ax.set_title(f"{title}\nAUC = {roc_auc:.4f}")
    fig.tight_layout()
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
def save_pr_curve_png(
    y_true: np.ndarray,
    y_score: np.ndarray,
    path: Path,
    title: str = "Precision–Recall curve",
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(6, 5))
    prec, rec, _ = precision_recall_curve(y_true, y_score)
    ap = auc(rec, prec)
    disp = PrecisionRecallDisplay(precision=prec, recall=rec, average_precision=ap)
    disp.plot(ax=ax)
ax.set_title(f"{title}\nAP = {ap:.4f}")
    fig.tight_layout()
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)


def save_metrics_bar_png(
    metrics: Mapping[str, float],
    path: Path,
    title: str = "Hold-out metrics",
    y_max: float = 1.05,
) -> None:
    """Bar chart for scores in [0,1] such as accuracy, precision, recall, F1, ROC-AUC."""
    path.parent.mkdir(parents=True, exist_ok=True)
    names = list(metrics.keys())
 vals = [float(metrics[k]) for k in names]
    fig, ax = plt.subplots(figsize=(max(6, len(names) * 1.2), 5))
    colors = plt.cm.Set2(np.linspace(0, 1, len(names)))
    bars = ax.bar(names, vals, color=colors)
ax.set_ylim(0, y_max)
    ax.set_ylabel("Score")
    ax.set_title(title)
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, v + 0.02, f"{v:.3f}", ha="center", va="bottom", fontsize=10)
    plt.xticks(rotation=25, ha="right")
    fig.tight_layout()
fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)def save_cv_metrics_bar_png(
    cv_fold_rows: Sequence[Mapping[str, Any]],
    path: Path,
    title: str = "Cross-validation metrics by fold",
) -> None:
"""Line plot: each metric vs fold (clearer than many grouped bars)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    folds = [int(r["fold"]) for r in cv_fold_rows]
    metric_keys = ["accuracy", "precision_attack", "recall_attack", "f1_attack", "roc_auc"]
    labels = ["Accuracy", "Precision", "Recall", "F1", "ROC-AUC"]
fig, ax = plt.subplots(figsize=(8, 4.5))
    for key, lab in zip(metric_keys, labels):
        ys = []
        for r in cv_fold_rows:
            v = float(r.get(key, 0))
            if key == "roc_auc" and (v != v):
                v = 0.0
