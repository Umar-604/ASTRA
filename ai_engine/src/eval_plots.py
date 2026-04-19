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
 ys.append(max(0.0, min(1.0, v)))
        ax.plot(folds, ys, marker="o", label=lab)
    ax.set_xticks(folds)
    ax.set_xlabel("Fold")
    ax.set_ylabel("Score")
    ax.set_ylim(0, 1.05)
ax.legend(loc="lower right", fontsize=8)
    ax.grid(True, alpha=0.3)
    ax.set_title(title)
    fig.tight_layout()
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
def save_learning_curve_png(
    epochs: Sequence[int],
    train_values: Sequence[float],
    val_values: Optional[Sequence[float]],
    path: Path,
    y_label: str,
    title: str = "Learning curve",
) -> None:
path.parent.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(7, 4.5))
    ax.plot(epochs, train_values, label="Train", marker="o", markersize=3)
    if val_values is not None and len(val_values) == len(epochs):
        ax.plot(epochs, val_values, label="Validation", marker="s", markersize=3)
    ax.set_xlabel("Iteration / epoch")
    ax.set_ylabel(y_label)
    ax.set_title(title)
ax.legend()
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
def save_lightgbm_eval_plot(eval_result: Dict[str, Any], path: Path, title: str = "LightGBM training / validation") -> None:
    """Plot metrics from lgb.record_evaluation (valid_0 contains binary_logloss, auc, etc.)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    valid_key = "valid_0" if "valid_0" in eval_result else next((k for k in eval_result if k.startswith("valid")), None)
    if not valid_key or not eval_result.get(valid_key):
        return
 metrics_dict = eval_result[valid_key]
    keys = [k for k in metrics_dict if isinstance(metrics_dict[k], list) and metrics_dict[k]]
    if not keys:
        return
    n = min(len(keys), 3)
    fig, axes = plt.subplots(1, n, figsize=(5 * n, 4))
    if n == 1:
axes = [axes]
    for ax, mkey in zip(axes, keys[:n]):
        series = metrics_dict[mkey]
        ax.plot(range(1, len(series) + 1), series, lw=2)
        ax.set_title(mkey)
        ax.set_xlabel("Boosting iteration")
        ax.grid(True, alpha=0.3)
    fig.suptitle(title)
    fig.tight_layout()
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
def save_xgboost_evals_plot(evals_result: Dict[str, Any], path: Path, title: str = "XGBoost training metrics") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    val = evals_result.get("validation_0") or next(iter(evals_result.values()), {})
    if not val:
        return
 keys = list(val.keys())
    n = len(keys)
    fig, axes = plt.subplots(1, n, figsize=(5 * n, 4))
    if n == 1:
        axes = [axes]
