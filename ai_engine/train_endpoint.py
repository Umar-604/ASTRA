#!/usr/bin/env python3
"""
Train behavioral models for endpoint events
Supports Isolation Forest, Autoencoder, and LSTM models
"""
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report,
 roc_auc_score,
    confusion_matrix,
    precision_recall_fscore_support,
)
import os
import json
import warnings
from datetime import datetime, timezone
from typing import Dict, List, Any, Tuple, Optional
# Suppress TensorFlow mutex warnings
os.environ['OMP_NUM_THREADS'] = '1'
os.environ['OPENBLAS_NUM_THREADS'] = '1'
os.environ['MKL_NUM_THREADS'] = '1'
os.environ['NUMEXPR_NUM_THREADS'] = '1'
# Suppress specific warnings
warnings.filterwarnings('ignore', category=UserWarning, module='tensorflow')
import tensorflow as tf
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense, LSTM, Dropout, RepeatVector, TimeDistributed, BatchNormalization
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping
from tensorflow.keras.regularizers import L2
from .config import settings
from .features.endpoint_behavioral import (
 extract_endpoint_behavioral_features,
    get_canonical_feature_order,
    validate_feature_dict,
)

# Optional matplotlib for AE threshold visualization
try:
 import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    _HAS_MATPLOTLIB = True
except ImportError:
_HAS_MATPLOTLIB = False

try:
 from scipy.stats import gaussian_kde
    _HAS_SCIPY_KDE = True
except ImportError:
    _HAS_SCIPY_KDE = False
class EndpointModelTrainer:
    """Train behavioral models for endpoint events"""
def __init__(self, model_type: str = "isolation_forest"):
        self.model_type = model_type
        self.model = None
        self.scaler = StandardScaler()
        self.feature_names = Noneself.training_stats = {}
        
    def train(self, data_path: str, output_dir: str = None) -> Dict[str, Any]:
        """Train the endpoint behavioral model"""
        print(f"🚀 Training {self.model_type} model for endpoint behavioral analysis...")
# Load and prepare data
        X, y = self._load_and_prepare_data(data_path)
        
 # Split data (stratify only when both classes present)
        stratify_arg = y if len(np.unique(y)) > 1 else None
        X_train, X_test, y_train, y_test = train_test_split(
  X, y, test_size=0.2, random_state=42, stratify=stratify_arg
        )
        
        # Scale features
X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        plot_dir = str(output_dir if output_dir is not None else settings.MODEL_DIR)
 # Train model
        if self.model_type == "isolation_forest":
            self._train_isolation_forest(X_train_scaled, y_train)
        elif self.model_type == "autoencoder":
self._train_autoencoder(X_train_scaled, y_train, plot_dir=plot_dir)
        elif self.model_type == "lstm":
            self._train_lstm(X_train_scaled, y_train, plot_dir=plot_dir)
        else:
            raise ValueError(f"Unknown model type: {self.model_type}")
        if output_dir is None:
            output_dir = settings.MODEL_DIR # Evaluate model (for AE, pass output_dir and train data for threshold plot + FP minimization)
        if self.model_type == "autoencoder":
            metrics = self._evaluate_model(
                X_test_scaled, y_test,
                output_dir=output_dir, X_train=X_train_scaled, y_train=y_train,
            ) # Save model (metadata will include reconstruction stats and threshold metadata for AE)
        self._save_model(output_dir)
 print(f"✅ Training completed!")
        print(f"   Model: {self.model_type}")
        print(f"   Features: {len(self.feature_names)}")
        if self.model_type == "autoencoder":
 print(f"   Anomaly threshold: {metrics.get('anomaly_threshold', 0):.6f}")
        else:
            print(f"   Test AUC: {metrics.get('auc', 0):.3f}")
  return {
            "model_type": self.model_type,
            "feature_count": len(self.feature_names),
            "metrics": metrics,



        else:
            metrics = self._evaluate_model(X_test_scaled, y_test)
            metrics = self._evaluate_model(X_test_scaled, y_test) "reconstruction_error_mean", "reconstruction_error_std", "anomaly_threshold", "k_std", "anomaly_rate",
                "threshold_candidates", "threshold_metadata", "model_version", "fp_rate_benign_val",
            ):
                if k in metrics:

}
                    self.training_stats[k] = metrics[k]


 "training_stats": self.training_stats
        }
    
    def _load_and_prepare_data(self, data_path: str) -> Tuple[np.ndarray, np.ndarray]:
        """Load and prepare training data"""
print("📊 Loading and preparing data...")
        
        if data_path.endswith('.json'):
            # Load from JSON file
            with open(data_path, 'r') as f:
 data = json.load(f)
        elif data_path.endswith('.csv'):
            # Load from CSV file
            df = pd.read_csv(data_path)
            data = df.to_dict('records')
 else:
            raise ValueError("Unsupported file format. Use .json or .csv")
        
        print(f"   Loaded {len(data)} records")
        
 # Use canonical feature order so training and inference always match
        self.feature_names = get_canonical_feature_order()
        expected_window_events = len(data[0].get('events', [])) if data else None
        if expected_window_events is not None:
            self.training_stats["window_events"] = expected_window_eventsfeatures_list = []
        labels = []
 for i, record in enumerate(data):
            events = record.get('events', [])
            # Reject partial windows: only full windows go to the model
            if expected_window_events is not None and len(events) != expected_window_events:
                raise ValueError(
f"Record {i}: window has {len(events)} events, expected {expected_window_events}. "
                    "Partial windows must be rejected; use only full windows for training."
                )
features = extract_endpoint_behavioral_features(events)
            validate_feature_dict(features, self.feature_names)
            # Build row in exact canonical order
            features_list.append([float(features.get(k, 0.0)) for k in self.feature_names])
            labels.append(record.get('label', 0))  # 0 = benign, 1 = malicious
 X = np.array(features_list)
        y = np.array(labels)
assert X.shape[1] == len(self.feature_names), (
            f"Feature count mismatch: X has {X.shape[1]} columns, feature_names has {len(self.feature_names)}"
        )
print(f"   Extracted {X.shape[1]} features from {X.shape[0]} samples (canonical order)")
        print(f"   Window size: {expected_window_events} events")
        print(f"   Label distribution: {np.bincount(y)}")
        
        return X, y
 def _train_isolation_forest(self, X_train: np.ndarray, y_train: np.ndarray):
        """Train Isolation Forest model"""
        print("🌲 Training Isolation Forest...")
        
 # Use only benign samples for training (unsupervised)
        benign_mask = y_train == 0
        X_benign = X_train[benign_mask]
self.model = IsolationForest(
            contamination=0.1,  # Expected proportion of outliers
            random_state=42,
            n_estimators=100
        )
 self.model.fit(X_benign)
        
        self.training_stats = {
            "training_samples": len(X_benign),
            "contamination": 0.1,
            "n_estimators": 100
        }
def _train_autoencoder(self, X_train: np.ndarray, y_train: np.ndarray, plot_dir: str | None = None):
        """Train Autoencoder model: deeper architecture with L2 and dropout regularization."""
        print("🔧 Training Autoencoder (deep, regularized)...")
# Train strictly on benign windows only (label=0)
        benign_mask = y_train == 0
        X_benign = X_train[benign_mask]
input_dim = X_benign.shape[1]
        encoding_dim = max(32, input_dim // 4)
        reg = L2(1e-5)
        drop = 0.3
        
 # Encoder: input -> Dense -> BN -> Dropout -> Dense -> Dropout -> bottleneck
        input_layer = Input(shape=(input_dim,))
        x = Dense(encoding_dim * 2, activation="relu", kernel_regularizer=reg)(input_layer)
        x = BatchNormalization()(x)
        x = Dropout(drop)(x)
        x = Dense(encoding_dim, activation="relu", kernel_regularizer=reg)(x)
        x = Dropout(drop)(x)
        bottleneck = Dense(max(16, encoding_dim // 2), activation="relu", kernel_regularizer=reg)(x)
 # Decoder: bottleneck -> Dense -> Dropout -> Dense -> Dropout -> output
        x = Dense(encoding_dim, activation="relu", kernel_regularizer=reg)(bottleneck)
        x = Dropout(drop)(x)x = Dense(encoding_dim * 2, activation="relu", kernel_regularizer=reg)(x)
        x = Dropout(drop)(x)
        output = Dense(input_dim, activation="sigmoid")(x) autoencoder = Model(input_layer, output)
        autoencoder.compile(optimizer=Adam(learning_rate=0.001), loss='mse')
        
        early_stopping = EarlyStopping(monitor='val_loss', patience=15, restore_best_weights=True)
 history = autoencoder.fit(
            X_benign, X_benign,
            epochs=150,
            batch_size=32,
            validation_split=0.2, callbacks=[early_stopping],
            verbose=0
        )
self.model = autoencoder

        if plot_dir:
            try:
  from pathlib import Path
                from src.eval_plots import save_keras_history_png
                os.makedirs(plot_dir, exist_ok=True)
                save_keras_history_png(
                    history.history,
Path(plot_dir) / "endpoint_autoencoder_loss_curve.png",
                    title="Endpoint autoencoder — training",
                )
            except Exception as _e:
                print(f"⚠️  Could not save AE loss curve plot: {_e}")
self.training_stats = {
            "training_samples": len(X_benign),
            "input_dim": input_dim,
            "encoding_dim": encoding_dim,
 "epochs_trained": len(history.history['loss']),
            "final_loss": float(history.history['loss'][-1]),
        }
def _train_lstm(self, X_train: np.ndarray, y_train: np.ndarray, plot_dir: str | None = None):
        """Train LSTM model for sequence analysis"""
        print("🧠 Training LSTM...") # Reshape data for LSTM (samples, timesteps, features)
        # For now, treat each sample as a single timestep
        X_reshaped = X_train.reshape(X_train.shape[0], 1, X_train.shape[1])
  input_dim = X_train.shape[1]
        lstm_units = 64
 # Build LSTM model
        input_layer = Input(shape=(1, input_dim))
        lstm_layer = LSTM(lstm_units, return_sequences=True)(input_layer)
        lstm_layer = Dropout(0.2)(lstm_layer)
        lstm_layer = LSTM(lstm_units // 2)(lstm_layer)
        lstm_layer = Dropout(0.2)(lstm_layer)
        output_layer = Dense(1, activation='sigmoid')(lstm_layer)
 model = Model(input_layer, output_layer)
        model.compile( optimizer=Adam(learning_rate=0.001),
            loss='binary_crossentropy',
            metrics=['accuracy']
        )
 # Train LSTM
        early_stopping = EarlyStopping(monitor='val_loss', patience=10, restore_best_weights=True)
  history = model.fit(
            X_reshaped, y_train,
            epochs=100,
            batch_size=32,
            validation_split=0.2,
 callbacks=[early_stopping],
            verbose=0
        )
 self.model = model

        if plot_dir:
            try:
 from pathlib import Path
                from src.eval_plots import save_keras_history_png
                os.makedirs(plot_dir, exist_ok=True)
                save_keras_history_png(
                    history.history,
 Path(plot_dir) / "endpoint_lstm_loss_accuracy_curve.png",
                    title="Endpoint LSTM — training",
                )

self.training_stats = {
            "training_samples": len(X_train),
            "input_dim": input_dim,
            "lstm_units": lstm_units,
 "epochs_trained": len(history.history['loss']),
            "final_loss": history.history['loss'][-1]
        }

    def _compute_ae_threshold_candidates(
        self,
        mse_benign: np.ndarray,
        percentiles: Tuple[int, ...] = (95, 97, 99),
        k_std: float = 3.0,
) -> Tuple[Dict[str, float], float, float]:
        """Compute threshold candidates from benign validation reconstruction errors.
        Returns (candidates_dict, mean_mse, std_mse)."""
        if len(mse_benign) == 0:
            mean_mse = 0.0
std_mse = 1.0
            candidates = {"p95": 0.0, "p97": 0.0, "p99": 0.0, "mean_k_std": 0.0}
            return candidates, mean_mse, std_mse
        mean_mse = float(np.mean(mse_benign))
        std_mse = float(np.std(mse_benign)) or 1e-9
  candidates: Dict[str, float] = {}
        for p in percentiles:
            candidates[f"p{p}"] = float(np.percentile(mse_benign, p))
        candidates["mean_k_std"] = mean_mse + k_std * std_mse
        return candidates, mean_mse, std_mse
def _select_ae_threshold(
        self,
        candidates: Dict[str, float],
        strategy: str = "minimize_fp",
        default_percentile: int = 99,
 ) -> Tuple[float, Dict[str, Any]]:
        """Select a stable default threshold from candidates.
        strategy: 'minimize_fp' -> use percentile (default 99) so few benign windows exceed.
        Returns (threshold_value, metadata dict)."""
        if strategy == "minimize_fp":
            key = f"p{default_percentile}"
 threshold = candidates.get(key, candidates.get("p99", candidates["mean_k_std"]))
            metadata = {
                "threshold_method": "percentile",
                "threshold_percentile": default_percentile,
                "candidates": candidates,
 else:
            threshold = candidates.get("mean_k_std", candidates.get("p99", 0.0))
            metadata = {
                "threshold_method": "mean_k_std",
                "candidates": candidates,
     "candidates": candidates,
            }
        return threshold, metadata

def _plot_ae_reconstruction_distribution(
        self,
        mse_train_benign: Optional[np.ndarray],
        mse_val_benign: np.ndarray,
        mse_val_anomaly: Optional[np.ndarray],
        candidates: Dict[str, float],
        selected_threshold: float,
  output_path: str,
        *,
        mean_mse: Optional[float] = None,
        std_mse: Optional[float] = None,
        fp_rate_benign: Optional[float] = None,
        anomaly_rate: Optional[float] = None,
        threshold_method: Optional[str] = None,
 threshold_percentile: Optional[int] = None,
    ) -> None:
        """Plot reconstruction error distribution: KDE curves (train/val benign), log10 X-axis
        limited to [min_error, threshold*1.2], P99 thick black, P95/P97 thin dashed.
        Poster-ready; raw MSE unchanged (no scaling/normalization)."""
        if not _HAS_MATPLOTLIB:
  return
        # Visible range: [min_error, threshold * 1.2] — raw MSE unchanged
        all_mse = []
        if mse_train_benign is not None and len(mse_train_benign) > 0:
            all_mse.extend(mse_train_benign.ravel().tolist())
        all_mse.extend(mse_val_benign.ravel().tolist()) all_mse = np.array(all_mse)
        min_mse = max(1e-10, np.min(all_mse[all_mse > 0])) if np.any(all_mse > 0) else 1e-10
        x_max = selected_threshold * 1.2
        x_grid = np.logspace(np.log10(min_mse), np.log10(x_max + 1e-10), 200)

   "axes.facecolor": "#fafafa",
            "figure.facecolor": "white",
        })
fig, ax = plt.subplots(figsize=(14, 8), facecolor="white")
        ax.set_facecolor("#fafafa")
        # Colorblind-friendly palette (Okabe–Ito–style): blue, orange
        train_color, val_color = "#0173B2", "#DE8F05"
        # KDE curves for train (benign) and validation (benign); display-only clamp for log scale
        if _HAS_SCIPY_KDE:
 if mse_train_benign is not None and len(mse_train_benign) > 0:
                mse_t = np.maximum(mse_train_benign.ravel(), min_mse)
                try:
kde_t = gaussian_kde(mse_t, bw_method="scott")
                    dens_t = np.maximum(kde_t(x_grid), 1e-12)
                    ax.fill_between(x_grid, dens_t, alpha=0.25, color=train_color)
                    ax.plot(x_grid, dens_t, color=train_color, linewidth=2.5, label="Train (benign)")
                except Exception:
                    pass
mse_v = np.maximum(mse_val_benign.ravel(), min_mse)
            try:
                kde_v = gaussian_kde(mse_v, bw_method="scott")
                dens_v = np.maximum(kde_v(x_grid), 1e-12)
                ax.fill_between(x_grid, dens_v, alpha=0.25, color=val_color)
                ax.plot(x_grid, dens_v, color=val_color, linewidth=2.5, label="Validation (benign)")
            except Exception:
                pass

        else:
            # Fallback: histograms if scipy not available
            bin_edges = np.logspace(np.log10(min_mse), np.log10(x_max + 1e-10), 50)
            if mse_train_benign is not None and len(mse_train_benign) > 0:
                mse_t = np.maximum(mse_train_benign.ravel(), min_mse)
 ax.hist(mse_t, bins=bin_edges, alpha=0.5, label="Train (benign)", color=train_color, density=True, histtype="stepfilled")
            mse_v = np.maximum(mse_val_benign.ravel(), min_mse)
            ax.hist(mse_v, bins=bin_edges, alpha=0.5, label="Validation (benign)", color=val_color, density=True, histtype="stepfilled")
        # P95 and P97: thin, light dashed; P99: thick solid black
        p95_val = candidates.get("p95")
        p97_val = candidates.get("p97")
  if p95_val is not None and min_mse <= p95_val <= x_max:
            ax.axvline(p95_val, color="#9ca3af", linestyle="--", linewidth=1, alpha=0.7, label="P95")
        if p97_val is not None and min_mse <= p97_val <= x_max:
            ax.axvline(p97_val, color="#9ca3af", linestyle="--", linewidth=1, alpha=0.7, label="P97")
        ax.axvline(
   selected_threshold, color="black", linestyle="-", linewidth=3.5,
            label=f"Threshold (P{threshold_percentile or 99})", zorder=10,
        )
        ax.set_xscale("log")
        ax.set_xlim(min_mse, x_max) ax.set_xlabel("Reconstruction error (MSE)", fontsize=20, color="#374151")
        ax.set_ylabel("Density", fontsize=20, color="#374151")
        ax.set_title(
            "Normal behavior vs anomaly boundary",
            fontsize=24, fontweight="600", color="#111827", pad=18,
        )
ax.tick_params(axis="both", labelsize=16, colors="#4B5563")
        ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda x, _: f"{x:.2f}"))
        ax.grid(True, axis="y", alpha=0.15, color="#d1d5db", linestyle="-")
        ax.set_axisbelow(True)
        ax.legend(loc="upper right", fontsize=14, frameon=True, fancybox=False, framealpha=0.98, edgecolor="#e5e7eb")
        # Simplified annotation: Mean MSE, Threshold, FP rate — clean corner box
 lines = []
        if mean_mse is not None:
            lines.append(f"Mean MSE: {mean_mse:.6f}")
        lines.append(f"Threshold: {selected_threshold:.6f}")
        if fp_rate_benign is not None:
            lines.append(f"FP rate: {fp_rate_benign * 100:.2f}%")
        if lines:
 ax.text(
                0.03, 0.97, "\n".join(lines),
                transform=ax.transAxes, fontsize=14, verticalalignment="top", horizontalalignment="left",
                bbox=dict(boxstyle="round,pad=0.5", facecolor="white", edgecolor="#d1d5db", alpha=0.95),
                fontfamily="monospace", color="#374151",
            )
fig.tight_layout()
        fig.savefig(output_path, dpi=300, bbox_inches="tight", facecolor="white", edgecolor="none")
        plt.close(fig)
def _evaluate_model(
        self,
        X_test: np.ndarray,
        y_test: np.ndarray,
        output_dir: Optional[str] = None,
        X_train: Optional[np.ndarray] = None,  y_train: Optional[np.ndarray] = None,
    ) -> Dict[str, Any]:
        """Evaluate the trained model"""
        print("📈 Evaluating model...")
 if self.model_type == "autoencoder":
            # Autoencoder: evaluate via reconstruction error; threshold from benign validation to minimize FP
            reconstructions = self.model.predict(X_test)
            mse_all = np.mean(np.power(X_test - reconstructions, 2), axis=1)
            y_test = np.asarray(y_test).ravel()
            val_benign_mask = y_test == 0
            val_anomaly_mask = y_test == 1
  mse_val_benign = mse_all[val_benign_mask]
            mse_val_anomaly = mse_all[val_anomaly_mask] if np.any(val_anomaly_mask) else None

            # Optional: train benign MSE for plot (if caller passed train data)
 mse_train_benign = None
            if X_train is not None and y_train is not None:
                y_train = np.asarray(y_train).ravel()
                train_benign_mask = y_train == 0
                if np.any(train_benign_mask):
 rec_train = self.model.predict(X_train[train_benign_mask])
                    mse_train_benign = np.mean(np.power(X_train[train_benign_mask] - rec_train, 2), axis=1)

 k_std = float(os.environ.get("AE_THRESHOLD_K_STD", "3"))
            percentiles = (95, 97, 99)
            candidates, mean_mse, std_mse = self._compute_ae_threshold_candidates(
                mse_val_benign, percentiles=percentiles, k_std=k_std
            )
            default_percentile = int(os.environ.get("AE_THRESHOLD_PERCENTILE", "99"))
            threshold, threshold_metadata = self._select_ae_threshold(
                candidates, strategy="minimize_fp", default_percentile=default_percentile
            )anomaly_rate = float((mse_all > threshold).mean())
            fp_rate_benign = float((mse_val_benign > threshold).mean()) if len(mse_val_benign) > 0 else 0.0

            print("   Autoencoder reconstruction error statistics (benign validation):")
            print(f"      mean MSE        : {mean_mse:.6f}")
            print(f"      std  MSE        : {std_mse:.6f}") print(f"      candidates      : p95={candidates.get('p95', 0):.6f} p97={candidates.get('p97', 0):.6f} p99={candidates.get('p99', 0):.6f} mean+{k_std}*std={candidates.get('mean_k_std', 0):.6f}")
            print(f"      selected thresh : {threshold:.6f} ({threshold_metadata.get('threshold_method', '')} {threshold_metadata.get('threshold_percentile', '')})")
            print(f"      FP rate (benign): {fp_rate_benign * 100:.2f}% | anomaly rate (all): {anomaly_rate * 100:.2f}%")
model_version = datetime.now(timezone.utc).isoformat()
            plot_path = None
            if output_dir:
os.makedirs(output_dir, exist_ok=True)
                suffix = os.environ.get("AE_NAME_SUFFIX", "").strip()
                plot_name = f"ae_reconstruction_error_distribution_{suffix}.png" if suffix else "ae_reconstruction_error_distribution.png"
                plot_path = os.path.join(output_dir, plot_name)
                self._plot_ae_reconstruction_distribution(
 mse_train_benign, mse_val_benign, mse_val_anomaly,
                    candidates, threshold, plot_path,
                    mean_mse=mean_mse,
                    std_mse=std_mse,
                    fp_rate_benign=fp_rate_benign,
anomaly_rate=anomaly_rate,
                    threshold_method=threshold_metadata.get("threshold_method"),
                    threshold_percentile=threshold_metadata.get("threshold_percentile"),
                )
 if _HAS_MATPLOTLIB:
                    print(f"      plot saved       : {plot_path}")

            out = {
 "reconstruction_error_mean": mean_mse,
                "reconstruction_error_std": std_mse,
                "anomaly_threshold": threshold,
                "k_std": k_std,
                "anomaly_rate": anomaly_rate,
 "fp_rate_benign_val": fp_rate_benign,
                "threshold_candidates": candidates,
                "threshold_metadata": threshold_metadata,
                "model_version": model_version,
            }
            if plot_path:
 out["plot_path"] = plot_path
            return out
 # Classification-style metrics for non-AE models
        if self.model_type == "isolation_forest":
            # Isolation Forest returns -1 for outliers, 1 for inliers
            predictions = self.model.predict(X_test)
            scores = self.model.score_samples(X_test) # Convert to binary: -1 (outlier) -> 1 (anomaly), 1 (inlier) -> 0 (normal)
            y_pred = (predictions == -1).astype(int)
            
            # Convert scores to probabilities (higher score = more normal)
            y_proba = 1 - (scores - scores.min()) / (scores.max() - scores.min() + 1e-9)
elif self.model_type == "lstm":
            # LSTM binary classification
            X_test_reshaped = X_test.reshape(X_test.shape[0], 1, X_test.shape[1])
            y_proba = self.model.predict(X_test_reshaped).flatten()
            y_pred = (y_proba > 0.5).astype(int)
# Calculate metrics
        try:
            auc = roc_auc_score(y_test, y_proba)
        except:
            auc = 0.5
        accuracy = np.mean(y_pred == y_test)
  # Confusion matrix and classification metrics
        # Labels: 0 = benign/normal, 1 = malicious/anomalous
        cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_test,
            y_pred,
            average="binary",
            zero_division=0,
        )
 print(f"   Accuracy : {accuracy:.3f}")
        print(f"   Precision: {precision:.3f}")
        print(f"   Recall   : {recall:.3f}")
        print(f"   F1-score : {f1:.3f}")
        print(f"   AUC      : {auc:.3f}")
        print("   Confusion matrix [[TN, FP], [FN, TP]]:")
        print(f"      {cm.tolist()}")
