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
