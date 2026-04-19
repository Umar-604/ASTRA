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
        
