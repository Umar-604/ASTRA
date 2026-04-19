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
