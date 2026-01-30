"""
Endpoint behavioral model predictor
Integrates with ASTRA's existing pipeline
"""
import joblib
import numpy as np
import os
import warnings

# Suppress TensorFlow mutex warnings
os.environ['OMP_NUM_THREADS'] = '1'
os.environ['OPENBLAS_NUM_THREADS'] = '1'
os.environ['MKL_NUM_THREADS'] = '1'
os.environ['NUMEXPR_NUM_THREADS'] = '1'

# Suppress specific warnings
warnings.filterwarnings('ignore', category=UserWarning, module='tensorflow')

import tensorflow as tf
from collections import deque
from typing import Dict, List, Any, Optional, Tuple

# Cumulative scoring: keep last N raw MSE values per (host_id, process_id)
_CUMULATIVE_MAX_LEN = 100
# Cumulative threshold = multiple of per-event threshold; repeated low scores can trigger
_CUMULATIVE_THRESHOLD_MULTIPLIER = 2.5


class EndpointPredictor:
    """Predict endpoint behavioral anomalies with optional cumulative scoring per host/process."""
    
    def __init__(self, model_path: str = None):
        self.model = None
        self.scaler = None
        self.feature_names = None
        self.model_type = None
        self.training_stats = None
        # Cumulative anomaly scores: (host_id, process_id) -> deque of raw MSE values
        self._cumulative: Dict[Tuple[str, str], deque] = {}

        if model_path:
            self.load_model(model_path)
    
    def load_model(self, model_path: str):
        """Load trained endpoint model"""
        try:
            if os.path.isdir(model_path):
                # TensorFlow model directory
                self.model = tf.keras.models.load_model(model_path)
                
                # Load metadata
                metadata_path = os.path.join(model_path, 'metadata.pkl')
                if os.path.exists(metadata_path):
                    metadata = joblib.load(metadata_path)
                    self.scaler = metadata.get('scaler')
                    self.feature_names = metadata.get('feature_names')
                    self.model_type = metadata.get('model_type')
                    self.training_stats = metadata.get('training_stats')
            elif model_path.endswith('.keras'):
                # Keras model file
                self.model = tf.keras.models.load_model(model_path)
                base = os.path.splitext(model_path)[0]
                metadata_path = f"{base}_metadata.pkl"
                if os.path.exists(metadata_path):
                    metadata = joblib.load(metadata_path)
                    self.scaler = metadata.get('scaler')
                    self.feature_names = metadata.get('feature_names')
                    self.model_type = metadata.get('model_type') or 'autoencoder'
                    self.training_stats = metadata.get('training_stats')
                else:
                    self.model_type = 'autoencoder'
            else:
                # Pickle file (sklearn model)
                data = joblib.load(model_path)
                self.model = data.get('model')
                self.scaler = data.get('scaler')
                self.feature_names = data.get('feature_names')
                self.model_type = data.get('model_type')
                self.training_stats = data.get('training_stats')
            print(f"✅ Loaded endpoint model: {self.model_type}")
            print(f"   Features: {len(self.feature_names) if self.feature_names else 'unknown'}")
            
        except Exception as e:
            print(f"⚠️  Failed to load endpoint model: {e}")
            self.model = None
    
    def predict(
        self,
        events: List[Dict[str, Any]],
        threshold: float = 0.5,
        host_id: Optional[str] = None,
        process_id: Optional[str] = None,
        use_cumulative: bool = True,
        ) -> Dict[str, Any]:
        """Predict behavioral anomaly for endpoint events.
        Uses mean+k*std threshold from training_stats when available.
        If host_id/process_id are provided and use_cumulative is True, repeated
        low-score anomalies can still raise an alert via cumulative scoring."""
        if self.model is None:
            return {
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "cumulative_score": 0.0,
                "confidence": 0.0,
                "model_used": False,
                "error": "No model loaded"
            }
        try:
            # Extract behavioral features
            features = extract_endpoint_behavioral_features(events)
            
            # Build array in model's feature order (handles old 26-feature models with new 30-feature extractor)
            if self.feature_names:
                feature_array = np.array([[
                    float(features.get(k, 0.0)) for k in self.feature_names
                ]]).reshape(1, -1)
            else:
                feature_array = np.array([list(features.values())]).reshape(1, -1)
            
            # Scale features
            if self.scaler:
                feature_array = self.scaler.transform(feature_array)

            raw_mse: Optional[float] = None
            saved_threshold: Optional[float] = None
            if self.training_stats and isinstance(self.training_stats, dict):
                saved_threshold = self.training_stats.get("anomaly_threshold")

                cumulative_score = 0.0
            
            # Make prediction
            if self.model_type == "isolation_forest":
                prediction = self.model.predict(feature_array)[0]
                score = self.model.score_samples(feature_array)[0]
                anomaly_score = 1 - (score - score.min()) / (score.max() - score.min() + 1e-9)
                is_anomaly = prediction == -1
            
            elif self.model_type == "autoencoder":
                reconstruction = self.model.predict(feature_array)
                mse = float(np.mean(np.power(feature_array - reconstruction, 2)))
                raw_mse = mse

                if saved_threshold is not None:
                    anomaly_score = min(mse / max(float(saved_threshold), 1e-9), 1.0)
                    is_anomaly = mse > saved_threshold
                else:
                    anomaly_score = min(mse / 10.0, 1.0)
                    is_anomaly = anomaly_score > threshold