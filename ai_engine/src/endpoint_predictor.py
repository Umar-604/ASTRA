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

from .features.endpoint_behavioral import extract_endpoint_behavioral_features

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
                
                # Cumulative scoring per host/process: repeated low scores can raise alert
                if use_cumulative and (host_id is not None or process_id is not None):
                    key = (host_id or "default", process_id or "default")
                    if key not in self._cumulative:
                        self._cumulative[key] = deque(maxlen=_CUMULATIVE_MAX_LEN)
                    self._cumulative[key].append(raw_mse)
                    cumulative_score = float(sum(self._cumulative[key]))
                    cum_thresh = (saved_threshold or 0.0) * _CUMULATIVE_THRESHOLD_MULTIPLIER
                    if cum_thresh > 0 and cumulative_score > cum_thresh:
                        is_anomaly = True
                
            elif self.model_type == "lstm":
                feature_reshaped = feature_array.reshape(1, 1, -1)
                proba = self.model.predict(feature_reshaped)[0][0]
                anomaly_score = float(proba)
                is_anomaly = proba > threshold
                
            else:
                raise ValueError(f"Unknown model type: {self.model_type}")
            
            confidence = abs(anomaly_score - 0.5) * 2
            
            out: Dict[str, Any] = {
                "is_anomaly": bool(is_anomaly),
                "anomaly_score": float(anomaly_score),
                "confidence": float(confidence),
                "model_used": True,
                "model_type": self.model_type,
                "features_extracted": len(features),
            }
            if raw_mse is not None:
                out["raw_mse"] = raw_mse
            if cumulative_score > 0 or (raw_mse is not None and use_cumulative):
                out["cumulative_score"] = cumulative_score
            return out
            
        except Exception as e:
            return {
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "cumulative_score": 0.0,
                "confidence": 0.0,
                "model_used": False,
                "error": str(e)
            }
    
    def get_feature_importance(self, events: List[Dict[str, Any]]) -> Dict[str, float]:
        """Get feature importance for the prediction"""
        if self.model is None or self.feature_names is None:
            return {}
        
        try:
            # Extract features
            features = extract_endpoint_behavioral_features(events)
            feature_values = list(features.values())
            
            # Calculate feature importance (simplified)
            # For now, return normalized feature values as importance
            max_val = max(feature_values) if feature_values else 1.0
            importance = {name: abs(val) / max_val for name, val in zip(self.feature_names, feature_values)}
            
            return importance
            
        except Exception as e:
            print(f"⚠️  Error calculating feature importance: {e}")
            return {}

def create_endpoint_predictor(model_path: str = None) -> EndpointPredictor:
    """Create endpoint predictor instance"""
    if model_path is None:
        # Try to find default model
        from .config import settings
        model_dir = settings.MODEL_DIR
        
        # Look for endpoint models
        possible_paths = [
            # Prefer dataset-specific AEs if present
            os.path.join(model_dir, "endpoint_model_autoencoder_execution.keras"),
            os.path.join(model_dir, "endpoint_model_autoencoder_lateral.keras"),
            # Generic AE
            os.path.join(model_dir, "endpoint_model_autoencoder.keras"),
            os.path.join(model_dir, "endpoint_model_autoencoder"),
            # Other models
            os.path.join(model_dir, "endpoint_model_isolation_forest.pkl"),
            os.path.join(model_dir, "endpoint_model_lstm")
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                model_path = path
                break
    
    return EndpointPredictor(model_path)
