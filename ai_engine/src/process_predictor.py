"""
Process behavioral model predictor
Dedicated predictor for process events with real behavioral analysis
"""

import joblib
import numpy as np
import os
import warnings
from typing import Dict, List, Any, Optional

# Suppress TensorFlow mutex warnings
os.environ['OMP_NUM_THREADS'] = '1'
os.environ['OPENBLAS_NUM_THREADS'] = '1'
os.environ['MKL_NUM_THREADS'] = '1'
os.environ['NUMEXPR_NUM_THREADS'] = '1'

# Suppress specific warnings
warnings.filterwarnings('ignore', category=UserWarning, module='tensorflow')

import tensorflow as tf
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences

from .features.process_features import extract_process_features

class ProcessPredictor:
    """Predict process behavioral anomalies with real behavioral analysis"""
    
    def _init_(self, model_path: str = None):
        self.model = None
        self.scaler = None
        self.feature_names = None
        self.model_type = None
        self.training_stats = None
        self.tokenizer = None
        
        if model_path:
            self.load_model(model_path)
    
def load_model(self, model_path: str):
        """Load trained process model"""
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
                    self.tokenizer = metadata.get('tokenizer')
else:
                # Pickle file (sklearn model)
                data = joblib.load(model_path)
                self.model = data.get('model')
                self.scaler = data.get('scaler')
                self.feature_names = data.get('feature_names')
                self.model_type = data.get('model_type')
                self.training_stats = data.get('training_stats')
            
class ProcessPredictor:
    """Predict process behavioral anomalies with real behavioral analysis"""
    
    def _init_(self, model_path: str = None):
        self.model = None
        self.scaler = None
        self.feature_names = None
        self.model_type = None
        self.training_stats = None
        self.tokenizer = None
        
        if model_path:
            self.load_model(model_path)
    
    def load_model(self, model_path: str):
        """Load trained process model"""
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
                    self.tokenizer = metadata.get('tokenizer')
            else:
                # Pickle file (sklearn model)
                data = joblib.load(model_path)
                self.model = data.get('model')
                self.scaler = data.get('scaler')
                self.feature_names = data.get('feature_names')
                self.model_type = data.get('model_type')
                self.training_stats = data.get('training_stats')
            
            print(f"✅ Loaded process model: {self.model_type}")
            print(f"   Features: {len(self.feature_names) if self.feature_names else 'unknown'}")
            
        except Exception as e:
            print(f"⚠️  Failed to load process model: {e}")
            self.model = None
    def predict(self, events: List[Dict[str, Any]], threshold: float = 0.5) -> Dict[str, Any]:
        """Predict process behavioral anomaly"""
        if self.model is None:
            return {
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "confidence": 0.0,
                "model_used": False,
                "error": "No model loaded"
            }
        
        try:
            # Extract process features
            features = extract_process_features(events)
            
            if self.model_type == "lstm_commands":
                # LSTM model for command analysis
                return self._predict_lstm(events, features, threshold)
            else:
                # Traditional ML models
                return self._predict_traditional(features, threshold)
           
        except Exception as e:
            return {
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "confidence": 0.0,
                "model_used": False,
                "error": str(e)
            }
    
    def _predict_traditional(self, features: Dict[str, Any], threshold: float) -> Dict[str, Any]:
        """Predict using traditional ML models"""
        # Convert to array
        feature_array = np.array([list(features.values())]).reshape(1, -1)
        
        # Scale features
        if self.scaler:
            feature_array = self.scaler.transform(feature_array)
        # Make prediction
        if self.model_type == "isolation_forest":
            # Isolation Forest: -1 = outlier, 1 = inlier
            prediction = self.model.predict(feature_array)[0]
            score = self.model.score_samples(feature_array)[0]
            
            # Convert to anomaly score (higher = more anomalous)
            anomaly_score = 1 - (score - score.min()) / (score.max() - score.min() + 1e-9)
            is_anomaly = prediction == -1
            
        elif self.model_type == "autoencoder":
            # Autoencoder: reconstruction error
            reconstruction = self.model.predict(feature_array)
            mse = np.mean(np.power(feature_array - reconstruction, 2))
            
            # Higher MSE = more anomalous
            anomaly_score = min(mse / 10.0, 1.0)  # Normalize to 0-1
            is_anomaly = anomaly_score > threshold
            
        else:  # Random Forest
            proba = self.model.predict_proba(feature_array)[0]
            anomaly_score = float(proba[1])  # Probability of being malicious
            is_anomaly = anomaly_score > threshold
        
        