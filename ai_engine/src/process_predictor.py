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
