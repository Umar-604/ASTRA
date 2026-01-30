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