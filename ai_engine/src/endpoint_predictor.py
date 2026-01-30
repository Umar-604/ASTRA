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