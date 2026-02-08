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

