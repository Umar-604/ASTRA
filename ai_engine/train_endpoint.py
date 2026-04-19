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
