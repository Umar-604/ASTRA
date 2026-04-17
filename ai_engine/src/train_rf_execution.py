#!/usr/bin/env python3
"""
Train a Random Forest classifier on properly labeled endpoint event data.

Uses the re-labeled attack/benign JSONL files produced by
scripts/prepare_behavioral_data.py instead of the unreliable weak-supervision
heuristic.  Features are richer than the behavioral LightGBM pipeline — they
include DictVectorizer-expanded categorical fields (image basenames, EventID
categories) alongside numeric and binary indicator features.

Usage (from ai_engine/):
  python -m src.train_rf_execution
  python -m src.train_rf_execution --attack ../dataset/MachineLearningCVE/attack_relabeled.jsonl \
                                    --benign ../dataset/MachineLearningCVE/benign_combined.jsonl
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any, Dict, List

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import DictVectorizer