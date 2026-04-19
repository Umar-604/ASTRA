"""
Train XGBoost on CICIDS-2017 merged netflow CSV.

Improvements over the original pipeline:
  - Stratified sampling that guarantees minimum samples per class
    (rare attacks like Heartbleed/Infiltration are kept in full).
  - Class-balanced sample weights via compute_sample_weight.
  - Optional Destination Port removal (--drop-port) to test model
    reliance on the known-leaky port feature.
  - Per-class evaluation, MCC, macro/weighted metrics.
  - Feature importance analysis.
  - Proper train-vs-validation loss comparison.
"""