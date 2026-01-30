import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder
from ai_engine.src.features import to_netflow_frame, to_endpoint_frame
from ai_engine.src.models import get_model
from ai_engine.src.config import settings


class Pipeline:
    def __init__(self, model_name=None, task=None):
        self.model_name = model_name or settings.MODEL_NAME
        self.task = task or settings.TASK
        self.model = None
        self.label_encoder = None

    def _to_frame(self, records):
        if self.task == "netflow":
            return to_netflow_frame(records)
        elif self.task == "endpoint":
            return to_endpoint_frame(records)
        elif self.task == "url":
            # records = [{"url": "..."}]
            df = pd.DataFrame(records)
            return df
        else:
            raise ValueError("Unknown task")

    def fit(self, records, y=None):
        X = self._to_frame(records)
        if self.model_name in {"ae"}:
            # Autoencoder: learn normal only (y ignored or use benign subset)
            self.model = get_model(self.model_name, input_dim=X.shape[1])
            self.model.fit(X.values, X.values, epochs=10, batch_size=64, verbose=0)
        else:
            self.model = get_model(self.model_name, input_dim=X.shape[1], settings=settings)
            if y is None:
                raise ValueError("Supervised model requires labels")
            
            # Handle string labels by encoding them to numbers
            if isinstance(y, np.ndarray) and len(y) > 0 and isinstance(y[0], str):
                print("🏷️  Encoding string labels to numbers...")
                self.label_encoder = LabelEncoder()
                y_encoded = self.label_encoder.fit_transform(y)
                print(f"✅ Encoded {len(self.label_encoder.classes_)} classes: {list(self.label_encoder.classes_)}")
            else:
                y_encoded = y
                
            self.model.fit(X, y_encoded)
        return self

    def predict_proba(self, records):
        X = self._to_frame(records)
        if self.model_name == "iforest":
            # anomaly score → convert to [0,1], higher = more anomalous
            scores = -self.model.score_samples(X)  # larger = more anomalous
            s = (scores - scores.min()) / (scores.max() - scores.min() + 1e-9)
            return s
        elif self.model_name == "ae":
            recon = self.model.predict(X.values, verbose=0)
            err = ((recon - X.values)**2).mean(axis=1)
            s = (err - err.min()) / (err.max() - err.min() + 1e-9)
            return s
        else:
            if hasattr(self.model, "predict_proba"):
                return self.model.predict_proba(X)[:,1]
            else:
                # Keras models (lstm/cnn_url)
                return self.model.predict(X, verbose=0).ravel()

    def predict(self, records, threshold=None):
        X = self._to_frame(records)
        
        if self.model_name in {"iforest", "ae"}:
            # Anomaly detection models
            p = self.predict_proba(records)
            t = threshold if threshold is not None else settings.THRESHOLD
            return (p >= t).astype(int), p
        else:
            # Classification models
            predictions = self.model.predict(X)
            probabilities = self.model.predict_proba(X)
            
            # Get max probability for each prediction
            max_probs = probabilities.max(axis=1)
            
            # Apply threshold if provided
            if threshold is not None:
                confident_predictions = (max_probs >= threshold).astype(int)
                return confident_predictions, max_probs
            else:
                return predictions, max_probs
