"""
AegisNDR - ML Detection Engine
Unsupervised anomaly detection using Isolation Forest + behavioral baseline.
Implements online learning and concept drift handling.
"""
import logging
import threading
import time
import pickle
import os
from typing import List, Optional, Dict
from collections import deque

import numpy as np

from models import Flow, Alert, AlertType, AlertSeverity
from core.feature_engine import FeatureEngine
import config

logger = logging.getLogger(__name__)


class MLEngine:
    """
    Isolation Forest-based anomaly detection.

    Lifecycle:
      1. Collect samples until MIN_SAMPLES
      2. Train model on baseline (normal traffic)
      3. Score each new flow; flag anomalies
      4. Retrain periodically with fresh data (concept drift)
    """

    MODEL_PATH = "models/isolation_forest.pkl"

    def __init__(self):
        self._model = None
        self._scaler = None
        self._samples: deque = deque(maxlen=10_000)
        self._lock = threading.Lock()
        self._trained = False
        self._last_train = 0.0
        self._anomaly_count = 0
        self._total_scored  = 0

        # Per-IP behavioral baseline
        self._ip_baselines: Dict[str, Dict] = {}

        os.makedirs("models", exist_ok=True)
        self._try_load_model()

    # ── Public API ──────────────────────────────────────────────────────────
    def analyze(self, flow: Flow) -> List[Alert]:
        features = FeatureEngine.extract(flow)
        vec = FeatureEngine.feature_vector(flow)

        # Always collect samples for training
        with self._lock:
            self._samples.append(vec)

        # Auto-train when enough samples and interval elapsed
        n_samples = len(self._samples)
        if (n_samples >= config.ML_TRAIN_MIN_SAMPLES and
                time.time() - self._last_train > config.ML_RETRAIN_INTERVAL):
            threading.Thread(target=self._train, daemon=True).start()

        if not self._trained or self._model is None:
            return []

        # Score the flow
        score, anomaly = self._score(vec, flow.src_ip, features)
        self._total_scored += 1

        if anomaly:
            self._anomaly_count += 1
            return [self._make_alert(flow, score, features)]
        return []

    def force_train(self):
        self._train()

    @property
    def status(self) -> Dict:
        return {
            "trained":         self._trained,
            "samples":         len(self._samples),
            "anomaly_count":   self._anomaly_count,
            "total_scored":    self._total_scored,
            "last_train":      self._last_train,
        }

    # ── Training ─────────────────────────────────────────────────────────
    def _train(self):
        try:
            from sklearn.ensemble import IsolationForest
            from sklearn.preprocessing import RobustScaler

            with self._lock:
                data = list(self._samples)

            if len(data) < config.ML_TRAIN_MIN_SAMPLES:
                return

            X = np.array(data, dtype=np.float32)
            X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)

            scaler = RobustScaler()
            X_scaled = scaler.fit_transform(X)

            model = IsolationForest(
                n_estimators=200,
                contamination=config.ML_CONTAMINATION,
                random_state=42,
                n_jobs=-1,
            )
            model.fit(X_scaled)

            with self._lock:
                self._model  = model
                self._scaler = scaler
                self._trained = True
                self._last_train = time.time()

            self._save_model()
            logger.info(f"ML model trained on {len(data)} samples")

        except ImportError:
            logger.warning("scikit-learn not installed. ML engine disabled.")
        except Exception as e:
            logger.error(f"ML training failed: {e}")

    def _score(self, vec: List[float], src_ip: str,
               features: Dict) -> tuple:
        """Returns (anomaly_score 0-100, is_anomaly bool)."""
        try:
            X = np.array([vec], dtype=np.float32)
            X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)

            with self._lock:
                X_scaled = self._scaler.transform(X)
                raw_score = self._model.decision_function(X_scaled)[0]
                pred      = self._model.predict(X_scaled)[0]

            # IF: -1 = anomaly, +1 = normal
            # Convert decision_function score to 0-100 anomaly score
            # raw_score < 0 → anomaly; more negative = more anomalous
            anomaly_score = max(0, min(100, (-raw_score + 0.5) * 100))
            is_anomaly    = pred == -1 and anomaly_score > 60

            # Behavioral baseline check (per-IP)
            self._update_baseline(src_ip, features)
            behavioral_deviation = self._behavioral_score(src_ip, features)

            final_score = (anomaly_score * 0.6) + (behavioral_deviation * 0.4)
            return final_score, final_score > 60

        except Exception as e:
            logger.debug(f"Scoring error: {e}")
            return 0.0, False

    # ── Behavioral Baseline (UEBA-lite) ──────────────────────────────────
    def _update_baseline(self, ip: str, features: Dict):
        """Maintain rolling mean for key features per IP."""
        TRACKED = ["pkt_rate", "byte_rate", "pkt_size_mean", "duration"]
        if ip not in self._ip_baselines:
            self._ip_baselines[ip] = {
                k: {"sum": 0.0, "sq_sum": 0.0, "n": 0}
                for k in TRACKED
            }
        bl = self._ip_baselines[ip]
        for k in TRACKED:
            v = features.get(k, 0.0)
            bl[k]["sum"]    += v
            bl[k]["sq_sum"] += v * v
            bl[k]["n"]      += 1

    def _behavioral_score(self, ip: str, features: Dict) -> float:
        """Score deviation from established per-IP baseline."""
        if ip not in self._ip_baselines:
            return 0.0
        bl = self._ip_baselines[ip]
        deviations = []
        for k, stats in bl.items():
            n = stats["n"]
            if n < 10: continue  # not enough history
            mean = stats["sum"] / n
            var  = stats["sq_sum"] / n - mean ** 2
            std  = var ** 0.5 if var > 0 else 1e-6
            val  = features.get(k, 0.0)
            z    = abs(val - mean) / std
            deviations.append(min(z / 5, 1.0))  # normalize z-score to 0-1

        if not deviations: return 0.0
        return (sum(deviations) / len(deviations)) * 100

    # ── Persistence ──────────────────────────────────────────────────────
    def _save_model(self):
        try:
            with open(self.MODEL_PATH, "wb") as f:
                pickle.dump({"model": self._model, "scaler": self._scaler}, f)
        except Exception as e:
            logger.warning(f"Model save failed: {e}")

    def _try_load_model(self):
        if not os.path.exists(self.MODEL_PATH): return
        try:
            with open(self.MODEL_PATH, "rb") as f:
                data = pickle.load(f)
            self._model   = data["model"]
            self._scaler  = data["scaler"]
            self._trained = True
            logger.info("Loaded pre-trained ML model")
        except Exception as e:
            logger.warning(f"Could not load saved model: {e}")

    # ── Alert Factory ─────────────────────────────────────────────────────
    def _make_alert(self, flow: Flow, score: float, features: Dict) -> Alert:
        top_features = sorted(
            [(k, v) for k, v in features.items()],
            key=lambda x: abs(x[1]), reverse=True
        )[:5]

        return Alert(
            alert_type=AlertType.ANOMALY,
            severity=AlertSeverity.from_score(score),
            score=round(score, 2),
            src_ip=flow.src_ip, dst_ip=flow.dst_ip,
            src_port=flow.src_port, dst_port=flow.dst_port,
            protocol=flow.protocol.value,
            description=f"ML anomaly detected (score: {score:.1f})",
            evidence={
                "anomaly_score": round(score, 2),
                "top_features":  dict(top_features),
                "pkt_rate":      round(features.get("pkt_rate", 0), 2),
                "byte_rate":     round(features.get("byte_rate", 0), 2),
            },
            mitre=config.MITRE_MAPPING.get("ANOMALY", {}),
            flow_id=flow.flow_id,
        )
