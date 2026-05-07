"""
AegisNDR - Threat Scoring Engine
Aggregates scores from all detection engines and applies decay + intel enrichment.
"""
import time
import logging
from collections import defaultdict
from typing import Dict, List

from models import Alert, AlertSeverity
import config

logger = logging.getLogger(__name__)


class ThreatScorer:
    """
    Composite scoring:
      Score = w1*Frequency + w2*Severity + w3*BehavioralDeviation + w4*ThreatIntel

    Maintains per-IP risk scores with time decay.
    """

    SEVERITY_BASE = {
        AlertSeverity.LOW:      20,
        AlertSeverity.MEDIUM:   45,
        AlertSeverity.HIGH:     70,
        AlertSeverity.CRITICAL: 95,
    }

    def __init__(self):
        # {ip: {"score": float, "last_update": float, "alert_count": int}}
        self._ip_scores: Dict[str, Dict] = defaultdict(
            lambda: {"score": 0.0, "last_update": time.time(),
                     "alert_count": 0, "last_type": ""}
        )

    def score_alert(self, alert: Alert, ti_score: float = 0.0,
                    chain_bonus: float = 0.0) -> float:
        """
        Calculate final composite score for an alert.
        Updates per-IP running score.
        Returns final score (0-100).
        """
        now = time.time()
        ip  = alert.src_ip

        # Apply decay to existing score
        self._apply_decay(ip, now)

        state = self._ip_scores[ip]
        freq_factor = min(1.0, state["alert_count"] / 10)  # normalised 0-1

        # Component scores (each 0-100)
        severity_score    = self.SEVERITY_BASE[alert.severity]
        frequency_score   = freq_factor * 100
        behavioral_score  = alert.score                      # from detection engine
        intel_score       = ti_score                         # from threat intel module

        # Weighted composite
        composite = (
            0.35 * behavioral_score +
            0.25 * severity_score   +
            0.20 * frequency_score  +
            0.20 * intel_score
        )
        composite = min(100, composite + chain_bonus)

        # Update per-IP running score
        state["score"]       = min(100, (state["score"] * 0.7) + (composite * 0.3))
        state["last_update"] = now
        state["alert_count"] += 1
        state["last_type"]   = alert.alert_type.value

        alert.score    = round(composite, 2)
        alert.severity = AlertSeverity.from_score(composite)

        return composite

    def get_ip_score(self, ip: str) -> float:
        self._apply_decay(ip, time.time())
        return round(self._ip_scores[ip]["score"], 2)

    def top_threats(self, n: int = 10) -> List[Dict]:
        now = time.time()
        result = []
        for ip, state in self._ip_scores.items():
            self._apply_decay(ip, now)
            if state["score"] > 5:
                result.append({
                    "ip":          ip,
                    "score":       round(state["score"], 2),
                    "alert_count": state["alert_count"],
                    "last_type":   state["last_type"],
                    "severity":    AlertSeverity.from_score(state["score"]).value,
                })
        return sorted(result, key=lambda x: x["score"], reverse=True)[:n]

    def _apply_decay(self, ip: str, now: float):
        state = self._ip_scores[ip]
        elapsed_minutes = (now - state["last_update"]) / 60
        if elapsed_minutes > 0:
            decay = config.SCORE_DECAY_FACTOR ** elapsed_minutes
            state["score"] *= decay
