"""
AegisNDR - Correlation Engine
Links individual alerts into multi-stage attack kill chains using DAG and rule chaining.
"""
import logging
import time
from collections import defaultdict, deque
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
import uuid

from models import Alert, AlertType, AlertSeverity

logger = logging.getLogger(__name__)


@dataclass
class AttackChain:
    """A correlated sequence of alerts representing a multi-stage attack."""
    chain_id:   str   = field(default_factory=lambda: str(uuid.uuid4())[:8])
    src_ip:     str   = ""
    stages:     List[Alert] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    last_update: float = field(default_factory=time.time)
    chain_score: float = 0.0
    stage_names: List[str] = field(default_factory=list)
    kill_chain_phase: str = ""

    def to_dict(self):
        return {
            "chain_id":        self.chain_id,
            "src_ip":          self.src_ip,
            "stage_count":     len(self.stages),
            "stage_names":     self.stage_names,
            "chain_score":     round(self.chain_score, 2),
            "kill_chain_phase": self.kill_chain_phase,
            "start_time":      self.start_time,
            "last_update":     self.last_update,
            "alerts":          [a.to_dict() for a in self.stages],
        }


# ── Correlation Rules (DAG edges) ─────────────────────────────────────────────
# Each rule defines: which alert type can FOLLOW another, within a time window
# Format: (precursor_type, follower_type, max_gap_sec, boost_score, phase)

CHAIN_RULES: List[Tuple] = [
    # Recon → Exploitation
    (AlertType.PORT_SCAN,    AlertType.BRUTE_FORCE,  300, 20, "Exploitation"),
    (AlertType.PORT_SCAN,    AlertType.SQL_INJECTION, 300, 25, "Exploitation"),
    (AlertType.PORT_SCAN,    AlertType.XSS,           300, 20, "Exploitation"),
    # Exploitation → C2
    (AlertType.BRUTE_FORCE,  AlertType.BEACON,        600, 30, "Command & Control"),
    (AlertType.SQL_INJECTION, AlertType.BEACON,        600, 30, "Command & Control"),
    # C2 → Exfil
    (AlertType.BEACON,       AlertType.DATA_EXFIL,    1800, 35, "Exfiltration"),
    # Recon → Lateral Movement
    (AlertType.PORT_SCAN,    AlertType.LATERAL_MOVEMENT, 600, 25, "Lateral Movement"),
    # Lateral → Exfil
    (AlertType.LATERAL_MOVEMENT, AlertType.DATA_EXFIL, 1800, 30, "Exfiltration"),
    # Any anomaly after scan
    (AlertType.PORT_SCAN,    AlertType.ANOMALY,       300, 15, "Exploitation"),
]


class CorrelationEngine:
    """
    Correlates alerts from the same source IP into attack chains.
    Uses a sliding window and rule DAG.
    """

    CHAIN_TTL = 3600      # kill chain TTL (1 hour)
    MAX_CHAINS = 1000     # max active chains per IP

    def __init__(self):
        # {src_ip: list of recent alerts}
        self._alert_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))

        # {src_ip: AttackChain}  (one active chain per IP)
        self._active_chains: Dict[str, AttackChain] = {}

        # completed chains for reporting
        self._completed_chains: deque = deque(maxlen=500)

        self._chains_detected = 0

    def ingest(self, alert: Alert) -> Optional[AttackChain]:
        """
        Ingest an alert. Returns an AttackChain if this alert
        extends or creates a correlated chain.
        """
        now = time.time()
        src = alert.src_ip
        self._alert_history[src].append(alert)

        # Prune expired chains
        self._prune_chains(now)

        # Check if this alert extends an existing chain
        if src in self._active_chains:
            chain = self._active_chains[src]
            extended = self._try_extend(chain, alert, now)
            if extended:
                alert.correlated = True
                return chain

        # Try to start a new chain
        chain = self._try_new_chain(src, alert, now)
        if chain:
            alert.correlated = True
            self._active_chains[src] = chain
            self._chains_detected += 1
            logger.info(f"New attack chain {chain.chain_id} from {src}: {chain.stage_names}")
            return chain

        return None

    @property
    def active_chains(self) -> List[AttackChain]:
        return list(self._active_chains.values())

    @property
    def completed_chains(self) -> List[AttackChain]:
        return list(self._completed_chains)

    # ── Internal ──────────────────────────────────────────────────────────
    def _try_extend(self, chain: AttackChain, alert: Alert, now: float) -> bool:
        """Check if alert is a valid next stage in chain."""
        if not chain.stages: return False
        last = chain.stages[-1]
        gap  = now - last.timestamp

        for rule in CHAIN_RULES:
            prec, fol, max_gap, boost, phase = rule
            if last.alert_type == prec and alert.alert_type == fol:
                if gap <= max_gap:
                    chain.stages.append(alert)
                    chain.stage_names.append(alert.alert_type.value)
                    chain.chain_score = min(100, chain.chain_score + boost)
                    chain.kill_chain_phase = phase
                    chain.last_update = now
                    logger.debug(f"Chain {chain.chain_id} extended: {prec.value} → {fol.value}")
                    return True

        return False

    def _try_new_chain(self, src: str, alert: Alert, now: float) -> Optional[AttackChain]:
        """Try to start a new chain from recent history."""
        history = list(self._alert_history[src])
        if len(history) < 2: return None

        # Check if any recent alert pairs match a rule
        for rule in CHAIN_RULES:
            prec, fol, max_gap, boost, phase = rule
            if alert.alert_type == fol:
                # Look for a recent precursor
                for prev in reversed(history[:-1]):
                    gap = now - prev.timestamp
                    if prev.alert_type == prec and gap <= max_gap:
                        chain = AttackChain(
                            src_ip=src,
                            stages=[prev, alert],
                            chain_score=prev.score * 0.3 + boost,
                            stage_names=[prec.value, fol.value],
                            kill_chain_phase=phase,
                        )
                        return chain
        return None

    def _prune_chains(self, now: float):
        expired = [
            ip for ip, chain in self._active_chains.items()
            if now - chain.last_update > self.CHAIN_TTL
        ]
        for ip in expired:
            chain = self._active_chains.pop(ip)
            self._completed_chains.append(chain)
            logger.debug(f"Chain {chain.chain_id} expired after {len(chain.stages)} stages")
