"""
AegisNDR - Rule-Based Detection Engine
Stateful detection of known attack patterns using thresholds and time windows.
"""
import logging
import time
from collections import defaultdict, deque
from typing import List, Optional, Dict

from models import Flow, Alert, AlertType, AlertSeverity, Protocol
import config

logger = logging.getLogger(__name__)


class RuleEngine:
    """
    Stateful rule engine. Maintains sliding-window counters per IP.
    Detects:
      - Port Scan (horizontal / vertical)
      - Brute Force (high connection rate to auth ports)
      - DDoS (PPS/BPS spike to single destination)
      - Data Exfiltration (large outbound transfer)
      - Beaconing (periodic C2 interval detection)
      - Lateral Movement (internal east-west scanning)
    """

    def __init__(self):
        # {src_ip: deque of (timestamp, dst_port)} for port scan detection
        self._scan_tracker: Dict[str, deque] = defaultdict(deque)

        # {src_ip: deque of timestamps} for brute force
        self._brute_tracker: Dict[str, deque] = defaultdict(deque)

        # {dst_ip: deque of (timestamp, pkt_count)} for DDoS
        self._ddos_tracker: Dict[str, deque] = defaultdict(deque)

        # {src_ip: total_bytes_out} for exfil
        self._exfil_tracker: Dict[str, float] = defaultdict(float)

        # {src_ip: deque of timestamps} for beaconing
        self._beacon_tracker: Dict[str, deque] = defaultdict(deque)

        self._alerts_generated = 0

    def analyze(self, flow: Flow) -> List[Alert]:
        alerts = []

        a = self._check_port_scan(flow)
        if a: alerts.append(a)

        a = self._check_brute_force(flow)
        if a: alerts.append(a)

        a = self._check_ddos(flow)
        if a: alerts.append(a)

        a = self._check_exfiltration(flow)
        if a: alerts.append(a)

        a = self._check_beaconing(flow)
        if a: alerts.append(a)

        a = self._check_lateral_movement(flow)
        if a: alerts.append(a)

        self._alerts_generated += len(alerts)
        return alerts

    # ── Port Scan ────────────────────────────────────────────────────────
    def _check_port_scan(self, flow: Flow) -> Optional[Alert]:
        """Detect horizontal/vertical port scanning."""
        if flow.protocol not in (Protocol.TCP, Protocol.UDP):
            return None
        if flow.syn_count == 0 and flow.protocol == Protocol.TCP:
            return None   # not a new connection attempt

        now = flow.last_seen
        tracker = self._scan_tracker[flow.src_ip]
        tracker.append((now, flow.dst_port, flow.dst_ip))

        # Prune old entries outside window
        cutoff = now - config.PORT_SCAN_WINDOW
        while tracker and tracker[0][0] < cutoff:
            tracker.popleft()

        unique_ports = len({e[1] for e in tracker})
        unique_hosts = len({e[2] for e in tracker})

        if unique_ports >= config.PORT_SCAN_THRESHOLD:
            return self._make_alert(
                flow=flow,
                alert_type=AlertType.PORT_SCAN,
                score=min(90, 50 + unique_ports * 2),
                description=f"Port scan detected: {unique_ports} unique ports in {config.PORT_SCAN_WINDOW}s",
                evidence={"unique_ports": unique_ports, "unique_hosts": unique_hosts,
                          "window_sec": config.PORT_SCAN_WINDOW},
            )
        return None

    # ── Brute Force ──────────────────────────────────────────────────────
    AUTH_PORTS = {22, 23, 21, 3389, 445, 3306, 5432, 1433, 6379, 27017}

    def _check_brute_force(self, flow: Flow) -> Optional[Alert]:
        if flow.dst_port not in self.AUTH_PORTS:
            return None
        if flow.fwd_packets < 3:
            return None   # too short

        now = flow.last_seen
        tracker = self._brute_tracker[f"{flow.src_ip}:{flow.dst_port}"]
        tracker.append(now)

        cutoff = now - config.BRUTE_FORCE_WINDOW
        while tracker and tracker[0] < cutoff:
            tracker.popleft()

        attempts = len(tracker)
        if attempts >= config.BRUTE_FORCE_THRESHOLD:
            return self._make_alert(
                flow=flow,
                alert_type=AlertType.BRUTE_FORCE,
                score=min(95, 60 + attempts),
                description=f"Brute force on port {flow.dst_port}: {attempts} attempts in {config.BRUTE_FORCE_WINDOW}s",
                evidence={"attempts": attempts, "target_port": flow.dst_port},
            )
        return None

    # ── DDoS ─────────────────────────────────────────────────────────────
    def _check_ddos(self, flow: Flow) -> Optional[Alert]:
        if flow.duration < 1: return None

        pps = flow.total_packets / max(flow.duration, 1)
        bps = flow.total_bytes   / max(flow.duration, 1) * 8

        if pps >= config.DDOS_PPS_THRESHOLD or bps >= config.DDOS_BPS_THRESHOLD:
            return self._make_alert(
                flow=flow,
                alert_type=AlertType.DDOS,
                score=min(95, 70 + int(pps / 1000)),
                description=f"DDoS detected: {pps:.0f} PPS, {bps/1e6:.1f} Mbps to {flow.dst_ip}",
                evidence={"pps": round(pps,2), "mbps": round(bps/1e6, 2),
                          "total_packets": flow.total_packets},
            )
        return None

    # ── Data Exfiltration ─────────────────────────────────────────────────
    INTERNAL_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.",
                         "172.19.", "172.2", "172.3", "192.168.")

    def _is_internal(self, ip: str) -> bool:
        return any(ip.startswith(p) for p in self.INTERNAL_PREFIXES)

    def _check_exfiltration(self, flow: Flow) -> Optional[Alert]:
        # Only flag internal → external large transfers
        if not (self._is_internal(flow.src_ip) and not self._is_internal(flow.dst_ip)):
            return None

        self._exfil_tracker[flow.src_ip] += flow.fwd_bytes
        total = self._exfil_tracker[flow.src_ip]

        if total >= config.EXFIL_BYTES_THRESHOLD:
            self._exfil_tracker[flow.src_ip] = 0  # reset after alert
            return self._make_alert(
                flow=flow,
                alert_type=AlertType.DATA_EXFIL,
                score=85,
                description=f"Data exfiltration: {total/1e6:.1f} MB from {flow.src_ip} to {flow.dst_ip}",
                evidence={"total_mb": round(total/1e6, 2), "dst": flow.dst_ip},
            )
        return None

    # ── Beaconing ─────────────────────────────────────────────────────────
    def _check_beaconing(self, flow: Flow) -> Optional[Alert]:
        """Detect periodic C2 beaconing via IAT regularity."""
        if len(flow.iat_list) < 10: return None

        import statistics
        iats = flow.iat_list
        mean = statistics.mean(iats)
        std  = statistics.stdev(iats) if len(iats) > 1 else 0

        if mean < 5: return None  # too fast to be a beacon

        jitter = std / mean if mean else 1
        if jitter < config.BEACON_INTERVAL_TOLERANCE:
            return self._make_alert(
                flow=flow,
                alert_type=AlertType.BEACON,
                score=75,
                description=f"C2 beaconing: interval {mean:.1f}s ± {std:.2f}s (jitter {jitter*100:.1f}%)",
                evidence={"interval_sec": round(mean,2), "jitter_pct": round(jitter*100,2),
                          "dst": flow.dst_ip, "dst_port": flow.dst_port},
            )
        return None

    # ── Lateral Movement ──────────────────────────────────────────────────
    LATERAL_PORTS = {135, 139, 445, 3389, 5985, 5986, 22}

    def _check_lateral_movement(self, flow: Flow) -> Optional[Alert]:
        if not (self._is_internal(flow.src_ip) and self._is_internal(flow.dst_ip)):
            return None
        if flow.dst_port not in self.LATERAL_PORTS:
            return None
        if flow.syn_count < 1:
            return None

        # Multiple internal targets in short time
        tracker = self._scan_tracker[flow.src_ip]
        internal_targets = {e[2] for e in tracker if self._is_internal(e[2])}

        if len(internal_targets) >= 3:
            return self._make_alert(
                flow=flow,
                alert_type=AlertType.LATERAL_MOVEMENT,
                score=80,
                description=f"Lateral movement: {flow.src_ip} scanning {len(internal_targets)} internal hosts",
                evidence={"targets": list(internal_targets)[:10],
                          "dst_port": flow.dst_port},
            )
        return None

    # ── Helper ───────────────────────────────────────────────────────────
    def _make_alert(self, flow: Flow, alert_type: AlertType,
                    score: float, description: str,
                    evidence: dict) -> Alert:
        from config import MITRE_MAPPING
        mitre = MITRE_MAPPING.get(alert_type.value, {})
        return Alert(
            alert_type=alert_type,
            severity=AlertSeverity.from_score(score),
            score=score,
            src_ip=flow.src_ip, dst_ip=flow.dst_ip,
            src_port=flow.src_port, dst_port=flow.dst_port,
            protocol=flow.protocol.value,
            description=description,
            evidence=evidence,
            mitre=mitre,
            flow_id=flow.flow_id,
        )
