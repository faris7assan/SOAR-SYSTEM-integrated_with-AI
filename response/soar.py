"""
AegisNDR - Response Engine (SOAR-lite)
Executes automated response actions based on threat scores and playbooks.
"""
import logging
import subprocess
import time
import threading
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
import uuid

from models import Alert, AlertSeverity
import config

logger = logging.getLogger(__name__)


@dataclass
class ResponseAction:
    action_id:   str   = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp:   float = field(default_factory=time.time)
    action_type: str   = ""
    target_ip:   str   = ""
    alert_id:    str   = ""
    success:     bool  = False
    message:     str   = ""
    expires_at:  float = 0.0

    def to_dict(self):
        return {
            "action_id":   self.action_id,
            "timestamp":   self.timestamp,
            "action_type": self.action_type,
            "target_ip":   self.target_ip,
            "alert_id":    self.alert_id,
            "success":     self.success,
            "message":     self.message,
        }


class ResponseEngine:
    """
    Executes response playbooks triggered by alert scores.

    Playbook: CRITICAL (score > 80)  → Block IP + Alert + Log
              HIGH     (score > 60)  → Alert + Log
              MEDIUM   (score > 40)  → Log + Notify
              LOW                    → Log only
    """

    def __init__(self, enabled: bool = False):
        self.enabled     = enabled
        self._blocked_ips: Dict[str, float] = {}   # ip → expiry timestamp
        self._whitelist:   Set[str] = set(config.RESPONSE_WHITELIST_IPS)
        self._actions_log: List[ResponseAction] = []
        self._lock = threading.Lock()

        # Start unblock loop
        self._running = True
        threading.Thread(target=self._unblock_loop, daemon=True).start()

    # ── Public API ──────────────────────────────────────────────────────────
    def handle_alert(self, alert: Alert) -> List[ResponseAction]:
        actions = []

        if alert.severity == AlertSeverity.CRITICAL:
            actions += self._playbook_critical(alert)
        elif alert.severity == AlertSeverity.HIGH:
            actions += self._playbook_high(alert)
        elif alert.severity == AlertSeverity.MEDIUM:
            actions += self._playbook_medium(alert)
        else:
            actions += self._playbook_low(alert)

        with self._lock:
            self._actions_log.extend(actions)

        return actions

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            return ip in self._blocked_ips and self._blocked_ips[ip] > time.time()

    def block_ip(self, ip: str, alert_id: str = "", duration: int = None) -> ResponseAction:
        duration = duration or config.BLOCK_DURATION_SECONDS
        action = ResponseAction(
            action_type="BLOCK_IP",
            target_ip=ip,
            alert_id=alert_id,
            expires_at=time.time() + duration,
        )

        if ip in self._whitelist:
            action.success = False
            action.message = f"IP {ip} is whitelisted — not blocked"
            logger.warning(f"Block prevented: {ip} is whitelisted")
            return action

        if self.is_blocked(ip):
            action.success = True
            action.message = f"IP {ip} already blocked"
            return action

        with self._lock:
            self._blocked_ips[ip] = time.time() + duration

        if self.enabled:
            success, msg = self._iptables_block(ip)
        else:
            success = True
            msg = f"[SIMULATION] Would block {ip} via iptables"
            logger.info(msg)

        action.success = success
        action.message = msg
        return action

    def unblock_ip(self, ip: str) -> ResponseAction:
        action = ResponseAction(action_type="UNBLOCK_IP", target_ip=ip)

        with self._lock:
            if ip in self._blocked_ips:
                del self._blocked_ips[ip]

        if self.enabled:
            success, msg = self._iptables_unblock(ip)
        else:
            success = True
            msg = f"[SIMULATION] Would unblock {ip} via iptables"
            logger.info(msg)

        action.success = success
        action.message = msg
        return action

    @property
    def blocked_ips(self) -> List[Dict]:
        now = time.time()
        with self._lock:
            return [
                {"ip": ip, "expires_in": round(exp - now)}
                for ip, exp in self._blocked_ips.items()
                if exp > now
            ]

    @property
    def actions_log(self) -> List[Dict]:
        return [a.to_dict() for a in self._actions_log[-100:]]

    # ── Playbooks ────────────────────────────────────────────────────────
    def _playbook_critical(self, alert: Alert) -> List[ResponseAction]:
        actions = []
        logger.warning(f"🔴 CRITICAL: {alert.description} from {alert.src_ip}")

        # 1. Block IP
        block_action = self.block_ip(alert.src_ip, alert.alert_id)
        block_action.action_type = "BLOCK_IP"
        alert.auto_blocked = block_action.success
        actions.append(block_action)

        # 2. Log incident
        actions.append(self._log_incident(alert, "CRITICAL"))

        # 3. Alert notification (stub)
        actions.append(self._send_alert(alert))

        return actions

    def _playbook_high(self, alert: Alert) -> List[ResponseAction]:
        logger.warning(f"🟠 HIGH: {alert.description} from {alert.src_ip}")
        return [
            self._log_incident(alert, "HIGH"),
            self._send_alert(alert),
        ]

    def _playbook_medium(self, alert: Alert) -> List[ResponseAction]:
        logger.info(f"🟡 MEDIUM: {alert.description} from {alert.src_ip}")
        return [self._log_incident(alert, "MEDIUM")]

    def _playbook_low(self, alert: Alert) -> List[ResponseAction]:
        logger.debug(f"🟢 LOW: {alert.description} from {alert.src_ip}")
        return [self._log_incident(alert, "LOW")]

    # ── Actions ──────────────────────────────────────────────────────────
    def _iptables_block(self, ip: str) -> tuple:
        try:
            subprocess.run(
                ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True, timeout=5,
            )
            subprocess.run(
                ["iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP"],
                check=True, capture_output=True, timeout=5,
            )
            logger.info(f"Blocked IP via iptables: {ip}")
            return True, f"Blocked {ip} via iptables"
        except subprocess.CalledProcessError as e:
            return False, f"iptables error: {e.stderr.decode()}"
        except FileNotFoundError:
            return False, "iptables not found (needs root)"

    def _iptables_unblock(self, ip: str) -> tuple:
        try:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True, timeout=5,
            )
            subprocess.run(
                ["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"],
                check=True, capture_output=True, timeout=5,
            )
            return True, f"Unblocked {ip}"
        except Exception as e:
            return False, str(e)

    def _log_incident(self, alert: Alert, level: str) -> ResponseAction:
        action = ResponseAction(
            action_type="LOG_INCIDENT",
            target_ip=alert.src_ip,
            alert_id=alert.alert_id,
            success=True,
            message=f"[{level}] {alert.description}",
        )
        return action

    def _send_alert(self, alert: Alert) -> ResponseAction:
        # Stub — integrate with Slack/PagerDuty/SMTP in production
        logger.info(f"📢 ALERT NOTIFICATION: [{alert.severity.value}] {alert.description}")
        return ResponseAction(
            action_type="SEND_ALERT",
            target_ip=alert.src_ip,
            alert_id=alert.alert_id,
            success=True,
            message=f"Notification sent for {alert.alert_type.value}",
        )

    # ── Auto-unblock ──────────────────────────────────────────────────────
    def _unblock_loop(self):
        while self._running:
            now = time.time()
            to_unblock = []
            with self._lock:
                for ip, exp in list(self._blocked_ips.items()):
                    if exp <= now:
                        to_unblock.append(ip)
            for ip in to_unblock:
                self.unblock_ip(ip)
                logger.info(f"Auto-unblocked {ip} after timeout")
            time.sleep(60)
