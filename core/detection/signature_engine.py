"""
AegisNDR - Signature Detection Engine
Detects known attack patterns in packet payloads using regex and pattern matching.
"""
import re
import logging
from typing import List, Optional, Dict, Tuple

from models import Flow, Alert, AlertType, AlertSeverity
import config

logger = logging.getLogger(__name__)


# ── Signature Definitions ──────────────────────────────────────────────────────
# Format: (name, alert_type, score, patterns)
SIGNATURES: List[Tuple[str, AlertType, float, List[bytes]]] = [

    # SQL Injection
    ("SQL Injection - UNION SELECT", AlertType.SQL_INJECTION, 85, [
        b"UNION SELECT", b"union select", b"UNION+SELECT", b"union%20select",
    ]),
    ("SQL Injection - OR 1=1", AlertType.SQL_INJECTION, 75, [
        b"' OR '1'='1", b"' or '1'='1", b"OR 1=1", b"or 1=1",
        b"' OR 1=1--", b"admin'--",
    ]),
    ("SQL Injection - SLEEP/BENCHMARK", AlertType.SQL_INJECTION, 80, [
        b"SLEEP(", b"sleep(", b"BENCHMARK(", b"WAITFOR DELAY",
    ]),
    ("SQL Injection - DROP/INSERT", AlertType.SQL_INJECTION, 90, [
        b"DROP TABLE", b"drop table", b"INSERT INTO", b"DELETE FROM",
    ]),

    # XSS
    ("XSS - Script Tag", AlertType.XSS, 80, [
        b"<script>", b"<SCRIPT>", b"</script>",
        b"<script src=", b"<img src=x onerror=",
    ]),
    ("XSS - Event Handler", AlertType.XSS, 75, [
        b"javascript:", b"JAVASCRIPT:", b"onload=", b"onerror=",
        b"onclick=", b"onmouseover=", b"onfocus=",
    ]),

    # Command Injection
    ("Command Injection", AlertType.SQL_INJECTION, 90, [
        b"; cat /etc/passwd", b"| cat /etc/passwd", b"`id`", b"$(id)",
        b"; rm -rf", b"&&whoami", b"| whoami", b";whoami",
    ]),

    # Directory Traversal
    ("Directory Traversal", AlertType.SQL_INJECTION, 75, [
        b"../../../", b"..%2F..%2F", b"....//....//",
        b"/etc/passwd", b"/etc/shadow", b"C:\\Windows\\",
    ]),

    # Shellcode / exploit attempts
    ("Shellcode - NOP sled", AlertType.ANOMALY, 80, [
        b"\x90\x90\x90\x90\x90\x90\x90\x90",  # 8+ NOPs
    ]),

    # DNS Tunneling (oversized/encoded DNS queries)
    ("DNS Tunneling - Encoded", AlertType.DNS_TUNNELING, 70, [
        b"base64", b"BASE64",
    ]),
]

# Compile regex for common patterns
_SQLI_REGEX = re.compile(
    rb"(\bUNION\b.*\bSELECT\b|'.*\bOR\b.*'.*=.*'|--\s*$|\bDROP\b\s+\bTABLE\b)",
    re.IGNORECASE | re.DOTALL,
)
_XSS_REGEX = re.compile(
    rb"(<script[\s>]|javascript:|on\w+\s*=)",
    re.IGNORECASE,
)
_TRAVERSAL_REGEX = re.compile(
    rb"(\.\./){2,}|(%2e%2e%2f){2,}",
    re.IGNORECASE,
)


class SignatureEngine:
    """Scans flow payload against known attack signatures."""

    def __init__(self):
        self._hits = 0

    def analyze(self, flow: Flow) -> List[Alert]:
        if not flow.payload_sample:
            return []

        alerts = []
        payload = flow.payload_sample

        # Byte-pattern matching
        for name, atype, score, patterns in SIGNATURES:
            for pattern in patterns:
                if pattern in payload:
                    alerts.append(self._make_alert(
                        flow, atype, score, name,
                        {"matched_pattern": pattern.decode(errors="replace"),
                         "payload_preview": payload[:128].decode(errors="replace")}
                    ))
                    break  # one alert per signature rule

        # Regex matching
        if _SQLI_REGEX.search(payload):
            alerts.append(self._make_alert(
                flow, AlertType.SQL_INJECTION, 82,
                "SQL Injection (regex)",
                {"match": "sqli_pattern",
                 "payload_preview": payload[:128].decode(errors="replace")}
            ))

        if _XSS_REGEX.search(payload) and not any(
            a.alert_type == AlertType.XSS for a in alerts
        ):
            alerts.append(self._make_alert(
                flow, AlertType.XSS, 78,
                "XSS (regex)",
                {"payload_preview": payload[:128].decode(errors="replace")}
            ))

        if _TRAVERSAL_REGEX.search(payload):
            alerts.append(self._make_alert(
                flow, AlertType.SQL_INJECTION, 73,
                "Directory Traversal (regex)",
                {"payload_preview": payload[:128].decode(errors="replace")}
            ))

        # DNS-specific: oversized query (tunneling indicator)
        if flow.dst_port == 53 and len(flow.fwd_pkt_sizes) > 0:
            avg_dns = sum(flow.fwd_pkt_sizes) / len(flow.fwd_pkt_sizes)
            if avg_dns > 200:  # normal DNS query < 100 bytes
                alerts.append(self._make_alert(
                    flow, AlertType.DNS_TUNNELING, 65,
                    "DNS Tunneling - Oversized queries",
                    {"avg_query_size": round(avg_dns, 2), "threshold": 200}
                ))

        self._hits += len(alerts)
        return alerts

    def _make_alert(self, flow: Flow, alert_type: AlertType,
                    score: float, rule_name: str, evidence: dict) -> Alert:
        mitre = config.MITRE_MAPPING.get(alert_type.value, {})
        return Alert(
            alert_type=alert_type,
            severity=AlertSeverity.from_score(score),
            score=score,
            src_ip=flow.src_ip, dst_ip=flow.dst_ip,
            src_port=flow.src_port, dst_port=flow.dst_port,
            protocol=flow.protocol.value,
            description=f"Signature match: {rule_name}",
            evidence=evidence,
            mitre=mitre,
            flow_id=flow.flow_id,
        )
