"""
AegisNDR - Shared Data Models
"""
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from enum import Enum
import time
import uuid


class Protocol(Enum):
    TCP  = "TCP"
    UDP  = "UDP"
    ICMP = "ICMP"
    OTHER = "OTHER"


class AlertSeverity(Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"

    @classmethod
    def from_score(cls, score: float) -> "AlertSeverity":
        if score >= 80: return cls.CRITICAL
        if score >= 60: return cls.HIGH
        if score >= 40: return cls.MEDIUM
        return cls.LOW


class AlertType(Enum):
    PORT_SCAN        = "PORT_SCAN"
    BRUTE_FORCE      = "BRUTE_FORCE"
    DDOS             = "DDOS"
    DATA_EXFIL       = "DATA_EXFIL"
    BEACON           = "BEACON"
    SQL_INJECTION    = "SQL_INJECTION"
    XSS              = "XSS"
    DNS_TUNNELING    = "DNS_TUNNELING"
    ANOMALY          = "ANOMALY"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    MULTI_STAGE      = "MULTI_STAGE"


@dataclass
class Packet:
    """Raw parsed packet"""
    timestamp:   float
    src_ip:      str
    dst_ip:      str
    src_port:    int
    dst_port:    int
    protocol:    Protocol
    length:      int
    payload:     bytes = field(default_factory=bytes)
    tcp_flags:   int   = 0
    ttl:         int   = 64
    icmp_type:   int   = 0


@dataclass
class Flow:
    """Bidirectional network flow (similar to Zeek conn log)"""
    flow_id:       str   = field(default_factory=lambda: str(uuid.uuid4())[:8])
    src_ip:        str   = ""
    dst_ip:        str   = ""
    src_port:      int   = 0
    dst_port:      int   = 0
    protocol:      Protocol = Protocol.TCP

    start_time:    float = field(default_factory=time.time)
    last_seen:     float = field(default_factory=time.time)
    duration:      float = 0.0

    fwd_packets:   int   = 0
    bwd_packets:   int   = 0
    fwd_bytes:     int   = 0
    bwd_bytes:     int   = 0

    fwd_pkt_sizes: List[int] = field(default_factory=list)
    bwd_pkt_sizes: List[int] = field(default_factory=list)
    iat_list:      List[float] = field(default_factory=list)  # inter-arrival times

    tcp_flags:     int   = 0   # cumulative OR of all flags
    syn_count:     int   = 0
    fin_count:     int   = 0
    rst_count:     int   = 0
    psh_count:     int   = 0
    ack_count:     int   = 0

    is_active:     bool  = True
    payload_sample: bytes = field(default_factory=bytes)

    # enriched features (set by FeatureEngine)
    features:      Dict[str, float] = field(default_factory=dict)

    @property
    def total_packets(self): return self.fwd_packets + self.bwd_packets
    @property
    def total_bytes(self):   return self.fwd_bytes + self.bwd_bytes
    @property
    def key(self):
        """Canonical 5-tuple key"""
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol.value)


@dataclass
class Alert:
    """Security alert raised by any detection engine"""
    alert_id:    str  = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp:   float = field(default_factory=time.time)
    alert_type:  AlertType = AlertType.ANOMALY
    severity:    AlertSeverity = AlertSeverity.LOW
    score:       float = 0.0

    src_ip:      str  = ""
    dst_ip:      str  = ""
    src_port:    int  = 0
    dst_port:    int  = 0
    protocol:    str  = "TCP"

    description: str  = ""
    evidence:    Dict[str, Any] = field(default_factory=dict)
    mitre:       Dict[str, str] = field(default_factory=dict)

    flow_id:     Optional[str] = None
    correlated:  bool = False   # part of multi-stage chain
    auto_blocked: bool = False

    def to_dict(self) -> Dict:
        return {
            "alert_id":    self.alert_id,
            "timestamp":   self.timestamp,
            "alert_type":  self.alert_type.value,
            "severity":    self.severity.value,
            "score":       self.score,
            "src_ip":      self.src_ip,
            "dst_ip":      self.dst_ip,
            "src_port":    self.src_port,
            "dst_port":    self.dst_port,
            "protocol":    self.protocol,
            "description": self.description,
            "evidence":    self.evidence,
            "mitre":       self.mitre,
            "flow_id":     self.flow_id,
            "correlated":  self.correlated,
            "auto_blocked": self.auto_blocked,
        }
