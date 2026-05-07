"""
AegisNDR - Feature Engineering Engine
Extracts rich statistical and behavioral features from Flow objects.
These features feed both rule-based and ML detection engines.
"""
import math
import logging
import statistics
from typing import Dict, List

from models import Flow, Protocol

logger = logging.getLogger(__name__)


def _safe_mean(lst: List[float]) -> float:
    return statistics.mean(lst) if lst else 0.0

def _safe_std(lst: List[float]) -> float:
    return statistics.stdev(lst) if len(lst) > 1 else 0.0

def _safe_div(a: float, b: float) -> float:
    return a / b if b else 0.0

def _entropy(data: bytes) -> float:
    """Shannon entropy of a byte sequence. High entropy → encrypted/compressed."""
    if not data: return 0.0
    freq = [0] * 256
    for b in data: freq[b] += 1
    n = len(data)
    ent = 0.0
    for f in freq:
        if f > 0:
            p = f / n
            ent -= p * math.log2(p)
    return ent


class FeatureEngine:
    """
    Extracts ~30 features from a Flow and stores them in flow.features.

    Feature categories:
      - Volume: bytes, packets, rates
      - Packet size stats: mean, std, min, max
      - Inter-arrival time stats
      - TCP flag ratios
      - Payload entropy
      - Protocol-specific flags
      - Flow shape (symmetry, burstiness)
    """

    @staticmethod
    def extract(flow: Flow) -> Dict[str, float]:
        dur = max(flow.duration, 1e-6)  # avoid division by zero

        fwd = flow.fwd_pkt_sizes
        bwd = flow.bwd_pkt_sizes
        iat = flow.iat_list
        total_pkts = flow.total_packets
        total_bytes = flow.total_bytes

        # ── Volume features ───────────────────────────────────────────────
        features = {
            "duration":          dur,
            "total_packets":     float(total_pkts),
            "total_bytes":       float(total_bytes),
            "fwd_packets":       float(flow.fwd_packets),
            "bwd_packets":       float(flow.bwd_packets),
            "fwd_bytes":         float(flow.fwd_bytes),
            "bwd_bytes":         float(flow.bwd_bytes),
            "pkt_rate":          _safe_div(total_pkts, dur),
            "byte_rate":         _safe_div(total_bytes, dur),
            "fwd_pkt_rate":      _safe_div(flow.fwd_packets, dur),
            "bwd_pkt_rate":      _safe_div(flow.bwd_packets, dur),
        }

        # ── Packet size stats ─────────────────────────────────────────────
        all_sizes = fwd + bwd
        features.update({
            "pkt_size_mean":     _safe_mean(all_sizes),
            "pkt_size_std":      _safe_std(all_sizes),
            "pkt_size_min":      float(min(all_sizes)) if all_sizes else 0.0,
            "pkt_size_max":      float(max(all_sizes)) if all_sizes else 0.0,
            "fwd_pkt_size_mean": _safe_mean(fwd),
            "bwd_pkt_size_mean": _safe_mean(bwd),
        })

        # ── IAT stats ─────────────────────────────────────────────────────
        features.update({
            "iat_mean":          _safe_mean(iat),
            "iat_std":           _safe_std(iat),
            "iat_min":           float(min(iat)) if iat else 0.0,
            "iat_max":           float(max(iat)) if iat else 0.0,
        })

        # ── Flow symmetry (bidirectionality ratio) ────────────────────────
        features["byte_ratio"]    = _safe_div(flow.fwd_bytes,  flow.bwd_bytes + 1)
        features["packet_ratio"]  = _safe_div(flow.fwd_packets, flow.bwd_packets + 1)

        # ── TCP flag ratios ───────────────────────────────────────────────
        if total_pkts > 0:
            features["syn_ratio"] = flow.syn_count / total_pkts
            features["fin_ratio"] = flow.fin_count / total_pkts
            features["rst_ratio"] = flow.rst_count / total_pkts
            features["psh_ratio"] = flow.psh_count / total_pkts
            features["ack_ratio"] = flow.ack_count / total_pkts
        else:
            for f in ("syn_ratio","fin_ratio","rst_ratio","psh_ratio","ack_ratio"):
                features[f] = 0.0

        # ── Payload entropy ───────────────────────────────────────────────
        features["payload_entropy"] = _entropy(flow.payload_sample)

        # ── Protocol flag ─────────────────────────────────────────────────
        features["is_tcp"]  = 1.0 if flow.protocol == Protocol.TCP  else 0.0
        features["is_udp"]  = 1.0 if flow.protocol == Protocol.UDP  else 0.0
        features["is_icmp"] = 1.0 if flow.protocol == Protocol.ICMP else 0.0

        # ── Port features ─────────────────────────────────────────────────
        features["dst_port"]      = float(flow.dst_port)
        features["src_port"]      = float(flow.src_port)
        features["is_well_known"] = 1.0 if flow.dst_port < 1024 else 0.0
        features["is_ephemeral"]  = 1.0 if flow.src_port > 49151 else 0.0

        # Store on flow object
        flow.features = features
        return features

    @staticmethod
    def feature_vector(flow: Flow) -> List[float]:
        """Return features as an ordered list for ML models."""
        ORDERED_KEYS = [
            "duration", "total_packets", "total_bytes",
            "fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes",
            "pkt_rate", "byte_rate", "fwd_pkt_rate", "bwd_pkt_rate",
            "pkt_size_mean", "pkt_size_std", "pkt_size_min", "pkt_size_max",
            "fwd_pkt_size_mean", "bwd_pkt_size_mean",
            "iat_mean", "iat_std", "iat_min", "iat_max",
            "byte_ratio", "packet_ratio",
            "syn_ratio", "fin_ratio", "rst_ratio", "psh_ratio", "ack_ratio",
            "payload_entropy",
            "is_tcp", "is_udp", "is_icmp",
            "dst_port", "is_well_known", "is_ephemeral",
        ]
        feats = flow.features or FeatureEngine.extract(flow)
        return [feats.get(k, 0.0) for k in ORDERED_KEYS]
