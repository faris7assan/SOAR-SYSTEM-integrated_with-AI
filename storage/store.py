"""
AegisNDR - Storage Layer
In-memory store with optional PostgreSQL/Redis/Elasticsearch backends.
"""
import logging
import time
import json
import threading
from typing import List, Dict, Optional, Any
from collections import deque
import itertools

from models import Alert, Flow

logger = logging.getLogger(__name__)


class AlertStore:
    """
    Thread-safe alert storage.
    Provides: insert, query, stats, export.
    Backed by in-memory deque with optional PostgreSQL persistence.
    """

    def __init__(self, max_alerts: int = 100_000):
        self._alerts: deque = deque(maxlen=max_alerts)
        self._lock = threading.Lock()
        self._total_inserted = 0

    def insert(self, alert: Alert):
        with self._lock:
            self._alerts.append(alert)
            self._total_inserted += 1

    def get_all(self, limit: int = 100, offset: int = 0,
                severity: Optional[str] = None,
                alert_type: Optional[str] = None,
                src_ip: Optional[str] = None) -> List[Dict]:
        with self._lock:
            # Optimization: If no filters and asking for newest, just slice the end
            if not any([severity, alert_type, src_ip]) and offset == 0:
                # Get last 'limit' items and reverse them
                count = len(self._alerts)
                start = max(0, count - limit)
                latest = list(itertools.islice(self._alerts, start, count))
                latest.reverse()
                return [a.to_dict() for a in latest]
            
            alerts = list(self._alerts)

        # Filter
        if severity:
            alerts = [a for a in alerts if a.severity.value == severity.upper()]
        if alert_type:
            alerts = [a for a in alerts if a.alert_type.value == alert_type.upper()]
        if src_ip:
            alerts = [a for a in alerts if a.src_ip == src_ip]

        # Sort newest first, paginate
        alerts = sorted(alerts, key=lambda a: a.timestamp, reverse=True)
        return [a.to_dict() for a in alerts[offset:offset+limit]]

    def get_by_id(self, alert_id: str) -> Optional[Dict]:
        with self._lock:
            for alert in self._alerts:
                if alert.alert_id == alert_id:
                    return alert.to_dict()
        return None

    def stats(self) -> Dict:
        with self._lock:
            alerts = list(self._alerts)

        counts_by_severity = {}
        counts_by_type     = {}
        for a in alerts:
            s = a.severity.value
            t = a.alert_type.value
            counts_by_severity[s] = counts_by_severity.get(s, 0) + 1
            counts_by_type[t]     = counts_by_type.get(t, 0) + 1

        return {
            "total_in_memory": len(alerts),
            "total_inserted":  self._total_inserted,
            "by_severity":     counts_by_severity,
            "by_type":         counts_by_type,
        }

    def recent(self, minutes: int = 5) -> List[Dict]:
        cutoff = time.time() - (minutes * 60)
        with self._lock:
            return [a.to_dict() for a in self._alerts if a.timestamp >= cutoff]

    def timeline(self, minutes: int = 60, bucket_size: int = 5) -> List[Dict]:
        """Return alert counts bucketed by time for timeline chart."""
        now    = time.time()
        cutoff = now - (minutes * 60)
        bucket_sec = bucket_size * 60
        n_buckets  = minutes // bucket_size

        buckets = [0] * n_buckets
        with self._lock:
            for a in self._alerts:
                if a.timestamp < cutoff: continue
                idx = int((a.timestamp - cutoff) / bucket_sec)
                if 0 <= idx < n_buckets:
                    buckets[idx] += 1

        return [
            {
                "time":  time.strftime(
                    "%H:%M", time.localtime(cutoff + i * bucket_sec)
                ),
                "count": buckets[i],
            }
            for i in range(n_buckets)
        ]


class FlowStore:
    """In-memory flow store for recent flows."""

    def __init__(self, max_flows: int = 50_000):
        self._flows: deque = deque(maxlen=max_flows)
        self._lock = threading.Lock()

    def insert(self, flow: Flow):
        with self._lock:
            self._flows.append(flow)

    def get_all(self, limit: int = 100, src_ip: Optional[str] = None,
                dst_ip: Optional[str] = None) -> List[Dict]:
        with self._lock:
            # Optimization: If no filters, just slice the end
            if not src_ip and not dst_ip:
                count = len(self._flows)
                start = max(0, count - limit)
                latest = list(itertools.islice(self._flows, start, count))
                latest.reverse()
                return [self._flow_to_dict(f) for f in latest]

            flows = list(self._flows)

        if src_ip: flows = [f for f in flows if f.src_ip == src_ip]
        if dst_ip: flows = [f for f in flows if f.dst_ip == dst_ip]

        flows = sorted(flows, key=lambda f: f.start_time, reverse=True)
        return [self._flow_to_dict(f) for f in flows[:limit]]

    def stats(self) -> Dict:
        with self._lock:
            flows = list(self._flows)
        proto_count = {}
        for f in flows:
            p = f.protocol.value
            proto_count[p] = proto_count.get(p, 0) + 1
        return {
            "total_flows": len(flows),
            "by_protocol": proto_count,
        }

    def top_talkers(self, n: int = 10) -> List[Dict]:
        with self._lock:
            flows = list(self._flows)
        byte_map = {}
        for f in flows:
            byte_map[f.src_ip] = byte_map.get(f.src_ip, 0) + f.total_bytes
        return sorted(
            [{"ip": k, "bytes": v} for k, v in byte_map.items()],
            key=lambda x: x["bytes"], reverse=True
        )[:n]

    @staticmethod
    def _flow_to_dict(f: Flow) -> Dict:
        return {
            "flow_id":      f.flow_id,
            "src_ip":       f.src_ip,
            "dst_ip":       f.dst_ip,
            "src_port":     f.src_port,
            "dst_port":     f.dst_port,
            "protocol":     f.protocol.value,
            "start_time":   f.start_time,
            "duration":     round(f.duration, 3),
            "total_packets": f.total_packets,
            "total_bytes":  f.total_bytes,
            "fwd_bytes":    f.fwd_bytes,
            "bwd_bytes":    f.bwd_bytes,
        }
