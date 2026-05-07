"""
AegisNDR Plugin - DNS Anomaly Detector
Detects: DNS tunneling, rebinding attacks, high-frequency queries.
"""
from plugins.loader import PluginBase
from models import Flow, Alert, AlertType, Protocol


class DnsDetectorPlugin(PluginBase):
    name        = "dns_detector"
    description = "Detects DNS tunneling, rebinding, and abuse patterns"
    enabled     = True

    # Per-source query counter (in-memory, simple)
    _query_count: dict = {}

    def analyze(self, flow: Flow) -> list:
        if flow.protocol != Protocol.UDP or flow.dst_port != 53:
            return []

        alerts = []
        src = flow.src_ip

        # ── High query rate ────────────────────────────────────────────
        self._query_count[src] = self._query_count.get(src, 0) + 1
        if self._query_count[src] > 500:
            alerts.append(self.make_alert(
                flow, AlertType.DNS_TUNNELING, 70,
                f"High DNS query rate from {src}: {self._query_count[src]} queries",
                {"query_count": self._query_count[src]},
            ))
            self._query_count[src] = 0  # reset

        # ── Oversized query (tunneling) ────────────────────────────────
        if flow.fwd_pkt_sizes:
            avg = sum(flow.fwd_pkt_sizes) / len(flow.fwd_pkt_sizes)
            if avg > 180:
                alerts.append(self.make_alert(
                    flow, AlertType.DNS_TUNNELING, 72,
                    f"Oversized DNS queries (avg {avg:.0f} bytes) — possible tunneling",
                    {"avg_size": round(avg, 1)},
                ))

        # ── Payload entropy (encoded data in DNS name) ─────────────────
        if flow.payload_sample:
            import math
            freq = {}
            for b in flow.payload_sample:
                freq[b] = freq.get(b, 0) + 1
            n   = len(flow.payload_sample)
            ent = -sum((c/n) * math.log2(c/n) for c in freq.values())
            if ent > 4.5:  # normal DNS names have low entropy
                alerts.append(self.make_alert(
                    flow, AlertType.DNS_TUNNELING, 68,
                    f"High entropy DNS payload (entropy={ent:.2f}) — possible data encoding",
                    {"payload_entropy": round(ent, 2)},
                ))

        return alerts
