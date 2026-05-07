"""
AegisNDR - Flow Generator
Assembles raw packets into bidirectional network flows.
Implements active/idle timeout, session tracking, and flow expiry.
"""
import logging
import threading
import queue
import time
from typing import Dict, Optional, Callable, List
from collections import defaultdict

from models import Packet, Flow, Protocol

logger = logging.getLogger(__name__)

# TCP flag bitmasks
FLAG_FIN = 0x01
FLAG_SYN = 0x02
FLAG_RST = 0x04
FLAG_PSH = 0x08
FLAG_ACK = 0x10
FLAG_URG = 0x20


class FlowGenerator:
    """
    Converts a stream of Packet objects → Flow objects.

    Flow key: (src_ip, dst_ip, src_port, dst_port, protocol)
    Bidirectional: both directions map to the same flow.

    Timeouts:
      - active:  flow has been open > FLOW_TIMEOUT_ACTIVE → expire
      - idle:    no packet for > FLOW_TIMEOUT_IDLE → expire
      - TCP FIN/RST: immediate expire
    """

    def __init__(
        self,
        packet_queue: queue.Queue,
        flow_callback: Optional[Callable[[Flow], None]] = None,
        active_timeout: int  = 120,
        idle_timeout:   int  = 30,
        max_packets:    int  = 5000,
    ):
        self.packet_queue    = packet_queue
        self.flow_callback   = flow_callback or (lambda f: None)
        self.active_timeout  = active_timeout
        self.idle_timeout    = idle_timeout
        self.max_packets     = max_packets

        self._flows: Dict[tuple, Flow] = {}
        self._lock  = threading.Lock()
        self._running = False
        self._stats = {
            "flows_created":  0,
            "flows_expired":  0,
            "packets_processed": 0,
        }

        # Background thread for timeout expiry
        self._expiry_thread: Optional[threading.Thread] = None

    # ── Public API ──────────────────────────────────────────────────────────
    def start(self):
        self._running = True
        self._expiry_thread = threading.Thread(
            target=self._expiry_loop, daemon=True, name="flow-expiry")
        self._expiry_thread.start()
        logger.info("FlowGenerator started")

    def stop(self):
        self._running = False
        # Expire all remaining flows
        with self._lock:
            for flow in list(self._flows.values()):
                self._expire_flow(flow)
            self._flows.clear()
        logger.info(f"FlowGenerator stopped. Stats: {self._stats}")

    def process_packet(self, pkt: Packet):
        """Process one packet and update its flow."""
        with self._lock:
            key = self._canonical_key(pkt)
            if key not in self._flows:
                flow = self._create_flow(pkt, key)
            else:
                flow = self._flows[key]

            self._update_flow(flow, pkt)
            self._stats["packets_processed"] += 1

            # Expire on TCP FIN/RST
            if pkt.protocol == Protocol.TCP:
                flags = pkt.tcp_flags
                if (flags & FLAG_FIN) or (flags & FLAG_RST):
                    self._expire_flow(flow)
                    del self._flows[key]
                    return

            # Expire if max packets reached
            if flow.total_packets >= self.max_packets:
                self._expire_flow(flow)
                del self._flows[key]

    def run_forever(self):
        """Blocking consume loop — call from a thread."""
        while self._running:
            try:
                pkt = self.packet_queue.get(timeout=1.0)
                self.process_packet(pkt)
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"FlowGenerator error: {e}")

    @property
    def active_flows(self) -> List[Flow]:
        with self._lock:
            return list(self._flows.values())

    @property
    def stats(self): return dict(self._stats)

    # ── Internal ────────────────────────────────────────────────────────────
    def _canonical_key(self, pkt: Packet) -> tuple:
        """Return a canonical (ordered) 5-tuple so A→B and B→A share a key."""
        a = (pkt.src_ip, pkt.src_port)
        b = (pkt.dst_ip, pkt.dst_port)
        lo, hi = (a, b) if a <= b else (b, a)
        return (*lo, *hi, pkt.protocol.value)

    def _create_flow(self, pkt: Packet, key: tuple) -> Flow:
        flow = Flow(
            src_ip=pkt.src_ip, dst_ip=pkt.dst_ip,
            src_port=pkt.src_port, dst_port=pkt.dst_port,
            protocol=pkt.protocol,
            start_time=pkt.timestamp, last_seen=pkt.timestamp,
        )
        self._flows[key] = flow
        self._stats["flows_created"] += 1
        logger.debug(f"New flow: {pkt.src_ip}:{pkt.src_port} → {pkt.dst_ip}:{pkt.dst_port}")
        return flow

    def _update_flow(self, flow: Flow, pkt: Packet):
        is_forward = (pkt.src_ip == flow.src_ip and pkt.src_port == flow.src_port)

        # IAT
        iat = pkt.timestamp - flow.last_seen
        flow.iat_list.append(iat)
        flow.last_seen = pkt.timestamp
        flow.duration  = flow.last_seen - flow.start_time

        if is_forward:
            flow.fwd_packets += 1
            flow.fwd_bytes   += pkt.length
            flow.fwd_pkt_sizes.append(pkt.length)
        else:
            flow.bwd_packets += 1
            flow.bwd_bytes   += pkt.length
            flow.bwd_pkt_sizes.append(pkt.length)

        # TCP flags accumulation
        flow.tcp_flags |= pkt.tcp_flags
        if pkt.tcp_flags & FLAG_SYN: flow.syn_count += 1
        if pkt.tcp_flags & FLAG_FIN: flow.fin_count += 1
        if pkt.tcp_flags & FLAG_RST: flow.rst_count += 1
        if pkt.tcp_flags & FLAG_PSH: flow.psh_count += 1
        if pkt.tcp_flags & FLAG_ACK: flow.ack_count += 1

        # Keep first meaningful payload
        if not flow.payload_sample and pkt.payload:
            flow.payload_sample = pkt.payload[:256]

    def _expire_flow(self, flow: Flow):
        flow.is_active = False
        flow.duration  = flow.last_seen - flow.start_time
        self._stats["flows_expired"] += 1
        try:
            self.flow_callback(flow)
        except Exception as e:
            logger.error(f"Flow callback error: {e}")

    def _expiry_loop(self):
        """Periodically check and expire timed-out flows."""
        while self._running:
            time.sleep(5)  # check every 5 seconds
            now = time.time()
            to_expire = []

            with self._lock:
                for key, flow in list(self._flows.items()):
                    idle_elapsed   = now - flow.last_seen
                    active_elapsed = now - flow.start_time

                    if idle_elapsed > self.idle_timeout or active_elapsed > self.active_timeout:
                        to_expire.append((key, flow))

            with self._lock:
                for key, flow in to_expire:
                    if key in self._flows:
                        self._expire_flow(flow)
                        del self._flows[key]

            if to_expire:
                logger.debug(f"Expired {len(to_expire)} flows by timeout")
