"""
AegisNDR - Packet Capture Layer
Captures raw packets from the network interface and pushes to a queue.
"""
import logging
import threading
import queue
import time
from typing import Optional, Callable

from models import Packet, Protocol

logger = logging.getLogger(__name__)


def _parse_scapy_packet(pkt) -> Optional[Packet]:
    """Convert a Scapy packet to our Packet dataclass."""
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.inet6 import IPv6

        # Require IP layer
        if IP not in pkt and IPv6 not in pkt:
            return None

        ip_layer = pkt[IP] if IP in pkt else pkt[IPv6]
        src_ip = str(ip_layer.src)
        dst_ip = str(ip_layer.dst)
        ttl    = getattr(ip_layer, "ttl", 64)
        length = len(pkt)
        ts     = float(pkt.time)

        # Transport layer
        src_port = dst_port = 0
        protocol = Protocol.OTHER
        tcp_flags = 0
        payload   = b""
        icmp_type = 0

        if TCP in pkt:
            protocol  = Protocol.TCP
            src_port  = pkt[TCP].sport
            dst_port  = pkt[TCP].dport
            tcp_flags = int(pkt[TCP].flags)
            payload   = bytes(pkt[TCP].payload)[:256]   # first 256 bytes

        elif UDP in pkt:
            protocol = Protocol.UDP
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            payload  = bytes(pkt[UDP].payload)[:256]

        elif ICMP in pkt:
            protocol  = Protocol.ICMP
            icmp_type = pkt[ICMP].type

        return Packet(
            timestamp=ts, src_ip=src_ip, dst_ip=dst_ip,
            src_port=src_port, dst_port=dst_port,
            protocol=protocol, length=length, payload=payload,
            tcp_flags=tcp_flags, ttl=ttl, icmp_type=icmp_type,
        )
    except Exception as e:
        logger.debug(f"Packet parse error: {e}")
        return None


class PacketCapture:
    """
    Live packet capture using Scapy's AsyncSniffer.
    Falls back to a mock generator for testing without root / interface.
    """

    def __init__(
        self,
        interface: str,
        bpf_filter: str = "",
        packet_queue: Optional[queue.Queue] = None,
        promiscuous: bool = True,
        mock_mode: bool = False,
    ):
        self.interface   = interface
        self.bpf_filter  = bpf_filter
        self.queue       = packet_queue or queue.Queue(maxsize=100_000)
        self.promiscuous = promiscuous
        self.mock_mode   = mock_mode
        self._sniffer    = None
        self._mock_thread: Optional[threading.Thread] = None
        self._running    = False
        self._stats      = {"captured": 0, "dropped": 0, "errors": 0}

    # ── Public API ──────────────────────────────────────────────────────────
    def start(self):
        self._running = True
        if self.mock_mode:
            logger.info("PacketCapture: starting in MOCK mode")
            self._mock_thread = threading.Thread(
                target=self._mock_generator, daemon=True)
            self._mock_thread.start()
        else:
            self._start_live()

    def stop(self):
        self._running = False
        if self._sniffer:
            try: self._sniffer.stop()
            except: pass
        logger.info(f"PacketCapture stopped. Stats: {self._stats}")

    @property
    def stats(self): return dict(self._stats)

    # ── Live capture ────────────────────────────────────────────────────────
    def _start_live(self):
        try:
            from scapy.sendrecv import AsyncSniffer
        except ImportError:
            logger.error("Scapy not installed. Run: pip install scapy")
            return

        kwargs = {
            "iface":   self.interface,
            "prn":     self._on_packet,
            "store":   False,
        }
        if self.bpf_filter:
            kwargs["filter"] = self.bpf_filter

        self._sniffer = AsyncSniffer(**kwargs)
        self._sniffer.start()
        logger.info(f"PacketCapture: live capture on {self.interface}")

    def _on_packet(self, pkt):
        pkt_obj = _parse_scapy_packet(pkt)
        if pkt_obj:
            self._stats["captured"] += 1
            try:
                self.queue.put_nowait(pkt_obj)
            except queue.Full:
                self._stats["dropped"] += 1

    # ── Mock generator ──────────────────────────────────────────────────────
    def _mock_generator(self):
        """Generates realistic synthetic traffic for development/testing."""
        import random, math
        hosts   = [f"192.168.1.{i}" for i in range(2, 20)]
        ext_ips = ["8.8.8.8", "1.1.1.1", "203.0.113.5", "198.51.100.7"]
        ports   = [80, 443, 22, 53, 8080, 3306, 5432, 445]
        seq     = 0

        while self._running:
            seq += 1
            ts = time.time()

            # Simulate various traffic patterns
            pattern = random.choices(
                ["normal_web", "ssh", "dns", "db", "heavy_scan", "ddos_burst"],
                weights=[50, 15, 20, 10, 3, 2],
            )[0]

            if pattern == "normal_web":
                src = random.choice(hosts)
                dst = random.choice(ext_ips)
                pkt = Packet(timestamp=ts, src_ip=src, dst_ip=dst,
                             src_port=random.randint(1024,65535),
                             dst_port=random.choice([80,443]),
                             protocol=Protocol.TCP,
                             length=random.randint(64, 1460),
                             tcp_flags=0x18)  # PSH+ACK

            elif pattern == "ssh":
                src = random.choice(hosts)
                dst = random.choice(hosts)
                pkt = Packet(timestamp=ts, src_ip=src, dst_ip=dst,
                             src_port=random.randint(1024,65535), dst_port=22,
                             protocol=Protocol.TCP, length=random.randint(64, 512),
                             tcp_flags=0x18)

            elif pattern == "dns":
                src = random.choice(hosts)
                pkt = Packet(timestamp=ts, src_ip=src, dst_ip="8.8.8.8",
                             src_port=random.randint(1024,65535), dst_port=53,
                             protocol=Protocol.UDP, length=random.randint(50, 120))

            elif pattern == "db":
                src = random.choice(hosts[:5])
                pkt = Packet(timestamp=ts, src_ip=src, dst_ip=hosts[0],
                             src_port=random.randint(1024,65535),
                             dst_port=random.choice([3306, 5432]),
                             protocol=Protocol.TCP, length=random.randint(100, 2000),
                             tcp_flags=0x18)

            elif pattern == "heavy_scan":
                # Simulate port scan — attacker scanning many ports
                attacker = "10.0.0.99"
                target   = hosts[0]
                for p in random.sample(range(1, 1024), min(20, 20)):
                    if not self._running: break
                    sp = Packet(timestamp=ts, src_ip=attacker, dst_ip=target,
                                src_port=random.randint(1024,65535), dst_port=p,
                                protocol=Protocol.TCP, length=44, tcp_flags=0x02)  # SYN
                    try: self.queue.put_nowait(sp)
                    except queue.Full: pass
                    self._stats["captured"] += 1
                time.sleep(0.1)
                continue

            elif pattern == "ddos_burst":
                # Short DDoS burst
                victim = hosts[1]
                for _ in range(50):
                    if not self._running: break
                    src = f"172.{random.randint(16,31)}.{random.randint(0,255)}.{random.randint(1,254)}"
                    sp = Packet(timestamp=ts, src_ip=src, dst_ip=victim,
                                src_port=random.randint(1024,65535), dst_port=80,
                                protocol=Protocol.TCP, length=64, tcp_flags=0x02)
                    try: self.queue.put_nowait(sp)
                    except queue.Full: pass
                    self._stats["captured"] += 1
                time.sleep(0.05)
                continue
            else:
                continue

            self._stats["captured"] += 1
            try:
                self.queue.put_nowait(pkt)
            except queue.Full:
                self._stats["dropped"] += 1

            time.sleep(random.uniform(0.001, 0.05))
