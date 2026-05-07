"""
AegisNDR - Attack Simulation Module
Generates synthetic attack traffic to test detection capabilities.
"""
import time
import random
import queue
import logging
import threading
from typing import Optional

from models import Packet, Protocol

logger = logging.getLogger(__name__)


class AttackSimulator:
    """
    Injects realistic attack packets into the capture queue.
    Used for testing, red-team exercises, and demo mode.

    Attacks:
      - Port Scan (TCP SYN sweep)
      - Brute Force (SSH/RDP)
      - DDoS (SYN flood)
      - Data Exfiltration (large outbound flow)
      - C2 Beaconing (periodic connections)
      - SQL Injection (HTTP payload)
      - DNS Tunneling (oversized queries)
      - Lateral Movement (internal scanning)
    """

    def __init__(self, packet_queue: queue.Queue):
        self.queue    = packet_queue
        self._running = False
        self._threads = []

    def run_all(self, delay_between: float = 5.0):
        """Run all attack simulations sequentially in background."""
        attacks = [
            self.simulate_port_scan,
            self.simulate_brute_force,
            self.simulate_ddos,
            self.simulate_exfiltration,
            self.simulate_beaconing,
            self.simulate_sql_injection,
            self.simulate_dns_tunneling,
            self.simulate_lateral_movement,
        ]
        def _runner():
            for attack in attacks:
                if not self._running: break
                logger.info(f"[SIM] Running: {attack.__name__}")
                attack()
                time.sleep(delay_between)
        t = threading.Thread(target=_runner, daemon=True)
        t.start()
        self._threads.append(t)

    def start(self):
        self._running = True

    def stop(self):
        self._running = False

    # ── Simulated Attacks ────────────────────────────────────────────────

    def simulate_port_scan(
        self,
        attacker: str = "10.0.0.99",
        target:   str = "192.168.1.10",
        port_range: range = range(1, 1025),
    ):
        """TCP SYN scan across port range."""
        logger.info(f"[SIM] Port scan: {attacker} → {target}")
        for port in port_range:
            self._push(Packet(
                timestamp=time.time(),
                src_ip=attacker, dst_ip=target,
                src_port=random.randint(30000, 60000), dst_port=port,
                protocol=Protocol.TCP, length=44, tcp_flags=0x02,  # SYN
            ))
            time.sleep(0.002)

    def simulate_brute_force(
        self,
        attacker: str = "10.0.0.99",
        target:   str = "192.168.1.5",
        port: int = 22,
        attempts: int = 50,
    ):
        """SSH brute force — rapid connection attempts."""
        logger.info(f"[SIM] Brute force: {attacker} → {target}:{port}")
        for i in range(attempts):
            # SYN
            self._push(Packet(
                timestamp=time.time(),
                src_ip=attacker, dst_ip=target,
                src_port=random.randint(30000, 60000), dst_port=port,
                protocol=Protocol.TCP, length=44, tcp_flags=0x02,
            ))
            time.sleep(0.1)
            # RST (simulate rejected login)
            self._push(Packet(
                timestamp=time.time(),
                src_ip=target, dst_ip=attacker,
                src_port=port, dst_port=random.randint(30000, 60000),
                protocol=Protocol.TCP, length=44, tcp_flags=0x04,  # RST
            ))
            time.sleep(0.05)

    def simulate_ddos(
        self,
        victim:      str = "192.168.1.1",
        attackers:   int = 50,
        duration:    float = 5.0,
    ):
        """SYN flood DDoS from multiple spoofed sources."""
        logger.info(f"[SIM] DDoS SYN flood → {victim}")
        end = time.time() + duration
        while time.time() < end:
            src = f"172.{random.randint(16,31)}.{random.randint(0,255)}.{random.randint(1,254)}"
            self._push(Packet(
                timestamp=time.time(),
                src_ip=src, dst_ip=victim,
                src_port=random.randint(1024, 65535), dst_port=80,
                protocol=Protocol.TCP, length=60, tcp_flags=0x02,
            ))
            time.sleep(0.001)

    def simulate_exfiltration(
        self,
        src:   str = "192.168.1.15",
        dst:   str = "203.0.113.5",   # external IP
        mb:    float = 60.0,
    ):
        """Large outbound data transfer to external IP."""
        logger.info(f"[SIM] Exfiltration: {src} → {dst} ({mb}MB)")
        total_bytes = int(mb * 1_000_000)
        sent = 0
        while sent < total_bytes:
            chunk = min(1460, total_bytes - sent)
            self._push(Packet(
                timestamp=time.time(),
                src_ip=src, dst_ip=dst,
                src_port=random.randint(30000, 60000), dst_port=443,
                protocol=Protocol.TCP, length=chunk,
                payload=bytes(random.randint(0, 255) for _ in range(min(chunk, 64))),
                tcp_flags=0x18,
            ))
            sent += chunk
            time.sleep(0.005)

    def simulate_beaconing(
        self,
        infected: str = "192.168.1.20",
        c2:       str = "198.51.100.7",
        interval: float = 30.0,
        count:    int = 15,
    ):
        """Periodic C2 beacon with consistent timing."""
        logger.info(f"[SIM] C2 Beaconing: {infected} → {c2} every {interval}s")
        for i in range(count):
            self._push(Packet(
                timestamp=time.time(),
                src_ip=infected, dst_ip=c2,
                src_port=random.randint(30000, 60000), dst_port=443,
                protocol=Protocol.TCP, length=random.randint(100, 300),
                payload=b"GET /beacon HTTP/1.1\r\nHost: c2.evil.com\r\n\r\n",
                tcp_flags=0x18,
            ))
            # Add small jitter (±5%)
            jitter = interval * random.uniform(-0.05, 0.05)
            time.sleep(max(0.1, interval + jitter))

    def simulate_sql_injection(
        self,
        attacker: str = "10.0.0.99",
        target:   str = "192.168.1.100",
        port: int = 80,
        count: int = 10,
    ):
        """HTTP requests with SQL injection payloads."""
        payloads = [
            b"GET /search?q=1'+UNION+SELECT+1,2,3--+- HTTP/1.1\r\n",
            b"GET /login?user=admin'--&pass=x HTTP/1.1\r\n",
            b"POST /api?id=1+OR+1=1 HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n",
            b"GET /item?id=1;DROP+TABLE+users-- HTTP/1.1\r\n",
            b"GET /search?q='+SLEEP(5)-- HTTP/1.1\r\n",
        ]
        logger.info(f"[SIM] SQL Injection: {attacker} → {target}:{port}")
        for i in range(count):
            payload = random.choice(payloads)
            self._push(Packet(
                timestamp=time.time(),
                src_ip=attacker, dst_ip=target,
                src_port=random.randint(30000, 60000), dst_port=port,
                protocol=Protocol.TCP, length=len(payload) + 20,
                payload=payload, tcp_flags=0x18,
            ))
            time.sleep(0.5)

    def simulate_dns_tunneling(
        self,
        client: str = "192.168.1.25",
        dns:    str = "8.8.8.8",
        count:  int = 30,
    ):
        """Oversized DNS queries simulating data tunneling."""
        logger.info(f"[SIM] DNS Tunneling: {client} → {dns}")
        for i in range(count):
            # Encode fake data in large DNS query
            encoded = bytes(random.randint(32, 126) for _ in range(200))
            payload = b"base64." + encoded[:50] + b".evil-tunnel.com"
            self._push(Packet(
                timestamp=time.time(),
                src_ip=client, dst_ip=dns,
                src_port=random.randint(1024, 65535), dst_port=53,
                protocol=Protocol.UDP,
                length=len(payload) + 28,
                payload=payload,
            ))
            time.sleep(0.3)

    def simulate_lateral_movement(
        self,
        attacker: str = "192.168.1.50",
        targets:  list = None,
    ):
        """Internal east-west scanning of SMB/RDP ports."""
        if targets is None:
            targets = [f"192.168.1.{i}" for i in range(1, 20)]
        lateral_ports = [445, 139, 3389, 5985, 22]
        logger.info(f"[SIM] Lateral Movement: {attacker} → internal subnet")
        for target in targets:
            for port in lateral_ports:
                self._push(Packet(
                    timestamp=time.time(),
                    src_ip=attacker, dst_ip=target,
                    src_port=random.randint(30000, 60000), dst_port=port,
                    protocol=Protocol.TCP, length=44, tcp_flags=0x02,
                ))
                time.sleep(0.05)

    # ── Helper ────────────────────────────────────────────────────────────
    def _push(self, pkt: Packet):
        try:
            self.queue.put_nowait(pkt)
        except queue.Full:
            pass
