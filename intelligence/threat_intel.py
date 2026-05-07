"""
AegisNDR - Threat Intelligence Module
IP reputation, blacklist enrichment, and feed aggregation.
"""
import logging
import time
import json
import os
import threading
from typing import Dict, Optional, List, Set
from collections import defaultdict

import config

logger = logging.getLogger(__name__)


# ── Built-in Threat Feeds (static) ────────────────────────────────────────────
# Known malicious IP ranges (demo — in prod, pull from MISP, OTX, VirusTotal)
STATIC_BLACKLIST: Set[str] = {
    "10.0.0.99",      # demo attacker IP
    "192.0.2.1",
    "198.51.100.7",
    "203.0.113.5",
}

STATIC_TOR_EXIT: Set[str] = {
    "185.220.101.1",
    "185.220.101.2",
    "162.247.74.74",
}

KNOWN_C2_RANGES = [
    "91.108.4.",   # Telegram abuse range (example)
    "5.188.86.",   # Known botnet range (example)
]


class ThreatIntelligence:
    """
    Enriches alerts/IPs with threat intelligence context.

    Sources:
      - Static blacklists (bundled)
      - AbuseIPDB API (if key provided)
      - Local reputation cache (Redis-backed in prod)
      - Tor exit node list
    """

    CACHE_PATH = "data/ti_cache.json"

    def __init__(self):
        self._cache: Dict[str, Dict] = {}
        self._cache_ttl: Dict[str, float] = {}
        self._lock = threading.Lock()
        self._api_key = config.ABUSE_IPDB_API_KEY

        os.makedirs("data", exist_ok=True)
        self._load_cache()

    # ── Public API ──────────────────────────────────────────────────────────
    def enrich(self, ip: str) -> Dict:
        """
        Returns enrichment dict for an IP:
        {
          "ip": str,
          "is_blacklisted": bool,
          "is_tor": bool,
          "is_c2": bool,
          "reputation_score": float,  # 0=clean, 100=malicious
          "categories": [str],
          "country": str,
          "isp": str,
          "confidence": float,
        }
        """
        # Check cache first
        cached = self._get_cached(ip)
        if cached:
            return cached

        result = self._check_static(ip)

        # Try AbuseIPDB if key available
        if self._api_key:
            api_result = self._query_abuseipdb(ip)
            result.update(api_result)

        result["ip"] = ip
        self._cache_result(ip, result)
        return result

    def reputation_score(self, ip: str) -> float:
        """Returns 0-100 reputation score for use in composite scoring."""
        data = self.enrich(ip)
        return data.get("reputation_score", 0.0)

    def bulk_enrich(self, ips: List[str]) -> Dict[str, Dict]:
        return {ip: self.enrich(ip) for ip in ips}

    # ── Static Checks ────────────────────────────────────────────────────
    def _check_static(self, ip: str) -> Dict:
        is_blacklisted = ip in STATIC_BLACKLIST
        is_tor         = ip in STATIC_TOR_EXIT
        is_c2          = any(ip.startswith(r) for r in KNOWN_C2_RANGES)

        categories = []
        score = 0.0

        if is_blacklisted:
            categories.append("blacklisted")
            score = max(score, 85.0)
        if is_tor:
            categories.append("tor-exit")
            score = max(score, 60.0)
        if is_c2:
            categories.append("known-c2")
            score = max(score, 90.0)

        # Private IPs get 0 score
        if self._is_private(ip):
            score = 0.0
            categories.append("private")

        return {
            "is_blacklisted":    is_blacklisted,
            "is_tor":            is_tor,
            "is_c2":             is_c2,
            "reputation_score":  score,
            "categories":        categories,
            "country":           "N/A",
            "isp":               "N/A",
            "confidence":        0.9 if (is_blacklisted or is_tor or is_c2) else 0.5,
        }

    # ── AbuseIPDB ─────────────────────────────────────────────────────────
    def _query_abuseipdb(self, ip: str) -> Dict:
        try:
            import urllib.request
            url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
            req = urllib.request.Request(url, headers={
                "Key": self._api_key,
                "Accept": "application/json",
            })
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())["data"]
                abuse_score = data.get("abuseConfidenceScore", 0)
                return {
                    "reputation_score": float(abuse_score),
                    "country":          data.get("countryCode", "N/A"),
                    "isp":              data.get("isp", "N/A"),
                    "categories":       [str(c) for c in data.get("reports", [])[:3]],
                    "confidence":       0.95,
                }
        except Exception as e:
            logger.debug(f"AbuseIPDB query failed for {ip}: {e}")
            return {}

    # ── Cache ─────────────────────────────────────────────────────────────
    def _get_cached(self, ip: str) -> Optional[Dict]:
        with self._lock:
            if ip in self._cache:
                if time.time() < self._cache_ttl.get(ip, 0):
                    return self._cache[ip]
        return None

    def _cache_result(self, ip: str, result: Dict):
        with self._lock:
            self._cache[ip] = result
            self._cache_ttl[ip] = time.time() + config.THREAT_INTEL_CACHE_TTL
        self._save_cache()

    def _load_cache(self):
        try:
            if os.path.exists(self.CACHE_PATH):
                with open(self.CACHE_PATH) as f:
                    data = json.load(f)
                    self._cache     = data.get("cache", {})
                    self._cache_ttl = data.get("ttl", {})
        except Exception:
            pass

    def _save_cache(self):
        try:
            with self._lock:
                data = {"cache": self._cache, "ttl": self._cache_ttl}
            with open(self.CACHE_PATH, "w") as f:
                json.dump(data, f)
        except Exception:
            pass

    @staticmethod
    def _is_private(ip: str) -> bool:
        prefixes = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                    "172.2", "172.3", "192.168.", "127.", "::1")
        return any(ip.startswith(p) for p in prefixes)
