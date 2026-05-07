"""
AegisNDR - Configuration
"""
import os

# ─── Network ──────────────────────────────────────────────────────────────────
CAPTURE_INTERFACE = os.getenv("CAPTURE_INTERFACE", "eth0")
CAPTURE_FILTER    = os.getenv("CAPTURE_FILTER", "")          # BPF filter
CAPTURE_PROMISC   = True

# ─── Flow Engine ──────────────────────────────────────────────────────────────
FLOW_TIMEOUT_ACTIVE  = 120   # seconds - active flow timeout
FLOW_TIMEOUT_IDLE    = 30    # seconds - idle flow timeout
FLOW_MAX_PACKETS     = 5000  # max packets per flow

# ─── Detection Thresholds ─────────────────────────────────────────────────────
PORT_SCAN_THRESHOLD        = 15    # unique dst ports in window
PORT_SCAN_WINDOW           = 10    # seconds
BRUTE_FORCE_THRESHOLD      = 20    # failed auth attempts
BRUTE_FORCE_WINDOW         = 60    # seconds
DDOS_PPS_THRESHOLD         = 5000  # packets per second
DDOS_BPS_THRESHOLD         = 100_000_000  # 100 Mbps
EXFIL_BYTES_THRESHOLD      = 50_000_000   # 50 MB outbound
BEACON_INTERVAL_TOLERANCE  = 0.15  # 15% jitter tolerance

# ─── ML Engine ────────────────────────────────────────────────────────────────
ML_CONTAMINATION        = 0.05   # expected anomaly fraction
ML_TRAIN_MIN_SAMPLES    = 200    # min samples before training
ML_RETRAIN_INTERVAL     = 3600   # seconds between retrains

# ─── Scoring ──────────────────────────────────────────────────────────────────
SCORE_BLOCK_THRESHOLD    = 80
SCORE_ALERT_THRESHOLD    = 40
SCORE_DECAY_FACTOR       = 0.9   # per minute

# ─── Storage ──────────────────────────────────────────────────────────────────
POSTGRES_URL  = os.getenv("POSTGRES_URL", "postgresql://aegis:aegis@localhost:5432/aegis_ndr")
REDIS_HOST    = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT    = int(os.getenv("REDIS_PORT", 6379))
ES_HOST       = os.getenv("ES_HOST", "http://localhost:9200")

# ─── API ──────────────────────────────────────────────────────────────────────
API_HOST      = os.getenv("API_HOST", "0.0.0.0")
API_PORT      = int(os.getenv("API_PORT", 8000))
JWT_SECRET    = os.getenv("JWT_SECRET", "CHANGE_THIS_IN_PRODUCTION_aegisndr2024")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 60

# ─── Response Engine ──────────────────────────────────────────────────────────
RESPONSE_ENABLED        = os.getenv("RESPONSE_ENABLED", "false").lower() == "true"
RESPONSE_WHITELIST_IPS  = os.getenv("WHITELIST_IPS", "127.0.0.1").split(",")
BLOCK_DURATION_SECONDS  = 3600   # 1 hour auto-unblock

# ─── Threat Intel ─────────────────────────────────────────────────────────────
ABUSE_IPDB_API_KEY = os.getenv("ABUSE_IPDB_API_KEY", "")
THREAT_INTEL_CACHE_TTL = 3600   # seconds

# ─── Logging ──────────────────────────────────────────────────────────────────
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE  = os.getenv("LOG_FILE", "logs/aegis_ndr.log")

# ─── MITRE ATT&CK Mapping ─────────────────────────────────────────────────────
MITRE_MAPPING = {
    "PORT_SCAN":         {"tactic": "Reconnaissance",   "technique": "T1046 - Network Service Discovery"},
    "BRUTE_FORCE":       {"tactic": "Credential Access","technique": "T1110 - Brute Force"},
    "DDOS":              {"tactic": "Impact",           "technique": "T1498 - Network DoS"},
    "DATA_EXFIL":        {"tactic": "Exfiltration",     "technique": "T1041 - Exfiltration Over C2 Channel"},
    "BEACON":            {"tactic": "Command & Control","technique": "T1071 - Application Layer Protocol"},
    "SQL_INJECTION":     {"tactic": "Initial Access",   "technique": "T1190 - Exploit Public-Facing App"},
    "XSS":               {"tactic": "Execution",        "technique": "T1059 - Command and Scripting"},
    "DNS_TUNNELING":     {"tactic": "Exfiltration",     "technique": "T1048.003 - Exfiltration Over DNS"},
    "ANOMALY":           {"tactic": "Unknown",          "technique": "T1000 - Unknown"},
    "LATERAL_MOVEMENT":  {"tactic": "Lateral Movement", "technique": "T1021 - Remote Services"},
}
