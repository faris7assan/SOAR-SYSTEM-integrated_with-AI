# 🛡️ AegisNDR — Intelligent Network Detection & Response Platform

> A full-stack, production-grade NDR platform built in Python.
> Hybrid detection engine · ML anomaly detection · SOAR-lite automation · Real-time SOC dashboard.

---

## Architecture

```
[Packet Capture] → [Flow Generator] → [Feature Engine]
                                             ↓
                          ┌──────────────────────────────┐
                          │       Detection Layer         │
                          │  Rule Engine  (thresholds)    │
                          │  Signature    (regex/bytes)   │
                          │  ML Engine    (Isolation Forest│
                          │  Plugins      (extensible)    │
                          └──────────────────────────────┘
                                             ↓
                          [Correlation Engine (DAG/chains)]
                                             ↓
                          [Threat Scoring Engine (composite)]
                                             ↓
                          [Response Engine (SOAR-lite)]
                                             ↓
                          [Storage: PostgreSQL / Redis / ES]
                                             ↓
                          [SOC Dashboard + REST API]
```

---

## Quick Start

### Option 1: Demo Mode (no root, no interface)
```bash
pip install -r requirements.txt
python main.py --mock
```
Opens:
- API: http://localhost:8000/docs
- Dashboard: open `dashboard/index.html` in browser

### Option 2: With Attack Simulation
```bash
python main.py --mock --simulate
```
Automatically injects: port scan → brute force → DDoS → exfil → beaconing → SQLi → DNS tunneling → lateral movement

### Option 3: Live Capture (Linux, needs root)
```bash
sudo python main.py --interface eth0
```

### Option 4: Docker (full stack)
```bash
docker-compose up -d
```
Services:
| Service | URL |
|---------|-----|
| SOC Dashboard | http://localhost:8080 |
| API Docs | http://localhost:8000/docs |
| Kibana | http://localhost:5601 |
| Elasticsearch | http://localhost:9200 |

---

## Detection Capabilities

| Detection Engine | Threats Detected |
|-----------------|-----------------|
| Rule Engine | Port Scan, Brute Force, DDoS, Data Exfil, Beaconing, Lateral Movement |
| Signature Engine | SQL Injection, XSS, Command Injection, Directory Traversal, DNS Tunneling |
| ML Engine (Isolation Forest) | Zero-day anomalies, behavioral deviations, unknown threats |
| Plugin System | Custom detections (drop `.py` in `/plugins/`) |
| Correlation Engine | Multi-stage kill chains (Recon → Exploit → C2 → Exfil) |

---

## MITRE ATT&CK Coverage

| Tactic | Technique | Detection |
|--------|-----------|-----------|
| Reconnaissance | T1046 - Network Service Discovery | Port Scan |
| Credential Access | T1110 - Brute Force | Brute Force |
| Impact | T1498 - Network DoS | DDoS |
| Exfiltration | T1041 - Exfil Over C2 | Data Exfil |
| Command & Control | T1071 - App Layer Protocol | Beaconing |
| Initial Access | T1190 - Exploit Public-Facing App | SQL Injection |
| Exfiltration | T1048.003 - DNS | DNS Tunneling |
| Lateral Movement | T1021 - Remote Services | Lateral Move |

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/login` | Get JWT token |
| GET | `/alerts` | List alerts (filterable) |
| GET | `/alerts/timeline` | Alert timeline for charts |
| GET | `/flows` | Network flows |
| GET | `/flows/top-talkers` | Top bandwidth IPs |
| GET | `/threat_score/{ip}` | IP risk score |
| POST | `/block_ip` | Block an IP (admin) |
| DELETE | `/block_ip/{ip}` | Unblock IP |
| GET | `/chains/active` | Active attack chains |
| GET | `/intel/{ip}` | Threat intelligence lookup |
| GET | `/stats` | System statistics |

All endpoints require JWT Bearer token. Login: `admin / aegis2024!`

---

## Writing a Plugin

Drop a `.py` file in `/plugins/`:

```python
from plugins.loader import PluginBase
from models import Flow, Alert, AlertType, Protocol

class MyCustomDetector(PluginBase):
    name        = "my_detector"
    description = "Detects custom threat pattern"

    def analyze(self, flow: Flow) -> list:
        # Your detection logic here
        if flow.dst_port == 1337 and flow.fwd_bytes > 10000:
            return [self.make_alert(
                flow, AlertType.ANOMALY, 75,
                "Suspicious traffic on port 1337"
            )]
        return []
```

---

## Scoring Formula

```
Score = 0.35 × BehavioralScore
      + 0.25 × SeverityScore
      + 0.20 × FrequencyScore
      + 0.20 × ThreatIntelScore
      + ChainBonus (if correlated attack)
```

Score thresholds: `LOW < 40 ≤ MEDIUM < 60 ≤ HIGH < 80 ≤ CRITICAL`

---

## Project Structure

```
aegis-ndr/
├── main.py                    # Entry point + CLI
├── engine.py                  # Main orchestrator
├── config.py                  # All configuration
├── models.py                  # Shared data models
├── core/
│   ├── capture.py             # Packet capture (Scapy + mock)
│   ├── flow_generator.py      # Packet → Flow (Zeek-style)
│   ├── feature_engine.py      # Feature extraction (~35 features)
│   └── detection/
│       ├── rule_engine.py     # Threshold-based rules
│       ├── signature_engine.py# Payload signature matching
│       └── ml_engine.py       # Isolation Forest + UEBA
├── correlation/
│   └── engine.py              # DAG-based kill chain correlation
├── scoring/
│   └── threat_scorer.py       # Composite threat scoring + decay
├── response/
│   └── soar.py                # SOAR-lite playbooks + iptables
├── intelligence/
│   └── threat_intel.py        # IP reputation + blacklists
├── storage/
│   └── store.py               # Alert/Flow stores
├── api/
│   └── app.py                 # FastAPI REST API (JWT, RBAC)
├── plugins/
│   ├── loader.py              # Plugin manager
│   └── dns_detector.py        # Example: DNS anomaly plugin
├── simulation/
│   └── attacker.py            # 8-attack simulation module
├── dashboard/
│   └── index.html             # Full SOC dark-mode dashboard
├── Dockerfile
├── docker-compose.yml         # Full stack (PG, Redis, ES, Kibana)
└── requirements.txt
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Packet Capture | Scapy, AF_PACKET, libpcap |
| ML Detection | scikit-learn (Isolation Forest), NumPy |
| API | FastAPI, JWT, Pydantic |
| Storage | PostgreSQL, Redis, Elasticsearch |
| Dashboard | Vanilla JS, Chart.js |
| Deployment | Docker, Docker Compose |

---

## Dashboard Credentials

| User | Password | Role |
|------|----------|------|
| admin | aegis2024! | Full access + blocking |
| analyst | analyst123 | Read-only |

---

Built by Hassan Hamed Faris — AegisNDR v1.0
