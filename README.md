# AegisNDR

## Network Detection & Response Platform

AegisNDR is a cybersecurity portfolio project that combines network-flow analysis, rule-based detection, signature matching, anomaly detection, event correlation, threat scoring, threat intelligence, and SOC-style response workflows.

> **Project status:** Educational / experimental. The repository is intended for authorized lab and research environments and should be security-reviewed before production deployment.

## Architecture

```text
Packet Capture / Simulation
          ↓
Flow Generation
          ↓
Feature Extraction
          ↓
Detection Layer
 ┌────────┼────────┐
Rules   Signatures   ML
 └────────┼────────┘
          ↓
Event Correlation
          ↓
Threat Scoring
          ↓
Response Workflows
          ↓
Storage / SOC Dashboard / API
```

## Detection Components

| Component | Purpose |
|---|---|
| Rule engine | Threshold and behavioral detections |
| Signature engine | Pattern-based security detections |
| ML engine | Anomaly detection using Isolation Forest |
| Correlation engine | Links related events into attack chains |
| Threat scoring | Combines multiple signals into a risk score |
| Threat intelligence | Adds external reputation/context |
| Response engine | Demonstrates authorized response workflows |

## MITRE ATT&CK Examples

The project maps example detections to ATT&CK techniques such as:

- Network Service Discovery — T1046
- Brute Force — T1110
- Network Denial of Service — T1498
- Exfiltration Over C2 — T1041
- Application Layer Protocol — T1071
- Exploit Public-Facing Application — T1190
- DNS tunneling — T1048.003
- Remote Services — T1021

## Local Setup

Create your local environment from the example configuration:

```bash
cp .env.example .env
```

Set your own credentials and configuration values. **Never commit `.env` or real credentials.**

### Demo / Mock Mode

```bash
pip install -r requirements.txt
python main.py --mock
```

### Simulated Attack Workflow

```bash
python main.py --mock --simulate
```

Use simulation mode only in an isolated and authorized environment.

### Live Capture

On Linux, live packet capture may require elevated privileges:

```bash
sudo python main.py --interface eth0
```

### Docker

```bash
docker-compose up -d
```

Use the repository's current `.env.example` and compose configuration to determine the services and ports available in your local environment.

## Example API Areas

The project includes API functionality for areas such as:

- Authentication
- Alert retrieval
- Network-flow inspection
- Threat scoring
- IP blocking workflows
- Attack-chain status
- Threat-intelligence lookup
- System statistics

Review the running API documentation at `/docs` when the local service is started.

## Technology Stack

- Python
- FastAPI
- Scapy / packet capture tooling
- scikit-learn / Isolation Forest
- PostgreSQL
- Redis
- Elasticsearch
- JWT / RBAC
- Docker / Docker Compose
- JavaScript dashboard

## Security Notes

- Keep secrets in environment variables rather than source code.
- Test automated response actions only against systems you own or are explicitly authorized to administer.
- IP blocking and live packet capture may require Linux privileges.
- Treat ML detections as investigation signals rather than proof of compromise.

## Author

**Hassan Faris**  
Cybersecurity Graduate | SOC | Network Security | Threat Detection

- GitHub: https://github.com/faris7assan
- Portfolio: https://hassanhamedfaris69.base44.app/
- LinkedIn: https://www.linkedin.com/in/hassan-faris/
