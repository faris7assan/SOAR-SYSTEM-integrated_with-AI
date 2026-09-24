# AegisNDR

## Network Detection & Response Platform

AegisNDR is a Python-based cybersecurity research platform combining network-flow analysis, rule/signature detection, anomaly detection, event correlation, threat scoring, threat intelligence, MITRE ATT&CK mapping, and SOC-style response workflows.

> Status: Educational / experimental. Not presented as production-ready.

## Architecture

~~~text
Packet Capture / Simulation
          ↓
Flow Generation → Feature Extraction
          ↓
Rules / Signatures / ML
          ↓
Event Correlation → Threat Scoring
          ↓
Response Workflows
          ↓
Storage / SOC Dashboard / API
~~~

## Detection pipeline

- Network-flow and packet-derived features
- Rule and signature matching
- Isolation Forest anomaly detection
- Event correlation / attack-chain context
- Threat scoring
- Threat-intelligence enrichment
- MITRE ATT&CK mapping
- Demonstration response workflows

## Local setup

~~~bash
cp .env.example .env
pip install -r requirements.txt
python main.py --mock
~~~

Simulation:

~~~bash
python main.py --mock --simulate
~~~

Live capture may require elevated privileges:

~~~bash
sudo python main.py --interface eth0
~~~

Docker/Compose support is included in the repository.

## Security posture

- Never commit .env, API keys, JWT secrets, or credentials.
- JWT_SECRET must be supplied at deployment time.
- Keep automated response disabled during development.
- Restrict response actions to explicitly managed/allowlisted assets.
- Treat ML detections as investigation signals, not proof of compromise.
- Run live capture and response actions only in authorized environments.

See SECURITY.md and docs/SECURITY_REVIEW.md.

## Stack

Python, FastAPI, Scapy, scikit-learn, PostgreSQL, Redis, Elasticsearch, JWT/RBAC, Docker, and JavaScript dashboard components.

## Author

Hassan Faris — Cybersecurity Engineer | SOC | Network Security

- GitHub: https://github.com/faris7assan
- LinkedIn: https://www.linkedin.com/in/hassan-faris
- Portfolio: https://hassanhamedfaris69.base44.app
