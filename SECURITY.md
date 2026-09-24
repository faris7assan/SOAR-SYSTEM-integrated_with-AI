# Security Policy

AegisNDR is an educational/research NDR platform. Use it only in systems and networks you own or are explicitly authorized to monitor.

## Required deployment controls

- Set a unique high-entropy `JWT_SECRET`; never use a source-code default.
- Keep AbuseIPDB, database, Redis, and Elasticsearch credentials in environment variables or a secret manager.
- Keep automated response disabled by default during development.
- Restrict response actions to an explicit allowlist of managed assets.
- Run packet capture with the minimum privileges required.
- Restrict the API to trusted origins and networks.
- Review ML detections as investigation signals, not proof of compromise.

## Reporting

Use GitHub's private security reporting mechanism when available. Do not publish credentials, private packet captures, exploit details, or sensitive infrastructure information in issues.
