# AegisNDR Security Review

## Findings addressed

### 1. Insecure JWT fallback
The application previously contained a predictable source-code fallback for `JWT_SECRET`. This is unsafe because anyone who can inspect the repository can derive signing material.

**Remediation:** require `JWT_SECRET` from the environment and fail closed when it is missing.

### 2. Response automation
IP blocking and other response actions can have operational impact.

**Required posture:** response automation remains disabled by default and should use an explicit allowlist of managed assets.

### 3. Network capture privileges
Live packet capture may require elevated privileges.

**Required posture:** grant only the minimum capture capability needed by the deployment and keep the API/dashboard on trusted interfaces.

### 4. ML confidence
Anomaly detection is probabilistic.

**Required posture:** expose model output as a detection signal with supporting evidence rather than an assertion of compromise.

## Verification checklist

- [ ] No `.env` or real API keys are committed.
- [ ] `JWT_SECRET` is injected at deployment time.
- [ ] CORS is restricted.
- [ ] Administrative endpoints enforce authorization.
- [ ] Response actions are disabled in demo mode.
- [ ] Response targets are allowlisted.
- [ ] Logs do not expose secrets.
