"""
AegisNDR - FastAPI REST API Layer
JWT auth, RBAC, rate limiting, and all endpoints.
"""
import time
import logging
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import jwt

import config
from storage.store import AlertStore, FlowStore
from scoring.threat_scorer import ThreatScorer
from response.soar import ResponseEngine
from intelligence.threat_intel import ThreatIntelligence

logger = logging.getLogger(__name__)

# ── Global state (set by engine at startup) ────────────────────────────────────
_alert_store:   AlertStore     = None
_flow_store:    FlowStore      = None
_threat_scorer: ThreatScorer   = None
_response_eng:  ResponseEngine = None
_threat_intel:  ThreatIntelligence = None
_engine_stats:  dict           = {}

def init_api(alert_store, flow_store, threat_scorer,
             response_eng, threat_intel):
    global _alert_store, _flow_store, _threat_scorer, _response_eng, _threat_intel
    _alert_store   = alert_store
    _flow_store    = flow_store
    _threat_scorer = threat_scorer
    _response_eng  = response_eng
    _threat_intel  = threat_intel


# ── JWT Auth ───────────────────────────────────────────────────────────────────
bearer_scheme = HTTPBearer(auto_error=False)

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    if credentials is None:
        raise HTTPException(status_code=401, detail="Missing token")
    try:
        payload = jwt.decode(
            credentials.credentials,
            config.JWT_SECRET,
            algorithms=[config.JWT_ALGORITHM],
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


# ── App ────────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="AegisNDR API",
    description="Intelligent Network Detection & Response Platform",
    version="1.0.0",
    docs_url="/docs",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Auth Endpoints ─────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str

# Demo credentials (use proper auth in production)
DEMO_USERS = {
    "admin":  {"password": "aegis2024!", "role": "admin"},
    "analyst": {"password": "analyst123", "role": "analyst"},
}

@app.post("/auth/login", tags=["Auth"])
def login(req: LoginRequest):
    user = DEMO_USERS.get(req.username)
    if not user or user["password"] != req.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    payload = {
        "sub":  req.username,
        "role": user["role"],
        "exp":  time.time() + config.JWT_EXPIRE_MINUTES * 60,
    }
    token = jwt.encode(payload, config.JWT_SECRET, algorithm=config.JWT_ALGORITHM)
    return {"access_token": token, "token_type": "bearer", "role": user["role"]}


# ── Health ─────────────────────────────────────────────────────────────────────
@app.get("/health", tags=["System"])
def health():
    return {
        "status":    "ok",
        "timestamp": time.time(),
        "version":   "1.0.0",
    }

@app.get("/stats", tags=["System"])
def system_stats(user=Depends(verify_token)):
    return {
        "alerts":  _alert_store.stats() if _alert_store else {},
        "flows":   _flow_store.stats()  if _flow_store  else {},
        "ml":      _engine_stats.get("ml", {}),
        "engine":  _engine_stats.get("capture", {}),
    }


# ── Alerts ─────────────────────────────────────────────────────────────────────
@app.get("/alerts", tags=["Alerts"])
def get_alerts(
    limit:      int           = Query(50, le=500),
    offset:     int           = Query(0),
    severity:   Optional[str] = None,
    alert_type: Optional[str] = None,
    src_ip:     Optional[str] = None,
    user=Depends(verify_token),
):
    return _alert_store.get_all(
        limit=limit, offset=offset,
        severity=severity, alert_type=alert_type, src_ip=src_ip,
    )

@app.get("/alerts/recent", tags=["Alerts"])
def recent_alerts(minutes: int = Query(5), user=Depends(verify_token)):
    return _alert_store.recent(minutes=minutes)

@app.get("/alerts/timeline", tags=["Alerts"])
def alerts_timeline(
    minutes:     int = Query(60),
    bucket_size: int = Query(5),
    user=Depends(verify_token),
):
    return _alert_store.timeline(minutes=minutes, bucket_size=bucket_size)

@app.get("/alerts/{alert_id}", tags=["Alerts"])
def get_alert(alert_id: str, user=Depends(verify_token)):
    alert = _alert_store.get_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


# ── Flows ──────────────────────────────────────────────────────────────────────
@app.get("/flows", tags=["Flows"])
def get_flows(
    limit:  int           = Query(100, le=1000),
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    user=Depends(verify_token),
):
    return _flow_store.get_all(limit=limit, src_ip=src_ip, dst_ip=dst_ip)

@app.get("/flows/top-talkers", tags=["Flows"])
def top_talkers(n: int = Query(10, le=50), user=Depends(verify_token)):
    return _flow_store.top_talkers(n=n)


# ── Threat Scoring ─────────────────────────────────────────────────────────────
@app.get("/threat_score/{ip}", tags=["Scoring"])
def threat_score(ip: str, user=Depends(verify_token)):
    score = _threat_scorer.get_ip_score(ip) if _threat_scorer else 0
    ti    = _threat_intel.enrich(ip) if _threat_intel else {}
    return {
        "ip":               ip,
        "score":            score,
        "severity":         "CRITICAL" if score >= 80 else
                            "HIGH"     if score >= 60 else
                            "MEDIUM"   if score >= 40 else "LOW",
        "threat_intel":     ti,
    }

@app.get("/threat_score", tags=["Scoring"])
def top_threats(n: int = Query(10, le=50), user=Depends(verify_token)):
    return _threat_scorer.top_threats(n=n) if _threat_scorer else []


# ── Response ───────────────────────────────────────────────────────────────────
class BlockRequest(BaseModel):
    ip:       str
    duration: Optional[int] = None
    reason:   Optional[str] = ""

@app.post("/block_ip", tags=["Response"])
def block_ip(req: BlockRequest, user=Depends(verify_token)):
    if user.get("role") not in ("admin",):
        raise HTTPException(status_code=403, detail="Admin role required")
    action = _response_eng.block_ip(req.ip, duration=req.duration)
    return action.to_dict()

@app.delete("/block_ip/{ip}", tags=["Response"])
def unblock_ip(ip: str, user=Depends(verify_token)):
    if user.get("role") not in ("admin",):
        raise HTTPException(status_code=403, detail="Admin role required")
    action = _response_eng.unblock_ip(ip)
    return action.to_dict()

@app.get("/blocked_ips", tags=["Response"])
def blocked_ips(user=Depends(verify_token)):
    return _response_eng.blocked_ips if _response_eng else []

@app.get("/response/log", tags=["Response"])
def response_log(user=Depends(verify_token)):
    return _response_eng.actions_log if _response_eng else []


# ── Threat Intelligence ────────────────────────────────────────────────────────
@app.get("/intel/{ip}", tags=["Intelligence"])
def intel_lookup(ip: str, user=Depends(verify_token)):
    return _threat_intel.enrich(ip) if _threat_intel else {}


# ── Attack Chains ──────────────────────────────────────────────────────────────
_correlation_engine = None

def set_correlation_engine(engine):
    global _correlation_engine
    _correlation_engine = engine

@app.get("/chains/active", tags=["Correlation"])
def active_chains(user=Depends(verify_token)):
    if not _correlation_engine: return []
    return [c.to_dict() for c in _correlation_engine.active_chains]

@app.get("/chains/history", tags=["Correlation"])
def chain_history(user=Depends(verify_token)):
    if not _correlation_engine: return []
    return [c.to_dict() for c in _correlation_engine.completed_chains]


# ── Engine Stats update hook ───────────────────────────────────────────────────
def update_engine_stats(stats: dict):
    _engine_stats.update(stats)
