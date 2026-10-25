from __future__ import annotations

import json
import os
import re
import sqlite3
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import HTMLResponse
from fastapi import Request
from app.ai_engine import analyze_uploaded_content, investigate_with_ai, retrieve_passages
from app.evidence_review import review_claims_with_agent, score_review_assessments
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.getenv("DROPZONE_DB_PATH", str(BASE_DIR / "dropzone.db")))
API_KEY = os.getenv("DROPZONE_API_KEY", "dev-change-me").strip() or "dev-change-me"
DOCS_DIR = BASE_DIR / "docs"

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="DropZone AI Security Investigation Agent",
    description="A portfolio starter for evidence-based security alert triage with human approval.",
    version="0.4.0",
    lifespan=lifespan,
)

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}


class SecurityEventIn(BaseModel):
    source: str = Field(min_length=1, max_length=120)
    event_type: str = Field(min_length=1, max_length=120)
    title: str = Field(min_length=3, max_length=240)
    description: str = Field(min_length=3, max_length=5000)
    severity: Literal["critical", "high", "medium", "low", "informational"] = "medium"
    asset: str | None = Field(default=None, max_length=240)
    user: str | None = Field(default=None, max_length=240)
    indicators: list[str] = Field(default_factory=list, max_length=50)
    occurred_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class DecisionIn(BaseModel):
    decision: Literal["approved", "rejected"]
    reviewer: str = Field(min_length=2, max_length=120)
    comment: str = Field(default="", max_length=2000)


class UploadedLogIn(BaseModel):
    filename: str = Field(min_length=1, max_length=255)
    content: str = Field(min_length=1, max_length=200_000)


class SupportRequestIn(BaseModel):
    email: str = Field(min_length=3, max_length=254, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    message: str = Field(min_length=10, max_length=2000)
    context_type: Literal[
        "incident_no_findings", "incident_no_evidence",
        "upload_no_findings", "upload_no_evidence",
    ]
    investigation_id: str | None = Field(default=None, max_length=64)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY, source TEXT NOT NULL, event_type TEXT NOT NULL,
                title TEXT NOT NULL, description TEXT NOT NULL, severity TEXT NOT NULL,
                asset TEXT, username TEXT, indicators_json TEXT NOT NULL,
                occurred_at TEXT, metadata_json TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS investigations (
                id TEXT PRIMARY KEY, event_id TEXT NOT NULL UNIQUE REFERENCES events(id),
                priority_score INTEGER NOT NULL, priority TEXT NOT NULL,
                confidence TEXT NOT NULL, summary TEXT NOT NULL,
                evidence_json TEXT NOT NULL, recommendations_json TEXT NOT NULL,
                missing_information_json TEXT NOT NULL, status TEXT NOT NULL,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                engine TEXT NOT NULL DEFAULT 'rules', model TEXT, ai_status TEXT NOT NULL DEFAULT 'not_configured',
                ai_error TEXT, ai_findings_json TEXT NOT NULL DEFAULT '[]',
                retrieved_passage_count INTEGER NOT NULL DEFAULT 0, cited_passage_count INTEGER NOT NULL DEFAULT 0,
                workflow_trace_json TEXT NOT NULL DEFAULT '[]', quality_status TEXT NOT NULL DEFAULT 'needs_review',
                evidence_review_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS decisions (
                id TEXT PRIMARY KEY, investigation_id TEXT NOT NULL REFERENCES investigations(id),
                decision TEXT NOT NULL, reviewer TEXT NOT NULL, comment TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL,
                target_type TEXT NOT NULL, target_id TEXT NOT NULL,
                details_json TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS support_requests (
                id TEXT PRIMARY KEY, email TEXT NOT NULL, message TEXT NOT NULL,
                context_type TEXT NOT NULL, investigation_id TEXT,
                created_at TEXT NOT NULL
            );
            """
        )
        existing = {row[1] for row in conn.execute("PRAGMA table_info(investigations)").fetchall()}
        migrations = {
            "engine": "TEXT NOT NULL DEFAULT 'rules'", "model": "TEXT",
            "ai_status": "TEXT NOT NULL DEFAULT 'not_configured'", "ai_error": "TEXT",
            "ai_findings_json": "TEXT NOT NULL DEFAULT '[]'",
            "retrieved_passage_count": "INTEGER NOT NULL DEFAULT 0",
            "cited_passage_count": "INTEGER NOT NULL DEFAULT 0",
            "workflow_trace_json": "TEXT NOT NULL DEFAULT '[]'",
            "quality_status": "TEXT NOT NULL DEFAULT 'needs_review'",
            "evidence_review_json": "TEXT NOT NULL DEFAULT '{}'",
        }
        for column, definition in migrations.items():
            if column not in existing:
                conn.execute(f"ALTER TABLE investigations ADD COLUMN {column} {definition}")


def require_api_key(x_api_key: str | None = Header(default=None)) -> dict[str, str]:
    """Authenticate API keys and return a role-bearing principal.

    Preferred config: DROPZONE_API_KEYS='{"secret":{"username":"analyst1","role":"analyst"}}'
    Legacy DROPZONE_API_KEY is treated as an admin key for local backward compatibility.
    """
    configured = os.getenv("DROPZONE_API_KEYS", "").strip()
    normalized_key = (x_api_key or "").strip()
    if configured:
        try:
            key_map = json.loads(configured)
        except json.JSONDecodeError:
            raise HTTPException(status_code=503, detail="DROPZONE_API_KEYS must be valid JSON")
        record = key_map.get(normalized_key)
        if not isinstance(record, dict):
            raise HTTPException(status_code=401, detail="Missing or invalid X-API-Key header")
        role = record.get("role")
        if role not in {"admin", "analyst", "reviewer", "viewer"}:
            raise HTTPException(status_code=503, detail="Configured user has an invalid role")
        return {"username": str(record.get("username", "user"))[:120], "role": role}
    effective_api_key = API_KEY.strip() if isinstance(API_KEY, str) else ""
    if not effective_api_key or effective_api_key == "dev-change-me":
        raise HTTPException(status_code=503, detail="Configure DROPZONE_API_KEY or DROPZONE_API_KEYS before using protected endpoints.")
    if normalized_key != effective_api_key:
        raise HTTPException(status_code=401, detail="Missing or invalid X-API-Key header")
    return {"username": "admin", "role": "admin"}


def require_roles(user: dict[str, str], *roles: str) -> dict[str, str]:
    if user.get("role") not in roles:
        raise HTTPException(status_code=403, detail="Your role is not allowed to perform this action")
    return user


def write_audit(actor: str, action: str, target_type: str, target_id: str, details: dict[str, Any]) -> None:
    with db() as conn:
        conn.execute(
            "INSERT INTO audit_log VALUES (?, ?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), actor, action, target_type, target_id, json.dumps(details), now_iso()),
        )


def load_docs() -> list[dict[str, str]]:
    docs: list[dict[str, str]] = []
    for path in sorted(DOCS_DIR.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        title = next((line.lstrip("# ").strip() for line in text.splitlines() if line.startswith("#")), path.stem)
        docs.append({"id": path.name, "title": title, "text": text})
    return docs


def retrieve_docs(query: str, limit: int = 3) -> list[dict[str, Any]]:
    terms = {t.lower() for t in re.findall(r"[a-zA-Z0-9_.-]{3,}", query)}
    ranked = []
    for doc in load_docs():
        words = set(re.findall(r"[a-zA-Z0-9_.-]{3,}", doc["text"].lower()))
        score = len(terms & words)
        if score:
            ranked.append((score, doc))
    ranked.sort(key=lambda x: (-x[0], x[1]["id"]))
    return [
        {"document_id": d["id"], "title": d["title"], "excerpt": d["text"][:800], "match_score": s}
        for s, d in ranked[:limit]
    ]


def assess_event(event: dict[str, Any]) -> dict[str, Any]:
    text = " ".join([
        event.get("title", ""), event.get("description", ""), event.get("event_type", ""),
        " ".join(event.get("indicators", [])),
    ]).lower()
    score = {"critical": 80, "high": 65, "medium": 40, "low": 20, "informational": 5}.get(event["severity"], 40)
    signals: list[str] = []
    keyword_rules = [
        (("ransomware", "encryption of files", "mass file rename"), 25, "Possible ransomware or destructive file activity"),
        (("privilege escalation", "admin privileges", "root access"), 20, "Possible privilege escalation"),
        (("multiple failed login", "brute force", "password spray"), 15, "Possible credential attack"),
        (("known malicious", "malware", "command and control", "c2 beacon"), 20, "Possible malware or command-and-control activity"),
        (("exfiltration", "large outbound transfer", "data theft"), 25, "Possible data exfiltration"),
        (("mfa fatigue", "impossible travel", "suspicious login"), 15, "Potential account compromise signal"),
    ]
    for keywords, points, signal in keyword_rules:
        if any(k in text for k in keywords):
            score += points
            signals.append(signal)
    score = min(score, 100)
    if score >= 85:
        priority = "critical"
    elif score >= 65:
        priority = "high"
    elif score >= 40:
        priority = "medium"
    else:
        priority = "low"

    evidence = [{"type": "event_field", "field": "severity", "value": event["severity"], "reason": f"Initial source severity contributes to score ({event['severity']})."}]
    evidence.extend({"type": "rule_match", "field": "description/title/indicators", "value": s, "reason": "Matched a transparent local triage rule; this is a signal, not proof of compromise."} for s in signals)
    docs = retrieve_passages(" ".join([event.get("title", ""), event.get("description", ""), event.get("event_type", ""), " ".join(event.get("indicators", []))]))
    evidence.extend({"type": "documentation", **d, "reason": "Retrieved reference passage. Confirm it applies to the local policy before acting."} for d in docs)

    recommendations = [
        {"id": str(uuid.uuid4()), "action": "Validate the alert against source logs and surrounding events", "reason": "Confirm whether the signal is accurate and establish a timeline.", "requires_approval": False, "status": "suggested"},
        {"id": str(uuid.uuid4()), "action": "Preserve relevant logs and evidence", "reason": "Maintain investigation context and support later review.", "requires_approval": False, "status": "suggested"},
    ]
    if priority in ("high", "critical"):
        recommendations.append({"id": str(uuid.uuid4()), "action": "Ask an authorized incident responder to assess containment options", "reason": "The combination of severity and matched signals may warrant urgent human review.", "requires_approval": True, "status": "pending_review"})
    else:
        recommendations.append({"id": str(uuid.uuid4()), "action": "Collect additional context before taking disruptive action", "reason": "Current evidence may be incomplete or benign.", "requires_approval": True, "status": "pending_review"})

    missing = []
    if not event.get("asset"):
        missing.append("Affected asset or hostname")
    if not event.get("user"):
        missing.append("Associated user or service account")
    if not event.get("indicators"):
        missing.append("Observable indicators such as IP, domain, hash, or process name")
    if not event.get("occurred_at"):
        missing.append("Original event timestamp from the source system")

    summary = f"{priority.title()} priority based on source severity and transparent local rule matches. "
    summary += "Signals detected: " + ("; ".join(signals) if signals else "no additional keyword signals matched") + ". "
    summary += "This is preliminary triage, not a confirmed finding; verify against source logs."
    confidence = "medium" if signals and len(missing) <= 2 else "low"
    return {"priority_score": score, "priority": priority, "confidence": confidence, "summary": summary,
            "evidence": evidence, "recommendations": recommendations, "missing_information": missing}


def serialize_row(row: sqlite3.Row) -> dict[str, Any]:
    item = dict(row)
    for key in ("indicators_json", "metadata_json", "evidence_json", "recommendations_json", "missing_information_json", "details_json", "ai_findings_json", "workflow_trace_json", "evidence_review_json"):
        if key in item:
            try:
                item[key.removesuffix("_json")] = json.loads(item[key])
            except (TypeError, json.JSONDecodeError):
                item[key.removesuffix("_json")] = []
            del item[key]
    return item


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    return """<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>DropZone AI SOC</title><style>
    :root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;font:14px Inter,system-ui,sans-serif;background:#080d18;color:#e5eaf4}header{padding:22px 28px;border-bottom:1px solid #202b40;background:#0c1424;display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}h1{margin:0;font-size:24px}h2{font-size:16px;margin:0 0 14px}.sub{color:#94a3b8;margin-top:5px}main{max-width:1400px;margin:auto;padding:24px}.toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.toolbar input{max-width:300px}.metrics{display:grid;grid-template-columns:repeat(4,minmax(130px,1fr));gap:14px;margin:20px 0}.metric,.panel{background:#101a2b;border:1px solid #25334b;border-radius:14px;padding:18px}.metric .value{font-size:30px;font-weight:750;margin-top:7px}.muted{color:#9baac0}.layout{display:grid;grid-template-columns:minmax(0,1.1fr) minmax(0,1fr);gap:16px}.incident{border-top:1px solid #26354b;padding:13px 2px;cursor:pointer}.incident:hover{background:#152239}.pill{display:inline-block;padding:4px 8px;border-radius:99px;background:#26354b;font-size:11px;text-transform:uppercase;margin-right:6px}.critical{background:#7f1d1d}.high{background:#7c2d12}.medium{background:#713f12}.low{background:#14532d}input,textarea,select,button{font:inherit;border-radius:8px;border:1px solid #34445d;background:#0a1220;color:#e5eaf4;padding:10px;width:100%;margin:5px 0 10px}button{background:#245eea;border:0;cursor:pointer;font-weight:650;width:auto}button.secondary{background:#25334b}button.danger{background:#9f3030}label{display:block;color:#b6c3d5}.row{display:grid;grid-template-columns:1fr 1fr;gap:10px}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#080f1c;padding:12px;border-radius:8px;max-height:420px;overflow:auto}.citation{border-left:2px solid #3b82f6;padding:8px 10px;margin:8px 0;background:#0b1424}.empty{padding:24px;text-align:center;color:#94a3b8}@media(max-width:850px){.layout{grid-template-columns:1fr}.metrics{grid-template-columns:repeat(2,1fr)}}@media(max-width:480px){main{padding:12px}.metrics{gap:8px}.metric{padding:12px}}
    </style></head><body><header><div><h1>◈ DropZone AI</h1><div class='sub'>Security investigation workspace · evidence-first triage</div></div><div class='toolbar'><input id='key' type='password' placeholder='API key' aria-label='API key'><button onclick='refresh()'>Refresh data</button></div></header><main>
    <div class='metrics'><div class='metric'><div class='muted'>Total incidents</div><div class='value' id='total'>—</div></div><div class='metric'><div class='muted'>Critical / high</div><div class='value' id='urgent'>—</div></div><div class='metric'><div class='muted'>Awaiting review</div><div class='value' id='pending'>—</div></div><div class='metric'><div class='muted'>AI engine</div><div class='value' style='font-size:18px' id='engine'>—</div></div></div>
    <div class='layout'><section class='panel'><h2>Incident queue</h2><div class='toolbar'><select id='filter' onchange='renderList()' style='max-width:180px'><option value='all'>All priorities</option><option>critical</option><option>high</option><option>medium</option><option>low</option></select><button class='secondary' onclick='document.getElementById("new-event").hidden=!document.getElementById("new-event").hidden'>+ New alert</button></div><div id='new-event' hidden><div class='row'><div><label>Source</label><input id='source' value='demo-siem'></div><div><label>Event type</label><input id='type' value='authentication_alert'></div></div><label>Title</label><input id='title' value='Multiple failed login attempts'><label>Description</label><textarea id='description' rows='3'>Multiple failed login attempts against a privileged account from an unfamiliar source.</textarea><div class='row'><div><label>Severity</label><select id='severity'><option>low</option><option selected>medium</option><option>high</option><option>critical</option><option>informational</option></select></div><div><label>Asset</label><input id='asset' placeholder='server-01'></div></div><button onclick='submitEvent()'>Submit alert</button></div><div id='list' class='empty'>Enter your API key and refresh to load incidents.</div></section>
    <section class='panel'><h2>Investigation details</h2><div id='detail' class='empty'>Select an incident to review evidence, citations, recommendations, and decisions.</div></section></div>
    <section class='panel' style='margin-top:16px'><h2>Analyze uploaded logs</h2><div class='muted'>Upload TXT, LOG, JSON, JSONL, or CSV files up to 200 KB. Uploaded content is sent to your configured AI provider when AI is enabled and is not stored by this app.</div><label for='log-file'>Log or event file</label><input id='log-file' type='file' accept='.txt,.log,.json,.jsonl,.csv'><button onclick='analyzeLogFile()'>Analyze file</button><pre id='log-analysis'>No file analyzed yet.</pre><div id='log-support'></div></section>
    <section class='panel' style='margin-top:16px'><div class='toolbar' style='justify-content:space-between'><h2>Investigation quality evaluation</h2><button onclick='runEval()'>Run fixed test set</button><button class='secondary' onclick='runReviewerCalibration()'>Calibrate evidence reviewer</button></div><div class='muted'>Evaluates a versioned set of synthetic alerts against expected priority labels and citation validity. This is a benchmark, not a certification of production accuracy.</div><pre id='eval'>No evaluation run yet.</pre></section>
    <div class='muted' style='margin-top:18px'>API documentation: <a href='/docs' style='color:#93c5fd'>/docs</a> · Health: <a href='/health' style='color:#93c5fd'>/health</a></div></main><script>
    let incidents=[];let selected=null;const key=()=>document.getElementById('key').value;async function api(url,opts={}){const r=await fetch(url,{...opts,headers:{'Content-Type':'application/json','X-API-Key':key(),...(opts.headers||{})}});const d=await r.json();if(!r.ok)throw Error(d.detail||('HTTP '+r.status));return d}function esc(x){return String(x??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
    async function refresh(){try{const d=await api('/incidents?limit=200');incidents=d.incidents||[];document.getElementById('total').textContent=incidents.length;document.getElementById('urgent').textContent=incidents.filter(x=>['critical','high'].includes(x.priority)).length;document.getElementById('pending').textContent=incidents.filter(x=>x.status==='awaiting_review').length;document.getElementById('engine').textContent=incidents.some(x=>x.engine==='llm_grounded')?'LLM + rules':'Rules / fallback';renderList();}catch(e){document.getElementById('list').textContent=e.message}}
    function renderList(){const f=document.getElementById('filter').value;const rows=incidents.filter(x=>f==='all'||x.priority===f);document.getElementById('list').innerHTML=rows.length?rows.map(x=>`<div class="incident" onclick="openIncident('${x.id}')"><span class="pill ${esc(x.priority)}">${esc(x.priority)}</span><span class="pill">${esc(x.status)}</span><b>${esc(x.title||x.summary||'Incident')}</b><div class="muted" style="margin-top:7px">Score ${esc(x.priority_score)} · ${esc(x.source||'unknown source')} · ${esc(x.created_at||'')}</div></div>`).join(''):'<div class="empty">No incidents match this filter.</div>'}
    function supportFormMarkup(formId,contextType,investigationId){return `<section class="citation"><h3>Need help with these results?</h3><p class="muted">Send a customer support request, or email <a href="mailto:clintonjunior6@gmail.com" style="color:#93c5fd">clintonjunior6@gmail.com</a>. Requests include only your message and the investigation reference, not uploaded files or evidence.</p><label for="${esc(formId)}-email">Your email</label><input id="${esc(formId)}-email" type="email" maxlength="254" required placeholder="you@example.com"><label for="${esc(formId)}-message">How can support help?</label><textarea id="${esc(formId)}-message" rows="3" minlength="10" maxlength="2000" placeholder="Describe what you expected or what you need help with." required></textarea><button onclick="submitSupportRequest('${esc(formId)}','${esc(contextType)}','${esc(investigationId||'')}')">Send support request</button><p id="${esc(formId)}-status" class="muted" aria-live="polite"></p></section>`}
    async function openIncident(id){selected=id;try{const x=await api('/incidents/'+id);const evidence=x.evidence||[];const findings=x.ai_findings||[];document.getElementById('detail').innerHTML=`<span class="pill ${esc(x.priority)}">${esc(x.priority)}</span><span class="pill">Score ${esc(x.priority_score)}</span><span class="pill">Confidence ${esc(x.confidence)}</span><h3>${esc(x.title)}</h3><p>${esc(x.summary)}</p><p class="muted">Engine: ${esc(x.engine||'rules')} · AI status: ${esc(x.ai_status||'not recorded')} · Quality: ${esc(x.quality_status||'needs_review')}</p><h3>Investigation workflow trace</h3><div>${(x.workflow_trace||[]).map(t=>`<div class=\"citation\"><b>${esc(t.stage)} · ${esc(t.status)}</b><p>${esc(t.detail)}</p></div>`).join('')||'<p>No trace recorded.</p>'}</div><h3>Independent evidence review</h3>${(x.evidence_review&&x.evidence_review.assessments||[]).map(a=>`<div class="citation"><b>${esc(a.verdict)} · ${esc(a.claim_id)}</b><p>${esc(a.rationale||'')}</p></div>`).join('')||'<p class="muted">No second-agent review recorded; rules fallback may be active.</p>'}<h3>Evidence and citations</h3>${evidence.map(e=>`<div class="citation"><b>${esc(e.title||e.field||e.type)}</b><div class="muted">${esc(e.citation_id||e.document_id||'Event evidence')} ${e.line_start?'· lines '+e.line_start+'–'+e.line_end:''}</div><p>${esc(e.text||e.reason||e.value||'')}</p></div>`).join('')||'<p>No evidence attached.</p>'}<h3>Recommended next steps</h3>${(x.recommendations||[]).map(r=>`<div class="citation"><b>${esc(r.action)}</b><p>${esc(r.reason)}</p><span class="pill">${r.requires_approval?'Approval required':'Non-disruptive'}</span></div>`).join('')}<h3>AI findings</h3><ul>${findings.map(f=>`<li>${esc(f)}</li>`).join('')||'<li>No LLM findings recorded; rules/fallback may be active.</li>'}</ul><h3>Missing information</h3><p>${(x.missing_information||[]).map(esc).join(' · ')||'None listed'}</p><h3>Human review</h3><label>Reviewer comment</label><textarea id="comment" rows="2" placeholder="Document why you approve or reject"></textarea><button onclick="decision('approved')">Approve recommendation</button> <button class="danger" onclick="decision('rejected')">Reject</button><button class="secondary" onclick="reinvestigate()">Re-investigate</button><h3>Decision history</h3><pre>${esc(JSON.stringify(x.decisions||[],null,2))}</pre>`;if(!findings.length||!evidence.length){const reason=!evidence.length?'incident_no_evidence':'incident_no_findings';document.getElementById('detail').insertAdjacentHTML('beforeend',supportFormMarkup('incident-'+id,reason,id))}}catch(e){document.getElementById('detail').textContent=e.message}}
    async function submitSupportRequest(formId,contextType,investigationId){const status=document.getElementById(formId+'-status');try{status.textContent='Saving request…';const result=await api('/support/requests',{method:'POST',body:JSON.stringify({email:document.getElementById(formId+'-email').value,message:document.getElementById(formId+'-message').value,context_type:contextType,investigation_id:investigationId||null})});status.textContent=`Request saved locally (${result.request_id}); email delivery is not configured. For direct support, email clintonjunior6@gmail.com.`}catch(e){status.textContent=e.message}}
    async function decision(decision){if(!selected)return;try{await api('/incidents/'+selected+'/decisions',{method:'POST',body:JSON.stringify({decision,reviewer:'dashboard-user',comment:document.getElementById('comment').value})});await refresh();await openIncident(selected)}catch(e){alert(e.message)}}async function reinvestigate(){try{await api('/incidents/'+selected+'/investigate',{method:'POST'});await refresh();await openIncident(selected)}catch(e){alert(e.message)}}
    async function analyzeLogFile(){const input=document.getElementById('log-file');const file=input.files[0];const output=document.getElementById('log-analysis');const support=document.getElementById('log-support');if(!file){output.textContent='Choose a file first.';return}if(file.size>200000){output.textContent='File exceeds the 200 KB limit.';return}try{support.innerHTML='';output.textContent='Analyzing…';const content=await file.text();const result=await api('/uploads/analyze',{method:'POST',body:JSON.stringify({filename:file.name,content})});output.textContent=JSON.stringify(result,null,2);if(!(result.findings||[]).length||!(result.evidence||[]).length){const reason=!(result.evidence||[]).length?'upload_no_evidence':'upload_no_findings';support.innerHTML=supportFormMarkup('upload',reason,'')}}catch(e){output.textContent=e.message}}
    async function submitEvent(){try{const body={source:document.getElementById('source').value,event_type:document.getElementById('type').value,title:document.getElementById('title').value,description:document.getElementById('description').value,severity:document.getElementById('severity').value,asset:document.getElementById('asset').value||null};const d=await api('/events',{method:'POST',body:JSON.stringify(body)});document.getElementById('new-event').hidden=true;await refresh();await openIncident(d.investigation_id)}catch(e){alert(e.message)}}async function runEval(){try{document.getElementById('eval').textContent='Running…';const d=await api('/evaluation/run',{method:'POST'});document.getElementById('eval').textContent=JSON.stringify(d,null,2)}catch(e){document.getElementById('eval').textContent=e.message}}async function runReviewerCalibration(){try{document.getElementById('eval').textContent='Calibrating reviewer…';const d=await api('/evaluation/reviewer-calibration',{method:'POST'});document.getElementById('eval').textContent=JSON.stringify(d,null,2)}catch(e){document.getElementById('eval').textContent=e.message}}if(key())refresh();</script></body></html>"""


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "dropzone-ai", "time": now_iso()}


@app.post("/events", status_code=201)
async def ingest_event(payload: SecurityEventIn, user: dict[str, str] = Depends(require_api_key)) -> dict[str, Any]:
    require_roles(user, "admin", "analyst")
    event_id = str(uuid.uuid4())
    created = now_iso()
    event = payload.model_dump(mode="json")
    with db() as conn:
        conn.execute(
            "INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (event_id, payload.source, payload.event_type, payload.title, payload.description, payload.severity,
             payload.asset, payload.user, json.dumps(payload.indicators),
             payload.occurred_at.isoformat() if payload.occurred_at else None,
             json.dumps(payload.metadata), created),
        )
    write_audit(user["username"], "event.created", "event", event_id, {"source": payload.source, "severity": payload.severity})
    event["id"] = event_id
    result = await investigate_with_ai(event, assess_event(event))
    investigation_id = str(uuid.uuid4())
    with db() as conn:
        conn.execute(
            "INSERT INTO investigations (id,event_id,priority_score,priority,confidence,summary,evidence_json,recommendations_json,missing_information_json,status,created_at,updated_at,engine,model,ai_status,ai_error,ai_findings_json,retrieved_passage_count,cited_passage_count,workflow_trace_json,quality_status,evidence_review_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (investigation_id, event_id, result["priority_score"], result["priority"], result["confidence"], result["summary"],
             json.dumps(result["evidence"]), json.dumps(result["recommendations"]), json.dumps(result["missing_information"]),
             "awaiting_review", created, created, result.get("engine", "rules"), result.get("model"), result.get("ai_status", "not_configured"), result.get("ai_error"), json.dumps(result.get("ai_findings", [])), result.get("retrieved_passage_count", 0), result.get("cited_passage_count", 0), json.dumps(result.get("workflow_trace", [])), result.get("quality_status", "needs_review"), json.dumps(result.get("evidence_review", {}))),
        )
    write_audit("triage-engine", "investigation.created", "investigation", investigation_id,
                {"event_id": event_id, "priority": result["priority"], "score": result["priority_score"]})
    return {"event_id": event_id, "investigation_id": investigation_id, "event": event,
            "investigation": {**result, "status": "awaiting_review", "created_at": created}}


@app.post("/uploads/analyze")
async def analyze_upload(payload: UploadedLogIn, user: dict[str, str] = Depends(require_api_key)) -> dict[str, Any]:
    require_roles(user, "admin", "analyst")
    if len(payload.content.encode("utf-8")) > 200_000:
        raise HTTPException(status_code=413, detail="Uploaded content exceeds the 200 KB limit")
    try:
        result = await analyze_uploaded_content(payload.filename, payload.content)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    write_audit(user["username"], "upload.analyzed", "upload", str(uuid.uuid4()), {
        "format": result["format"],
        "record_count": result["record_count"],
        "records_analyzed": result["records_analyzed"],
    })
    return result


@app.post("/support/requests", status_code=201)
def create_support_request(payload: SupportRequestIn, user: dict[str, str] = Depends(require_api_key)) -> dict[str, Any]:
    if payload.investigation_id:
        with db() as conn:
            exists = conn.execute("SELECT id FROM investigations WHERE id=?", (payload.investigation_id,)).fetchone()
        if not exists:
            raise HTTPException(status_code=404, detail="Investigation not found")

    request_id = str(uuid.uuid4())
    created = now_iso()
    with db() as conn:
        conn.execute(
            "INSERT INTO support_requests (id,email,message,context_type,investigation_id,created_at) VALUES (?,?,?,?,?,?)",
            (request_id, payload.email, payload.message, payload.context_type, payload.investigation_id, created),
        )
    write_audit(user["username"], "support.request.created", "support_request", request_id, {
        "context_type": payload.context_type,
        "investigation_id": payload.investigation_id,
    })
    return {
        "request_id": request_id,
        "created_at": created,
        "support_email": "clintonjunior6@gmail.com",
        "message": "Request saved locally. Email delivery is not configured.",
    }


@app.get("/support/requests")
def list_support_requests(
    limit: int = Query(default=100, ge=1, le=500),
    user: dict[str, str] = Depends(require_api_key),
) -> dict[str, Any]:
    require_roles(user, "admin")
    with db() as conn:
        rows = conn.execute(
            "SELECT id,email,message,context_type,investigation_id,created_at "
            "FROM support_requests ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return {"count": len(rows), "requests": [dict(row) for row in rows]}


@app.get("/incidents")
def list_incidents(limit: int = Query(default=50, ge=1, le=200), user: dict[str, str] = Depends(require_api_key)) -> dict[str, Any]:
    with db() as conn:
        rows = conn.execute("SELECT i.*, e.title, e.source, e.severity AS source_severity FROM investigations i JOIN events e ON e.id=i.event_id ORDER BY i.created_at DESC LIMIT ?", (limit,)).fetchall()
    return {"count": len(rows), "incidents": [serialize_row(r) for r in rows]}


@app.get("/incidents/{investigation_id}")
def get_incident(investigation_id: str, user: dict[str, str] = Depends(require_api_key)) -> dict[str, Any]:
    with db() as conn:
        row = conn.execute("SELECT i.*, e.source, e.event_type, e.title, e.description, e.severity AS source_severity, e.asset, e.username, e.indicators_json, e.occurred_at FROM investigations i JOIN events e ON e.id=i.event_id WHERE i.id=?", (investigation_id,)).fetchone()
        decisions = conn.execute("SELECT * FROM decisions WHERE investigation_id=? ORDER BY created_at DESC", (investigation_id,)).fetchall()
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")
    result = serialize_row(row)
    result["decisions"] = [dict(d) for d in decisions]
    return result


@app.post("/incidents/{investigation_id}/investigate")
async def reinvestigate(investigation_id: str, user: dict[str, str] = Depends(require_api_key)) -> dict[str, Any]:
    require_roles(user, "admin", "analyst")
    with db() as conn:
        row = conn.execute("SELECT e.* FROM events e JOIN investigations i ON i.event_id=e.id WHERE i.id=?", (investigation_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")
    event = dict(row)
    event["user"] = event.get("username")
    event["indicators"] = json.loads(event.pop("indicators_json"))
    event["metadata"] = json.loads(event.pop("metadata_json"))
    result = await investigate_with_ai(event, assess_event(event))
    with db() as conn:
        conn.execute("UPDATE investigations SET priority_score=?, priority=?, confidence=?, summary=?, evidence_json=?, recommendations_json=?, missing_information_json=?, updated_at=?, engine=?, model=?, ai_status=?, ai_error=?, ai_findings_json=?, retrieved_passage_count=?, cited_passage_count=?, workflow_trace_json=?, quality_status=?, evidence_review_json=? WHERE id=?",
                     (result["priority_score"], result["priority"], result["confidence"], result["summary"], json.dumps(result["evidence"]), json.dumps(result["recommendations"]), json.dumps(result["missing_information"]), now_iso(), result.get("engine", "rules"), result.get("model"), result.get("ai_status", "not_configured"), result.get("ai_error"), json.dumps(result.get("ai_findings", [])), result.get("retrieved_passage_count", 0), result.get("cited_passage_count", 0), json.dumps(result.get("workflow_trace", [])), result.get("quality_status", "needs_review"), json.dumps(result.get("evidence_review", {})), investigation_id))
    write_audit(user["username"], "investigation.rerun", "investigation", investigation_id, {"priority": result["priority"]})
    return {"investigation_id": investigation_id, **result}


@app.post("/incidents/{investigation_id}/decisions", status_code=201)
def decide(investigation_id: str, payload: DecisionIn, user: dict[str, str] = Depends(require_api_key)) -> dict[str, Any]:
    require_roles(user, "admin", "reviewer")
    payload.reviewer = user["username"]
    with db() as conn:
        exists = conn.execute("SELECT id FROM investigations WHERE id=?", (investigation_id,)).fetchone()
        if not exists:
            raise HTTPException(status_code=404, detail="Incident not found")
        decision_id = str(uuid.uuid4())
        created = now_iso()
        conn.execute("INSERT INTO decisions VALUES (?, ?, ?, ?, ?, ?)", (decision_id, investigation_id, payload.decision, payload.reviewer, payload.comment, created))
        conn.execute("UPDATE investigations SET status=?, updated_at=? WHERE id=?", ("approved" if payload.decision == "approved" else "rejected", created, investigation_id))
    write_audit(payload.reviewer, f"recommendation.{payload.decision}", "investigation", investigation_id, {"decision_id": decision_id, "comment": payload.comment})
    return {"decision_id": decision_id, "investigation_id": investigation_id, "decision": payload.decision, "reviewer": payload.reviewer, "created_at": created}


@app.get("/docs/search")
def search_docs(q: str = Query(min_length=2, max_length=500), limit: int = Query(default=3, ge=1, le=10), user: dict[str, str] = Depends(require_api_key)) -> dict[str, Any]:
    return {"query": q, "results": retrieve_passages(q, limit)}


@app.get("/audit")
def audit_log(limit: int = Query(default=100, ge=1, le=500), user: dict[str, str] = Depends(require_api_key)) -> dict[str, Any]:
    require_roles(user, "admin", "reviewer")
    with db() as conn:
        rows = conn.execute("SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    return {"count": len(rows), "entries": [serialize_row(r) for r in rows]}


@app.get("/evaluation/dataset")
def evaluation_dataset(user: dict[str, str] = Depends(require_api_key)) -> dict[str, Any]:
    require_roles(user, "admin", "analyst", "reviewer")
    path = BASE_DIR / "evaluation" / "security_alerts.json"
    dataset = json.loads(path.read_text(encoding="utf-8"))
    return {"version": dataset["version"], "count": len(dataset["cases"]), "cases": dataset["cases"]}


@app.post("/evaluation/run")
async def run_evaluation(user: dict[str, str] = Depends(require_api_key)) -> dict[str, Any]:
    require_roles(user, "admin", "analyst", "reviewer")
    dataset = json.loads((BASE_DIR / "evaluation" / "security_alerts.json").read_text(encoding="utf-8"))
    results = []
    priority_hits = 0
    rule_priority_hits = 0
    citation_coverage_cases = 0
    valid_citation_cases = 0
    llm_cases = 0
    llm_priority_hits = 0
    ai_citations_attempted = 0
    ai_citations_accepted = 0
    ai_citation_ids_rejected = 0
    reviewed_claims = 0
    supported_claims = 0
    contradicted_claims = 0
    insufficient_claims = 0
    blocked_summaries = 0
    paired_cases = 0
    paired_agent1_hits = 0
    paired_agent2_hits = 0
    engine_counts: dict[str, int] = {}

    def citation_is_valid(item: dict[str, Any]) -> bool:
        document_id = item.get("document_id", "")
        path = (BASE_DIR / "docs" / document_id).resolve()
        docs_root = (BASE_DIR / "docs").resolve()
        if docs_root not in path.parents or not path.is_file():
            return False
        start, end = item.get("line_start"), item.get("line_end")
        if not isinstance(start, int) or not isinstance(end, int) or start < 1 or end < start:
            return False
        lines = path.read_text(encoding="utf-8").splitlines()
        expected_id = f"{document_id}#L{start}-L{end}"
        text = item.get("text", "")
        actual_text = "\n".join(lines[start - 1:end])
        return end <= len(lines) and item.get("citation_id") == expected_id and bool(text) and text[:2000] in actual_text

    for case in dataset["cases"]:
        event = {**case["event"], "metadata": {}}
        rule_result = assess_event(event)
        result = await investigate_with_ai(event, rule_result)
        priority_ok = result["priority"] == case["expected_priority"]
        rule_ok = rule_result["priority"] == case["expected_priority"]
        priority_hits += int(priority_ok)
        rule_priority_hits += int(rule_ok)
        engine = result.get("engine", "rules")
        engine_counts[engine] = engine_counts.get(engine, 0) + 1
        docs = [e for e in result["evidence"] if e.get("type") == "documentation"]
        citation_valid = bool(docs) and all(citation_is_valid(e) for e in docs)
        citation_coverage_cases += int(bool(docs))
        valid_citation_cases += int(citation_valid)
        is_llm = result.get("ai_status") == "ok" and engine == "llm_grounded"
        if is_llm:
            llm_cases += 1
            llm_priority_hits += int(priority_ok)
            passages = result.get("ai_cited_passages", [])
            ai_citations_attempted += len(passages) + int(result.get("rejected_citation_count", 0))
            ai_citations_accepted += len(passages)
            ai_citation_ids_rejected += int(result.get("rejected_citation_count", 0))
        review = result.get("evidence_review") or {}
        if review.get("review_completed") and review.get("first_agent_priority") in {"critical", "high", "medium", "low"}:
            paired_cases += 1
            paired_agent1_hits += int(review["first_agent_priority"] == case["expected_priority"])
            paired_agent2_hits += int(result["priority"] == case["expected_priority"])
        verdict_counts = review.get("verdict_counts", {})
        supported_claims += int(verdict_counts.get("supported", 0))
        contradicted_claims += int(verdict_counts.get("contradicted", 0))
        insufficient_claims += int(verdict_counts.get("insufficient", 0))
        reviewed_claims += sum(int(verdict_counts.get(k, 0)) for k in ("supported", "contradicted", "insufficient"))
        blocked_summaries += int(result.get("ai_status") == "unsupported_summary")
        results.append({
            "case_id": case["id"], "expected_priority": case["expected_priority"],
            "rule_priority": rule_result["priority"], "rule_priority_match": rule_ok,
            "first_agent_priority": review.get("first_agent_priority"),
            "final_priority": result["priority"], "final_priority_match": priority_ok,
            "second_agent_review_completed": bool(review.get("review_completed", False)),
            "engine": engine, "ai_status": result.get("ai_status"),
            "valid_document_citations": citation_valid,
            "ai_cited_passage_count": result.get("cited_passage_count", 0),
            "reviewed_claims": sum(int(verdict_counts.get(k, 0)) for k in ("supported", "contradicted", "insufficient")),
            "supported_claims": int(verdict_counts.get("supported", 0)),
            "contradicted_claims": int(verdict_counts.get("contradicted", 0)),
            "insufficient_claims": int(verdict_counts.get("insufficient", 0)),
            "summary_blocked_by_reviewer": result.get("ai_status") == "unsupported_summary",
            "missing_information_count": len(result["missing_information"]),
        })
    n = len(results) or 1
    gold_path = BASE_DIR / "evaluation" / "claim_support_cases.json"
    gold_dataset = json.loads(gold_path.read_text(encoding="utf-8"))
    output = {
        "dataset_version": dataset["version"], "cases": len(results), "engine_counts": engine_counts,
        "rule_baseline_priority_accuracy": round(rule_priority_hits / n, 4),
        "two_agent_final_priority_accuracy": round(priority_hits / n, 4),
        "priority_accuracy_delta_vs_rules": round((priority_hits - rule_priority_hits) / n, 4),
        "paired_one_agent_vs_two_agent": {
            "cases_with_completed_reviewer": paired_cases,
            "one_agent_priority_accuracy": round(paired_agent1_hits / paired_cases, 4) if paired_cases else None,
            "two_agent_final_priority_accuracy": round(paired_agent2_hits / paired_cases, 4) if paired_cases else None,
            "accuracy_delta": round((paired_agent2_hits - paired_agent1_hits) / paired_cases, 4) if paired_cases else None,
        },
        "document_citation_coverage": round(citation_coverage_cases / n, 4),
        "valid_document_citation_rate_when_present": round(valid_citation_cases / max(citation_coverage_cases, 1), 4),
        "llm_cases_evaluated": llm_cases,
        "llm_priority_accuracy": round(llm_priority_hits / llm_cases, 4) if llm_cases else None,
        "llm_citation_allowlist_rate": round(ai_citations_accepted / ai_citations_attempted, 4) if ai_citations_attempted else None,
        "llm_citation_ids_rejected": ai_citation_ids_rejected,
        "claim_support": {
            "claims_reviewed_by_second_agent": reviewed_claims,
            "supported": supported_claims, "contradicted": contradicted_claims,
            "insufficient_evidence": insufficient_claims,
            "supported_rate": round(supported_claims / reviewed_claims, 4) if reviewed_claims else None,
            "unsupported_or_uncertain_rate": round((contradicted_claims + insufficient_claims) / reviewed_claims, 4) if reviewed_claims else None,
            "summaries_blocked": blocked_summaries,
            "gold_calibration_dataset_version": gold_dataset["version"],
            "gold_calibration_cases_available": len(gold_dataset["cases"]),
            "gold_calibration_note": "The labelled claim/passage fixture is available for reviewer calibration; this route does not count it as model-verified accuracy unless the reviewer is run against it.",
        },
        "results": results,
        "notes": "Synthetic benchmark only. The second agent is itself a model judge; claim support rates are estimates, not ground truth. The 30 manually labelled claim/passage pairs are intended for calibration. Run with a configured model provider to measure actual two-agent behavior. Compare priority accuracy with the deterministic baseline and inspect per-case verdicts; do not infer production readiness from this dataset.",
    }
    write_audit(user["username"], "evaluation.run", "evaluation", dataset["version"], {
        "cases": len(results), "priority_accuracy": output["two_agent_final_priority_accuracy"],
        "rule_baseline_priority_accuracy": output["rule_baseline_priority_accuracy"],
        "claims_reviewed": reviewed_claims,
    })
    return output



@app.post("/evaluation/reviewer-calibration")
async def reviewer_calibration(user: dict[str, str] = Depends(require_api_key)) -> dict[str, Any]:
    """Measure the second agent against the versioned manually labelled claim set."""
    require_roles(user, "admin", "analyst", "reviewer")
    dataset = json.loads((BASE_DIR / "evaluation" / "claim_support_cases.json").read_text(encoding="utf-8"))
    claims = []
    passages = []
    gold = {}
    for case in dataset["cases"]:
        citation_id = case["id"]
        claims.append({"claim_id": case["id"], "claim": case["claim"], "evidence_citation_ids": [citation_id]})
        passages.append({"citation_id": citation_id, "document_id": "gold-fixture", "line_start": 1, "line_end": 1, "text": case["passage"]})
        gold[case["id"]] = case["gold_verdict"]
    try:
        review = await review_claims_with_agent(claims, passages)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Reviewer calibration unavailable: {type(exc).__name__}") from exc
    scored = score_review_assessments(review["assessments"], gold)
    output = {"dataset_version": dataset["version"], "reviewer_model": review["model"], **scored,
              "note": "Exact-label accuracy against a small manually labelled synthetic fixture; inspect per-case errors. This is calibration, not proof of general entailment ability."}
    write_audit(user["username"], "evaluation.reviewer_calibration", "evaluation", dataset["version"], {"claims": scored["claims_evaluated"], "accuracy": scored["accuracy"]})
    return output
