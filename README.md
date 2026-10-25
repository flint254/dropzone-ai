# DropZone AI — Security Investigation Agent (v0.4 two-agent evidence review)

DropZone AI is a portfolio project for evidence-based security alert triage. It ingests synthetic security events, scores them with transparent rules, retrieves specific passages from trusted Markdown reference material, optionally asks a configured LLM for a structured investigation, records reviewer decisions, and maintains an audit trail.

## License

The original DropZone AI project code and documentation are licensed under the MIT License; see [LICENSE](LICENSE). Third-party software and materials are not relicensed by this project license. The bundled Oracle JDK in the local working copy is excluded from the Git repository; the Docker build uses the Python runtime and does not require that JDK.

> **Safety and scope:** this is a demonstration, not a production SOC platform. It does not connect to a live SIEM/EDR or execute containment. The LLM is optional; without a configured provider or when the provider fails, the app explicitly falls back to deterministic rules. Human review is required for decisions. The included evaluation set is synthetic and its labels are a starter benchmark, not ground truth.

## What's included

- **Two-agent investigation:** Agent 1 drafts a structured triage report; Agent 2 independently checks the summary and each finding against the exact cited passages. A missing/failed reviewer or unsupported summary blocks the model report and falls back to deterministic rules; unsupported individual findings are excluded.
- **AI model integration:** OpenAI-compatible Chat Completions API, configurable base URL/model, strict JSON parsing, timeout, error fallback, constrained citation IDs, and no model-triggered tool execution. Configure `DROPZONE_REVIEWER_MODEL` to use a separate reviewer model; otherwise the reviewer uses `OPENAI_MODEL`.
- **Passage-level retrieval:** chunked Markdown sections with source filename, line range, excerpt, retrieval score, and stable citation ID (for example `incident-response-basics.md#L10-L15`). The small dependency-free retriever is a baseline; replace it with a reviewed embedding/reranking stack if the corpus grows.
- **Incident dashboard:** metrics, severity filter, incident queue, detailed evidence, citations, AI findings, missing context, approval/rejection controls, re-investigation, and fixed-dataset evaluation.
- **Uploaded log analysis:** analyze TXT/LOG, JSON/JSONL, and CSV files up to 200 KB from the dashboard or `POST /uploads/analyze`. Model-generated summaries and findings are checked by the independent evidence reviewer and cite uploaded records; deterministic keyword checks are used when AI is unavailable. Upload contents are not stored by the application.
- **Role-based access:** API keys mapped to `admin`, `analyst`, `reviewer`, or `viewer`; server-side role checks enforce who can ingest, re-investigate, decide, and read audit records.
- **Audit history:** event creation, investigation creation, review decisions, re-investigation, and evaluation runs are recorded.
- **Evaluation:** 32 synthetic alert cases plus 30 manually labelled claim/passage pairs. Reports rule-baseline vs two-agent final priority accuracy, second-agent supported/contradicted/insufficient verdict counts, summary blocks, citation provenance, and per-case comparisons.
- **Tests:** API RBAC, retrieval citations, assessment behavior, and dataset schema.

## Run locally (Python 3.11+)

```bash
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
```

Configure one private admin key for local use:

```powershell
# Windows PowerShell
$env:DROPZONE_API_KEY = "replace-with-a-long-random-secret"
uvicorn app.main:app --reload
```

```bash
# macOS/Linux
export DROPZONE_API_KEY="replace-with-a-long-random-secret"
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000` and enter that key in the dashboard. Interactive API docs are at `http://127.0.0.1:8000/docs`.

## Configure a real AI model

Set the provider key and model before starting the server. The default uses OpenAI's API; an OpenAI-compatible provider can be configured with `OPENAI_BASE_URL` and `OPENAI_MODEL`.

```powershell
$env:OPENAI_API_KEY = "your-provider-api-key"
$env:OPENAI_MODEL = "gpt-4.1-mini"
# Optional for a compatible provider:
# $env:OPENAI_BASE_URL = "https://your-provider.example/v1"
uvicorn app.main:app --reload
```

Never commit API keys to Git. The API key is sent from the local dashboard to the backend; only use this demo over a trusted local connection until production authentication, HTTPS, and secret management are configured. The model is only called when `OPENAI_API_KEY` is set. Provider errors are handled by falling back to rules and storing an error class, not the secret or raw provider response.

## Role-based access configuration

For multiple roles, set `DROPZONE_API_KEYS` to a JSON object. When this variable is present it takes precedence over the single-key compatibility setting. Use unique, long random secrets per user and do not use the example values below in a real environment.

```powershell
$env:DROPZONE_API_KEYS = '{"admin-secret":{"username":"security-admin","role":"admin"},"analyst-secret":{"username":"analyst-1","role":"analyst"},"reviewer-secret":{"username":"reviewer-1","role":"reviewer"},"viewer-secret":{"username":"auditor-1","role":"viewer"}}'
uvicorn app.main:app --reload
```

| Role | Read incidents | Ingest / re-investigate | Approve / reject | Read audit log | Run evaluation |
|---|---:|---:|---:|---:|---:|
| `admin` | Yes | Yes | Yes | Yes | Yes |
| `analyst` | Yes | Yes | No | No | Yes |
| `reviewer` | Yes | No | Yes | Yes | Yes |
| `viewer` | Yes | No | No | No | No |

This is API-key role-based access for a portfolio demo, not full enterprise identity management. Keys are presented in the `X-API-Key` header. For public deployment, replace it with OIDC/OAuth, hashed credentials or a secrets manager, per-user revocation, rate limits, and tenant-scoped authorization.

## API endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/health` | Health check |
| `GET` | `/` | Incident dashboard |
| `POST` | `/events` | Validate, store, and investigate a security event |
| `POST` | `/uploads/analyze` | Analyze a TXT/LOG, JSON/JSONL, or CSV file (admin/analyst; maximum 200 KB) |
| `POST` | `/support/requests` | Submit a customer-support request after an investigation without supported findings or evidence |
| `GET` | `/support/requests` | Review locally stored support requests (admin only) |
| `GET` | `/incidents` | Filterable-by-client incident list |
| `GET` | `/incidents/{id}` | Incident, evidence, recommendations, decisions |
| `POST` | `/incidents/{id}/investigate` | Re-run assessment / optional LLM investigation |
| `POST` | `/incidents/{id}/decisions` | Record reviewer approval/rejection |
| `GET` | `/docs/search?q=password%20spray` | Passage retrieval with line citations |
| `GET` | `/audit` | Audit history (admin/reviewer) |
| `GET` | `/evaluation/dataset` | Read the fixed synthetic benchmark |
| `POST` | `/evaluation/run` | Run the 32-case benchmark and compare rules baseline with the two-agent result |
| `POST` | `/evaluation/reviewer-calibration` | Score the second agent against the 30 manually labelled claim/passage pairs |

Approval only records the human decision; it does not execute the recommendation.

Uploaded log analysis accepts a JSON body with `filename` and UTF-8 `content`. When an AI provider is configured, the content is sent to that provider for analysis; an independent reviewer checks each returned claim against its cited uploaded records. The app does not persist upload contents, and its audit entry records only the file format and record counts. If AI or evidence review is unavailable, the response clearly indicates a deterministic keyword-based fallback. Treat all results as preliminary and have an analyst validate them.

When an incident has no AI-supported findings or no attached evidence, or an uploaded-log analysis returns no findings or evidence, the dashboard offers a support request form and a mail link to `clintonjunior6@gmail.com`. Requests are stored locally in SQLite; the app does not send email. Admins can review them using `GET /support/requests`. The form stores the sender's email and message, plus the incident reference when applicable; it does not automatically attach event data, uploaded files, or evidence.

## Evaluation

The versioned alert dataset is `evaluation/security_alerts.json` (32 synthetic cases). Run it from the dashboard's **Run fixed test set** button or call `POST /evaluation/run` with an authorized API key. The endpoint reports the rule-only priority baseline alongside final two-agent priority accuracy, delta vs rules, citation provenance, claim verdict counts, supported rate, uncertain/contradicted rate, and summaries blocked by the reviewer.

The second agent is still a model-based judge, not ground truth. Its verdicts can be wrong. The separate `evaluation/claim_support_cases.json` fixture contains 30 manually labelled claim/passage pairs across `supported`, `contradicted`, and `insufficient` classes. Call `POST /evaluation/reviewer-calibration` with a configured model to score the reviewer against these labels and inspect per-case errors. Do not run the alert benchmark and claim reviewer calibration without an `OPENAI_API_KEY`; the AI workflow will fall back to rules if the provider is not configured. `DROPZONE_REVIEWER_MODEL` can specify a separate model for Agent 2.

The benchmark is synthetic and should be reviewed/adjudicated by a security practitioner. Compare results on the same dataset, and expand it with real redacted incidents, benign lookalikes, adversarial prompt-injection cases, and reviewed claim labels before making production accuracy claims. The second agent adds latency and provider cost.

## Run tests

```bash
python -m pytest -q
```

The tests cover role enforcement, line-level retrieval citations, schema/assessment basics, and human-review permissions. They do not replace a professional security review.

## Docker

Set environment variables in your shell or an untracked `.env` file, then run:

```bash
docker compose up --build
```

For AI mode, set `OPENAI_API_KEY`, and optionally `OPENAI_BASE_URL` / `OPENAI_MODEL`, in the environment before starting Compose. Never bake credentials into the Docker image.

## Architecture

```text
Alert / dashboard
       |
       v
FastAPI validation + API-key role checks
       |
       +------> SQLite events / decisions / audit log
       |
       v
Transparent triage rules -----> passage retrieval + exact line citations
       |                                      |
       +------------------+-------------------+
                          v
                Optional LLM investigation
                 structured JSON + allowlisted citations
                          |
                          v
               Human review / approval decision
                          |
                          v
               Audit trail + fixed-set evaluation
```

## Before public or production deployment

- Use HTTPS and a production-grade identity provider (OIDC/OAuth), not shared API keys in a browser.
- Use PostgreSQL with migrations, backups, access controls, and tenant isolation.
- Add rate limiting, request size limits, strict CORS, CSRF protections if cookie auth is introduced, and secret rotation.
- Redact personal data and secrets from model prompts and logs; define retention and deletion policies.
- Protect against prompt injection and malicious documents; treat event fields and retrieved content as untrusted data.
- Add independent citation-entailment tests, reviewed evaluation data, monitoring, cost limits, and provider retry/circuit-breaker policies.
- Keep disruptive actions behind explicit, audited human approval. Never automatically isolate devices, disable accounts, block addresses, or delete files from this prototype.

## Bounded two-agent investigation workflow (v0.4)

This version adds a separate evidence reviewer after the first investigation draft:

1. **Deterministic triage** records the initial rule-based assessment.
2. **Passage retrieval** ranks section-level Markdown passages with a lightweight BM25-like lexical scorer and exact source line citations.
3. **Optional model analysis** receives the event, deterministic assessment, and retrieved passages. Event fields and documents are explicitly treated as untrusted data.
4. **Evidence reviewer (Agent 2)** judges the generated summary and each finding as supported, contradicted, or insufficient using only the cited passages. A missing or failed reviewer triggers the rules fallback; unsupported summaries are blocked and unsupported findings are omitted.
5. **Quality gate and human review** remain in place. Workflow trace and reviewer assessments are persisted and shown in the dashboard.

The evaluation endpoint checks citation provenance (document exists, line range is in bounds, and citation ID matches the source text), compares rule-only and two-agent priority accuracy, and reports claim verdicts. The reviewer calibration endpoint scores Agent 2 against 30 labelled claim/passage pairs.

**Important limitation:** Agent 2 is itself a model-based judge and can be wrong. The lexical retriever is not semantic search, and the synthetic labels/claim pairs need independent security-practitioner review. Treat support rates as estimates, not ground truth; human review remains required.

### Additional reliability tests

The suite includes mocked model responses to verify that invented citation IDs are rejected, missing summaries cause a safe fallback, valid citations are retained, disruptive recommendations cannot bypass human approval, and unrelated queries return no passages. The test suite is run with:

```bash
python -m pytest -q
```
