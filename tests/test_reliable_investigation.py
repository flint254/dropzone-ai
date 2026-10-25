import asyncio
import json

import app.ai_engine as engine


PASSAGE = {
    "citation_id": "incident-response-basics.md#L10-L15",
    "document_id": "incident-response-basics.md",
    "title": "Initial triage",
    "line_start": 10,
    "line_end": 15,
    "text": "Validate the alert against original source logs and nearby events.",
    "retrieval_score": 1.25,
}

RULE_RESULT = {
    "priority_score": 65,
    "priority": "high",
    "confidence": "medium",
    "summary": "Rule-based preliminary triage.",
    "evidence": [{"type": "rule_match", "value": "Possible credential attack"}],
    "recommendations": [],
    "missing_information": [],
}


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return {"choices": [{"message": {"content": json.dumps(self.payload)}}]}


class FakeAsyncClient:
    instance_count = 0

    def __init__(self, *, payload, **kwargs):
        self.payload = payload
        FakeAsyncClient.instance_count += 1
        self.instance_number = FakeAsyncClient.instance_count

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def post(self, *args, **kwargs):
        if self.instance_number == 1:
            return FakeResponse(self.payload)
        import json as _json
        prompt = _json.loads(kwargs["json"]["messages"][1]["content"])
        claims = prompt.get("claims_to_check", [])
        citations = [p["citation_id"] for p in prompt.get("evidence_passages", []) if p.get("citation_id")]
        reviewer = {"assessments": [{"claim_id": c["claim_id"], "verdict": "supported", "citation_ids": citations, "rationale": "Directly supported in this test fixture."} for c in claims]}
        return FakeResponse(reviewer)


def event():
    return {"title": "Password spray", "description": "Multiple failed login attempts", "event_type": "identity_alert", "severity": "high", "indicators": ["203.0.113.4"]}


def configure_fake_model(monkeypatch, payload):
    FakeAsyncClient.instance_count = 0
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setattr(engine, "retrieve_passages", lambda query, limit=5: [PASSAGE])
    monkeypatch.setattr(engine.httpx, "AsyncClient", lambda **kwargs: FakeAsyncClient(payload=payload, **kwargs))


def test_model_report_requires_allowlisted_citation(monkeypatch):
    configure_fake_model(monkeypatch, {
        "summary": "A suspicious authentication pattern requires validation.",
        "priority": "high", "confidence": "medium", "findings": [],
        "cited_passages": ["made-up-document.md#L1-L2"], "recommendations": [], "missing_information": [],
    })
    result = asyncio.run(engine.investigate_with_ai(event(), RULE_RESULT))
    assert result["engine"] == "rules_fallback"
    assert result["ai_status"] == "invalid_or_missing_citations"
    assert result["quality_status"] == "needs_review"
    assert result["workflow_trace"][-1]["status"] == "blocked"


def test_valid_citation_is_kept_and_disruptive_action_requires_approval(monkeypatch):
    configure_fake_model(monkeypatch, {
        "summary": "The alert may indicate a credential attack; validate against source logs.",
        "priority": "high", "confidence": "medium", "findings": ["Multiple failed logins observed"],
        "cited_passages": [PASSAGE["citation_id"]],
        "recommendations": [{"action": "Disable the account", "reason": "Potential compromise", "requires_approval": False}],
        "missing_information": ["Authentication log context"],
    })
    result = asyncio.run(engine.investigate_with_ai(event(), RULE_RESULT))
    assert result["engine"] == "llm_grounded"
    assert result["cited_passage_count"] == 1
    assert any(e.get("citation_id") == PASSAGE["citation_id"] for e in result["evidence"])
    assert result["recommendations"][0]["requires_approval"] is True
    assert result["recommendations"][0]["status"] == "pending_review"
    assert result["workflow_trace"][-1]["status"] == "passed"
    assert result["evidence_review"]["verdict_counts"]["supported"] >= 1
    assert any(stage["stage"] == "evidence_reviewer" and stage["status"] == "completed" for stage in result["workflow_trace"])


def test_model_output_without_summary_falls_back(monkeypatch):
    configure_fake_model(monkeypatch, {"priority": "critical", "cited_passages": [PASSAGE["citation_id"]]})
    result = asyncio.run(engine.investigate_with_ai(event(), RULE_RESULT))
    assert result["engine"] == "rules_fallback"
    assert result["ai_status"] == "fallback"
    assert result["ai_error"] == "ValueError"


def test_retrieval_has_stable_line_citations_and_ignores_unrelated_query():
    results = engine.retrieve_passages("ransomware preserve endpoint evidence containment")
    assert results
    assert all("#L" in row["citation_id"] for row in results)
    assert all(row["line_start"] <= row["line_end"] for row in results)
    assert engine.retrieve_passages("xylophone lunar gardening nebula") == []


def test_reviewer_missing_or_invalid_claim_verdict_fails_closed(monkeypatch):
    class BrokenReviewerClient(FakeAsyncClient):
        async def post(self, *args, **kwargs):
            if self.instance_number == 1:
                return FakeResponse({
                    "summary": "A suspicious authentication pattern requires validation.",
                    "priority": "high", "confidence": "medium", "findings": [],
                    "cited_passages": [PASSAGE["citation_id"]], "recommendations": [], "missing_information": [],
                })
            return FakeResponse({"assessments": []})
    FakeAsyncClient.instance_count = 0
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setattr(engine, "retrieve_passages", lambda query, limit=5: [PASSAGE])
    monkeypatch.setattr(engine.httpx, "AsyncClient", lambda **kwargs: BrokenReviewerClient(payload={}, **kwargs))
    result = asyncio.run(engine.investigate_with_ai(event(), RULE_RESULT))
    assert result["engine"] == "rules_fallback"
    assert result["ai_status"] == "reviewer_failed"
