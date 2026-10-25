import asyncio
import json

from fastapi.testclient import TestClient
import pytest

import app.ai_engine as ai_engine
from app.ai_engine import parse_uploaded_content
import app.main as main


@pytest.mark.parametrize(
    ("filename", "content", "expected_citation"),
    [
        ("auth.log", "login failed\nlogin succeeded\n", "auth.log#L1"),
        ("events.jsonl", '{"event":"login"}\n{"event":"logout"}\n', "events.jsonl#L1"),
        ("events.csv", "event,user\nlogin,alice\nlogout,bob\n", "events.csv#L1-L2"),
        ("events.json", '[{"event":"login"},{"event":"logout"}]', "events.json#record-1"),
    ],
)
def test_uploaded_records_keep_source_citations(filename, content, expected_citation):
    file_format, records, total = parse_uploaded_content(filename, content)

    assert records[0]["citation_id"] == expected_citation
    assert total == 2
    assert file_format == filename.rsplit(".", 1)[1]


def test_uploaded_record_limit_is_reported():
    _, records, total = parse_uploaded_content("many.log", "\n".join(f"event {n}" for n in range(105)))

    assert total == 105
    assert len(records) == 100


def test_upload_parse_rejects_unsupported_and_invalid_files():
    with pytest.raises(ValueError, match="Unsupported file type"):
        parse_uploaded_content("payload.exe", "not a log")
    with pytest.raises(ValueError, match="Invalid JSONL on line 2"):
        parse_uploaded_content("events.jsonl", '{"event":"ok"}\nnot-json')


def test_uploaded_analysis_accepts_only_independently_supported_model_claims(monkeypatch):
    model_response = {
        "summary": "The log contains a failed login for the admin account.",
        "summary_citations": ["auth.log#L1"],
        "findings": [{
            "claim": "An admin login attempt failed.",
            "evidence_citations": ["auth.log#L1"],
        }],
    }

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"choices": [{"message": {"content": json.dumps(model_response)}}]}

    class FakeClient:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, *args, **kwargs):
            return FakeResponse()

    async def supported_review(claims, passages):
        assert passages[0]["citation_id"] == "auth.log#L1"
        return {
            "model": "reviewer-test",
            "assessments": [
                {"claim_id": claim["claim_id"], "verdict": "supported", "citation_ids": claim["evidence_citation_ids"], "rationale": "Directly present in the record."}
                for claim in claims
            ],
        }

    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setattr(ai_engine.httpx, "AsyncClient", FakeClient)
    monkeypatch.setattr(ai_engine, "review_claims_with_agent", supported_review)

    result = asyncio.run(ai_engine.analyze_uploaded_content("auth.log", "failed login for admin"))

    assert result["engine"] == "llm_grounded"
    assert result["ai_status"] == "ok"
    assert result["findings"][0]["evidence_citations"] == ["auth.log#L1"]
    assert result["evidence_review"]["review_completed"] is True


def test_upload_analysis_endpoint_enforces_role_and_returns_cited_fallback(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "uploads.db")
    monkeypatch.setenv("OPENAI_API_KEY", "")
    monkeypatch.setenv("DROPZONE_API_KEYS", json.dumps({
        "analyst-key": {"username": "analyst", "role": "analyst"},
        "viewer-key": {"username": "viewer", "role": "viewer"},
    }))
    payload = {
        "filename": "auth.log",
        "content": "failed login for admin\nsuccessful login for analyst",
    }
    with TestClient(main.app) as client:
        denied = client.post("/uploads/analyze", headers={"X-API-Key": "viewer-key"}, json=payload)
        assert denied.status_code == 403

        response = client.post("/uploads/analyze", headers={"X-API-Key": "analyst-key"}, json=payload)
        too_many_bytes = client.post("/uploads/analyze", headers={"X-API-Key": "analyst-key"}, json={
            "filename": "unicode.log",
            "content": "é" * 100_001,
        })

    assert response.status_code == 200
    result = response.json()
    assert result["ai_status"] == "not_configured"
    assert result["records_analyzed"] == 2
    assert result["findings"][0]["evidence_citations"] == ["auth.log#L1"]
    assert too_many_bytes.status_code == 413
