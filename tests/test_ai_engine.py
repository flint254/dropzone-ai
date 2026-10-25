import asyncio
from app.ai_engine import investigate_with_ai, retrieve_passages


def test_retrieval_returns_exact_passage_line_citations():
    results = retrieve_passages("ransomware preserve endpoint evidence containment")
    assert results
    first = results[0]
    assert first["citation_id"].startswith("incident-response-basics.md#L")
    assert first["line_start"] <= first["line_end"]
    assert first["text"]


def test_retrieval_does_not_make_up_documents():
    results = retrieve_passages("completely unrelated lunar gardening subject")
    assert all(r["document_id"] == "incident-response-basics.md" for r in results)


def test_ai_engine_explicitly_falls_back_without_provider_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    rule_result = {"priority": "low", "evidence": [], "recommendations": [], "missing_information": [], "summary": "Rule summary"}
    result = asyncio.run(investigate_with_ai({"title": "test", "description": "test", "indicators": []}, rule_result))
    assert result["engine"] == "rules_fallback"
    assert result["ai_status"] == "not_configured"


def test_blank_model_env_uses_default(monkeypatch):
    monkeypatch.setenv("OPENAI_MODEL", "   ")
    monkeypatch.setenv("DROPZONE_REVIEWER_MODEL", "   ")
    assert "gpt-4.1-mini" == __import__("app.ai_engine", fromlist=["_env_value"])._env_value("OPENAI_MODEL", "DROPZONE_REVIEWER_MODEL", default="gpt-4.1-mini")
