import json
from pathlib import Path
from app.main import assess_event

BASE = Path(__file__).resolve().parents[1]


def test_fixed_dataset_has_expected_schema_and_nonempty_cases():
    data = json.loads((BASE / "evaluation" / "security_alerts.json").read_text())
    assert data["version"]
    assert len(data["cases"]) >= 30
    assert all("expected_priority" in c and "event" in c for c in data["cases"])
    assert len({c["id"] for c in data["cases"]}) == len(data["cases"])


def test_claim_support_fixture_has_gold_labels_and_evidence_pairs():
    data = json.loads((BASE / "evaluation" / "claim_support_cases.json").read_text())
    assert data["version"]
    assert len(data["cases"]) >= 25
    assert {c["gold_verdict"] for c in data["cases"]} == {"supported", "contradicted", "insufficient"}
    assert all(c["claim"].strip() and c["passage"].strip() for c in data["cases"])


def test_assessment_has_explanation_and_missing_information_fields():
    data = json.loads((BASE / "evaluation" / "security_alerts.json").read_text())
    result = assess_event({**data["cases"][0]["event"], "metadata": {}})
    assert result["priority"] in {"critical", "high", "medium", "low"}
    assert result["summary"]
    assert isinstance(result["evidence"], list)
    assert isinstance(result["missing_information"], list)
