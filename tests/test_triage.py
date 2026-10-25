from app.main import assess_event


def event(**overrides):
    base = {
        "source": "test-siem",
        "event_type": "endpoint_alert",
        "title": "Multiple failed login attempts",
        "description": "Possible password spray against a privileged account",
        "severity": "high",
        "asset": "server-01",
        "user": "admin",
        "indicators": ["203.0.113.15"],
        "occurred_at": "2026-10-23T12:00:00+00:00",
        "metadata": {},
    }
    base.update(overrides)
    return base


def test_password_spray_increases_priority():
    result = assess_event(event())
    assert result["priority"] in ("high", "critical")
    assert any("credential attack" in e.get("value", "").lower() for e in result["evidence"])


def test_missing_context_is_reported():
    result = assess_event(event(asset=None, user=None, indicators=[], occurred_at=None))
    assert len(result["missing_information"]) == 4


def test_recommendations_require_human_approval_for_disruptive_actions():
    result = assess_event(event(severity="critical", title="Possible ransomware", description="ransomware encryption of files detected"))
    assert any(r["requires_approval"] and r["status"] == "pending_review" for r in result["recommendations"])
