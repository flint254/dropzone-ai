import json
from fastapi.testclient import TestClient
import app.main as main


def test_role_based_permissions(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "rbac.db")
    monkeypatch.setenv("DROPZONE_API_KEYS", json.dumps({
        "admin-key": {"username": "root", "role": "admin"},
        "analyst-key": {"username": "alex", "role": "analyst"},
        "reviewer-key": {"username": "rhea", "role": "reviewer"},
        "viewer-key": {"username": "view", "role": "viewer"},
    }))
    with TestClient(main.app) as client:
        denied = client.post("/events", headers={"X-API-Key": "viewer-key"}, json={
            "source": "test", "event_type": "auth", "title": "Routine login notice",
            "description": "Routine login event", "severity": "low"
        })
        assert denied.status_code == 403
        created = client.post("/events", headers={"X-API-Key": "analyst-key"}, json={
            "source": "test", "event_type": "auth", "title": "Multiple failed login attempts",
            "description": "Possible password spray against privileged account", "severity": "high"
        })
        assert created.status_code == 201
        iid = created.json()["investigation_id"]
        incident_detail = client.get(f"/incidents/{iid}", headers={"X-API-Key": "analyst-key"})
        assert incident_detail.status_code == 200
        assert incident_detail.json()["workflow_trace"]
        assert incident_detail.json()["quality_status"] == "needs_review"
        viewer_decision = client.post(f"/incidents/{iid}/decisions", headers={"X-API-Key": "viewer-key"}, json={"decision": "approved", "reviewer": "ignored", "comment": "test"})
        assert viewer_decision.status_code == 403
        reviewer_decision = client.post(f"/incidents/{iid}/decisions", headers={"X-API-Key": "reviewer-key"}, json={"decision": "approved", "reviewer": "ignored", "comment": "Reviewed test evidence"})
        assert reviewer_decision.status_code == 201
        assert reviewer_decision.json()["reviewer"] == "rhea"
