import json

from fastapi.testclient import TestClient

import app.main as main


def test_support_requests_are_saved_without_email_delivery(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "support.db")
    monkeypatch.setenv("DROPZONE_API_KEYS", json.dumps({
        "viewer-key": {"username": "viewer", "role": "viewer"},
        "analyst-key": {"username": "analyst", "role": "analyst"},
        "admin-key": {"username": "admin", "role": "admin"},
    }))
    payload = {
        "email": "customer@example.com",
        "message": "Please help explain why this investigation found no evidence.",
        "context_type": "incident_no_evidence",
    }

    with TestClient(main.app) as client:
        response = client.post("/support/requests", headers={"X-API-Key": "viewer-key"}, json=payload)
        analyst_list = client.get("/support/requests", headers={"X-API-Key": "analyst-key"})
        admin_list = client.get("/support/requests", headers={"X-API-Key": "admin-key"})

    assert response.status_code == 201
    assert response.json()["support_email"] == "clintonjunior6@gmail.com"
    assert response.json()["message"] == "Request saved locally. Email delivery is not configured."
    assert analyst_list.status_code == 403
    assert admin_list.status_code == 200
    assert admin_list.json()["requests"][0]["email"] == payload["email"]
    assert admin_list.json()["requests"][0]["message"] == payload["message"]


def test_support_request_validates_email_and_investigation_reference(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "support-validation.db")
    monkeypatch.setenv("DROPZONE_API_KEYS", json.dumps({
        "analyst-key": {"username": "analyst", "role": "analyst"},
    }))
    with TestClient(main.app) as client:
        invalid_email = client.post("/support/requests", headers={"X-API-Key": "analyst-key"}, json={
            "email": "not-an-email",
            "message": "Please help with this investigation.",
            "context_type": "upload_no_findings",
        })
        missing_incident = client.post("/support/requests", headers={"X-API-Key": "analyst-key"}, json={
            "email": "customer@example.com",
            "message": "Please help with this investigation.",
            "context_type": "incident_no_findings",
            "investigation_id": "missing-investigation",
        })

    assert invalid_email.status_code == 422
    assert missing_incident.status_code == 404


def test_dashboard_contains_support_prompt_and_contact_email():
    dashboard = main.dashboard()

    assert "clintonjunior6@gmail.com" in dashboard
    assert "incident_no_findings" in dashboard
    assert "upload_no_findings" in dashboard
    assert "submitSupportRequest" in dashboard
