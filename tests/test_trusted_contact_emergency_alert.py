import pytest
import os
import time
import pymongo
from starlette.testclient import TestClient
from server import app

@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c

def _create_isolated_victim(client, name_suffix):
    ts = int(time.time() * 1000)
    email = f"victim_alert_{ts}_{name_suffix.lower().replace(' ', '_')}@example.com"
    reg = client.post("/api/auth/register", json={
        "email": email,
        "password": "Password123",
        "name": f"Victim {name_suffix}",
        "role": "victim"
    })
    assert reg.status_code == 200, f"Registration failed: {reg.text}"
    token = reg.json()["token"]
    user_id = reg.json()["user"]["id"]
    return user_id, token

def test_safety_plan_secret_code_encryption_at_rest(client):
    """Verify that secret_code and alert_message_template are encrypted with AES-256-GCM at rest."""
    sync_db = pymongo.MongoClient("mongodb://127.0.0.1:27017")["nivara"]
    _, token = _create_isolated_victim(client, "Encryption Test")

    secret_code = "SILVER_FOX_99"
    template = "URGENT DURESS: I am in danger, please contact authorities!"
    contacts = [
        {"name": "Alice Guardian", "phone": "+919876543210", "code_word": "RED_ROSE"}
    ]

    put_res = client.put(
        "/api/safety-plan",
        json={
            "secret_code": secret_code,
            "alert_message_template": template,
            "alert_include_location": True,
            "trusted_contacts": contacts,
            "emergency_notes": "Hidden safe behind bookcase"
        },
        headers={"Authorization": f"Bearer {token}"}
    )
    assert put_res.status_code == 200
    plan_data = put_res.json()
    plan_id = plan_data["_id"]

    # Verify MongoDB raw document contains enc:v1: ciphertext and NOT raw secret code
    raw = sync_db.safety_plans.find_one({"_id": plan_id})
    assert raw is not None
    assert "secret_code" in raw
    assert raw["secret_code"].startswith("enc:v1:")
    assert secret_code not in raw["secret_code"]

    assert "alert_message_template" in raw
    assert raw["alert_message_template"].startswith("enc:v1:")
    assert "DURESS" not in raw["alert_message_template"]

    # Verify GET transparently decrypts
    get_res = client.get("/api/safety-plan", headers={"Authorization": f"Bearer {token}"})
    assert get_res.status_code == 200
    body = get_res.json()
    assert body["secret_code"] == secret_code
    assert body["alert_message_template"] == template
    assert body["alert_include_location"] is True

def test_alert_authorization_and_role_protection(client):
    """Verify that only authenticated victims can trigger alerts, rejecting anon, officer, counsellor."""
    # 1. Anonymous -> 401
    anon_res = client.post("/api/safety-plan/alert", json={"secret_code": "ANY"})
    assert anon_res.status_code == 401

    # 2. Officer -> 403
    off_login = client.post("/api/auth/login", json={"email": "officer@nivara.app", "password": "Password123"})
    assert off_login.status_code == 200
    off_token = off_login.json()["token"]

    off_res = client.post(
        "/api/safety-plan/alert",
        headers={"Authorization": f"Bearer {off_token}"},
        json={"secret_code": "ANY"}
    )
    assert off_res.status_code == 403

    # 3. Counsellor -> 403
    coun_login = client.post("/api/auth/login", json={"email": "counsellor@nivara.app", "password": "Password123"})
    assert coun_login.status_code == 200
    coun_token = coun_login.json()["token"]

    coun_res = client.post(
        "/api/safety-plan/alert",
        headers={"Authorization": f"Bearer {coun_token}"},
        json={"secret_code": "ANY"}
    )
    assert coun_res.status_code == 403

def test_alert_requires_trusted_contacts(client):
    """Reject alert with 400 Bad Request if no trusted contacts are configured in the safety plan."""
    _, token = _create_isolated_victim(client, "No Contacts")

    # Set plan without trusted contacts
    client.put(
        "/api/safety-plan",
        json={"secret_code": "SAFE123", "trusted_contacts": []},
        headers={"Authorization": f"Bearer {token}"}
    )

    res = client.post(
        "/api/safety-plan/alert",
        headers={"Authorization": f"Bearer {token}"},
        json={"secret_code": "SAFE123"}
    )
    assert res.status_code == 400
    assert "No trusted contacts configured" in res.json()["detail"]

def test_alert_validates_secret_code(client):
    """Reject alert with 401 Unauthorized if secret code does not match plan code or contact safe-word."""
    _, token = _create_isolated_victim(client, "Code Auth")

    client.put(
        "/api/safety-plan",
        json={
            "secret_code": "CORRECT_CODE",
            "trusted_contacts": [{"name": "Bob", "phone": "+919999999999", "code_word": "FALLBACK_WORD"}]
        },
        headers={"Authorization": f"Bearer {token}"}
    )

    # Wrong code -> 401
    bad_res = client.post(
        "/api/safety-plan/alert",
        headers={"Authorization": f"Bearer {token}"},
        json={"secret_code": "WRONG_CODE"}
    )
    assert bad_res.status_code == 401
    assert "Invalid duress secret code" in bad_res.json()["detail"]

    # Fallback contact word is accepted if secret_code was not matched
    # Let's test with a plan where secret_code is empty but contact has code_word
    _, token2 = _create_isolated_victim(client, "Word Auth")
    client.put(
        "/api/safety-plan",
        json={
            "secret_code": "",
            "trusted_contacts": [{"name": "Charlie", "phone": "+918888888888", "code_word": "APPLE_TREE"}]
        },
        headers={"Authorization": f"Bearer {token2}"}
    )

    res_word = client.post(
        "/api/safety-plan/alert",
        headers={"Authorization": f"Bearer {token2}"},
        json={"secret_code": "apple_tree"}  # Case-insensitive match
    )
    # Should authenticate and proceed to provider check (status 200)
    assert res_word.status_code == 200

def test_alert_honest_reporting_when_provider_unavailable(client):
    """When EMERGENCY_ALERT_PROVIDER is not set, API returns ok: False, status: provider_unavailable."""
    sync_db = pymongo.MongoClient("mongodb://127.0.0.1:27017")["nivara"]
    _, token = _create_isolated_victim(client, "Honest Provider")

    # Ensure environment provider is unset
    old_val = os.environ.pop("EMERGENCY_ALERT_PROVIDER", None)

    try:
        client.put(
            "/api/safety-plan",
            json={
                "secret_code": "HONEST_TEST",
                "trusted_contacts": [{"name": "Mom", "phone": "+919123456780", "relationship": "Mother"}]
            },
            headers={"Authorization": f"Bearer {token}"}
        )

        res = client.post(
            "/api/safety-plan/alert",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "secret_code": "HONEST_TEST",
                "latitude": 12.9716,
                "longitude": 77.5946,
                "location_label": "Bengaluru MG Road"
            }
        )
        assert res.status_code == 200
        data = res.json()
        assert data["ok"] is False
        assert data["status"] == "provider_unavailable"
        assert "not configured" in data["message"] and "unavailable" in data["message"]
        assert len(data["contacts_to_reach"]) == 1
        assert data["contacts_to_reach"][0]["name"] == "Mom"
        assert data["contacts_to_reach"][0]["phone"] == "+919123456780"
        assert "112" in data["helpline_advice"]

        # Verify audit log was recorded
        audit = sync_db.audit_logs.find_one({"action": "trusted_contact_alert_provider_unavailable"})
        assert audit is not None
    finally:
        if old_val is not None:
            os.environ["EMERGENCY_ALERT_PROVIDER"] = old_val

def test_alert_dispatch_when_provider_configured(client):
    """When EMERGENCY_ALERT_PROVIDER is configured, API returns ok: True, status: dispatched and updates last_alert_sent_at."""
    sync_db = pymongo.MongoClient("mongodb://127.0.0.1:27017")["nivara"]
    _, token = _create_isolated_victim(client, "Configured Provider")

    old_val = os.environ.get("EMERGENCY_ALERT_PROVIDER")
    os.environ["EMERGENCY_ALERT_PROVIDER"] = "mock_provider"

    try:
        client.put(
            "/api/safety-plan",
            json={
                "secret_code": "DISPATCH_TEST",
                "trusted_contacts": [{"name": "Brother", "phone": "+919555555555"}]
            },
            headers={"Authorization": f"Bearer {token}"}
        )

        res = client.post(
            "/api/safety-plan/alert",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "secret_code": "DISPATCH_TEST",
                "latitude": 13.0827,
                "longitude": 80.2707,
                "location_label": "Chennai Central"
            }
        )
        assert res.status_code == 200
        data = res.json()
        assert data["ok"] is True
        assert data["status"] == "dispatched"
        assert data["recipients_count"] == 1
        assert "dispatched to 1 trusted contact" in data["message"]

        # Check safety plan was updated with last_alert_sent_at
        plan_res = client.get("/api/safety-plan", headers={"Authorization": f"Bearer {token}"})
        assert plan_res.status_code == 200
        assert plan_res.json().get("last_alert_sent_at") is not None

        # Verify audit log was recorded
        audit = sync_db.audit_logs.find_one({"action": "trusted_contact_alert_dispatched"})
        assert audit is not None
    finally:
        if old_val is not None:
            os.environ["EMERGENCY_ALERT_PROVIDER"] = old_val
        else:
            os.environ.pop("EMERGENCY_ALERT_PROVIDER", None)

def test_checklist_step_toggle_never_triggers_alert(client):
    """Verify that toggling checklist steps strictly updates step completion and NEVER sends an alert."""
    _, token = _create_isolated_victim(client, "Checklist Decoupled")

    put_res = client.put(
        "/api/safety-plan",
        json={
            "secret_code": "CHECK_SECRET",
            "trusted_contacts": [{"name": "Friend", "phone": "+919111122222"}],
            "last_alert_sent_at": None
        },
        headers={"Authorization": f"Bearer {token}"}
    )
    assert put_res.status_code == 200
    plan_id = put_res.json()["_id"]
    steps = put_res.json()["steps"]
    assert len(steps) > 0
    step_id = steps[0]["id"]
    initial_completed = steps[0]["completed"]

    # Toggle step via PATCH
    patch_res = client.patch(
        f"/api/safety-plan/{plan_id}/step/{step_id}",
        headers={"Authorization": f"Bearer {token}"},
        json={"completed": not initial_completed}
    )
    assert patch_res.status_code == 200
    patch_data = patch_res.json()
    assert patch_data["success"] is True
    assert patch_data["completed"] == (not initial_completed)

    # Retrieve full plan via GET to verify step state and guarantee alert was not triggered
    get_res = client.get("/api/safety-plan", headers={"Authorization": f"Bearer {token}"})
    assert get_res.status_code == 200
    updated_plan = get_res.json()
    matched_step = next(s for s in updated_plan["steps"] if s["id"] == step_id)
    assert matched_step["completed"] == (not initial_completed)

    # CRITICAL: last_alert_sent_at MUST remain None / unchanged
    assert updated_plan.get("last_alert_sent_at") is None
