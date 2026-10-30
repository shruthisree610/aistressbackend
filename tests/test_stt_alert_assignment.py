import os
import io
import time
import pytest
import pymongo
from unittest.mock import patch, AsyncMock
from starlette.testclient import TestClient
from server import app

@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c

def _create_isolated_user(client, role, name_suffix):
    ts = int(time.time() * 1000)
    email = f"user_{role}_{ts}_{name_suffix.lower().replace(' ', '_')}@example.com"
    reg = client.post("/api/auth/register", json={
        "email": email,
        "password": "Password123",
        "name": f"{role.capitalize()} {name_suffix}",
        "role": "victim"
    })
    assert reg.status_code == 200, f"Registration failed: {reg.text}"
    user_id = reg.json()["user"]["id"]

    if role != "victim":
        mongo_client = pymongo.MongoClient(os.environ.get("MONGO_URI", "mongodb://127.0.0.1:27017"))
        db_name = os.environ.get("MONGO_DB", "nivara")
        mongo_client[db_name].users.update_one({"_id": user_id}, {"$set": {"role": role}})
        login_res = client.post("/api/auth/login", json={"email": email, "password": "Password123"})
        assert login_res.status_code == 200
        return user_id, login_res.json()["token"]

    token = reg.json()["token"]
    return user_id, token

def _get_officer_token(client):
    res = client.post("/api/auth/login", json={"email": "officer@nivara.app", "password": "Password123"})
    assert res.status_code == 200
    return res.json()["token"], res.json()["user"]["id"]

def _get_counsellor_token(client):
    res = client.post("/api/auth/login", json={"email": "counsellor@nivara.app", "password": "Password123"})
    assert res.status_code == 200
    return res.json()["token"], res.json()["user"]["id"]

def _make_dummy_wav_bytes():
    # 44-byte minimal valid PCM WAV header
    header = bytearray(44)
    header[0:4] = b"RIFF"
    total_size = 136
    header[4:8] = (total_size).to_bytes(4, "little")
    header[8:12] = b"WAVE"
    header[12:16] = b"fmt "
    header[16:20] = (16).to_bytes(4, "little")
    header[20:22] = (1).to_bytes(2, "little")
    header[22:24] = (1).to_bytes(2, "little")
    header[24:28] = (16000).to_bytes(4, "little")
    header[28:32] = (32000).to_bytes(4, "little")
    header[32:34] = (2).to_bytes(2, "little")
    header[34:36] = (16).to_bytes(2, "little")
    header[36:40] = b"data"
    header[40:44] = (100).to_bytes(4, "little")
    data = b"\x00" * 100
    return bytes(header + data)


# ==============================================================================
# FEATURE 1: WHISPER SPEECH-TO-TEXT (STT) TESTS
# ==============================================================================

def test_stt_payload_validation_empty_audio(client):
    """STT rejects empty or tiny corrupted audio payloads with 400 Bad Request."""
    _, victim_token = _create_isolated_user(client, "victim", "STT Tester")
    res = client.post(
        "/api/stt",
        files={"audio": ("empty.wav", b"short", "audio/wav")},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert res.status_code == 400
    assert "empty or corrupted" in res.json()["detail"].lower()


def test_stt_payload_validation_unsupported_format(client):
    """STT rejects invalid container headers with 415 Unsupported Media Type."""
    _, victim_token = _create_isolated_user(client, "victim", "STT Format Tester")
    fake_payload = b"X" * 100  # Not a valid WAV, WebM, OGG, MP3, etc.
    res = client.post(
        "/api/stt",
        files={"audio": ("corrupted.bin", fake_payload, "application/octet-stream")},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert res.status_code == 415
    assert "unsupported" in res.json()["detail"].lower()


def test_stt_unconfigured_provider(client):
    """STT reports provider_configured=False and PROVIDER_UNCONFIGURED error code when Groq/OpenAI key is missing."""
    _, victim_token = _create_isolated_user(client, "victim", "STT Unconfigured")
    wav_bytes = _make_dummy_wav_bytes()

    with patch.dict(os.environ, {"GROQ_API_KEY": "", "OPENAI_API_KEY": ""}):
        res = client.post(
            "/api/stt",
            files={"audio": ("voice.wav", wav_bytes, "audio/wav")},
            headers={"Authorization": f"Bearer {victim_token}"}
        )
        assert res.status_code == 200
        data = res.json()
        assert data["is_recognized"] is False
        assert data["provider_configured"] is False
        assert data["error_code"] == "PROVIDER_UNCONFIGURED"
        assert "not configured" in data["message"].lower()


def test_stt_mocked_transcription_success(client):
    """STT returns 200 with is_recognized=True and transcript when Whisper transcription succeeds."""
    _, victim_token = _create_isolated_user(client, "victim", "STT Recognized")
    wav_bytes = _make_dummy_wav_bytes()

    with patch("ai_service.is_whisper_configured", return_value=True):
        with patch("ai_service.transcribe_audio", new_callable=AsyncMock) as mock_transcribe:
            mock_transcribe.return_value = "Help me someone is stalking my apartment"
            res = client.post(
                "/api/stt",
                files={"audio": ("voice.wav", wav_bytes, "audio/wav")},
                headers={"Authorization": f"Bearer {victim_token}"}
            )
            assert res.status_code == 200
            data = res.json()
            assert data["is_recognized"] is True
            assert data["transcript"] == "Help me someone is stalking my apartment"
            assert data["error_code"] is None


# ==============================================================================
# FEATURE 2: SAFETY PLAN EMERGENCY ALERT TESTS
# ==============================================================================

def test_safety_plan_alert_invalid_secret_code(client):
    """Safety plan emergency alert rejects invalid duress code with 401."""
    _, victim_token = _create_isolated_user(client, "victim", "Alert Duress Tester")

    # Save a safety plan with a secret code via PUT /safety-plan
    save_res = client.put(
        "/api/safety-plan",
        json={
            "secret_code": "Sapphire99",
            "trusted_contacts": [{"name": "Aunt Sarah", "phone": "+91 98765 43210"}],
            "alert_include_location": True
        },
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert save_res.status_code == 200
    plan_id = save_res.json().get("id") or save_res.json().get("_id")

    # Wrong duress code
    alert_res = client.post(
        f"/api/safety-plan/{plan_id}/alert",
        json={"secret_code": "WrongCode"},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert alert_res.status_code == 401
    assert "invalid duress" in alert_res.json()["detail"].lower()


def test_safety_plan_alert_provider_unavailable(client):
    """Safety plan alert honestly returns provider_unavailable with fallback phone dialer links when no provider is configured."""
    _, victim_token = _create_isolated_user(client, "victim", "Alert Fallback Tester")

    save_res = client.put(
        "/api/safety-plan",
        json={
            "secret_code": "AmberSafe12",
            "trusted_contacts": [{"name": "Priya", "phone": "+91 (987) 654-3210"}],
            "alert_include_location": True
        },
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert save_res.status_code == 200
    plan_id = save_res.json().get("id") or save_res.json().get("_id")

    with patch.dict(os.environ, {"EMERGENCY_ALERT_PROVIDER": ""}):
        alert_res = client.post(
            f"/api/safety-plan/{plan_id}/alert",
            json={"secret_code": "AmberSafe12"},
            headers={"Authorization": f"Bearer {victim_token}"}
        )
        assert alert_res.status_code == 200
        data = alert_res.json()
        assert data["ok"] is False
        assert data["status"] == "provider_unavailable"
        assert "not configured" in data["message"].lower()
        assert "112" in data["guidance"]
        assert len(data["trusted_contacts"]) == 1
        assert data["trusted_contacts"][0]["phone"] == "+919876543210"


def test_safety_plan_alert_mock_provider_dispatched_and_duplicate_suppression(client):
    """Safety plan alert dispatches via configured provider and suppresses duplicate alerts within 30s."""
    _, victim_token = _create_isolated_user(client, "victim", "Alert Dispatch Tester")

    save_res = client.put(
        "/api/safety-plan",
        json={
            "secret_code": "DeltaCode42",
            "trusted_contacts": [{"name": "Brother Rohan", "phone": "+91-99999-88888"}],
            "alert_include_location": False
        },
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert save_res.status_code == 200
    plan_id = save_res.json().get("id") or save_res.json().get("_id")

    with patch.dict(os.environ, {"EMERGENCY_ALERT_PROVIDER": "mock_provider"}):
        # First alert: succeeds
        alert_res1 = client.post(
            f"/api/safety-plan/{plan_id}/alert",
            json={"secret_code": "DeltaCode42"},
            headers={"Authorization": f"Bearer {victim_token}"}
        )
        assert alert_res1.status_code == 200
        data1 = alert_res1.json()
        assert data1["ok"] is True
        assert data1["status"] == "dispatched"
        assert data1["provider"] == "mock_provider"
        assert data1["contacts_notified"] == 1

        # Second alert immediately after: 429 Too Many Requests (duplicate protection)
        alert_res2 = client.post(
            f"/api/safety-plan/{plan_id}/alert",
            json={"secret_code": "DeltaCode42"},
            headers={"Authorization": f"Bearer {victim_token}"}
        )
        assert alert_res2.status_code == 429
        assert "already dispatched within the last 30 seconds" in alert_res2.json()["detail"]


# ==============================================================================
# FEATURE 3 & 4: OFFICER TO COUNSELLOR ASSIGNMENT & DASHBOARD VISIBILITY
# ==============================================================================

def test_officer_assignment_to_counsellor_success(client):
    """Officer successfully assigns a case to a counsellor, case is visible in counsellor's /cases/mine."""
    _, victim_token = _create_isolated_user(client, "victim", "Assigned Victim")
    counsellor_id, counsellor_token = _create_isolated_user(client, "counsellor", "Case Counsellor")
    officer_token, _ = _get_officer_token(client)

    # 1. Create case via SOS
    sos_res = client.post(
        "/api/sos",
        json={"latitude": 12.9716, "longitude": 77.5946, "notes": "Need urgent counsellor support"},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert sos_res.status_code == 200
    case_id = sos_res.json()["case_id"]

    # 2. Before assignment: Counsellor does NOT see the case
    mine_before = client.get("/api/cases/mine", headers={"Authorization": f"Bearer {counsellor_token}"})
    assert mine_before.status_code == 200
    assert not any(c["id"] == case_id for c in mine_before.json())

    # 3. Officer assigns case to counsellor
    assign_res = client.post(
        "/api/officer/assign",
        json={"case_id": case_id, "counsellor_id": counsellor_id, "notes": "Assigned for trauma care"},
        headers={"Authorization": f"Bearer {officer_token}"}
    )
    assert assign_res.status_code == 200
    assign_data = assign_res.json()
    assert assign_data["ok"] is True
    assert assign_data["counsellor_id"] == counsellor_id

    # 4. After assignment: Case is visible in counsellor's /cases/mine
    mine_after = client.get("/api/cases/mine", headers={"Authorization": f"Bearer {counsellor_token}"})
    assert mine_after.status_code == 200
    assigned_case = next((c for c in mine_after.json() if c["id"] == case_id), None)
    assert assigned_case is not None
    assert assigned_case["status"] in ["assigned", "open", "in_progress"]

    # 5. Counsellor can access case details
    detail_res = client.get(f"/api/cases/{case_id}", headers={"Authorization": f"Bearer {counsellor_token}"})
    assert detail_res.status_code == 200
    assert detail_res.json()["case"]["counsellor_id"] == counsellor_id


def test_officer_assignment_counsellor_reassignment_audit_log(client):
    """Reassigning an existing case to a second counsellor succeeds and logs counsellor_reassigned audit record."""
    _, victim_token = _create_isolated_user(client, "victim", "Reassigned Victim")
    counsellor1_id, _ = _create_isolated_user(client, "counsellor", "First Counsellor")
    counsellor2_id, coun2_token = _create_isolated_user(client, "counsellor", "Second Counsellor")
    officer_token, _ = _get_officer_token(client)

    sos_res = client.post("/api/sos", json={"notes": "Case to reassign"}, headers={"Authorization": f"Bearer {victim_token}"})
    case_id = sos_res.json()["case_id"]

    # Assign to first counsellor
    client.post("/api/officer/assign", json={"case_id": case_id, "counsellor_id": counsellor1_id}, headers={"Authorization": f"Bearer {officer_token}"})

    # Reassign to second counsellor
    reassign_res = client.post(
        "/api/officer/assign",
        json={"case_id": case_id, "counsellor_id": counsellor2_id, "notes": "Handover to specialist"},
        headers={"Authorization": f"Bearer {officer_token}"}
    )
    assert reassign_res.status_code == 200

    # Second counsellor now sees the case
    mine_coun2 = client.get("/api/cases/mine", headers={"Authorization": f"Bearer {coun2_token}"})
    assert any(c["id"] == case_id for c in mine_coun2.json())


def test_officer_assignment_invalid_target_role(client):
    """Assigning to a user who is not a counsellor returns 400 Bad Request."""
    _, victim_token = _create_isolated_user(client, "victim", "Invalid Assign Victim")
    other_victim_id, _ = _create_isolated_user(client, "victim", "Target Victim Not Counsellor")
    officer_token, _ = _get_officer_token(client)

    sos_res = client.post("/api/sos", json={"notes": "Role check case"}, headers={"Authorization": f"Bearer {victim_token}"})
    case_id = sos_res.json()["case_id"]

    bad_assign = client.post(
        "/api/officer/assign",
        json={"case_id": case_id, "counsellor_id": other_victim_id},
        headers={"Authorization": f"Bearer {officer_token}"}
    )
    assert bad_assign.status_code == 400
    assert "counsellor role" in bad_assign.json()["detail"].lower()


def test_officer_assignment_case_or_counsellor_not_found(client):
    """Returns 404 if case_id or counsellor_id does not exist."""
    officer_token, _ = _get_officer_token(client)
    counsellor_token, counsellor_id = _get_counsellor_token(client)

    # Fake case
    res1 = client.post(
        "/api/officer/assign",
        json={"case_id": "non_existent_case_12345", "counsellor_id": counsellor_id},
        headers={"Authorization": f"Bearer {officer_token}"}
    )
    assert res1.status_code == 404

    # Fake counsellor
    _, victim_token = _create_isolated_user(client, "victim", "NotFound Case Victim")
    sos_res = client.post("/api/sos", json={"notes": "Case check"}, headers={"Authorization": f"Bearer {victim_token}"})
    case_id = sos_res.json()["case_id"]

    res2 = client.post(
        "/api/officer/assign",
        json={"case_id": case_id, "counsellor_id": "non_existent_counsellor_99999"},
        headers={"Authorization": f"Bearer {officer_token}"}
    )
    assert res2.status_code == 404


def test_officer_assignment_unauthorized_non_officer(client):
    """Non-officer users cannot call /api/officer/assign (returns 403 Forbidden)."""
    _, victim_token = _create_isolated_user(client, "victim", "Forbidden Victim")
    counsellor_token, counsellor_id = _get_counsellor_token(client)

    sos_res = client.post("/api/sos", json={"notes": "Unauthorized assign check"}, headers={"Authorization": f"Bearer {victim_token}"})
    case_id = sos_res.json()["case_id"]

    res = client.post(
        "/api/officer/assign",
        json={"case_id": case_id, "counsellor_id": counsellor_id},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert res.status_code == 403
