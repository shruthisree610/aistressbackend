import pytest
import io
import time
import os
from starlette.testclient import TestClient
from server import app

@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c

def _create_isolated_victim(client, name_suffix):
    ts = int(time.time() * 1000)
    email = f"victim_flawfix_{ts}_{name_suffix.lower().replace(' ', '_')}@example.com"
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

def _get_officer_token(client):
    res = client.post("/api/auth/login", json={"email": "officer@nivara.app", "password": "Password123"})
    assert res.status_code == 200
    return res.json()["token"], res.json()["user"]["id"]

def _get_counsellor_token(client):
    res = client.post("/api/auth/login", json={"email": "counsellor@nivara.app", "password": "Password123"})
    assert res.status_code == 200
    return res.json()["token"], res.json()["user"]["id"]


# ==============================================================================
# BUG 1 TESTS: Victim GPS Coordinates, Sources, and Accuracy Preservation
# ==============================================================================

def test_bug1_gps_coordinates_and_accuracy_preservation(client):
    """Bug 1: Victim GPS coordinates, accuracy in meters, and location source preservation."""
    _, victim_token = _create_isolated_victim(client, "GPS Accuracy Victim")
    officer_token, _ = _get_officer_token(client)

    # 1. Trigger SOS with GPS coordinates and accuracy
    sos_res = client.post(
        "/api/sos",
        json={
            "latitude": 12.9279,
            "longitude": 77.6271,
            "location_label": "Koramangala 5th Block",
            "accuracy": 18.5,
            "message": "Immediate help needed, someone following me"
        },
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert sos_res.status_code == 200
    case_id = sos_res.json()["case_id"]

    # 2. Officer inspects case details
    detail_res = client.get(f"/api/cases/{case_id}", headers={"Authorization": f"Bearer {officer_token}"})
    assert detail_res.status_code == 200
    case_data = detail_res.json()["case"]
    assert case_data["latitude"] == pytest.approx(12.9279)
    assert case_data["longitude"] == pytest.approx(77.6271)
    assert case_data["gps_accuracy"] == pytest.approx(18.5)
    assert case_data["location_label"] == "Koramangala 5th Block"

    # 3. Victim confirms a manual map pin
    confirm_res = client.post(
        f"/api/cases/{case_id}/confirm-location",
        json={
            "latitude": 12.9285,
            "longitude": 77.6280,
            "location_label": "Opposite Cafe Coffee Day",
            "notes": "Victim verified exact street corner"
        },
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert confirm_res.status_code == 200

    # 4. Officer verifies both live SOS GPS and victim-confirmed pin are preserved distinctly
    detail_res2 = client.get(f"/api/cases/{case_id}", headers={"Authorization": f"Bearer {officer_token}"})
    assert detail_res2.status_code == 200
    c2 = detail_res2.json()["case"]
    assert c2["latitude"] == pytest.approx(12.9279) # Original GPS intact
    assert c2["longitude"] == pytest.approx(77.6271)
    assert c2["manual_latitude"] == pytest.approx(12.9285) # Confirmed pin
    assert c2["manual_longitude"] == pytest.approx(77.6280)
    assert c2["manual_location_label"] == "Opposite Cafe Coffee Day"


# ==============================================================================
# BUG 2 TESTS: Evidence Media Preview, Download, Filename, and Authorization
# ==============================================================================

def test_bug2_evidence_preview_and_download_workflow(client):
    """Bug 2: Media upload, authorization check, preview, download, and integrity verification."""
    victim_id, victim_token = _create_isolated_victim(client, "Evidence Media Victim")
    officer_token, officer_id = _get_officer_token(client)

    # 1. Create case
    sos_res = client.post(
        "/api/sos",
        json={"latitude": 12.9716, "longitude": 77.5946, "message": "Emergency with evidence"},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert sos_res.status_code == 200
    case_id = sos_res.json()["case_id"]

    # 2. Victim uploads photo evidence with original filename
    file_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
    upload_res = client.post(
        "/api/evidence/upload-file",
        data={
            "case_id": case_id,
            "title": "Threatening Message Screenshot",
            "notes": "Screenshot showing threatening messages received on WhatsApp"
        },
        files={"file": ("threatening_whatsapp_evidence.png", io.BytesIO(file_bytes), "image/png")},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert upload_res.status_code == 200
    evidence_id = upload_res.json()["id"]
    assert upload_res.json()["sharing_status"] == "private"

    # 3. Officer attempts to access private unshared media -> 403 Forbidden
    media_forbidden = client.get(
        f"/api/evidence/media/{evidence_id}",
        headers={"Authorization": f"Bearer {officer_token}"}
    )
    assert media_forbidden.status_code == 403
    assert "private" in media_forbidden.json()["detail"].lower()

    # 4. Victim shares evidence with officer
    share_res = client.post(
        f"/api/evidence/{evidence_id}/share",
        json={"case_id": case_id, "notes": "Sharing screenshot with responding officer"},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert share_res.status_code == 200
    assert share_res.json()["sharing_status"] == "shared"

    # 5. Officer accesses preview (inline disposition)
    preview_res = client.get(
        f"/api/evidence/media/{evidence_id}",
        headers={"Authorization": f"Bearer {officer_token}"}
    )
    assert preview_res.status_code == 200
    assert preview_res.headers["content-type"] == "image/png"
    assert "inline" in preview_res.headers["content-disposition"]
    assert "threatening_whatsapp_evidence.png" in preview_res.headers["content-disposition"]
    assert preview_res.headers["X-Evidence-Integrity"] == "SHA256-Verified-Intact"
    assert preview_res.content == file_bytes

    # 6. Officer accesses route with duplicate /api alias (defense-in-depth)
    alias_res = client.get(
        f"/api/api/evidence/media/{evidence_id}",
        headers={"Authorization": f"Bearer {officer_token}"}
    )
    assert alias_res.status_code == 200
    assert alias_res.content == file_bytes

    # 7. Officer downloads evidence (?download=true, attachment disposition)
    download_res = client.get(
        f"/api/evidence/media/{evidence_id}?download=true",
        headers={"Authorization": f"Bearer {officer_token}"}
    )
    assert download_res.status_code == 200
    assert "attachment" in download_res.headers["content-disposition"]
    assert "threatening_whatsapp_evidence.png" in download_res.headers["content-disposition"]
    assert download_res.content == file_bytes

    # 8. Evidence lists include original_name and file_name
    case_detail_res = client.get(f"/api/cases/{case_id}", headers={"Authorization": f"Bearer {officer_token}"})
    assert case_detail_res.status_code == 200
    evidence_list = case_detail_res.json()["evidence"]
    assert len(evidence_list) >= 1
    target_ev = next(e for e in evidence_list if e["id"] == evidence_id)
    assert target_ev["original_name"] == "threatening_whatsapp_evidence.png"
    assert target_ev["integrity_verified"] is True

    # 9. Victim revokes evidence -> officer access becomes 403 Forbidden
    revoke_res = client.post(
        f"/api/evidence/{evidence_id}/revoke",
        json={"reason": "Revoking access"},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert revoke_res.status_code == 200
    assert revoke_res.json()["sharing_status"] == "revoked"

    revoked_access = client.get(
        f"/api/evidence/media/{evidence_id}",
        headers={"Authorization": f"Bearer {officer_token}"}
    )
    assert revoked_access.status_code == 403
    assert "revoked" in revoked_access.json()["detail"].lower()


# ==============================================================================
# BUG 3 TESTS: Counsellor Dropdown Restricted to Dr. Priya and shru
# ==============================================================================

def test_bug3_counsellor_dropdown_restriction_and_assignment(client):
    """Bug 3: Counsellors endpoint with approved filter returns strictly Dr. Priya and shru."""
    officer_token, _ = _get_officer_token(client)

    # 1. Query approved counsellors
    resp = client.get(
        "/api/users/counsellors?data_filter=approved",
        headers={"Authorization": f"Bearer {officer_token}"}
    )
    assert resp.status_code == 200
    counsellors = resp.json()
    assert len(counsellors) == 2, f"Expected exactly 2 approved counsellors, got {len(counsellors)}"

    emails = {c["email"].lower() for c in counsellors}
    names = {c["name"].lower() for c in counsellors}
    assert "counsellor@nivara.app" in emails
    assert "shruthi12345@gmail.com" in emails
    assert any("priya" in n for n in names)
    assert any("shru" in n for n in names)

    # None of the 53 test accounts should appear
    for c in counsellors:
        assert "example.com" not in c["email"].lower()

    # 2. Valid assignment to Dr. Priya succeeds
    dr_priya = next(c for c in counsellors if "priya" in c["name"].lower())
    _, victim_token = _create_isolated_victim(client, "Assignment Victim")
    sos = client.post("/api/sos", json={"message": "Need assignment test"}, headers={"Authorization": f"Bearer {victim_token}"})
    assert sos.status_code == 200
    case_id = sos.json()["case_id"]

    assign_res = client.post(
        "/api/officer/assign",
        json={"case_id": case_id, "counsellor_id": dr_priya["id"], "notes": "Assigned to Dr. Priya for guidance"},
        headers={"Authorization": f"Bearer {officer_token}"}
    )
    assert assign_res.status_code == 200
    assert assign_res.json()["ok"] is True


# ==============================================================================
# BUG 4 TESTS: AI Voice TTS API & Playback Integrity
# ==============================================================================

def test_bug4_tts_endpoint_availability(client):
    """Bug 4: Backend TTS responds cleanly for speech playback."""
    victim_id, victim_token = _create_isolated_victim(client, "Voice TTS Victim")

    tts_res = client.post(
        "/api/tts",
        json={"text": "Hello, Nivara is here to assist you safely.", "language": "en"},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert tts_res.status_code == 200
    assert len(tts_res.content) > 0
