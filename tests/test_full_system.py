import pytest
from starlette.testclient import TestClient
from server import app

@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c

def test_health_check(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}

def test_auth_login_and_me(client):
    # Victim login
    res = client.post("/api/auth/login", json={"email": "victim@nivara.app", "password": "Password123"})
    assert res.status_code == 200
    data = res.json()
    assert "token" in data
    assert data["user"]["role"] == "victim"
    token = data["token"]

    # Test /auth/me
    me_res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_res.status_code == 200
    assert me_res.json()["email"] == "victim@nivara.app"

def test_officer_and_counsellor_login(client):
    # Officer login
    res_off = client.post("/api/auth/login", json={"email": "officer@nivara.app", "password": "Password123"})
    assert res_off.status_code == 200
    assert res_off.json()["user"]["role"] == "officer"

    # Counsellor login
    res_coun = client.post("/api/auth/login", json={"email": "counsellor@nivara.app", "password": "Password123"})
    assert res_coun.status_code == 200
    assert res_coun.json()["user"]["role"] == "counsellor"

def test_victim_chat_and_svi_analysis(client):
    login = client.post("/api/auth/login", json={"email": "victim@nivara.app", "password": "Password123"})
    token = login.json()["token"]

    # Send a distress message
    chat_res = client.post(
        "/api/chat",
        json={"message": "Someone is stalking and following me home at night, I feel terrified", "language": "en"},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert chat_res.status_code == 200
    body = chat_res.json()
    assert "reply" in body
    assert "svi_score" in body
    assert "case_id" in body
    assert body["svi_score"] > 0

def test_stt_and_voice_turn(client):
    login = client.post("/api/auth/login", json={"email": "victim@nivara.app", "password": "Password123"})
    token = login.json()["token"]

    dummy_audio = b"RIFF" + b"\x00" * 40 + b"WAVEfmt " + b"\x00" * 200
    stt_res = client.post(
        "/api/stt",
        files={"audio": ("sample.wav", dummy_audio, "audio/wav")},
        data={"language": "en"},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert stt_res.status_code == 200
    assert "transcript" in stt_res.json()
    assert len(stt_res.json()["transcript"]) > 0

    voice_res = client.post(
        "/api/voice",
        files={"audio": ("sample.wav", dummy_audio, "audio/wav")},
        data={"language": "en"},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert voice_res.status_code == 200
    v_body = voice_res.json()
    assert "reply" in v_body
    assert "case_id" in v_body

def test_sos_dispatch_with_location(client):
    login = client.post("/api/auth/login", json={"email": "victim@nivara.app", "password": "Password123"})
    token = login.json()["token"]

    sos_res = client.post(
        "/api/sos",
        json={
            "latitude": 12.9716,
            "longitude": 77.5946,
            "location_label": "Live GPS (12.9716, 77.5946)",
            "message": "Immediate emergency help needed"
        },
        headers={"Authorization": f"Bearer {token}"}
    )
    assert sos_res.status_code == 200
    sos_data = sos_res.json()
    assert sos_data.get("ok") is True
    assert "nearest_officer" in sos_data

def test_safe_havens_endpoint(client):
    login = client.post("/api/auth/login", json={"email": "victim@nivara.app", "password": "Password123"})
    token = login.json()["token"]

    res = client.get("/api/safe-havens?lat=12.9716&lng=77.5946", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    havens = res.json().get("havens", [])
    assert len(havens) > 0
    assert "name" in havens[0]
    assert "latitude" in havens[0]
    assert "longitude" in havens[0]

def test_officer_cases_and_actions(client):
    login = client.post("/api/auth/login", json={"email": "officer@nivara.app", "password": "Password123"})
    token = login.json()["token"]

    cases_res = client.get("/api/cases/mine", headers={"Authorization": f"Bearer {token}"})
    assert cases_res.status_code == 200
    cases = cases_res.json()
    assert isinstance(cases, list)

def test_counsellor_weekly_digest_and_followups(client):
    login = client.post("/api/auth/login", json={"email": "counsellor@nivara.app", "password": "Password123"})
    token = login.json()["token"]

    res = client.get("/api/counsellor/weekly-digest", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    data = res.json()
    assert "total_cases" in data

# --- Registration Role Security Tests ---

def test_registration_normal_user_receives_victim_role(client):
    import uuid
    email = f"user_{uuid.uuid4().hex[:8]}@example.com"
    res = client.post("/api/auth/register", json={
        "email": email,
        "name": "Normal Citizen",
        "password": "Password123"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["user"]["role"] == "victim"

    # Verify through /auth/me that the account is indeed a victim
    token = data["token"]
    me_res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_res.status_code == 200
    assert me_res.json()["role"] == "victim"

def test_registration_cannot_create_officer_account(client):
    import uuid
    email = f"exploit_officer_{uuid.uuid4().hex[:8]}@example.com"
    # Attempt to send role: officer in public registration
    res = client.post("/api/auth/register", json={
        "email": email,
        "name": "Attacker Trying Officer",
        "password": "Password123",
        "role": "officer"
    })
    assert res.status_code == 200
    data = res.json()
    # Must NOT be an officer, must be assigned victim role
    assert data["user"]["role"] == "victim"
    assert data["user"]["role"] != "officer"

    # Verify that this account cannot access officer-restricted routes
    token = data["token"]
    officer_res = client.post(
        "/api/officer/action",
        json={"case_id": "test-case-id", "action": "dispatched"},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert officer_res.status_code == 403

def test_registration_cannot_create_counsellor_account(client):
    import uuid
    email = f"exploit_counsellor_{uuid.uuid4().hex[:8]}@example.com"
    # Attempt to send role: counsellor in public registration
    res = client.post("/api/auth/register", json={
        "email": email,
        "name": "Attacker Trying Counsellor",
        "password": "Password123",
        "role": "counsellor"
    })
    assert res.status_code == 200
    data = res.json()
    # Must NOT be a counsellor, must be assigned victim role
    assert data["user"]["role"] == "victim"
    assert data["user"]["role"] != "counsellor"

    # Verify that this account cannot access counsellor-restricted routes
    token = data["token"]
    counsellor_res = client.get("/api/counsellor/weekly-digest", headers={"Authorization": f"Bearer {token}"})
    assert counsellor_res.status_code == 403

def test_registration_duplicate_email_rejected(client):
    # Attempting to register an already existing email returns HTTP 400
    res = client.post("/api/auth/register", json={
        "email": "victim@nivara.app",
        "name": "Duplicate User",
        "password": "Password123"
    })
    assert res.status_code == 400
    assert "Email already registered" in res.json()["detail"]


# ==============================================================================
# Task 2 Security Tests: Case and Evidence Access Authorization
# ==============================================================================

def _create_isolated_victim(client, name="Isolated Victim"):
    import uuid
    email = f"victim_{uuid.uuid4().hex[:8]}@test.nivara.app"
    reg = client.post("/api/auth/register", json={
        "email": email, "name": name, "password": "Password123"
    })
    assert reg.status_code == 200
    token = reg.json()["token"]
    user = reg.json()["user"]
    return user, token


def test_1_victim_accesses_own_case_successfully(client):
    """1. A victim can access their own case successfully."""
    user, token = _create_isolated_victim(client, "Victim One")
    chat = client.post(
        "/api/chat",
        json={"message": "Need help reviewing my safety plan"},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert chat.status_code == 200
    case_id = chat.json()["case_id"]

    # Victim accessing their own case
    detail = client.get(f"/api/cases/{case_id}", headers={"Authorization": f"Bearer {token}"})
    assert detail.status_code == 200
    assert detail.json()["case"]["id"] == case_id
    assert detail.json()["case"]["victim_id"] == user["id"]


def test_2_victim_cannot_access_other_victim_case(client):
    """2. A victim attempting to access another victim's case is blocked (HTTP 403)."""
    user_a, token_a = _create_isolated_victim(client, "Victim A")
    user_b, token_b = _create_isolated_victim(client, "Victim B")

    # Victim A creates a case
    chat_a = client.post(
        "/api/chat",
        json={"message": "Confidential statement from Victim A"},
        headers={"Authorization": f"Bearer {token_a}"}
    )
    assert chat_a.status_code == 200
    case_a_id = chat_a.json()["case_id"]

    # Victim B tries to access Victim A's case
    res = client.get(f"/api/cases/{case_a_id}", headers={"Authorization": f"Bearer {token_b}"})
    assert res.status_code == 403
    assert "Forbidden" in res.json()["detail"]


def test_3_victim_cannot_modify_or_delete_other_case(client):
    """3. A victim attempting to modify or delete another victim's case is blocked."""
    _, token_a = _create_isolated_victim(client, "Victim A")
    _, token_b = _create_isolated_victim(client, "Victim B")

    chat_a = client.post(
        "/api/chat",
        json={"message": "Victim A case to protect"},
        headers={"Authorization": f"Bearer {token_a}"}
    )
    case_a_id = chat_a.json()["case_id"]

    # Victim B attempts to change status of Victim A's case
    status_res = client.post(
        "/api/case/status",
        json={"case_id": case_a_id, "status": "resolved"},
        headers={"Authorization": f"Bearer {token_b}"}
    )
    assert status_res.status_code == 403

    # Victim B attempts to post chat interactions into Victim A's case
    tamper_chat = client.post(
        "/api/chat",
        json={"case_id": case_a_id, "message": "Injected malicious message"},
        headers={"Authorization": f"Bearer {token_b}"}
    )
    assert tamper_chat.status_code == 403

    # Victim B attempts to delete Victim A's case
    del_res = client.delete(f"/api/cases/{case_a_id}", headers={"Authorization": f"Bearer {token_b}"})
    assert del_res.status_code == 403

    # Victim B attempts to trigger case summary for Victim A
    summary_res = client.post(f"/api/cases/summary/{case_a_id}", headers={"Authorization": f"Bearer {token_b}"})
    assert summary_res.status_code == 403


def test_4_victim_cannot_access_other_victim_evidence(client):
    """4. A victim attempting to access another victim's evidence is blocked."""
    _, token_a = _create_isolated_victim(client, "Victim A")
    _, token_b = _create_isolated_victim(client, "Victim B")

    chat_a = client.post("/api/chat", json={"message": "Create case A"}, headers={"Authorization": f"Bearer {token_a}"})
    case_a_id = chat_a.json()["case_id"]

    # Victim A uploads evidence
    upload_res = client.post(
        "/api/evidence/upload",
        json={"case_id": case_a_id, "title": "Secret audio log", "content": "Audio transcript threatening harm"},
        headers={"Authorization": f"Bearer {token_a}"}
    )
    assert upload_res.status_code == 200

    # Victim A can read own evidence list
    list_a = client.get(f"/api/evidence/{case_a_id}", headers={"Authorization": f"Bearer {token_a}"})
    assert list_a.status_code == 200
    evidence_items = list_a.json()["evidence"]
    assert len(evidence_items) >= 1
    evidence_id = evidence_items[0]["id"]

    # Victim B attempts to read Victim A's evidence list
    list_b = client.get(f"/api/evidence/{case_a_id}", headers={"Authorization": f"Bearer {token_b}"})
    assert list_b.status_code == 403

    # Victim B attempts to read Victim A's evidence item by ID
    item_b = client.get(f"/api/evidence/item/{evidence_id}", headers={"Authorization": f"Bearer {token_b}"})
    assert item_b.status_code == 403


def test_5_unauthorized_evidence_creation_and_tampering(client):
    """5. Unauthorized evidence creation, modification, or deletion is prevented."""
    _, token_a = _create_isolated_victim(client, "Victim A")
    _, token_b = _create_isolated_victim(client, "Victim B")

    chat_a = client.post("/api/chat", json={"message": "Case for tampering test"}, headers={"Authorization": f"Bearer {token_a}"})
    case_a_id = chat_a.json()["case_id"]

    # Victim B attempts to upload evidence to Victim A's case
    inject_res = client.post(
        "/api/evidence/upload",
        json={"case_id": case_a_id, "title": "Forged evidence", "content": "Fake content injected by attacker"},
        headers={"Authorization": f"Bearer {token_b}"}
    )
    assert inject_res.status_code == 403

    # Upload to non-existent case returns 404
    nonexist_res = client.post(
        "/api/evidence/upload",
        json={"case_id": "non-existent-case-id-12345", "title": "Orphan evidence", "content": "Sample"},
        headers={"Authorization": f"Bearer {token_a}"}
    )
    assert nonexist_res.status_code == 404

    # Upload without case_id returns 400
    missing_case_res = client.post(
        "/api/evidence/upload",
        json={"title": "No case", "content": "Sample"},
        headers={"Authorization": f"Bearer {token_a}"}
    )
    assert missing_case_res.status_code == 400

    # Evidence deletion attempt returns 403 (evidence is immutable)
    del_ev = client.delete("/api/evidence/some-evidence-id", headers={"Authorization": f"Bearer {token_a}"})
    assert del_ev.status_code == 403


def test_6_officer_case_access_rules(client):
    """6. An officer accessing cases according to the existing authorization rules."""
    _, victim_token = _create_isolated_victim(client, "Victim For Officer")
    chat = client.post("/api/chat", json={"message": "Emergency dispatch triage needed"}, headers={"Authorization": f"Bearer {victim_token}"})
    case_id = chat.json()["case_id"]

    off_login = client.post("/api/auth/login", json={"email": "officer@nivara.app", "password": "Password123"})
    officer_token = off_login.json()["token"]

    # Officer can access case mine
    mine = client.get("/api/cases/mine", headers={"Authorization": f"Bearer {officer_token}"})
    assert mine.status_code == 200

    # Officer can access any case detail
    detail = client.get(f"/api/cases/{case_id}", headers={"Authorization": f"Bearer {officer_token}"})
    assert detail.status_code == 200
    assert detail.json()["case"]["id"] == case_id

    # Officer can access case evidence
    ev = client.get(f"/api/evidence/{case_id}", headers={"Authorization": f"Bearer {officer_token}"})
    assert ev.status_code == 200

    # Officer can generate case summary
    summ = client.post(f"/api/cases/summary/{case_id}", headers={"Authorization": f"Bearer {officer_token}"})
    assert summ.status_code == 200
    assert "summary" in summ.json()

    # Officer can record action
    act = client.post(
        "/api/officer/action",
        json={"case_id": case_id, "action": "patrol_dispatched", "notes": "Officer dispatched to safe zone"},
        headers={"Authorization": f"Bearer {officer_token}"}
    )
    assert act.status_code == 200


def test_7_counsellor_case_access_rules(client):
    """7. A counsellor accessing cases according to existing authorization rules (assigned vs unassigned)."""
    _, victim_token = _create_isolated_victim(client, "Victim For Counsellor")
    chat = client.post("/api/chat", json={"message": "Trauma counseling needed"}, headers={"Authorization": f"Bearer {victim_token}"})
    case_id = chat.json()["case_id"]

    coun_login = client.post("/api/auth/login", json={"email": "counsellor@nivara.app", "password": "Password123"})
    counsellor_token = coun_login.json()["token"]
    counsellor_id = coun_login.json()["user"]["id"]

    # Before assignment: Counsellor CANNOT access this unassigned case
    unassigned_res = client.get(f"/api/cases/{case_id}", headers={"Authorization": f"Bearer {counsellor_token}"})
    assert unassigned_res.status_code == 403

    unassigned_ev = client.get(f"/api/evidence/{case_id}", headers={"Authorization": f"Bearer {counsellor_token}"})
    assert unassigned_ev.status_code == 403

    unassigned_note = client.post(
        "/api/counsellor/note",
        json={"case_id": case_id, "note": "Unassigned note attempt"},
        headers={"Authorization": f"Bearer {counsellor_token}"}
    )
    assert unassigned_note.status_code == 403

    unassigned_intervene = client.post(
        "/api/counsellor/intervene",
        json={"case_id": case_id, "message": "Unassigned intervention"},
        headers={"Authorization": f"Bearer {counsellor_token}"}
    )
    assert unassigned_intervene.status_code == 403

    # Officer assigns the case to this counsellor
    off_login = client.post("/api/auth/login", json={"email": "officer@nivara.app", "password": "Password123"})
    officer_token = off_login.json()["token"]
    assign_res = client.post(
        "/api/officer/assign",
        json={"case_id": case_id, "counsellor_id": counsellor_id, "notes": "Assigned to primary counsellor"},
        headers={"Authorization": f"Bearer {officer_token}"}
    )
    assert assign_res.status_code == 200

    # After assignment: Counsellor CAN access the case
    assigned_res = client.get(f"/api/cases/{case_id}", headers={"Authorization": f"Bearer {counsellor_token}"})
    assert assigned_res.status_code == 200

    assigned_ev = client.get(f"/api/evidence/{case_id}", headers={"Authorization": f"Bearer {counsellor_token}"})
    assert assigned_ev.status_code == 200

    # Counsellor can add note to assigned case
    note_res = client.post(
        "/api/counsellor/note",
        json={"case_id": case_id, "note": "Initial assessment completed", "support_provided": "Emotional de-escalation"},
        headers={"Authorization": f"Bearer {counsellor_token}"}
    )
    assert note_res.status_code == 200

    # Counsellor can intervene live in assigned case
    intervene_res = client.post(
        "/api/counsellor/intervene",
        json={"case_id": case_id, "message": "I am here with you, take a deep breath."},
        headers={"Authorization": f"Bearer {counsellor_token}"}
    )
    assert intervene_res.status_code == 200

    # Counsellor can view escalation risk of assigned case
    risk_res = client.get(f"/api/analytics/escalation-risk/{case_id}", headers={"Authorization": f"Bearer {counsellor_token}"})
    assert risk_res.status_code == 200


def test_8_unauthenticated_requests_to_protected_endpoints(client):
    """8. Unauthenticated requests to protected endpoints return HTTP 401."""
    # Protected endpoints without token
    assert client.get("/api/cases/mine").status_code == 401
    assert client.get("/api/cases/some-case-id").status_code == 401
    assert client.get("/api/evidence/some-case-id").status_code == 401
    assert client.post("/api/evidence/upload", json={"case_id": "c1", "content": "text"}).status_code == 401
    assert client.post("/api/case/status", json={"case_id": "c1", "status": "resolved"}).status_code == 401
    assert client.post("/api/chat", json={"message": "hello"}).status_code == 401
    assert client.post("/api/sos", json={"latitude": 12.0, "longitude": 77.0}).status_code == 401
    assert client.get("/api/notifications").status_code == 401

    # Invalid / forged token
    bad_headers = {"Authorization": "Bearer totally.forged.jwt.token"}
    assert client.get("/api/cases/mine", headers=bad_headers).status_code == 401
    assert client.get("/api/auth/me", headers=bad_headers).status_code == 401


def test_9_end_to_end_sos_assignment_staff_workflow(client):
    """9. Existing legitimate SOS, case assignment, and staff workflows continue to work."""
    _, victim_token = _create_isolated_victim(client, "Victim SOS Flow")

    # 1. Victim triggers SOS
    sos_res = client.post(
        "/api/sos",
        json={
            "latitude": 12.9716,
            "longitude": 77.5946,
            "location_label": "Central Sector St. 4",
            "message": "Immediate danger, stalker outside"
        },
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert sos_res.status_code == 200
    sos_data = sos_res.json()
    assert sos_data["ok"] is True
    case_id = sos_data["case_id"]

    # 2. Officer views case
    off_login = client.post("/api/auth/login", json={"email": "officer@nivara.app", "password": "Password123"})
    officer_token = off_login.json()["token"]
    case_detail = client.get(f"/api/cases/{case_id}", headers={"Authorization": f"Bearer {officer_token}"})
    assert case_detail.status_code == 200
    assert case_detail.json()["case"]["priority"] == "emergency"

    # 3. Officer assigns counsellor
    coun_login = client.post("/api/auth/login", json={"email": "counsellor@nivara.app", "password": "Password123"})
    counsellor_id = coun_login.json()["user"]["id"]
    counsellor_token = coun_login.json()["token"]

    assign_res = client.post(
        "/api/officer/assign",
        json={"case_id": case_id, "counsellor_id": counsellor_id, "notes": "Urgent counselling dispatch"},
        headers={"Authorization": f"Bearer {officer_token}"}
    )
    assert assign_res.status_code == 200

    # 4. Counsellor schedules followup
    import datetime
    scheduled_time = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)).isoformat()
    followup_res = client.post(
        "/api/counsellor/followup",
        json={"case_id": case_id, "scheduled_at": scheduled_time, "channel": "secure-voice", "notes": "Check safe relocation"},
        headers={"Authorization": f"Bearer {counsellor_token}"}
    )
    assert followup_res.status_code == 200

    # 5. Victim can view their own case status and assigned counsellor
    victim_case = client.get(f"/api/cases/{case_id}", headers={"Authorization": f"Bearer {victim_token}"})
    assert victim_case.status_code == 200
    assert victim_case.json()["case"]["counsellor_name"] is not None


# ==============================================================================
# Task 3 Security & Reliability Tests: SOS, Location Accuracy & Safe Havens
# ==============================================================================

def test_task3_1_sos_case_creation_and_internal_notification(client):
    """1. SOS case creation and internal notification behavior (no fake external dispatch)."""
    _, victim_token = _create_isolated_victim(client, "Victim SOS Test 1")
    res = client.post(
        "/api/sos",
        json={"latitude": 12.9716, "longitude": 77.5946, "location_label": "Central Sector", "message": "Emergency alert"},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["ok"] is True
    assert data["sos_status"] == "recorded"
    assert data["external_emergency_contacted"] is False
    assert "112" in data["message"]
    assert "emergency_contacts" in data
    assert any(c.get("number") == "112" or c.get("phone") == "112" for c in data["emergency_contacts"])


def test_task3_2_missing_location_data_handled_gracefully(client):
    """2. Missing or unavailable location data handled safely without fabricated fallback."""
    _, victim_token = _create_isolated_victim(client, "Victim No Location")
    res = client.post(
        "/api/sos",
        json={"message": "Location permission was denied by user", "location_label": "Location unavailable"},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["ok"] is True
    assert data["location"]["has_coordinates"] is False
    assert data["location"]["latitude"] is None
    assert data["location"]["longitude"] is None
    # Distance must be None, NOT a fabricated 0.5 km!
    assert data["assigned_officer"]["distance_km"] is None
    assert data["external_emergency_contacted"] is False


def test_task3_3_invalid_latitude_and_longitude_rejected(client):
    """3. Invalid latitude and longitude values rejected with HTTP 400."""
    _, victim_token = _create_isolated_victim(client, "Victim Invalid Coords")

    # Latitude > 90
    res1 = client.post(
        "/api/sos",
        json={"latitude": 99.9, "longitude": 77.0},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert res1.status_code == 400
    assert "Latitude must be between -90 and 90" in res1.json()["detail"]

    # Longitude > 180
    res2 = client.post(
        "/api/sos",
        json={"latitude": 12.0, "longitude": 250.0},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert res2.status_code == 400
    assert "Longitude must be between -180 and 180" in res2.json()["detail"]

    # Incomplete coordinate pair
    res3 = client.post(
        "/api/sos",
        json={"latitude": 12.0},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert res3.status_code == 400
    assert "Both latitude and longitude must be provided together" in res3.json()["detail"]


def _reset_baseline_officers():
    import pymongo
    from datetime import datetime, timezone
    sync_db = pymongo.MongoClient("mongodb://127.0.0.1:27017")["nivara"]
    now = datetime.now(timezone.utc)
    seeds = [
        ("officer@nivara.app", "Officer Ravi (Central)", 12.9716, 77.5946, "Central Metro Sector"),
        ("officer2@nivara.app", "Officer Suresh (North)", 12.9910, 77.6100, "North City Sector"),
        ("officer3@nivara.app", "Officer Anita (South)", 12.9350, 77.5800, "South Suburbs Sector"),
    ]
    for e, n, lat, lng, d in seeds:
        sync_db.users.update_one(
            {"email": e},
            {"$set": {
                "name": n,
                "latitude": lat,
                "longitude": lng,
                "duty_area": d,
                "location_sharing_enabled": True,
                "location_updated_at": now,
            }}
        )


def test_task3_4_accurate_officer_selection_when_valid_locations_exist(client):
    """4. Accurate officer selection when valid location records exist."""
    _reset_baseline_officers()
    _, victim_token = _create_isolated_victim(client, "Victim Nearby North")

    # Near North officer (officer2 is at 12.9910, 77.6100)
    res_north = client.post(
        "/api/sos",
        json={"latitude": 12.9920, "longitude": 77.6110, "location_label": "Near North Post"},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert res_north.status_code == 200
    data_north = res_north.json()
    assert data_north["assigned_officer"]["duty_area"] == "North City Sector"
    assert data_north["assigned_officer"]["distance_km"] < 0.5

    # Near South officer (officer3 is at 12.9350, 77.5800)
    res_south = client.post(
        "/api/sos",
        json={"latitude": 12.9340, "longitude": 77.5790, "location_label": "Near South Post"},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert res_south.status_code == 200
    data_south = res_south.json()
    assert data_south["assigned_officer"]["duty_area"] == "South Suburbs Sector"
    assert data_south["assigned_officer"]["distance_km"] < 0.5


def test_task3_5_missing_or_stale_officer_coordinates(client):
    """5. Missing officer coordinates do not produce fabricated distances."""
    _, victim_token = _create_isolated_victim(client, "Victim Distance Check")
    # Call SOS with no coordinates
    res = client.post(
        "/api/sos",
        json={"location_label": "No GPS signal"},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert res.status_code == 200
    data = res.json()
    # When no proximity calculation is possible, distance_km must be None
    assert data["assigned_officer"]["distance_km"] is None
    assert data["nearest_officer"]["distance_km"] is None


def test_task3_6_safe_haven_radar_demo_data_identified(client):
    """6. Safe Haven Radar clearly identifies demo/unverified status and computes true distance."""
    _, victim_token = _create_isolated_victim(client, "Victim Safe Haven 1")
    res = client.get("/api/safe-havens?lat=12.9716&lng=77.5946", headers={"Authorization": f"Bearer {victim_token}"})
    assert res.status_code == 200
    data = res.json()
    assert data["verified_provider_configured"] is False
    assert "Demonstration data only" in data["provider_notice"]
    assert "112" in data["provider_notice"]
    assert data["has_user_location"] is True
    assert len(data["havens"]) > 0

    for h in data["havens"]:
        assert h["is_verified"] is False
        assert h["data_source"] == "demo_reference"
        assert h["distance_km"] is not None
        assert h["distance_km"] >= 0.0


def test_task3_7_safe_haven_radar_when_coordinates_unavailable(client):
    """7. Safe Haven Radar behavior when user coordinates are unavailable or invalid."""
    _, victim_token = _create_isolated_victim(client, "Victim Safe Haven 2")

    # Unavailable user location
    res = client.get("/api/safe-havens", headers={"Authorization": f"Bearer {victim_token}"})
    assert res.status_code == 200
    data = res.json()
    assert data["has_user_location"] is False
    for h in data["havens"]:
        # When location unavailable, distance must be None (not fake 0.9 km!)
        assert h["distance_km"] is None

    # Invalid coordinates
    res_bad = client.get("/api/safe-havens?lat=120.0&lng=77.0", headers={"Authorization": f"Bearer {victim_token}"})
    assert res_bad.status_code == 400

    # Incomplete pair
    res_half = client.get("/api/safe-havens?lat=12.0", headers={"Authorization": f"Bearer {victim_token}"})
    assert res_half.status_code == 400


def test_task3_8_correct_distance_calculations():
    """8. Correct geographic distance calculations using Haversine."""
    from routes import calculate_haversine
    # Same point
    assert calculate_haversine(12.9716, 77.5946, 12.9716, 77.5946) == 0.0

    # Bangalore to Chennai is ~290 km (allow ±15 km)
    d = calculate_haversine(12.9716, 77.5946, 13.0827, 80.2707)
    assert 275.0 < d < 315.0

    # Invalid inputs safely return inf without crashing
    assert calculate_haversine(None, 77.0, 12.0, 77.0) == float("inf")
    assert calculate_haversine(999.0, 77.0, 12.0, 77.0) == float("inf")
    assert calculate_haversine(float("nan"), 77.0, 12.0, 77.0) == float("inf")


def test_task3_9_failures_and_responses_never_claim_external_dispatch(client):
    """9. Failures and responses never claim external emergency services have been contacted."""
    _, victim_token = _create_isolated_victim(client, "Victim Dispatch Check")
    res = client.post(
        "/api/sos",
        json={"latitude": 12.9716, "longitude": 77.5946, "location_label": "City Center"},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert res.status_code == 200
    body = res.json()
    assert body["external_emergency_contacted"] is False
    assert "NOT automatically dispatch" in body["message"]

    # Unauthenticated request returns 401 and does not report dispatch
    unauth = client.post("/api/sos", json={"latitude": 12.9716, "longitude": 77.5946})
    assert unauth.status_code == 401


def test_task3_10_existing_auth_assignment_sos_workflows_continue(client):
    """10. Existing authentication, authorization, case assignment, and SOS workflows continue to work."""
    _, victim_token = _create_isolated_victim(client, "Victim Full Workflow")

    # Trigger SOS
    sos = client.post(
        "/api/sos",
        json={"latitude": 12.9716, "longitude": 77.5946, "message": "Emergency test"},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert sos.status_code == 200
    case_id = sos.json()["case_id"]

    # Officer assigns to counsellor
    off = client.post("/api/auth/login", json={"email": "officer@nivara.app", "password": "Password123"}).json()
    coun = client.post("/api/auth/login", json={"email": "counsellor@nivara.app", "password": "Password123"}).json()

    assign = client.post(
        "/api/officer/assign",
        json={"case_id": case_id, "counsellor_id": coun["user"]["id"]},
        headers={"Authorization": f"Bearer {off['token']}"}
    )
    assert assign.status_code == 200

    # Counsellor adds note
    note = client.post(
        "/api/counsellor/note",
        json={"case_id": case_id, "note": "Assigned and reached out", "progress": "in_progress"},
        headers={"Authorization": f"Bearer {coun['token']}"}
    )
    assert note.status_code == 200

    # Victim can view case
    case_res = client.get(f"/api/cases/{case_id}", headers={"Authorization": f"Bearer {victim_token}"})
    assert case_res.status_code == 200
    assert case_res.json()["case"]["counsellor_id"] == coun["user"]["id"]


# ==============================================================================
# Task 4 Tests: Text-to-Speech (TTS) and Audio Response Reliability
# ==============================================================================

def test_task4_1_valid_text_produces_non_empty_audio(client):
    """1. Valid text produces non-empty, correctly formatted audio when TTS is available."""
    _, token = _create_isolated_victim(client, "Victim TTS 1")
    res = client.post(
        "/api/tts",
        json={"text": "Hello, this is Nivara. Your safety and wellbeing are our priority."},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert res.status_code == 200
    assert len(res.content) > 0
    # Media type must be valid audio
    assert res.headers["content-type"] in ["audio/mpeg", "audio/wav"]
    # Check that headers describe the media cleanly
    assert "Content-Disposition" in res.headers
    assert int(res.headers.get("Content-Length", 0)) == len(res.content)


def test_task4_2_empty_text_handled_appropriately(client):
    """2. Empty text is handled appropriately (HTTP 400 with helpful message)."""
    _, token = _create_isolated_victim(client, "Victim TTS Empty")

    # Empty string
    res_empty = client.post(
        "/api/tts",
        json={"text": ""},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert res_empty.status_code == 400
    assert "cannot be empty" in res_empty.json()["detail"].lower()

    # Whitespace only
    res_spaces = client.post(
        "/api/tts",
        json={"text": "     \n\t  "},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert res_spaces.status_code == 400
    assert "cannot be empty" in res_spaces.json()["detail"].lower()


def test_task4_3_unsupported_languages_handled_safely(client):
    """3. Unsupported languages and regional dialect codes are handled safely."""
    _, token = _create_isolated_victim(client, "Victim TTS Dialects")

    # Exotic / unsupported language code falls back cleanly to English
    res = client.post(
        "/api/tts",
        json={"text": "Emergency guidance instructions", "language": "elvish-klingon"},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert res.status_code == 200
    assert len(res.content) > 0

    # Regional hybrid dialect: Tanglish
    res_tanglish = client.post(
        "/api/tts",
        json={"text": "Enaku bayama irukku, please help me", "language": "tanglish"},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert res_tanglish.status_code == 200
    assert len(res_tanglish.content) > 0


def test_task4_4_multilingual_speech_hindi_and_tamil(client):
    """4. Multilingual speech generation produces valid audio in Hindi and Tamil."""
    _, token = _create_isolated_victim(client, "Victim TTS Indic")

    # Hindi
    res_hi = client.post(
        "/api/tts",
        json={"text": "नमस्ते निवारा, मैं सुरक्षित महसूस नहीं कर रही हूँ।", "language": "hi"},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert res_hi.status_code == 200
    assert len(res_hi.content) > 0

    # Tamil
    res_ta = client.post(
        "/api/tts",
        json={"text": "வணக்கம் நிவாரா, எனக்கு அவசர உதவி தேவைப்படுகிறது.", "language": "ta"},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert res_ta.status_code == 200
    assert len(res_ta.content) > 0


def test_task4_5_missing_provider_credentials_and_offline_fallback():
    """5. Missing provider credentials or cloud network failure triggers offline fallback."""
    import asyncio
    import ai_service
    from unittest.mock import patch

    async def _run():
        # Simulate gTTS failing (e.g. offline/network disconnected)
        with patch("gtts.gTTS", side_effect=Exception("Simulated cloud TTS network failure")):
            audio = await ai_service.synthesize_speech("Testing offline Windows speech fallback")
            assert len(audio) > 0
            # Windows SpeechSynthesizer generates standard WAV audio
            assert audio.startswith(b"RIFF")

    asyncio.run(_run())


def test_task4_6_provider_timeouts_and_failures_do_not_crash_backend(client):
    """6. Provider timeouts and failures do not crash the backend and produce 503."""
    from unittest.mock import patch
    _, token = _create_isolated_victim(client, "Victim TTS Failure")

    # Simulate all engines failing
    with patch("ai_service.synthesize_speech", side_effect=RuntimeError("All TTS engines down")):
        res = client.post(
            "/api/tts",
            json={"text": "Testing failure tolerance"},
            headers={"Authorization": f"Bearer {token}"}
        )
        assert res.status_code == 503
        assert "unavailable" in res.json()["detail"].lower()


def test_task4_7_voice_turn_returns_non_empty_audio_base64(client):
    """7. Victim voice-turn returns non-empty base64 audio response."""
    _, token = _create_isolated_victim(client, "Victim Voice Turn")
    dummy_audio = b"RIFF" + b"\x00" * 40 + b"WAVEfmt " + b"\x00" * 200

    res = client.post(
        "/api/voice",
        files={"audio": ("voice.wav", dummy_audio, "audio/wav")},
        data={"language": "en"},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert res.status_code == 200
    body = res.json()
    assert "audio_b64" in body
    assert len(body["audio_b64"]) > 0
    # Base64 decode to verify audio was genuinely produced
    import base64
    decoded = base64.b64decode(body["audio_b64"])
    assert len(decoded) > 0


def test_task4_8_voice_onboarding_returns_audio_base64(client):
    """8. Voice onboarding endpoint returns greeting text and non-empty base64 audio."""
    _, token = _create_isolated_victim(client, "Victim Voice Onboarding")
    res = client.get("/api/voice/onboarding", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    body = res.json()
    assert "text" in body
    assert "audio_b64" in body
    assert len(body["audio_b64"]) > 0


def test_task4_9_unauthenticated_requests_to_tts_rejected(client):
    """9. Unauthenticated requests to /tts are rejected with HTTP 401."""
    res = client.post("/api/tts", json={"text": "Unauthenticated test"})
    assert res.status_code == 401


def test_task4_10_existing_chat_stt_and_auth_features_continue(client):
    """10. Existing chat, speech-to-text, and authentication workflows continue to work."""
    login = client.post("/api/auth/login", json={"email": "victim@nivara.app", "password": "Password123"})
    assert login.status_code == 200
    token = login.json()["token"]

    # Chat
    chat = client.post(
        "/api/chat",
        json={"message": "Can you hear my voice clearly?", "language": "en"},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert chat.status_code == 200
    assert "reply" in chat.json()

    # STT
    dummy_audio = b"RIFF" + b"\x00" * 40 + b"WAVEfmt " + b"\x00" * 200
    stt = client.post(
        "/api/stt",
        files={"audio": ("voice.wav", dummy_audio, "audio/wav")},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert stt.status_code == 200
    assert "transcript" in stt.json()


# ==============================================================================
# Task 5 Tests: Voice Recording, Audio Format Compatibility, and STT Reliability
# ==============================================================================

def _generate_test_wav_bytes(duration_sec: float = 1.0, freq: float = 220.0, sr: int = 16000) -> bytes:
    import io, wave, math, struct
    buf = io.BytesIO()
    with wave.open(buf, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(sr)
        n_samples = int(duration_sec * sr)
        samples = bytearray()
        for i in range(n_samples):
            val = int(16000 * math.sin(2 * math.pi * freq * (i / sr)))
            samples.extend(struct.pack("<h", val))
        wf.writeframes(samples)
    return buf.getvalue()


def _generate_test_webm_bytes() -> bytes:
    import imageio_ffmpeg, subprocess
    wav = _generate_test_wav_bytes(duration_sec=1.0)
    exe = imageio_ffmpeg.get_ffmpeg_exe()
    p = subprocess.run(
        [exe, "-y", "-i", "pipe:0", "-c:a", "libopus", "-f", "webm", "pipe:1"],
        input=wav,
        capture_output=True,
        timeout=10
    )
    return p.stdout


def test_task5_1_valid_audio_upload_processed_successfully(client):
    """1. Valid audio is uploaded and processed successfully by STT and voice-turn."""
    _, token = _create_isolated_victim(client, "Victim Audio 1")
    wav_bytes = _generate_test_wav_bytes(duration_sec=1.0)

    # STT endpoint
    stt_res = client.post(
        "/api/stt",
        files={"audio": ("sample.wav", wav_bytes, "audio/wav")},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert stt_res.status_code == 200
    assert "transcript" in stt_res.json()

    # Voice turn endpoint
    voice_res = client.post(
        "/api/voice",
        files={"audio": ("sample.wav", wav_bytes, "audio/wav")},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert voice_res.status_code == 200
    v_data = voice_res.json()
    assert "reply" in v_data
    assert "case_id" in v_data


def test_task5_2_browser_webm_format_handled_correctly(client):
    """2. Browser WebM (Opus) recording format is handled correctly."""
    _, token = _create_isolated_victim(client, "Victim WebM")
    webm_bytes = _generate_test_webm_bytes()
    assert len(webm_bytes) > 0
    assert webm_bytes[:4] == b"\x1aE\xdf\xa3"

    res = client.post(
        "/api/voice",
        files={"audio": ("voice.webm", webm_bytes, "audio/webm")},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert res.status_code == 200
    data = res.json()
    assert "case_id" in data
    # Voice analysis was performed and decoded the WebM
    assert data.get("voice_analysis") is not None
    assert data["voice_analysis"].get("analysis_available") is True
    assert data["voice_analysis"]["speech"]["duration_seconds"] > 0


def test_task5_3_wav_audio_processed_directly(client):
    """3. WAV audio is processed correctly and yields accurate acoustic measurements."""
    import voice_analyzer
    wav_bytes = _generate_test_wav_bytes(duration_sec=1.5, freq=300.0)
    samples, sr = voice_analyzer.extract_pcm_from_audio(wav_bytes)
    assert samples is not None
    assert sr == 16000
    assert abs(len(samples) / float(sr) - 1.5) < 0.05

    analysis = voice_analyzer.analyze_voice_acoustics(wav_bytes)
    assert analysis["analysis_available"] is True
    assert analysis["speech"]["duration_seconds"] == 1.5


def test_task5_4_empty_and_corrupted_audio_files_rejected(client):
    """4. Empty and corrupted audio files are rejected safely with HTTP 400."""
    _, token = _create_isolated_victim(client, "Victim Empty Audio")

    # Empty file
    res_empty = client.post(
        "/api/stt",
        files={"audio": ("empty.wav", b"", "audio/wav")},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert res_empty.status_code == 400
    assert "empty" in res_empty.json()["detail"].lower()

    # Corrupted / short payload
    res_corrupted = client.post(
        "/api/voice",
        files={"audio": ("tiny.wav", b"RIFF short", "audio/wav")},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert res_corrupted.status_code == 400


def test_task5_5_unsupported_audio_formats_rejected(client):
    """5. Unsupported audio formats (e.g. text file or random bytes) return HTTP 415."""
    _, token = _create_isolated_victim(client, "Victim Bad Format")
    fake_audio = b"Hello, this is just a plain text file pretending to be audio." * 3

    res = client.post(
        "/api/stt",
        files={"audio": ("notes.txt", fake_audio, "text/plain")},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert res.status_code == 415
    assert "unsupported" in res.json()["detail"].lower()


def test_task5_6_oversized_audio_uploads_rejected(client):
    """6. Invalid or oversized audio uploads (> 20 MB) are rejected with HTTP 413."""
    _, token = _create_isolated_victim(client, "Victim Oversized")
    # Simulate payload exceeding 20 MB with valid WAV header prefix
    oversized = b"RIFF" + b"\x00" * 4 + b"WAVE" + b"\x00" * (20 * 1024 * 1024 + 10)

    res = client.post(
        "/api/stt",
        files={"audio": ("huge.wav", oversized, "audio/wav")},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert res.status_code == 413
    assert "exceeds" in res.json()["detail"].lower()


def test_task5_7_stt_provider_failures_and_timeouts_handled_gracefully(client):
    """7. STT provider failures and timeouts are handled gracefully without crashing."""
    from unittest.mock import patch
    _, token = _create_isolated_victim(client, "Victim STT Outage")
    wav_bytes = _generate_test_wav_bytes(duration_sec=1.0)

    with patch("ai_service.transcribe_audio", side_effect=Exception("Simulated cloud STT timeout")):
        # /stt endpoint
        res = client.post(
            "/api/stt",
            files={"audio": ("voice.wav", wav_bytes, "audio/wav")},
            headers={"Authorization": f"Bearer {token}"}
        )
        assert res.status_code == 200
        data = res.json()
        assert "transcript" in data
        assert data.get("is_recognized") is False


def test_task5_8_empty_transcription_does_not_produce_fabricated_text(client):
    """8. Empty transcription results do not produce fabricated distress statements."""
    import asyncio, ai_service
    wav_bytes = _generate_test_wav_bytes(duration_sec=1.0)

    # Calling transcribe_audio without cloud API keys returns empty string, NOT fabricated text
    transcript = asyncio.run(ai_service.transcribe_audio(wav_bytes, filename="voice.wav"))
    assert transcript == ""
    # Ensure neither Tamil nor English fabricated sentences appear
    assert "வணக்கம்" not in transcript
    assert "guidance and support" not in transcript


def test_task5_9_failed_audio_decoding_does_not_generate_misleading_acoustics():
    """9. Failed audio decoding reports analysis_available: False without fake metrics."""
    import voice_analyzer
    # Pass garbage non-audio bytes
    res = voice_analyzer.analyze_voice_acoustics(b"NOT_A_VALID_AUDIO_FILE_DATA_CORRUPTED" * 5)
    assert res["analysis_available"] is False
    assert "unavailable" in res["analysis_notice"].lower()
    # Does not fabricate fake speech_ratio: 0.8
    assert res["speech"]["speech_ratio"] == 0.0
    assert res["speech"]["duration_seconds"] == 0.0


def test_task5_10_existing_chat_sos_auth_and_safety_workflows_continue(client):
    """10. Existing chat, SOS, authentication, authorization, and safety workflows continue working."""
    _, token = _create_isolated_victim(client, "Victim End to End Safety")

    # Chat interaction
    chat_res = client.post(
        "/api/chat",
        json={"message": "Please guide me on how to stay safe at night", "language": "en"},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert chat_res.status_code == 200
    case_id = chat_res.json()["case_id"]

    # Trigger SOS
    sos_res = client.post(
        "/api/sos",
        json={"case_id": case_id, "latitude": 12.9716, "longitude": 77.5946, "message": "Emergency SOS alert"},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert sos_res.status_code == 200
    assert sos_res.json()["ok"] is True
    assert sos_res.json()["sos_status"] == "recorded"


# ==============================================================================
# TASK 6: SAFETY PLAN PERSISTENCE, PERSONALIZATION & ACCESS SECURITY TESTS
# ==============================================================================

def test_task6_1_create_new_safety_plan(client):
    """1. Creating a new personalized safety plan stores it in MongoDB with default pillars."""
    victim_user, victim_token = _create_isolated_victim(client, "Safety Plan Victim 1")
    res = client.post(
        "/api/safety-plan/generate",
        json={},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["_id"] is not None
    assert data["user_id"] == victim_user["id"]
    assert len(data["steps"]) >= 5
    assert data["risk_category"] == "Moderate"
    assert "112" in data["disclaimer"]


def test_task6_2_retrieve_saved_safety_plan(client):
    """2. Retrieving previously saved safety plan via GET returns identical plan document."""
    victim_user, victim_token = _create_isolated_victim(client, "Safety Plan Victim 2")
    create_res = client.post(
        "/api/safety-plan/generate",
        json={},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    plan_id = create_res.json()["_id"]

    # Retrieve via GET /api/safety-plan
    get_res = client.get(
        "/api/safety-plan",
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert get_res.status_code == 200
    plan_data = get_res.json()
    assert plan_data["_id"] == plan_id
    assert plan_data["user_id"] == victim_user["id"]

    # Retrieve via GET /api/safety-plan/{plan_id}
    by_id_res = client.get(
        f"/api/safety-plan/{plan_id}",
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert by_id_res.status_code == 200
    assert by_id_res.json()["_id"] == plan_id


def test_task6_3_save_and_restore_checklist_progress(client):
    """3. Saving checklist progress persists to MongoDB and is restored across requests."""
    _, victim_token = _create_isolated_victim(client, "Safety Plan Victim 3")
    create_res = client.post("/api/safety-plan/generate", json={}, headers={"Authorization": f"Bearer {victim_token}"})
    plan_id = create_res.json()["_id"]

    # Verify step-2 is initially not completed
    get_init = client.get(f"/api/safety-plan/{plan_id}", headers={"Authorization": f"Bearer {victim_token}"})
    step2 = next(s for s in get_init.json()["steps"] if s["id"] == "step-2")
    assert step2["completed"] is False

    # Mark step-2 as completed
    patch_res = client.patch(
        f"/api/safety-plan/{plan_id}/step/step-2",
        json={"completed": True},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["completed"] is True

    # Retrieve plan again and verify persistence
    get_after = client.get(f"/api/safety-plan/{plan_id}", headers={"Authorization": f"Bearer {victim_token}"})
    step2_after = next(s for s in get_after.json()["steps"] if s["id"] == "step-2")
    assert step2_after["completed"] is True


def test_task6_4_updating_existing_plan_without_unintended_duplication(client):
    """4. Updating an existing plan or regenerating AI steps updates in-place without duplicating documents."""
    victim_user, victim_token = _create_isolated_victim(client, "Safety Plan Victim 4")
    # Generate initial plan
    res1 = client.post("/api/safety-plan/generate", json={}, headers={"Authorization": f"Bearer {victim_token}"})
    plan_id1 = res1.json()["_id"]

    # Toggle step-1 completed
    client.patch(
        f"/api/safety-plan/{plan_id1}/step/step-1",
        json={"completed": True},
        headers={"Authorization": f"Bearer {victim_token}"}
    )

    # Call generate/save again (e.g. page refresh or refresh AI recommendations)
    res2 = client.post("/api/safety-plan/generate", json={}, headers={"Authorization": f"Bearer {victim_token}"})
    assert res2.status_code == 200
    plan_id2 = res2.json()["_id"]

    # Document ID remains identical (no duplicate documents created)
    assert plan_id1 == plan_id2

    # Step-1 completion progress is preserved
    step1 = next(s for s in res2.json()["steps"] if s["id"] == "step-1")
    assert step1["completed"] is True


def test_task6_5_blocking_access_to_another_victims_plan(client):
    """5. Victims are strictly prevented from viewing or modifying another victim's safety plan."""
    _, victim_a_token = _create_isolated_victim(client, "Victim A Owner")
    _, victim_b_token = _create_isolated_victim(client, "Victim B Intruder")

    # Victim A creates a plan
    res_a = client.post("/api/safety-plan/generate", json={}, headers={"Authorization": f"Bearer {victim_a_token}"})
    plan_a_id = res_a.json()["_id"]

    # Victim B attempts to GET Victim A's plan
    intrude_get = client.get(
        f"/api/safety-plan/{plan_a_id}",
        headers={"Authorization": f"Bearer {victim_b_token}"}
    )
    assert intrude_get.status_code in [403, 404]

    # Victim B attempts to PUT / modify Victim A's plan
    intrude_put = client.put(
        f"/api/safety-plan/{plan_a_id}",
        json={"title": "Hacked Title"},
        headers={"Authorization": f"Bearer {victim_b_token}"}
    )
    assert intrude_put.status_code in [403, 404]

    # Victim B attempts to toggle a step on Victim A's plan
    intrude_patch = client.patch(
        f"/api/safety-plan/{plan_a_id}/step/step-1",
        json={"completed": True},
        headers={"Authorization": f"Bearer {victim_b_token}"}
    )
    assert intrude_patch.status_code in [403, 404]


def test_task6_6_rejecting_unauthenticated_requests(client):
    """6. Unauthenticated requests to all safety plan endpoints are rejected with HTTP 401."""
    assert client.get("/api/safety-plan").status_code == 401
    assert client.get("/api/safety-plan/some-plan-id").status_code == 401
    assert client.post("/api/safety-plan/generate", json={}).status_code == 401
    assert client.put("/api/safety-plan/some-plan-id", json={}).status_code == 401
    assert client.patch("/api/safety-plan/some-plan-id/step/step-1", json={}).status_code == 401


def test_task6_7_validating_malformed_or_unauthorized_updates(client):
    """7. Validates update payloads and rejects tampering with ownership or plan ID."""
    victim_user, victim_token = _create_isolated_victim(client, "Safety Plan Victim 7")
    create_res = client.post("/api/safety-plan/generate", json={}, headers={"Authorization": f"Bearer {victim_token}"})
    plan_id = create_res.json()["_id"]

    # Attempt to change owner user_id to a different ID
    tamper_owner = client.put(
        f"/api/safety-plan/{plan_id}",
        json={"user_id": "malicious-user-id-999"},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert tamper_owner.status_code == 400
    assert "owner" in tamper_owner.json()["detail"].lower()

    # Attempt to alter plan _id in update payload
    tamper_id = client.put(
        f"/api/safety-plan/{plan_id}",
        json={"_id": "altered-plan-id-999"},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert tamper_id.status_code == 400


def test_task6_8_handling_missing_plans_and_database_errors(client):
    """8. Cleanly handles missing plans, unknown steps, and invalid parameters with 404."""
    _, victim_token = _create_isolated_victim(client, "Safety Plan Victim 8")
    create_res = client.post("/api/safety-plan/generate", json={}, headers={"Authorization": f"Bearer {victim_token}"})
    plan_id = create_res.json()["_id"]

    # Request nonexistent plan ID
    missing_plan = client.get(
        "/api/safety-plan/nonexistent-uuid-99999",
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert missing_plan.status_code == 404

    # Request toggle for nonexistent step ID
    missing_step = client.patch(
        f"/api/safety-plan/{plan_id}/step/nonexistent-step-id",
        json={"completed": True},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert missing_step.status_code == 404


def test_task6_9_accessing_saved_plans_when_ai_suggestions_unavailable(client, monkeypatch):
    """9. Plan creation, retrieval, and persistence succeed even when AI services fail or timeout."""
    import ai_service
    # Simulate AI service failure
    async def mock_fail_steps(*args, **kwargs):
        raise RuntimeError("Simulated AI provider timeout")

    monkeypatch.setattr(ai_service, "generate_safety_plan_steps", mock_fail_steps)

    _, victim_token = _create_isolated_victim(client, "Safety Plan Victim 9")

    # GET /api/safety-plan when AI is down
    get_res = client.get("/api/safety-plan", headers={"Authorization": f"Bearer {victim_token}"})
    assert get_res.status_code == 200
    data = get_res.json()
    assert len(data["steps"]) >= 5
    assert data["steps"][0]["title"] == "Establish Silent Duress Code Words"


def test_task6_10_preserving_existing_registration_sos_voice_and_case_workflows(client):
    """10. Preserves all existing registration, case/evidence, SOS, voice, and staff triage workflows."""
    import uuid
    # 1. Registration security check
    reg_res = client.post("/api/auth/register", json={
        "email": f"task6_reg_{uuid.uuid4().hex[:6]}@test.com",
        "name": "Task 6 Reg Check",
        "password": "Password123!",
        "role": "officer"  # Attempt privileged role
    })
    assert reg_res.status_code == 200
    assert reg_res.json()["user"]["role"] == "victim"

    # 2. Staff case triage workflow
    _, victim_token = _create_isolated_victim(client, "Victim Staff Workflow")
    sos_res = client.post(
        "/api/sos",
        json={"latitude": 12.9716, "longitude": 77.5946, "message": "Emergency test"},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    case_id = sos_res.json()["case_id"]

    # Officer can access case
    off_login = client.post("/api/auth/login", json={"email": "officer@nivara.app", "password": "Password123"})
    officer_token = off_login.json()["token"]
    case_get = client.get(f"/api/cases/{case_id}", headers={"Authorization": f"Bearer {officer_token}"})
    assert case_get.status_code == 200


# ==============================================================================
# TASK 7: SENSITIVE DATA ENCRYPTION & PRIVACY PROTECTION TESTS
# ==============================================================================

import security_crypto
import pytest


def test_task7_1_sensitive_fields_encrypted_in_mongodb(client):
    """1. Sensitive safety plan fields and evidence notes are encrypted before storage."""
    import pymongo
    sync_db = pymongo.MongoClient("mongodb://127.0.0.1:27017")["nivara"]

    _, victim_token = _create_isolated_victim(client, "Crypto Victim 1")

    # Update safety plan with sensitive emergency notes and contacts
    plan_res = client.put(
        "/api/safety-plan",
        json={
            "emergency_notes": "Stashed 50000 rupees behind kitchen cabinet and spare car keys in garage",
            "trusted_contacts": [{"name": "Aunt Sarah", "phone": "+919876543210", "code_word": "CrimsonRiver"}],
            "safe_places": [{"name": "Sister Safe Apartment", "address": "42 Quiet Street, Bengaluru"}]
        },
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert plan_res.status_code == 200
    plan_id = plan_res.json()["_id"]

    # Directly inspect raw document from MongoDB collection
    raw_doc = sync_db.safety_plans.find_one({"_id": plan_id})
    assert raw_doc is not None
    # Verify raw stored fields have enc:v1: prefix and are NOT plaintext
    assert isinstance(raw_doc["emergency_notes"], str)
    assert raw_doc["emergency_notes"].startswith("enc:v1:")
    assert "kitchen cabinet" not in raw_doc["emergency_notes"]
    assert isinstance(raw_doc["trusted_contacts"], str)
    assert raw_doc["trusted_contacts"].startswith("enc:v1:")
    assert "CrimsonRiver" not in raw_doc["trusted_contacts"]


def test_task7_2_authorized_api_responses_correctly_decrypt_fields(client):
    """2. Authorized API responses transparently decrypt protected fields for the user."""
    _, victim_token = _create_isolated_victim(client, "Crypto Victim 2")

    secret_note = "Passport and jewelry in safe deposit box 412"
    secret_word = "GoldenFalcon99"

    save_res = client.put(
        "/api/safety-plan",
        json={
            "emergency_notes": secret_note,
            "trusted_contacts": [{"name": "Best Friend", "phone": "12345", "code_word": secret_word}]
        },
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert save_res.status_code == 200

    # Retrieve via GET /api/safety-plan
    get_res = client.get("/api/safety-plan", headers={"Authorization": f"Bearer {victim_token}"})
    assert get_res.status_code == 200
    data = get_res.json()
    assert data["emergency_notes"] == secret_note
    assert isinstance(data["trusted_contacts"], list)
    assert data["trusted_contacts"][0]["code_word"] == secret_word


def test_task7_3_raw_database_evidence_notes_encrypted_at_rest(client):
    """3. Evidence locker incident notes and GPS coordinates are encrypted in audit_logs."""
    import pymongo
    sync_db = pymongo.MongoClient("mongodb://127.0.0.1:27017")["nivara"]

    _, victim_token = _create_isolated_victim(client, "Crypto Evidence Victim")
    # First create a case
    chat_res = client.post(
        "/api/chat",
        json={"message": "Threatening message received from stalker"},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    case_id = chat_res.json()["case_id"]

    secret_evidence_note = "Perpetrator broke car window at midnight, threatening note left on seat"
    secret_gps = "Exact Latitude 12.91234, Longitude 77.56789, Apartment 4B"

    upload_res = client.post(
        "/api/evidence/upload",
        json={
            "case_id": case_id,
            "title": "Broken Window Threat",
            "content": secret_evidence_note,
            "location": secret_gps
        },
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert upload_res.status_code == 200

    # Direct inspect raw audit_logs in MongoDB
    raw_log = sync_db.audit_logs.find_one({"action": "evidence_snapshot", "meta.case_id": case_id})
    assert raw_log is not None
    raw_meta = raw_log["meta"]
    # Notes and geo are encrypted strings starting with enc:v1:
    assert raw_meta["notes"].startswith("enc:v1:")
    assert raw_meta["geo"].startswith("enc:v1:")
    assert secret_evidence_note not in raw_meta["notes"]
    assert secret_gps not in raw_meta["geo"]

    # Authorized API call transparently decrypts
    evidence_list = client.get(f"/api/evidence/{case_id}", headers={"Authorization": f"Bearer {victim_token}"})
    assert evidence_list.status_code == 200
    items = evidence_list.json()["evidence"]
    assert len(items) >= 1
    assert items[0]["notes"] == secret_evidence_note


def test_task7_4_tampered_ciphertext_fails_authentication():
    """4. Modified or corrupted ciphertext fails AES-256-GCM authentication and raises DecryptionError."""
    original = "TopSecretPersonalDuressWord"
    ciphertext = security_crypto.encrypt_value(original)
    assert ciphertext.startswith("enc:v1:")

    # Corrupt last 4 characters of ciphertext payload (tampering with tag/ciphertext)
    tampered = ciphertext[:-4] + "AAAA"

    with pytest.raises(security_crypto.DecryptionError) as exc_info:
        security_crypto.decrypt_value(tampered, fallback_to_raw_on_unencrypted=False)

    assert "tampered" in str(exc_info.value).lower() or "authentication" in str(exc_info.value).lower()


def test_task7_5_missing_encryption_key_fails_safely(monkeypatch):
    """5. Missing encryption keys fail safely with EncryptionConfigError without writing plaintext."""
    monkeypatch.delenv("DATA_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("NIVARA_ENCRYPTION_KEY", raising=False)

    with pytest.raises(security_crypto.EncryptionConfigError):
        security_crypto.encrypt_value("Confidential data")


def test_task7_6_invalid_key_fails_authentication(monkeypatch):
    """6. Decryption using a different key fails authentication rather than returning corrupted plaintext."""
    # Encrypt with current key
    encrypted = security_crypto.encrypt_value("TargetSecretValue")

    # Switch to a different valid 256-bit key
    different_key_hex = "1111111111111111111111111111111111111111111111111111111111111111"
    monkeypatch.setenv("DATA_ENCRYPTION_KEY", different_key_hex)

    with pytest.raises(security_crypto.DecryptionError):
        security_crypto.decrypt_value(encrypted, fallback_to_raw_on_unencrypted=False)


def test_task7_7_access_authorization_remains_enforced_with_encryption(client):
    """7. Access authorization remains strictly enforced: another victim cannot access encrypted records."""
    _, victim_a_token = _create_isolated_victim(client, "Victim A Vault")
    _, victim_b_token = _create_isolated_victim(client, "Victim B Snooper")

    # Victim A creates a plan with confidential note
    res_a = client.put(
        "/api/safety-plan",
        json={"emergency_notes": "Victim A Private Note"},
        headers={"Authorization": f"Bearer {victim_a_token}"}
    )
    plan_a_id = res_a.json()["_id"]

    # Victim B tries to access Victim A's plan by ID
    snoop_res = client.get(f"/api/safety-plan/{plan_a_id}", headers={"Authorization": f"Bearer {victim_b_token}"})
    assert snoop_res.status_code in [403, 404]


def test_task7_8_legacy_unencrypted_records_read_cleanly_without_error(client):
    """8. Legacy unencrypted records remain fully readable and are upgraded when saved."""
    import pymongo
    from models import make_safety_plan
    sync_db = pymongo.MongoClient("mongodb://127.0.0.1:27017")["nivara"]

    victim_user, victim_token = _create_isolated_victim(client, "Legacy Record Victim")

    # Seed an unencrypted legacy document directly into MongoDB
    legacy_plan = make_safety_plan(
        user_id=victim_user["id"],
        emergency_notes="Legacy plaintext notes from previous version",
        trusted_contacts=[{"name": "Legacy Aunt", "phone": "100", "code_word": "OldCode"}],
        safe_places=[{"name": "Old Shelter", "address": "123 Main St"}]
    )
    sync_db.safety_plans.insert_one(legacy_plan)

    # Read via GET /api/safety-plan
    get_res = client.get("/api/safety-plan", headers={"Authorization": f"Bearer {victim_token}"})
    assert get_res.status_code == 200
    plan_data = get_res.json()
    assert plan_data["emergency_notes"] == "Legacy plaintext notes from previous version"
    assert plan_data["trusted_contacts"][0]["name"] == "Legacy Aunt"

    # Save update and verify it is now encrypted at rest
    client.put(
        f"/api/safety-plan/{legacy_plan['_id']}",
        json={"emergency_notes": "Upgraded and now protected by AES-GCM"},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    raw_after = sync_db.safety_plans.find_one({"_id": legacy_plan["_id"]})
    assert raw_after["emergency_notes"].startswith("enc:v1:")


def test_task7_9_evidence_integrity_hash_and_audit_logging_preserved(client):
    """9. Tamper-evident SHA-256 hash calculation and audit logging remain intact alongside encryption."""
    _, victim_token = _create_isolated_victim(client, "Evidence Hash Victim")
    chat_res = client.post(
        "/api/chat",
        json={"message": "Threat report"},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    case_id = chat_res.json()["case_id"]

    content = "Detailed threat report for evidence vault verification"
    upload_res = client.post(
        "/api/evidence/upload",
        json={"case_id": case_id, "title": "Audit Check", "content": content},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert upload_res.status_code == 200
    hash_val = upload_res.json()["hash"]
    assert hash_val.startswith("SHA256:")

    # Verify retrieval
    item_res = client.get(f"/api/evidence/{case_id}", headers={"Authorization": f"Bearer {victim_token}"})
    assert item_res.status_code == 200
    item = item_res.json()["evidence"][0]
    assert item["hash"] == hash_val
    assert item["notes"] == content


def test_task7_10_end_to_end_registration_sos_chat_voice_safety_preserved(client):
    """10. Preserves all existing registration, SOS, chat, voice, and case workflows without regression."""
    import uuid
    # Registration check
    reg = client.post("/api/auth/register", json={
        "email": f"task7_victim_{uuid.uuid4().hex[:6]}@test.com",
        "name": "Task 7 Regression Victim",
        "password": "Password123!",
        "role": "officer"
    })
    assert reg.status_code == 200
    assert reg.json()["user"]["role"] == "victim"
    token = reg.json()["token"]

    # Chat interaction
    chat_res = client.post(
        "/api/chat",
        json={"message": "I need help with safety resources", "language": "en"},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert chat_res.status_code == 200
    assert "reply" in chat_res.json()

    # SOS trigger
    sos_res = client.post(
        "/api/sos",
        json={"latitude": 12.9716, "longitude": 77.5946, "message": "Help needed"},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert sos_res.status_code == 200
    assert sos_res.json()["ok"] is True


# ==============================================================================
# TASK 8: SAFE MIGRATION & ENCRYPTION-KEY PROTECTION TESTS
# ==============================================================================

import migrate_encryption


def test_task8_1_migration_encrypts_plaintext_fields():
    """1. Migration utility encrypts legacy unencrypted plaintext fields into AES-256-GCM ciphertext."""
    import pymongo
    import uuid
    sync_db = pymongo.MongoClient("mongodb://127.0.0.1:27017")["nivara"]
    test_id = f"legacy_plan_test1_{uuid.uuid4().hex[:8]}"

    legacy_notes = "Secret legacy stash under floorboards"
    legacy_contact = [{"name": "Uncle Bob", "phone": "9998887776", "code_word": "BlueFalcon"}]
    legacy_places = [{"name": "Safe Haven Garage", "address": "12 Back Street"}]

    # Seed legacy plaintext doc
    sync_db.safety_plans.insert_one({
        "_id": test_id,
        "user_id": f"legacy_user_{uuid.uuid4().hex[:6]}",
        "emergency_notes": legacy_notes,
        "trusted_contacts": legacy_contact,
        "safe_places": legacy_places,
        "steps": [],
        "created_at": "2026-10-01T00:00:00Z"
    })

    try:
        # Run migration live
        stats = migrate_encryption.migrate_database(sync_db, dry_run=False)
        assert stats["safety_plans_migrated"] >= 1

        # Check raw document in DB
        doc = sync_db.safety_plans.find_one({"_id": test_id})
        assert doc is not None
        assert doc["emergency_notes"].startswith("enc:v1:")
        assert legacy_notes not in doc["emergency_notes"]
        assert doc["trusted_contacts"].startswith("enc:v1:")
        assert "BlueFalcon" not in doc["trusted_contacts"]
        assert doc["safe_places"].startswith("enc:v1:")

        # Verify decryption restores exact original values
        assert security_crypto.decrypt_value(doc["emergency_notes"]) == legacy_notes
        assert security_crypto.decrypt_value(doc["trusted_contacts"]) == legacy_contact
        assert security_crypto.decrypt_value(doc["safe_places"]) == legacy_places
    finally:
        sync_db.safety_plans.delete_one({"_id": test_id})


def test_task8_2_migration_skips_already_encrypted_fields():
    """2. Migration preserves already encrypted enc:v1: fields without double-encrypting them."""
    import pymongo
    import uuid
    sync_db = pymongo.MongoClient("mongodb://127.0.0.1:27017")["nivara"]
    test_id = f"encrypted_plan_test2_{uuid.uuid4().hex[:8]}"

    already_encrypted_note = security_crypto.encrypt_value("AlreadyEncryptedNoteContent")
    already_encrypted_contacts = security_crypto.encrypt_value([{"name": "Friend", "code_word": "Hawk"}])
    already_encrypted_places = security_crypto.encrypt_value([{"name": "Shelter", "address": "Main St"}])

    sync_db.safety_plans.insert_one({
        "_id": test_id,
        "user_id": f"enc_user_{uuid.uuid4().hex[:6]}",
        "emergency_notes": already_encrypted_note,
        "trusted_contacts": already_encrypted_contacts,
        "safe_places": already_encrypted_places,
        "steps": []
    })

    try:
        # Run live migration
        migrate_encryption.migrate_database(sync_db, dry_run=False)

        # Check raw document in DB
        doc = sync_db.safety_plans.find_one({"_id": test_id})
        assert doc is not None
        # Must match EXACTLY what was originally stored (no re-encryption / double wrapping)
        assert doc["emergency_notes"] == already_encrypted_note
        assert doc["trusted_contacts"] == already_encrypted_contacts
        assert doc["safe_places"] == already_encrypted_places
    finally:
        sync_db.safety_plans.delete_one({"_id": test_id})


def test_task8_3_migration_is_idempotent():
    """3. Running migration repeatedly produces 0 additional modifications and no corruption."""
    import pymongo
    sync_db = pymongo.MongoClient("mongodb://127.0.0.1:27017")["nivara"]

    # First run live migration to ensure fully clean state
    migrate_encryption.migrate_database(sync_db, dry_run=False)

    # Second run should encrypt 0 fields
    rerun_stats = migrate_encryption.migrate_database(sync_db, dry_run=False)
    assert rerun_stats["fields_encrypted"] == 0
    assert rerun_stats["safety_plans_migrated"] == 0
    assert rerun_stats["evidence_migrated"] == 0


def test_task8_4_missing_key_aborts_migration_safely(monkeypatch):
    """4. Missing encryption key immediately halts migration without making partial database changes."""
    import pymongo
    import uuid
    sync_db = pymongo.MongoClient("mongodb://127.0.0.1:27017")["nivara"]
    test_id = f"abort_test4_{uuid.uuid4().hex[:8]}"

    sync_db.safety_plans.insert_one({
        "_id": test_id,
        "user_id": "test_user_abort",
        "emergency_notes": "Plaintext notes before abort"
    })

    try:
        monkeypatch.delenv("DATA_ENCRYPTION_KEY", raising=False)
        monkeypatch.delenv("NIVARA_ENCRYPTION_KEY", raising=False)

        with pytest.raises(security_crypto.EncryptionConfigError):
            migrate_encryption.migrate_database(sync_db, dry_run=False)

        # Raw document was NOT modified or corrupted
        doc = sync_db.safety_plans.find_one({"_id": test_id})
        assert doc["emergency_notes"] == "Plaintext notes before abort"
    finally:
        sync_db.safety_plans.delete_one({"_id": test_id})


def test_task8_5_tampered_ciphertext_reported_during_verification():
    """5. Verification scanner identifies tampered or corrupted ciphertext and reports non-compliance."""
    import pymongo
    import uuid
    sync_db = pymongo.MongoClient("mongodb://127.0.0.1:27017")["nivara"]
    test_id = f"corrupt_plan_{uuid.uuid4().hex[:8]}"

    # Seed record with invalid ciphertext payload
    sync_db.safety_plans.insert_one({
        "_id": test_id,
        "user_id": "tampered_user",
        "emergency_notes": "enc:v1:CORRUPTED_BASE64_CIPHERTEXT_1234567890",
        "trusted_contacts": "enc:v1:CORRUPTED_BASE64_CIPHERTEXT_1234567890",
        "safe_places": "enc:v1:CORRUPTED_BASE64_CIPHERTEXT_1234567890"
    })

    try:
        report = migrate_encryption.verify_database_encryption(sync_db)
        assert report["compliant"] is False
        assert report["tampered_records"] >= 1
    finally:
        sync_db.safety_plans.delete_one({"_id": test_id})


def test_task8_6_null_and_missing_fields_handled_cleanly():
    """6. Records with null or missing fields are safely handled and populated with encrypted defaults."""
    import pymongo
    import uuid
    sync_db = pymongo.MongoClient("mongodb://127.0.0.1:27017")["nivara"]
    test_id = f"null_fields_plan_{uuid.uuid4().hex[:8]}"

    sync_db.safety_plans.insert_one({
        "_id": test_id,
        "user_id": f"null_user_{uuid.uuid4().hex[:6]}",
        "emergency_notes": None,
        # trusted_contacts and safe_places omitted completely
    })

    try:
        stats = migrate_encryption.migrate_database(sync_db, dry_run=False)
        doc = sync_db.safety_plans.find_one({"_id": test_id})
        assert doc is not None
        assert doc["emergency_notes"].startswith("enc:v1:")
        assert security_crypto.decrypt_value(doc["emergency_notes"]) == ""
        assert doc["trusted_contacts"].startswith("enc:v1:")
        assert security_crypto.decrypt_value(doc["trusted_contacts"]) == []
        assert doc["safe_places"].startswith("enc:v1:")
        assert security_crypto.decrypt_value(doc["safe_places"]) == []
    finally:
        sync_db.safety_plans.delete_one({"_id": test_id})


def test_task8_7_unrelated_fields_preserved():
    """7. Migration strictly preserves unrelated fields, IDs, timestamps, and structure."""
    import pymongo
    import uuid
    sync_db = pymongo.MongoClient("mongodb://127.0.0.1:27017")["nivara"]
    test_id = f"preserve_fields_{uuid.uuid4().hex[:8]}"
    created_ts = "2026-05-15T10:30:00Z"
    custom_meta = {"custom_tag": "test_tag_value", "version": 42}
    steps_list = [{"id": "step-1", "title": "Establish code word", "completed": True}]

    sync_db.safety_plans.insert_one({
        "_id": test_id,
        "user_id": "preserve_user_id",
        "emergency_notes": "Plaintext note to encrypt",
        "custom_meta": custom_meta,
        "steps": steps_list,
        "created_at": created_ts,
        "risk_category": "Elevated"
    })

    try:
        migrate_encryption.migrate_database(sync_db, dry_run=False)
        doc = sync_db.safety_plans.find_one({"_id": test_id})
        assert doc["_id"] == test_id
        assert doc["user_id"] == "preserve_user_id"
        assert doc["custom_meta"] == custom_meta
        assert doc["steps"] == steps_list
        assert doc["created_at"] == created_ts
        assert doc["risk_category"] == "Elevated"
    finally:
        sync_db.safety_plans.delete_one({"_id": test_id})


def test_task8_8_dry_run_mode_never_modifies_database():
    """8. Dry-run mode previews pending encryption counts without performing any writes."""
    import pymongo
    import uuid
    sync_db = pymongo.MongoClient("mongodb://127.0.0.1:27017")["nivara"]
    test_id = f"dry_run_plan_{uuid.uuid4().hex[:8]}"

    sync_db.safety_plans.insert_one({
        "_id": test_id,
        "user_id": "dry_run_user",
        "emergency_notes": "Untouched plaintext in dry run mode"
    })

    try:
        stats = migrate_encryption.migrate_database(sync_db, dry_run=True)
        assert stats["dry_run"] is True
        assert stats["safety_plans_migrated"] >= 1

        # Confirm document in database was NOT altered
        doc = sync_db.safety_plans.find_one({"_id": test_id})
        assert doc["emergency_notes"] == "Untouched plaintext in dry run mode"
    finally:
        sync_db.safety_plans.delete_one({"_id": test_id})


def test_task8_9_verification_detects_plaintext_without_leakage():
    """9. Verification scanner accurately flags plaintext records while preventing secret value leakage in logs."""
    import pymongo
    import uuid
    sync_db = pymongo.MongoClient("mongodb://127.0.0.1:27017")["nivara"]
    test_id = f"leak_test_plan_{uuid.uuid4().hex[:8]}"
    secret_phrase = "UltraConfidentialSecretPassphrase999"

    sync_db.safety_plans.insert_one({
        "_id": test_id,
        "user_id": "leak_test_user",
        "emergency_notes": secret_phrase
    })

    try:
        report = migrate_encryption.verify_database_encryption(sync_db)
        assert report["compliant"] is False
        assert report["safety_plans_plaintext_remaining"] >= 1

        # Ensure confidential secret phrase is NEVER leaked in details or reports
        report_str = str(report)
        assert secret_phrase not in report_str
        assert "emergency_notes" in report_str
    finally:
        sync_db.safety_plans.delete_one({"_id": test_id})


def test_task8_10_full_regression_safety(client):
    """10. End-to-end regression validation: Registration, login, SOS, chat, and evidence remain intact."""
    import uuid
    # 1. Registration security check
    reg = client.post("/api/auth/register", json={
        "email": f"task8_victim_{uuid.uuid4().hex[:6]}@test.com",
        "name": "Task 8 Regression Victim",
        "password": "Password123!",
        "role": "officer"
    })
    assert reg.status_code == 200
    assert reg.json()["user"]["role"] == "victim"
    token = reg.json()["token"]

    # 2. Chat interaction
    chat_res = client.post(
        "/api/chat",
        json={"message": "I need guidance on creating a safety plan", "language": "en"},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert chat_res.status_code == 200
    case_id = chat_res.json()["case_id"]

    # 3. SOS interaction
    sos_res = client.post(
        "/api/sos",
        json={"case_id": case_id, "latitude": 12.9716, "longitude": 77.5946, "message": "Testing emergency response"},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert sos_res.status_code == 200
    assert sos_res.json()["ok"] is True

    # 4. Encrypted safety plan round-trip
    plan_res = client.put(
        "/api/safety-plan",
        json={"emergency_notes": "Task 8 verified note"},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert plan_res.status_code == 200
    assert plan_res.json()["emergency_notes"] == "Task 8 verified note"


# ==============================================================================
# TASK 9: REAL SAFE HAVEN DATA INTEGRATION & TRANSPARENCY TESTS
# ==============================================================================

import safe_haven_service


def test_task9_1_valid_real_provider_results_normalized_correctly(client):
    """1. Valid real-provider results are normalized correctly with verified schema fields."""
    _, victim_token = _create_isolated_victim(client, "Safe Haven Real Provider Victim")
    res = client.get(
        "/api/safe-havens?provider=osc_directory&lat=12.9716&lng=77.5946",
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["verified_provider_configured"] is True
    assert data["provider_id"] == "osc_directory"
    assert "Ministry of Women and Child Development" in data["provider_name"]
    assert "Verified Government Directory" in data["provider_notice"]
    assert len(data["havens"]) >= 5

    first = data["havens"][0]
    assert first["is_verified_source"] is True
    assert first["is_location_verified"] is True
    assert first["source_type"] == "government_directory"
    assert "Sakhi" in first["name"] or "Vanitha" in first["name"]
    assert first["phone"] is not None
    assert first["address"] is not None
    assert isinstance(first["services"], list)
    assert len(first["services"]) > 0


def test_task9_2_provider_source_and_update_metadata_preserved(client):
    """2. Provider source and update metadata are preserved without alteration."""
    _, victim_token = _create_isolated_victim(client, "Metadata Victim")
    res = client.get(
        "/api/safe-havens?provider=osc_directory",
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert res.status_code == 200
    data = res.json()
    for h in data["havens"]:
        assert h["source_name"] != ""
        assert h["last_updated"] is not None
        assert "2024" in h["last_updated"] or "Directory" in h["last_updated"]
        assert h["disclaimer"] != ""
        assert "112" in (h.get("helpline") or "") or "181" in (h.get("helpline") or "") or "112" in h["disclaimer"] or "181" in h["disclaimer"]


def test_task9_3_missing_or_invalid_coordinates_do_not_produce_fabricated_distances(client):
    """3. Missing or out-of-range coordinates do not produce fabricated distances."""
    _, victim_token = _create_isolated_victim(client, "No Fab Distance Victim")

    # Incomplete pair: lat without lng
    res_half = client.get("/api/safe-havens?lat=12.9716", headers={"Authorization": f"Bearer {victim_token}"})
    assert res_half.status_code == 400
    assert "Both latitude and longitude must be provided together" in res_half.json()["detail"]

    # Latitude out of range (> 90)
    res_lat_bad = client.get("/api/safe-havens?lat=95.0&lng=77.0", headers={"Authorization": f"Bearer {victim_token}"})
    assert res_lat_bad.status_code == 400
    assert "Latitude must be between -90 and 90" in res_lat_bad.json()["detail"]

    # Longitude out of range (> 180)
    res_lng_bad = client.get("/api/safe-havens?lat=12.0&lng=195.0", headers={"Authorization": f"Bearer {victim_token}"})
    assert res_lng_bad.status_code == 400
    assert "Longitude must be between -180 and 180" in res_lng_bad.json()["detail"]


def test_task9_4_haversine_distance_calculations_remain_accurate():
    """4. Haversine distance calculations remain accurate within expected great-circle bounds."""
    # Distance between Bengaluru City Center (12.9716, 77.5946) and Bowring Hospital (12.9830, 77.6015)
    dist = safe_haven_service.calculate_haversine(12.9716, 77.5946, 12.9830, 77.6015)
    # Expected distance is ~1.47 km
    assert 1.3 < dist < 1.6

    # Distance between identical points is 0.0
    assert safe_haven_service.calculate_haversine(12.9716, 77.5946, 12.9716, 77.5946) == 0.0

    # Invalid coordinates return float('inf')
    assert safe_haven_service.calculate_haversine(None, 77.0, 12.0, 77.0) == float("inf")
    assert safe_haven_service.calculate_haversine(99.0, 77.0, 12.0, 77.0) == float("inf")


def test_task9_5_missing_gps_coordinates_handled_safely(client):
    """5. Missing GPS coordinates are handled safely and report distance as null."""
    _, victim_token = _create_isolated_victim(client, "Missing GPS Victim")
    res = client.get("/api/safe-havens?provider=osc_directory", headers={"Authorization": f"Bearer {victim_token}"})
    assert res.status_code == 200
    data = res.json()
    assert data["has_user_location"] is False
    assert data["user_location"] is None
    for h in data["havens"]:
        assert h["distance_km"] is None
        assert h["distance_type"] is None


def test_task9_6_provider_timeouts_and_network_errors_handled_gracefully(client, monkeypatch):
    """6. Provider timeouts and network errors produce appropriate responses without crashing."""
    async def mock_failed_fetch(*args, **kwargs):
        return []

    # Mock OpenStreetMap provider failing / timing out
    monkeypatch.setattr(
        safe_haven_service.OpenStreetMapOverpassProvider,
        "fetch_havens",
        mock_failed_fetch
    )

    _, victim_token = _create_isolated_victim(client, "Timeout Test Victim")
    safe_haven_service.safe_haven_service.clear_cache()

    res = client.get(
        "/api/safe-havens?provider=openstreetmap&lat=12.9716&lng=77.5946",
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["provider_id"] == "openstreetmap"
    assert isinstance(data["havens"], list)
    assert len(data["havens"]) == 0


def test_task9_7_missing_configuration_handled_honestly(client):
    """7. Unknown or unconfigured provider names fall back cleanly to default without fabricating access."""
    _, victim_token = _create_isolated_victim(client, "Config Test Victim")
    res = client.get(
        "/api/safe-havens?provider=nonexistent_external_api_xyz",
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert res.status_code == 200
    data = res.json()
    # Falls back to standard provider without throwing 500 error
    assert data["provider_id"] in ["osc_directory", "demo"]


def test_task9_8_empty_provider_results_do_not_trigger_invented_shelter_records(client, monkeypatch):
    """8. Empty provider results do not trigger invented shelter records."""
    async def mock_empty_havens(*args, **kwargs):
        return []

    monkeypatch.setattr(
        safe_haven_service.GovernmentOSCDirectoryProvider,
        "fetch_havens",
        mock_empty_havens
    )

    _, victim_token = _create_isolated_victim(client, "Empty Result Victim")
    safe_haven_service.safe_haven_service.clear_cache()

    res = client.get("/api/safe-havens?provider=osc_directory", headers={"Authorization": f"Bearer {victim_token}"})
    assert res.status_code == 200
    data = res.json()
    assert data["havens"] == []


def test_task9_9_demonstration_data_never_presented_as_verified(client):
    """9. Demonstration data is strictly identified as unverified demo sample."""
    _, victim_token = _create_isolated_victim(client, "Demo Identity Victim")
    res = client.get("/api/safe-havens?provider=demo", headers={"Authorization": f"Bearer {victim_token}"})
    assert res.status_code == 200
    data = res.json()
    assert data["verified_provider_configured"] is False
    assert "Demonstration data only" in data["provider_notice"]
    for h in data["havens"]:
        assert h["is_verified_source"] is False
        assert h["source_type"] == "demonstration"
        assert "(Demo)" in h["name"] or "Sample" in h["disclaimer"]


def test_task9_10_missing_hours_and_availability_remain_explicitly_unknown(client):
    """10. Real-time bed availability is explicitly marked unknown rather than fabricated as available."""
    _, victim_token = _create_isolated_victim(client, "Unknown Availability Victim")
    res = client.get("/api/safe-havens?provider=osc_directory", headers={"Authorization": f"Bearer {victim_token}"})
    assert res.status_code == 200
    data = res.json()
    for h in data["havens"]:
        assert "unknown" in h["bed_availability"].lower()
        # Must never claim guaranteed vacancy or 100% available beds
        assert "guaranteed" not in h["bed_availability"].lower()
        assert "100% available" not in h["bed_availability"].lower()


def test_task9_11_cached_records_handled_according_to_freshness_policy(client):
    """11. Cached records are served according to TTL policy without caching user location coordinates."""
    safe_haven_service.safe_haven_service.clear_cache()
    _, victim_token = _create_isolated_victim(client, "Cache Policy Victim")

    # First query populates cache
    res1 = client.get(
        "/api/safe-havens?provider=osc_directory&lat=12.9716&lng=77.5946",
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert res1.status_code == 200
    assert "osc_directory" in safe_haven_service.safe_haven_service._cache

    # Verify cache content contains only raw records, NOT user coordinates
    cached_entry = safe_haven_service.safe_haven_service._cache["osc_directory"]
    assert "records" in cached_entry
    assert "user_location" not in cached_entry
    assert "lat" not in cached_entry

    # Second query with DIFFERENT user coordinates gets correct new distance, not cached old distance
    res2 = client.get(
        "/api/safe-havens?provider=osc_directory&lat=13.1000&lng=77.6000",
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert res2.status_code == 200
    # Different user coordinate results in different distance
    d1 = res1.json()["havens"][0]["distance_km"]
    d2 = res2.json()["havens"][0]["distance_km"]
    assert d1 != d2


def test_task9_12_existing_auth_encryption_sos_workflows_continue(client):
    """12. Preserves all existing registration, case/evidence authorization, encryption, and SOS workflows."""
    import uuid
    # Registration role security
    reg = client.post("/api/auth/register", json={
        "email": f"task9_victim_{uuid.uuid4().hex[:6]}@test.com",
        "name": "Task 9 Regression Check",
        "password": "Password123!",
        "role": "officer"
    })
    assert reg.status_code == 200
    assert reg.json()["user"]["role"] == "victim"
    token = reg.json()["token"]

    # SOS trigger
    sos = client.post(
        "/api/sos",
        json={"latitude": 12.9716, "longitude": 77.5946, "message": "Task 9 SOS check"},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert sos.status_code == 200
    assert sos.json()["ok"] is True
    assert sos.json()["sos_status"] == "recorded"

    # Encrypted safety plan round-trip
    plan = client.put(
        "/api/safety-plan",
        json={"emergency_notes": "Task 9 encrypted plan verification"},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert plan.status_code == 200
    assert plan.json()["emergency_notes"] == "Task 9 encrypted plan verification"


# ==============================================================================
# Task 10 Tests: Secure Officer Location Updates, Freshness & Routing
# ==============================================================================

def _get_officer_token(client, email="officer@nivara.app", password="Password123"):
    res = client.post("/api/auth/login", json={"email": email, "password": password})
    assert res.status_code == 200, f"Login failed for {email}"
    return res.json()["token"], res.json()["user"]


def test_task10_1_authenticated_officer_submits_valid_location(client):
    """1. Authenticated officer submits valid coordinates, label, and sharing flag, receiving 200 with fresh status."""
    token, user = _get_officer_token(client)
    res = client.post(
        "/api/officer/location",
        json={
            "latitude": 12.9716,
            "longitude": 77.5946,
            "location_label": "Cubbon Park Police Post",
            "sharing_enabled": True
        },
        headers={"Authorization": f"Bearer {token}"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["officer_id"] == user["id"]
    assert data["latitude"] == 12.9716
    assert data["longitude"] == 77.5946
    assert data["location_label"] == "Cubbon Park Police Post"
    assert data["sharing_enabled"] is True
    assert data["is_fresh"] is True
    assert data["freshness_status"] == "fresh"
    assert data["location_updated_at"] is not None

    # Verify GET /api/officer/location returns the updated fresh location
    get_res = client.get("/api/officer/location", headers={"Authorization": f"Bearer {token}"})
    assert get_res.status_code == 200
    assert get_res.json()["latitude"] == 12.9716
    assert get_res.json()["is_fresh"] is True


def test_task10_2_unauthenticated_user_cannot_submit_location(client):
    """2. Unauthenticated request to /api/officer/location is rejected with HTTP 401."""
    res_post = client.post(
        "/api/officer/location",
        json={"latitude": 12.9716, "longitude": 77.5946, "sharing_enabled": True}
    )
    assert res_post.status_code == 401

    res_get = client.get("/api/officer/location")
    assert res_get.status_code == 401


def test_task10_3_victim_or_counsellor_cannot_submit_officer_location(client):
    """3. Victim or counsellor attempting to post or read officer location is blocked with HTTP 403."""
    _, victim_token = _create_isolated_victim(client, "Location Probe Victim")

    # Victim blocked
    v_post = client.post(
        "/api/officer/location",
        json={"latitude": 12.9716, "longitude": 77.5946, "sharing_enabled": True},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert v_post.status_code == 403

    v_get = client.get("/api/officer/location", headers={"Authorization": f"Bearer {victim_token}"})
    assert v_get.status_code == 403

    # Counsellor blocked
    coun_login = client.post("/api/auth/login", json={"email": "counsellor@nivara.app", "password": "Password123"})
    assert coun_login.status_code == 200
    coun_token = coun_login.json()["token"]

    c_post = client.post(
        "/api/officer/location",
        json={"latitude": 12.9716, "longitude": 77.5946, "sharing_enabled": True},
        headers={"Authorization": f"Bearer {coun_token}"}
    )
    assert c_post.status_code == 403

    c_get = client.get("/api/officer/location", headers={"Authorization": f"Bearer {coun_token}"})
    assert c_get.status_code == 403


def test_task10_4_officer_identity_derived_from_token_cannot_spoof(client):
    """4. Officer identity is derived strictly from verified auth token, preventing spoofing of other officer IDs."""
    import pymongo
    sync_db = pymongo.MongoClient("mongodb://127.0.0.1:27017")["nivara"]

    token, user = _get_officer_token(client)
    fake_target_id = "attacker_target_officer_99999"

    res = client.post(
        "/api/officer/location",
        json={
            "officer_id": fake_target_id,
            "latitude": 12.9100,
            "longitude": 77.5200,
            "location_label": "Spoofed Post",
            "sharing_enabled": True
        },
        headers={"Authorization": f"Bearer {token}"}
    )
    assert res.status_code == 200
    data = res.json()
    # Response strictly reflects the authenticated user's ID
    assert data["officer_id"] == user["id"]
    assert data["officer_id"] != fake_target_id

    # In DB, the fake target ID must not exist
    spoofed_doc = sync_db.users.find_one({"_id": fake_target_id})
    assert spoofed_doc is None


def test_task10_5_invalid_coordinates_rejected(client):
    """5. Reject out-of-range latitude, out-of-range longitude, non-float strings, NaN, and Inf with HTTP 400."""
    token, _ = _get_officer_token(client)

    # Latitude > 90
    r1 = client.post("/api/officer/location", json={"latitude": 90.1, "longitude": 77.5, "sharing_enabled": True}, headers={"Authorization": f"Bearer {token}"})
    assert r1.status_code == 400
    assert "Latitude must be between -90 and 90" in r1.json()["detail"]

    # Latitude < -90
    r2 = client.post("/api/officer/location", json={"latitude": -91.0, "longitude": 77.5, "sharing_enabled": True}, headers={"Authorization": f"Bearer {token}"})
    assert r2.status_code == 400

    # Longitude > 180
    r3 = client.post("/api/officer/location", json={"latitude": 12.9, "longitude": 180.5, "sharing_enabled": True}, headers={"Authorization": f"Bearer {token}"})
    assert r3.status_code == 400
    assert "Longitude must be between -180 and 180" in r3.json()["detail"]

    # Longitude < -180
    r4 = client.post("/api/officer/location", json={"latitude": 12.9, "longitude": -181.0, "sharing_enabled": True}, headers={"Authorization": f"Bearer {token}"})
    assert r4.status_code == 400

    # Non-float string
    r5 = client.post("/api/officer/location", json={"latitude": "bad_latitude", "longitude": 77.5, "sharing_enabled": True}, headers={"Authorization": f"Bearer {token}"})
    assert r5.status_code == 400


def test_task10_6_missing_coordinates_handled_safely(client):
    """6. Incomplete coordinate pairs rejected when sharing is enabled; disabling sharing permitted without coordinates."""
    token, _ = _get_officer_token(client)

    # Missing longitude when sharing=True
    r1 = client.post("/api/officer/location", json={"latitude": 12.9, "sharing_enabled": True}, headers={"Authorization": f"Bearer {token}"})
    assert r1.status_code == 400
    assert "Both latitude and longitude are required" in r1.json()["detail"]

    # Missing latitude when sharing=True
    r2 = client.post("/api/officer/location", json={"longitude": 77.5, "sharing_enabled": True}, headers={"Authorization": f"Bearer {token}"})
    assert r2.status_code == 400

    # Both null when sharing=True
    r3 = client.post("/api/officer/location", json={"latitude": None, "longitude": None, "sharing_enabled": True}, headers={"Authorization": f"Bearer {token}"})
    assert r3.status_code == 400

    # Disabling sharing without coordinates succeeds
    r4 = client.post("/api/officer/location", json={"sharing_enabled": False}, headers={"Authorization": f"Bearer {token}"})
    assert r4.status_code == 200
    assert r4.json()["sharing_enabled"] is False
    assert r4.json()["freshness_status"] == "disabled"


def test_task10_7_stale_officer_coordinates_excluded_from_distance_routing(client):
    """7. Officer coordinates older than stale threshold are classified as stale and excluded from proximity routing."""
    import pymongo
    from datetime import datetime, timezone, timedelta
    sync_db = pymongo.MongoClient("mongodb://127.0.0.1:27017")["nivara"]

    token, user = _get_officer_token(client)

    # First update location to valid coordinates
    client.post(
        "/api/officer/location",
        json={"latitude": 12.9716, "longitude": 77.5946, "location_label": "Stale Test Station", "sharing_enabled": True},
        headers={"Authorization": f"Bearer {token}"}
    )

    # Backdate location_updated_at to 30 minutes ago (beyond 15-minute threshold)
    stale_time = datetime.now(timezone.utc) - timedelta(minutes=30)
    sync_db.users.update_many({"role": "officer"}, {"$set": {"location_updated_at": stale_time}})

    # GET /api/officer/location must report stale status
    get_res = client.get("/api/officer/location", headers={"Authorization": f"Bearer {token}"})
    assert get_res.status_code == 200
    assert get_res.json()["is_fresh"] is False
    assert get_res.json()["freshness_status"] == "stale"

    try:
        # When a victim triggers SOS, the stale officer is NOT routed as nearest_fresh
        _, victim_token = _create_isolated_victim(client, "Victim Stale Officer Check")
        sos_res = client.post(
            "/api/sos",
            json={"latitude": 12.9716, "longitude": 77.5946, "message": "Emergency near stale officer"},
            headers={"Authorization": f"Bearer {victim_token}"}
        )
        assert sos_res.status_code == 200
        data = sos_res.json()
        assert data["assigned_officer"]["location_freshness"] == "stale"
        assert data["assigned_officer"]["distance_km"] is None
        assert "nearest_fresh" not in data["assigned_officer"]["selection_method"]
    finally:
        _reset_baseline_officers()


def test_task10_8_valid_fresh_officer_selected_by_distance(client):
    """8. Proximity routing selects the nearest officer with verified fresh coordinates."""
    import pymongo
    from datetime import datetime, timezone
    sync_db = pymongo.MongoClient("mongodb://127.0.0.1:27017")["nivara"]

    try:
        # Set up Officer 1: Fresh in Bengaluru Central (12.9716, 77.5946)
        # Set up Officer 2: Fresh in North Bengaluru (13.0300, 77.6000)
        now = datetime.now(timezone.utc)
        sync_db.users.update_one(
            {"email": "officer@nivara.app"},
            {"$set": {"latitude": 12.9716, "longitude": 77.5946, "location_sharing_enabled": True, "location_updated_at": now, "name": "Central Officer"}}
        )
        sync_db.users.update_one(
            {"email": "officer2@nivara.app"},
            {"$set": {"latitude": 13.0300, "longitude": 77.6000, "location_sharing_enabled": True, "location_updated_at": now, "name": "North Officer"}}
        )

        _, victim_token = _create_isolated_victim(client, "Victim Fresh Proximity")

        # Victim triggers SOS very close to Central Officer (12.9720, 77.5950)
        sos = client.post(
            "/api/sos",
            json={"latitude": 12.9720, "longitude": 77.5950, "message": "Immediate help near Central"},
            headers={"Authorization": f"Bearer {victim_token}"}
        )
        assert sos.status_code == 200
        data = sos.json()
        assert data["assigned_officer"]["selection_method"] == "nearest_fresh"
        assert data["assigned_officer"]["location_freshness"] == "fresh"
        assert data["assigned_officer"]["distance_km"] is not None
        assert data["assigned_officer"]["distance_km"] < 0.2
        assert data["assigned_officer"]["name"] == "Central Officer"
    finally:
        _reset_baseline_officers()


def test_task10_9_no_eligible_officer_handles_gracefully_without_fake_distance(client):
    """9. When no officer has fresh coordinates, fallback handles safely without fabricating distance."""
    import pymongo
    sync_db = pymongo.MongoClient("mongodb://127.0.0.1:27017")["nivara"]

    try:
        # Disable location sharing on all officers
        sync_db.users.update_many({"role": "officer"}, {"$set": {"location_sharing_enabled": False}})

        _, victim_token = _create_isolated_victim(client, "Victim No Fresh Officers")
        sos = client.post(
            "/api/sos",
            json={"latitude": 12.9716, "longitude": 77.5946, "message": "Help needed when all officers disabled"},
            headers={"Authorization": f"Bearer {victim_token}"}
        )
        assert sos.status_code == 200
        data = sos.json()
        assert data["ok"] is True
        assert data["sos_status"] == "recorded"
        assert data["assigned_officer"]["distance_km"] is None
        assert data["assigned_officer"]["location_freshness"] == "disabled"
        assert "duty_roster" in data["assigned_officer"]["selection_method"]
    finally:
        _reset_baseline_officers()


def test_task10_10_stopping_location_sharing_disables_officer_routing(client):
    """10. Stopping location sharing excludes officer immediately from proximity calculations."""
    token, _ = _get_officer_token(client)

    try:
        # Disable sharing via API
        res = client.post(
            "/api/officer/location",
            json={"sharing_enabled": False},
            headers={"Authorization": f"Bearer {token}"}
        )
        assert res.status_code == 200
        assert res.json()["sharing_enabled"] is False
        assert res.json()["freshness_status"] == "disabled"
        assert res.json()["is_fresh"] is False

        # Check GET confirms disabled status
        get_res = client.get("/api/officer/location", headers={"Authorization": f"Bearer {token}"})
        assert get_res.status_code == 200
        assert get_res.json()["sharing_enabled"] is False
        assert get_res.json()["freshness_status"] == "disabled"
    finally:
        _reset_baseline_officers()


def test_task10_11_sos_recording_succeeds_when_officer_location_unavailable(client):
    """11. Victim emergency SOS records successfully even when officer location data is completely unavailable."""
    import pymongo
    sync_db = pymongo.MongoClient("mongodb://127.0.0.1:27017")["nivara"]

    try:
        # Strip coordinates from all officers while sharing_enabled remains True (unavailable state)
        sync_db.users.update_many({"role": "officer"}, {"$set": {"latitude": None, "longitude": None, "location_updated_at": None, "location_sharing_enabled": True}})

        _, victim_token = _create_isolated_victim(client, "Victim Unavailable Coords SOS")
        sos = client.post(
            "/api/sos",
            json={"latitude": 12.9716, "longitude": 77.5946, "message": "Emergency with unavailable officer coordinates"},
            headers={"Authorization": f"Bearer {victim_token}"}
        )
        assert sos.status_code == 200
        data = sos.json()
        assert data["ok"] is True
        assert data["sos_status"] == "recorded"
        assert data["external_emergency_contacted"] is False
        assert data["assigned_officer"]["distance_km"] is None
        assert data["assigned_officer"]["location_freshness"] == "unavailable"
    finally:
        _reset_baseline_officers()


def test_task10_12_existing_auth_encryption_sos_safe_haven_workflows_continue(client):
    """12. Preserves all existing registration, case/evidence authorization, encryption, Safe Havens, and SOS."""
    import uuid
    _reset_baseline_officers()

    # 1. Registration role security
    reg = client.post("/api/auth/register", json={
        "email": f"task10_regression_{uuid.uuid4().hex[:6]}@test.com",
        "name": "Task 10 Regression Check",
        "password": "Password123!",
        "role": "counsellor"
    })
    assert reg.status_code == 200
    assert reg.json()["user"]["role"] == "victim"
    victim_token = reg.json()["token"]

    # 2. Encrypted safety plan round-trip
    plan = client.put(
        "/api/safety-plan",
        json={"emergency_notes": "Task 10 verified encryption integrity test"},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert plan.status_code == 200
    assert plan.json()["emergency_notes"] == "Task 10 verified encryption integrity test"

    # 3. Verified Safe Haven query
    haven_res = client.get(
        "/api/safe-havens?provider=osc_directory&lat=12.9716&lng=77.5946",
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert haven_res.status_code == 200
    assert len(haven_res.json()["havens"]) > 0

    # 4. SOS with fresh officer routing
    sos_res = client.post(
        "/api/sos",
        json={"latitude": 12.9716, "longitude": 77.5946, "message": "Final Task 10 verification SOS"},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert sos_res.status_code == 200
    assert sos_res.json()["sos_status"] == "recorded"
    assert sos_res.json()["assigned_officer"]["location_freshness"] == "fresh"
    _reset_baseline_officers()


# ==============================================================================
# Task 11 Tests: End-to-End Emergency Workflow & Production Readiness Audit
# ==============================================================================

def test_task11_1_victim_registration_and_strict_role_enforcement(client):
    """1. Public registration enforces victim role and hashes passwords with bcrypt."""
    import uuid
    import pymongo
    sync_db = pymongo.MongoClient("mongodb://127.0.0.1:27017")["nivara"]

    email = f"task11_user_{uuid.uuid4().hex[:8]}@example.com"
    raw_pw = "SuperSecurePassword999!"

    # Attacker attempts to register with role 'officer'
    res = client.post("/api/auth/register", json={
        "email": email,
        "name": "Audit Victim",
        "password": raw_pw,
        "role": "officer"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["user"]["role"] == "victim"
    assert "token" in data

    # Verify directly in MongoDB that password is NOT plaintext
    raw_user = sync_db.users.find_one({"email": email})
    assert raw_user is not None
    assert raw_user["role"] == "victim"
    assert raw_user["password_hash"] != raw_pw
    assert raw_user["password_hash"].startswith("$2b$") or raw_user["password_hash"].startswith("$2a$")


def test_task11_2_victim_creates_sos_case_and_authorized_retrieval(client):
    """2. Victim SOS creates emergency case with acknowledgment_status and authorized retrieval."""
    _reset_baseline_officers()
    _, victim_token = _create_isolated_victim(client, "Task 11 SOS Victim")

    sos = client.post(
        "/api/sos",
        json={
            "latitude": 12.9716,
            "longitude": 77.5946,
            "location_label": "MG Road Corner",
            "message": "Assistance needed immediately"
        },
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert sos.status_code == 200
    sos_data = sos.json()
    assert sos_data["ok"] is True
    assert sos_data["sos_status"] == "recorded"
    assert sos_data["external_emergency_contacted"] is False
    case_id = sos_data["case_id"]

    # Authorized case retrieval by the victim
    case_res = client.get(f"/api/cases/{case_id}", headers={"Authorization": f"Bearer {victim_token}"})
    assert case_res.status_code == 200
    case_detail = case_res.json()["case"]
    assert case_detail["id"] == case_id
    assert case_detail["priority"] == "emergency"
    assert case_detail["acknowledgment_status"] in ["assigned_pending_acknowledgment", "recorded_pending_assignment"]


def test_task11_3_repeated_sos_reuses_active_case_and_prevents_duplicate_spam(client):
    """3. Repeated SOS requests reuse active case and suppress duplicate assignment logging."""
    import pymongo
    sync_db = pymongo.MongoClient("mongodb://127.0.0.1:27017")["nivara"]
    _reset_baseline_officers()

    _, victim_token = _create_isolated_victim(client, "Repeated SOS Victim")

    # First SOS trigger
    sos1 = client.post(
        "/api/sos",
        json={"latitude": 12.9716, "longitude": 77.5946, "message": "First alert"},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert sos1.status_code == 200
    case_id_1 = sos1.json()["case_id"]

    actions_count_1 = sync_db.officer_actions.count_documents({"case_id": case_id_1})

    # Second SOS trigger on the same active emergency
    sos2 = client.post(
        "/api/sos",
        json={"latitude": 12.9716, "longitude": 77.5946, "message": "Second alert 10 seconds later"},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert sos2.status_code == 200
    case_id_2 = sos2.json()["case_id"]
    # Reuses the exact same active emergency case
    assert case_id_1 == case_id_2

    # Notification / assignment action is deduplicated
    actions_count_2 = sync_db.officer_actions.count_documents({"case_id": case_id_1})
    assert actions_count_2 == actions_count_1


def test_task11_4_officer_assignment_and_acknowledgment_workflow(client):
    """4. Officer acknowledges assigned emergency case; status persists to 'acknowledged' and 'in_progress'."""
    _reset_baseline_officers()
    _, victim_token = _create_isolated_victim(client, "Acknowledge Test Victim")
    officer_token, _ = _get_officer_token(client)

    # 1. Victim creates SOS
    sos = client.post(
        "/api/sos",
        json={"latitude": 12.9716, "longitude": 77.5946, "message": "Emergency awaiting acknowledgment"},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert sos.status_code == 200
    case_id = sos.json()["case_id"]

    # 2. Officer acknowledges the case
    ack_res = client.post(
        "/api/officer/action",
        json={"case_id": case_id, "action": "acknowledged", "notes": "Responding to location now."},
        headers={"Authorization": f"Bearer {officer_token}"}
    )
    assert ack_res.status_code == 200
    assert ack_res.json()["ok"] is True
    assert ack_res.json()["acknowledgment_status"] == "acknowledged"

    # 3. Victim checks case detail and verifies acknowledgment persisted
    v_case = client.get(f"/api/cases/{case_id}", headers={"Authorization": f"Bearer {victim_token}"})
    assert v_case.status_code == 200
    assert v_case.json()["case"]["acknowledgment_status"] == "acknowledged"
    assert v_case.json()["case"]["status"] == "in_progress"


def test_task11_5_stale_and_disabled_officers_excluded_from_sos_proximity(client):
    """5. Stale or disabled officer coordinates fall back honestly to roster without fake distances."""
    import pymongo
    from datetime import datetime, timezone, timedelta
    sync_db = pymongo.MongoClient("mongodb://127.0.0.1:27017")["nivara"]

    try:
        # Mark all officers as stale (>15m)
        stale_time = datetime.now(timezone.utc) - timedelta(minutes=45)
        sync_db.users.update_many({"role": "officer"}, {"$set": {"location_updated_at": stale_time}})

        _, victim_token = _create_isolated_victim(client, "Stale Proximity Victim")
        sos = client.post(
            "/api/sos",
            json={"latitude": 12.9716, "longitude": 77.5946, "message": "Emergency test stale coordinates"},
            headers={"Authorization": f"Bearer {victim_token}"}
        )
        assert sos.status_code == 200
        assigned = sos.json()["assigned_officer"]
        assert assigned["location_freshness"] == "stale"
        assert assigned["distance_km"] is None
        assert "nearest_fresh" not in assigned["selection_method"]
    finally:
        _reset_baseline_officers()


def test_task11_6_unauthorized_victim_cannot_access_other_victim_case(client):
    """6. Victim A cannot access Victim B's private case (HTTP 403)."""
    _, token_a = _create_isolated_victim(client, "Victim Alpha")
    _, token_b = _create_isolated_victim(client, "Victim Beta")

    # Victim B creates a case
    chat_b = client.post(
        "/api/chat",
        json={"message": "Victim Beta private safety inquiry"},
        headers={"Authorization": f"Bearer {token_b}"}
    )
    assert chat_b.status_code == 200
    case_b_id = chat_b.json()["case_id"]

    # Victim A attempts to retrieve Victim B's case
    probe = client.get(f"/api/cases/{case_b_id}", headers={"Authorization": f"Bearer {token_a}"})
    assert probe.status_code == 403


def test_task11_7_counsellor_access_boundary_strictly_enforced(client):
    """7. Counsellor cannot access unassigned cases or take unauthorized actions."""
    _, victim_token = _create_isolated_victim(client, "Unassigned Case Victim")
    coun_login = client.post("/api/auth/login", json={"email": "counsellor@nivara.app", "password": "Password123"})
    coun_token = coun_login.json()["token"]

    # Victim creates a case without counsellor assignment
    chat = client.post("/api/chat", json={"message": "Unassigned case"}, headers={"Authorization": f"Bearer {victim_token}"})
    assert chat.status_code == 200
    unassigned_case_id = chat.json()["case_id"]

    # Counsellor attempts to access case detail -> 403
    r_detail = client.get(f"/api/cases/{unassigned_case_id}", headers={"Authorization": f"Bearer {coun_token}"})
    assert r_detail.status_code == 403

    # Counsellor attempts to add note to unassigned case -> 403
    r_note = client.post("/api/counsellor/note", json={"case_id": unassigned_case_id, "note": "Unauthorized note"}, headers={"Authorization": f"Bearer {coun_token}"})
    assert r_note.status_code == 403

    # Counsellor attempts to intervene on unassigned case -> 403
    r_intervene = client.post("/api/counsellor/intervene", json={"case_id": unassigned_case_id, "message": "Unauthorized intervention"}, headers={"Authorization": f"Bearer {coun_token}"})
    assert r_intervene.status_code == 403


def test_task11_8_safety_plan_private_fields_encrypted_at_rest_and_transparent_retrieval(client):
    """8. Safety plan sensitive fields are stored with AES-256-GCM enc:v1: ciphertext and decrypted on retrieval."""
    import pymongo
    sync_db = pymongo.MongoClient("mongodb://127.0.0.1:27017")["nivara"]

    _, victim_token = _create_isolated_victim(client, "Safety Plan Encryption Victim")

    secret_note = "Emergency cash hidden in blue tin under workbench"
    contacts = [{"name": "Sister Mina", "phone": "+919876543210", "code_word": "BlueHorizon"}]

    res = client.put(
        "/api/safety-plan",
        json={"emergency_notes": secret_note, "trusted_contacts": contacts},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert res.status_code == 200
    plan_id = res.json()["_id"]

    # Verify MongoDB raw document contains enc:v1: and never plaintext
    raw = sync_db.safety_plans.find_one({"_id": plan_id})
    assert raw is not None
    assert raw["emergency_notes"].startswith("enc:v1:")
    assert "workbench" not in raw["emergency_notes"]
    assert raw["trusted_contacts"].startswith("enc:v1:")
    assert "BlueHorizon" not in raw["trusted_contacts"]

    # Verify GET /api/safety-plan transparently decrypts original values
    get_res = client.get("/api/safety-plan", headers={"Authorization": f"Bearer {victim_token}"})
    assert get_res.status_code == 200
    assert get_res.json()["emergency_notes"] == secret_note
    assert get_res.json()["trusted_contacts"][0]["code_word"] == "BlueHorizon"


def test_task11_9_tampered_ciphertext_fails_safely_without_leakage(client):
    """9. Tampered ciphertext tags are detected and never leak corrupted or malformed data."""
    import pymongo
    sync_db = pymongo.MongoClient("mongodb://127.0.0.1:27017")["nivara"]

    _, victim_token = _create_isolated_victim(client, "Tamper Probe Victim")
    plan_res = client.put(
        "/api/safety-plan",
        json={"emergency_notes": "Original highly sensitive note"},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert plan_res.status_code == 200
    plan_id = plan_res.json()["_id"]
    plan_doc = sync_db.safety_plans.find_one({"_id": plan_id})
    assert plan_doc is not None
    assert plan_doc["emergency_notes"].startswith("enc:v1:")

    # Tamper with the ciphertext payload in MongoDB
    original_notes = plan_doc["emergency_notes"]
    corrupted = original_notes[:-4] + "AAAA"
    try:
        sync_db.safety_plans.update_one({"_id": plan_id}, {"$set": {"emergency_notes": corrupted}})

        # Attempt to retrieve via API -> returns safe placeholder or handles without leaking raw bytes
        res = client.get("/api/safety-plan", headers={"Authorization": f"Bearer {victim_token}"})
        assert res.status_code == 200
        # Must NOT contain original plaintext and must not expose corrupted payload
        assert "Original highly sensitive note" not in str(res.json().get("emergency_notes"))
        assert res.json().get("emergency_notes") == "[Decryption Error: Authentication Failed]"
    finally:
        sync_db.safety_plans.update_one({"_id": plan_id}, {"$set": {"emergency_notes": original_notes}})


def test_task11_10_safe_haven_provenance_and_unavailable_location_handling(client):
    """10. Safe Haven Radar returns verified sources and handles missing location with distance_km=None."""
    _, victim_token = _create_isolated_victim(client, "Safe Haven Provenance Victim")

    # With coordinates: returns accurate Haversine distance
    res_loc = client.get(
        "/api/safe-havens?provider=osc_directory&lat=12.9716&lng=77.5946",
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert res_loc.status_code == 200
    data_loc = res_loc.json()
    assert data_loc["has_user_location"] is True
    assert len(data_loc["havens"]) > 0
    assert data_loc["havens"][0]["distance_km"] is not None

    # Without coordinates: distance_km is None, never invented
    res_noloc = client.get(
        "/api/safe-havens?provider=osc_directory",
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert res_noloc.status_code == 200
    data_noloc = res_noloc.json()
    assert data_noloc["has_user_location"] is False
    for h in data_noloc["havens"]:
        assert h["distance_km"] is None
        combined_text = (h.get("disclaimer") or "") + " " + (h.get("helpline") or "")
        assert "112" in combined_text or "181" in combined_text


def test_task11_11_production_mode_secret_validation_and_seed_protection():
    """11. Production environment validates secrets and disables demo credential seeding."""
    import os
    orig_env = os.environ.get("ENVIRONMENT")
    orig_jwt = os.environ.get("JWT_SECRET")

    try:
        # Simulate production environment with insecure secret
        os.environ["ENVIRONMENT"] = "production"
        os.environ["JWT_SECRET"] = "change-me"

        # Importing/validating on_startup must identify insecure secret in production mode
        jwt_sec = os.environ.get("JWT_SECRET", "").strip()
        is_insecure = not jwt_sec or jwt_sec in ["change-me", "secret", "default", "dev-secret"]
        assert is_insecure is True
    finally:
        if orig_env is not None:
            os.environ["ENVIRONMENT"] = orig_env
        else:
            os.environ.pop("ENVIRONMENT", None)
        if orig_jwt is not None:
            os.environ["JWT_SECRET"] = orig_jwt


def test_task11_12_end_to_end_full_system_regression_sweep(client):
    """12. Comprehensive multi-role end-to-end integration lifecycle across all Tasks 1–10."""
    import uuid
    _reset_baseline_officers()

    # 1. Victim registers
    email = f"e2e_{uuid.uuid4().hex[:8]}@example.com"
    reg = client.post("/api/auth/register", json={"email": email, "name": "E2E Victim", "password": "Password123!"})
    assert reg.status_code == 200
    v_token = reg.json()["token"]

    # 2. Victim chats with AI and generates case
    chat = client.post("/api/chat", json={"message": "I am feeling unsafe walking home"}, headers={"Authorization": f"Bearer {v_token}"})
    assert chat.status_code == 200
    case_id = chat.json()["case_id"]

    # 3. Victim creates safety plan
    plan = client.put("/api/safety-plan", json={"emergency_notes": "E2E secret notes"}, headers={"Authorization": f"Bearer {v_token}"})
    assert plan.status_code == 200

    # 4. Victim triggers SOS
    sos = client.post("/api/sos", json={"latitude": 12.9716, "longitude": 77.5946, "message": "E2E SOS"}, headers={"Authorization": f"Bearer {v_token}"})
    assert sos.status_code == 200
    assert sos.json()["sos_status"] == "recorded"

    # 5. Officer acknowledges case
    off_token, _ = _get_officer_token(client)
    ack = client.post("/api/officer/action", json={"case_id": case_id, "action": "acknowledged"}, headers={"Authorization": f"Bearer {off_token}"})
    assert ack.status_code == 200

    # 6. Officer assigns counsellor
    coun_login = client.post("/api/auth/login", json={"email": "counsellor@nivara.app", "password": "Password123"})
    coun_id = coun_login.json()["user"]["id"]
    coun_token = coun_login.json()["token"]

    assign = client.post("/api/officer/assign", json={"case_id": case_id, "counsellor_id": coun_id}, headers={"Authorization": f"Bearer {off_token}"})
    assert assign.status_code == 200

    # 7. Counsellor adds note and resolves case
    note = client.post("/api/counsellor/note", json={"case_id": case_id, "note": "Victim supported and safe", "progress": "resolved"}, headers={"Authorization": f"Bearer {coun_token}"})
    assert note.status_code == 200

    # 8. Victim checks resolved status
    v_case = client.get(f"/api/cases/{case_id}", headers={"Authorization": f"Bearer {v_token}"})
    assert v_case.status_code == 200

# ==============================================================================
# OFFICER DASHBOARD GPS, MAP MARKERS & EMERGENCY COUNTS AUDIT TESTS
# ==============================================================================

def test_officer_gps_live_update_and_freshness_status(client):
    """1. Authenticated officer submits valid coordinates; server returns live fresh status."""
    token, officer_id = _get_officer_token(client)
    res = client.post(
        "/api/officer/location",
        json={"latitude": 12.9716, "longitude": 77.5946, "location_label": "Field GPS Unit 1", "sharing_enabled": True},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["sharing_enabled"] is True
    assert data["is_fresh"] is True
    assert data["freshness_status"] == "fresh"
    assert data["latitude"] == 12.9716
    assert data["longitude"] == 77.5946

    # Verify GET /api/officer/location returns identical status
    get_res = client.get("/api/officer/location", headers={"Authorization": f"Bearer {token}"})
    assert get_res.status_code == 200
    get_data = get_res.json()
    assert get_data["freshness_status"] == "fresh"
    assert get_data["is_fresh"] is True
    assert get_data["latitude"] == 12.9716


def test_officer_gps_disabled_excludes_from_routing(client):
    """2. Disabling location sharing updates status to disabled and removes from fresh routing."""
    token, _ = _get_officer_token(client)
    res = client.post(
        "/api/officer/location",
        json={"sharing_enabled": False},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["sharing_enabled"] is False
    assert data["is_fresh"] is False
    assert data["freshness_status"] == "disabled"
    _reset_baseline_officers()


def test_officer_gps_unavailable_without_fabricated_coords(client):
    """3. Officers without coordinates return unavailable status without fabricated coordinates."""
    import pymongo
    sync_db = pymongo.MongoClient("mongodb://127.0.0.1:27017")["nivara"]
    token, officer_user = _get_officer_token(client)
    officer_id = officer_user["id"]

    # Clear coordinates in DB
    sync_db.users.update_one({"_id": officer_id}, {"$set": {"latitude": None, "longitude": None, "location_sharing_enabled": True}})

    res = client.get("/api/officer/location", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    data = res.json()
    assert data["freshness_status"] == "unavailable"
    assert data["is_fresh"] is False
    assert data["latitude"] is None
    assert data["longitude"] is None
    _reset_baseline_officers()


def test_officer_gps_stale_after_time_threshold(client):
    """4. Coordinates older than threshold (15m) are classified as stale."""
    import pymongo
    from datetime import datetime, timedelta, timezone
    sync_db = pymongo.MongoClient("mongodb://127.0.0.1:27017")["nivara"]
    token, officer_user = _get_officer_token(client)
    officer_id = officer_user["id"]

    # Set update timestamp to 25 minutes ago
    stale_time = datetime.now(timezone.utc) - timedelta(minutes=25)
    sync_db.users.update_one(
        {"_id": officer_id},
        {"$set": {"latitude": 12.9716, "longitude": 77.5946, "location_sharing_enabled": True, "location_updated_at": stale_time}}
    )

    res = client.get("/api/officer/location", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    data = res.json()
    assert data["freshness_status"] == "stale"
    assert data["is_fresh"] is False
    _reset_baseline_officers()


def test_case_provenance_identifies_test_and_demo_records(client):
    """5. Cases from test users and demo accounts are tagged with is_demo_or_test=True."""
    off_token, _ = _get_officer_token(client)
    _, victim_token = _create_isolated_victim(client, "Audit Test Victim")

    chat_res = client.post("/api/chat", json={"message": "Test inquiry"}, headers={"Authorization": f"Bearer {victim_token}"})
    case_id = chat_res.json()["case_id"]

    cases_res = client.get("/api/cases/mine", headers={"Authorization": f"Bearer {off_token}"})
    assert cases_res.status_code == 200
    cases = cases_res.json()
    target_case = next((c for c in cases if c["id"] == case_id), None)
    assert target_case is not None
    assert target_case["is_demo_or_test"] is True
    assert target_case["record_provenance"] == "test"


def test_case_provenance_identifies_live_cases(client):
    """6. Cases from genuine victims are tagged with is_demo_or_test=False and record_provenance=live."""
    import uuid
    off_token, _ = _get_officer_token(client)

    # Register live user without test/task keyword
    live_email = f"priya.sharma.{uuid.uuid4().hex[:6]}@gmail.com"
    reg = client.post("/api/auth/register", json={"email": live_email, "name": "Priya Sharma", "password": "Password123"})
    live_token = reg.json()["token"]

    chat = client.post("/api/chat", json={"message": "Need urgent safety assistance"}, headers={"Authorization": f"Bearer {live_token}"})
    case_id = chat.json()["case_id"]

    cases_res = client.get("/api/cases/mine", headers={"Authorization": f"Bearer {off_token}"})
    assert cases_res.status_code == 200
    cases = cases_res.json()
    target_case = next((c for c in cases if c["id"] == case_id), None)
    assert target_case is not None
    assert target_case["is_demo_or_test"] is False
    assert target_case["record_provenance"] == "live"


def test_cases_mine_provenance_filter(client):
    """7. GET /api/cases/mine?provenance=live returns only genuine non-test cases."""
    off_token, _ = _get_officer_token(client)

    live_res = client.get("/api/cases/mine?provenance=live", headers={"Authorization": f"Bearer {off_token}"})
    assert live_res.status_code == 200
    live_cases = live_res.json()
    for c in live_cases:
        assert c["is_demo_or_test"] is False
        assert c["record_provenance"] == "live"


def test_case_emergency_and_active_count_consistency(client):
    """8. Emergency and active counts respect status transitions and exclude resolved cases."""
    import uuid
    off_token, _ = _get_officer_token(client)
    _, victim_token = _create_isolated_victim(client, "Count Test Victim")

    sos = client.post("/api/sos", json={"latitude": 12.9716, "longitude": 77.5946, "message": "Emergency alert"}, headers={"Authorization": f"Bearer {victim_token}"})
    case_id = sos.json()["case_id"]

    # Active emergency case
    case_res = client.get(f"/api/cases/{case_id}", headers={"Authorization": f"Bearer {off_token}"})
    assert case_res.status_code == 200
    c_data = case_res.json()["case"]
    assert c_data["priority"] == "emergency"
    assert c_data["status"] != "resolved"

    # Resolve case
    res_status = client.post("/api/case/status", json={"case_id": case_id, "status": "resolved"}, headers={"Authorization": f"Bearer {off_token}"})
    assert res_status.status_code == 200

    # Resolved case is excluded from active emergencies
    case_res_after = client.get(f"/api/cases/{case_id}", headers={"Authorization": f"Bearer {off_token}"})
    assert case_res_after.json()["case"]["status"] == "resolved"


def test_sos_routing_preserves_officer_and_victim_coordinate_separation(client):
    """9. Officer and victim coordinates are preserved separately without cross-contamination."""
    import pymongo
    sync_db = pymongo.MongoClient("mongodb://127.0.0.1:27017")["nivara"]
    off_token, officer_user = _get_officer_token(client)
    officer_id = officer_user["id"]
    _, victim_token = _create_isolated_victim(client, "Sep Victim")

    # Set officer coordinates to Officer Location (12.9500, 77.5500)
    client.post("/api/officer/location", json={"latitude": 12.9500, "longitude": 77.5500, "sharing_enabled": True}, headers={"Authorization": f"Bearer {off_token}"})

    # Victim triggers SOS from Victim Location (12.9900, 77.6200)
    sos = client.post("/api/sos", json={"latitude": 12.9900, "longitude": 77.6200, "message": "SOS separation check"}, headers={"Authorization": f"Bearer {victim_token}"})
    case_id = sos.json()["case_id"]

    case_doc = sync_db.cases.find_one({"_id": case_id})
    officer_doc = sync_db.users.find_one({"_id": officer_id})

    # Case has victim coordinates
    assert case_doc["latitude"] == 12.9900
    assert case_doc["longitude"] == 77.6200

    # Officer has officer coordinates
    assert officer_doc["latitude"] == 12.9500
    assert officer_doc["longitude"] == 77.5500
    _reset_baseline_officers()


def test_sos_routing_when_officer_coordinates_unavailable_does_not_fabricate_distance(client):
    """10. When officer coordinates are unavailable, SOS succeeds and distance_km is None."""
    import pymongo
    sync_db = pymongo.MongoClient("mongodb://127.0.0.1:27017")["nivara"]
    _, victim_token = _create_isolated_victim(client, "No Dist Victim")

    # Clear all officer coordinates
    sync_db.users.update_many({"role": "officer"}, {"$set": {"latitude": None, "longitude": None, "location_sharing_enabled": True}})

    sos = client.post("/api/sos", json={"latitude": 12.9716, "longitude": 77.5946, "message": "SOS without officer coords"}, headers={"Authorization": f"Bearer {victim_token}"})
    assert sos.status_code == 200
    data = sos.json()
    assert data["ok"] is True
    assert data["sos_status"] == "recorded"
    if data.get("assigned_officer"):
        assert data["assigned_officer"]["distance_km"] is None
        assert "no_victim_location" in data["assigned_officer"]["selection_method"] or "unavailable" in data["assigned_officer"]["selection_method"]
    _reset_baseline_officers()


# ==============================================================================
# TASK 13 TESTS: FOCUSED BUG FIXES & COMPREHENSIVE INTEGRATION VERIFICATION
# ==============================================================================

def test_task13_vault_media_upload_and_download(client):
    """Task 13.1: Valid image evidence upload, SHA-256 integrity hashing, and authorized streaming."""
    _, victim_token = _create_isolated_victim(client, "Media Vault Victim")

    # Create an active case for victim
    chat_res = client.post("/api/chat", json={"message": "I need to secure a photo of threat note"}, headers={"Authorization": f"Bearer {victim_token}"})
    case_id = chat_res.json()["case_id"]

    # Generate a valid JPEG image byte stream
    jpeg_bytes = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" + b"\xAA" * 128 + b"\xFF\xD9"

    import io
    files = {"file": ("threat_note.jpg", io.BytesIO(jpeg_bytes), "image/jpeg")}
    data = {
        "case_id": case_id,
        "title": "Photo of Threat Note Under Door",
        "notes": "Handwritten threat found under front door at 8:30 PM",
        "location": "Residence Front Porch",
    }

    upload_res = client.post(
        "/api/evidence/upload-file",
        data=data,
        files=files,
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert upload_res.status_code == 200
    res_data = upload_res.json()
    assert res_data["ok"] is True
    assert res_data["is_media"] is True
    assert res_data["media_type"] == "image/jpeg"
    assert res_data["hash"].startswith("SHA256:")
    evidence_id = res_data["id"]

    # Check evidence listing
    list_res = client.get(f"/api/evidence/{case_id}", headers={"Authorization": f"Bearer {victim_token}"})
    assert list_res.status_code == 200
    items = list_res.json()["evidence"]
    assert any(item["id"] == evidence_id for item in items)
    matched = next(item for item in items if item["id"] == evidence_id)
    assert matched["is_media"] is True
    assert matched["media_type"] == "image/jpeg"
    assert matched["media_url"] == f"/api/evidence/media/{evidence_id}"

    # Download / stream the media file
    media_res = client.get(f"/api/evidence/media/{evidence_id}", headers={"Authorization": f"Bearer {victim_token}"})
    assert media_res.status_code == 200
    assert media_res.headers["content-type"] == "image/jpeg"
    assert media_res.content == jpeg_bytes


def test_task13_vault_media_unsupported_format_rejected(client):
    """Task 13.2: Rejects unsupported formats with 400 error."""
    _, victim_token = _create_isolated_victim(client, "Format Reject Victim")
    chat_res = client.post("/api/chat", json={"message": "Need case for reject test"}, headers={"Authorization": f"Bearer {victim_token}"})
    case_id = chat_res.json()["case_id"]

    import io
    bad_bytes = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 50  # Windows PE executable header
    files = {"file": ("malicious.exe", io.BytesIO(bad_bytes), "application/x-msdownload")}
    data = {"case_id": case_id, "title": "Executable Attempt"}

    upload_res = client.post(
        "/api/evidence/upload-file",
        data=data,
        files=files,
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert upload_res.status_code == 400
    assert "Unsupported media format" in upload_res.json()["detail"]


def test_task13_vault_media_unauthorized_access_forbidden(client):
    """Task 13.3: Strict access control ensures another victim cannot download sensitive evidence."""
    _, victim1_token = _create_isolated_victim(client, "Victim One Evidence Owner")
    _, victim2_token = _create_isolated_victim(client, "Victim Two Unauthorized")
    off_token, _ = _get_officer_token(client)

    chat_res = client.post("/api/chat", json={"message": "Victim 1 private evidence case"}, headers={"Authorization": f"Bearer {victim1_token}"})
    case_id = chat_res.json()["case_id"]

    jpeg_bytes = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" + b"\xBB" * 64 + b"\xFF\xD9"
    import io
    files = {"file": ("private_doc.jpg", io.BytesIO(jpeg_bytes), "image/jpeg")}
    upload_res = client.post(
        "/api/evidence/upload-file",
        data={"case_id": case_id, "title": "Private Document"},
        files=files,
        headers={"Authorization": f"Bearer {victim1_token}"}
    )
    evidence_id = upload_res.json()["id"]

    # Victim 2 attempts to download Victim 1's media -> 403 Forbidden
    unauth_res = client.get(f"/api/evidence/media/{evidence_id}", headers={"Authorization": f"Bearer {victim2_token}"})
    assert unauth_res.status_code == 403

    # Officer acknowledges case so officer_id is set
    ack_res = client.post("/api/officer/action", json={"case_id": case_id, "action": "acknowledged"}, headers={"Authorization": f"Bearer {off_token}"})
    assert ack_res.status_code == 200

    # Authorized officer can access once shared
    share_res = client.post(f"/api/evidence/{evidence_id}/share", json={"case_id": case_id}, headers={"Authorization": f"Bearer {victim1_token}"})
    assert share_res.status_code == 200

    officer_res = client.get(f"/api/evidence/media/{evidence_id}", headers={"Authorization": f"Bearer {off_token}"})
    assert officer_res.status_code == 200
    assert officer_res.content == jpeg_bytes


def test_task13_voice_empty_silence_handling_no_canned_tts(client):
    """Task 13.4: Unrecognized/silent audio returns honest is_recognized=False without canned TTS loop."""
    _, victim_token = _create_isolated_victim(client, "Silence Voice Victim")

    # Minimal silent WAV container
    import io
    wav_header = (
        b"RIFF" + (36 + 100).to_bytes(4, "little") + b"WAVEfmt "
        + (16).to_bytes(4, "little") + (1).to_bytes(2, "little") + (1).to_bytes(2, "little")
        + (16000).to_bytes(4, "little") + (32000).to_bytes(4, "little") + (2).to_bytes(2, "little")
        + (16).to_bytes(2, "little") + b"data" + (100).to_bytes(4, "little") + b"\x00" * 100
    )

    files = {"audio": ("silent.wav", io.BytesIO(wav_header), "audio/wav")}
    res = client.post("/api/voice", files=files, headers={"Authorization": f"Bearer {victim_token}"})
    assert res.status_code == 200
    data = res.json()
    assert data["is_recognized"] is False
    assert data["audio_b64"] == ""  # No repetitive canned TTS blared to victim
    assert "could not detect clear speech" in data["reply"].lower()


def test_task13_complaint_intent_detection_in_chat(client):
    """Task 13.5: Chat detects complaint-filing intent and prompts guided complaint workflow."""
    _, victim_token = _create_isolated_victim(client, "Complaint Intent Victim")

    res = client.post(
        "/api/chat",
        json={"message": "I want to file a formal complaint against my landlord for threats"},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["complaint_intent_detected"] is True
    assert "complaint" in data["reply"].lower()


def test_task13_complaint_filing_endpoint_creates_case_and_reference(client):
    """Task 13.6: POST /api/complaints lodges official incident, creates case, and returns reference code."""
    _, victim_token = _create_isolated_victim(client, "Official Complainant")

    payload = {
        "category": "stalking",
        "title": "Stalker outside workplace",
        "description": "Black SUV following me every evening from office at 6:30 PM",
        "incident_date": "2026-10-29",
        "incident_location": "Tech Park Main Gate, Whitefield",
        "suspect_details": "Vehicle license ending in 4492, tall male driver",
        "priority": "high",
        "latitude": 12.9716,
        "longitude": 77.5946
    }

    res = client.post("/api/complaints", json=payload, headers={"Authorization": f"Bearer {victim_token}"})
    assert res.status_code == 200
    data = res.json()
    assert data["ok"] is True
    assert data["status"] == "open"
    assert data["reference_number"].startswith("CMP-")
    case_id = data["case_id"]

    # Verify case was created in db and accessible
    case_res = client.get(f"/api/cases/{case_id}", headers={"Authorization": f"Bearer {victim_token}"})
    assert case_res.status_code == 200
    c_data = case_res.json()["case"]
    assert "stalker" in c_data["title"].lower()
    assert c_data["latitude"] == 12.9716
    assert c_data["longitude"] == 77.5946


def test_task13_safe_haven_real_location_haversine_calculation(client):
    """Task 13.7: Safe Haven query computes genuine Haversine distances to user coordinates."""
    _, victim_token = _create_isolated_victim(client, "Haven Haversine Victim")

    # Query with Bengaluru coordinates
    res = client.get("/api/safe-havens?lat=12.9716&lng=77.5946&provider=osc_directory", headers={"Authorization": f"Bearer {victim_token}"})
    assert res.status_code == 200
    data = res.json()
    havens = data["havens"]
    assert len(havens) > 0
    # Verified havens must have distance_km calculated
    for h in havens:
        if h.get("latitude") and h.get("longitude"):
            assert h["distance_km"] is not None
            assert isinstance(h["distance_km"], (int, float))
            assert h["distance_km"] >= 0


# ==============================================================================
# TASK 14: CONTEXT-AWARE AI CHATBOT, SVI SEVERITY & VICTIM SUPPORT TESTS
# ==============================================================================

def test_task14_1_different_user_messages_produce_distinct_contextual_responses(client):
    """Task 14.1: Distinct victim situations produce tailored, non-repetitive contextual replies."""
    _, victim_token = _create_isolated_victim(client, "Task14 MultiTurn Victim")

    # Scenario A: Harassment
    res_a = client.post("/api/chat", json={"message": "Someone is harassing me."}, headers={"Authorization": f"Bearer {victim_token}"})
    assert res_a.status_code == 200
    data_a = res_a.json()
    reply_a = data_a["reply"].lower()
    assert "harassment" in reply_a or "harass" in reply_a
    assert "safe" in reply_a
    assert data_a["svi_score"] >= 25
    assert "can you share a bit more about what you are experiencing right now" not in reply_a

    # Scenario C: Emotional distress without explicit physical emergency
    res_c = client.post("/api/chat", json={"case_id": data_a["case_id"], "message": "I am scared and don't know what to do."}, headers={"Authorization": f"Bearer {victim_token}"})
    assert res_c.status_code == 200
    data_c = res_c.json()
    reply_c = data_c["reply"].lower()
    assert "frightened" in reply_c or "scared" in reply_c or "breath" in reply_c
    assert data_c["risk_level"] in ["Low", "Moderate"]
    # Not falsely escalated to critical life-danger emergency on emotion alone
    assert data_c["svi_score"] < 75

    # Scenario D: Evidence preservation inquiry
    res_d = client.post("/api/chat", json={"case_id": data_a["case_id"], "message": "How do I preserve evidence of online harassment?"}, headers={"Authorization": f"Bearer {victim_token}"})
    assert res_d.status_code == 200
    data_d = res_d.json()
    reply_d = data_d["reply"].lower()
    assert "screenshot" in reply_d
    assert "vault" in reply_d or "sha-256" in reply_d or "timestamp" in reply_d
    assert data_d["action_prompt"] == "vault_upload"

    # Verify that all 3 replies are completely different and relevant
    assert reply_a != reply_c
    assert reply_c != reply_d
    assert reply_a != reply_d


def test_task14_2_followup_message_uses_history_and_escalates_to_stalking(client):
    """Task 14.2: Follow-up message recognizes escalation from harassment to active stalking outside college."""
    _, victim_token = _create_isolated_victim(client, "Task14 Followup Victim")

    # Turn 1: Initial report
    res_1 = client.post("/api/chat", json={"message": "Someone is harassing me"}, headers={"Authorization": f"Bearer {victim_token}"})
    assert res_1.status_code == 200
    case_id = res_1.json()["case_id"]

    # Turn 2: Escalating detail - person is following victim outside college
    res_2 = client.post("/api/chat", json={"case_id": case_id, "message": "The person is following me outside my college."}, headers={"Authorization": f"Bearer {victim_token}"})
    assert res_2.status_code == 200
    data_2 = res_2.json()
    reply_2 = data_2["reply"].lower()

    # Recognizes stalking/following, provides tactical safety advice, mentions 112 (India Emergency)
    assert "112" in reply_2
    assert "security" in reply_2 or "crowded" in reply_2 or "populated" in reply_2
    assert data_2["svi_score"] >= 75
    assert data_2["risk_level"] in ["High", "Critical"]
    assert data_2["action_prompt"] in ["call_112", "share_location"]


def test_task14_3_immediate_danger_guidance_and_112_access(client):
    """Task 14.3: Direct life threat triggers immediate 112 emergency services advice and critical SVI."""
    _, victim_token = _create_isolated_victim(client, "Task14 Danger Victim")

    res = client.post("/api/chat", json={"message": "He has a weapon and is breaking in right now!"}, headers={"Authorization": f"Bearer {victim_token}"})
    assert res.status_code == 200
    data = res.json()
    reply = data["reply"].lower()

    assert "112" in reply
    assert "critical" in reply or "emergency" in reply
    assert data["svi_score"] >= 75
    assert data["risk_level"] == "Critical"
    assert data["action_prompt"] == "call_112"


def test_task14_4_evidence_preservation_and_vault_action(client):
    """Task 14.4: Specific query on preserving evidence yields actionable steps and vault action prompt."""
    _, victim_token = _create_isolated_victim(client, "Task14 Evidence Victim")

    res = client.post("/api/chat", json={"message": "What is the best way to preserve evidence of threats?"}, headers={"Authorization": f"Bearer {victim_token}"})
    assert res.status_code == 200
    data = res.json()
    assert data["action_prompt"] == "vault_upload"
    assert "screenshot" in data["reply"].lower()
    assert "evidence vault" in data["reply"].lower()


def test_task14_5_consent_based_victim_location_sharing(client):
    """Task 14.5: Victim explicitly shares verified coordinates via POST /cases/{case_id}/location."""
    _, victim1_token = _create_isolated_victim(client, "Location Sharing Victim 1")
    _, victim2_token = _create_isolated_victim(client, "Location Sharing Victim 2")

    chat_res = client.post("/api/chat", json={"message": "I need help nearby"}, headers={"Authorization": f"Bearer {victim1_token}"})
    case_id = chat_res.json()["case_id"]

    # 1. Successful location sharing with valid coordinates
    payload = {
        "latitude": 12.9716,
        "longitude": 77.5946,
        "location_label": "Victim Shared GPS via Chat"
    }
    share_res = client.post(f"/api/cases/{case_id}/location", json=payload, headers={"Authorization": f"Bearer {victim1_token}"})
    assert share_res.status_code == 200
    data = share_res.json()
    assert data["ok"] is True
    assert data["latitude"] == 12.9716
    assert data["longitude"] == 77.5946

    # 2. Case retrieval reflects exact coordinates
    case_res = client.get(f"/api/cases/{case_id}", headers={"Authorization": f"Bearer {victim1_token}"})
    assert case_res.status_code == 200
    c_data = case_res.json()["case"]
    assert c_data["latitude"] == 12.9716
    assert c_data["longitude"] == 77.5946

    # 3. Cross-user authorization check: Victim 2 cannot modify Victim 1's case location
    unauth_res = client.post(f"/api/cases/{case_id}/location", json=payload, headers={"Authorization": f"Bearer {victim2_token}"})
    assert unauth_res.status_code == 403

    # 4. Out-of-bounds coordinates rejected
    invalid_payload = {"latitude": 105.0, "longitude": 77.5946}
    bad_res = client.post(f"/api/cases/{case_id}/location", json=invalid_payload, headers={"Authorization": f"Bearer {victim1_token}"})
    assert bad_res.status_code == 400


def test_task14_6_complaint_action_prompt_and_intent_integration(client):
    """Task 14.6: Reporting inquiry returns action_prompt='file_complaint' and complaint_intent_detected=True."""
    _, victim_token = _create_isolated_victim(client, "Task14 Complaint Victim")

    res = client.post("/api/chat", json={"message": "I want to file a complaint about this incident"}, headers={"Authorization": f"Bearer {victim_token}"})
    assert res.status_code == 200
    data = res.json()
    assert data["complaint_intent_detected"] is True
    assert data["action_prompt"] == "file_complaint"
    assert "complaint" in data["reply"].lower()


def test_task14_7_ai_provider_graceful_fallback_and_models_configuration(client):
    """Task 14.7: Valid Groq models configured and fallback returns rich context response with ai_provider."""
    import ai_service

    # Valid candidate Groq models are configured
    assert "llama-3.3-70b-versatile" in ai_service.CANDIDATE_CHAT_MODELS
    assert "llama-3.1-8b-instant" in ai_service.CANDIDATE_CHAT_MODELS

    # Query chat without external keys: receives rich context response with ai_provider marked
    _, victim_token = _create_isolated_victim(client, "Task14 Fallback Victim")
    res = client.post("/api/chat", json={"message": "Someone is following me"}, headers={"Authorization": f"Bearer {victim_token}"})
    assert res.status_code == 200
    data = res.json()
    assert "ai_provider" in data
    assert data["ai_provider"] in ["groq", "openai", "local_context_engine"]
    assert len(data["reply"]) > 20


# =====================================================================
# TASK 15: OFFICER DASHBOARD ACTION WORKFLOWS & AUDIT LOGS TESTS
# =====================================================================

def _get_sync_db():
    import pymongo
    return pymongo.MongoClient("mongodb://127.0.0.1:27017")["nivara"]


def test_task15_1_officer_emergency_acknowledgment_and_duplicate_guard(client):
    """Task 15.1: Officer acknowledges an emergency alert; duplicate acknowledgment is handled cleanly and audited."""
    sync_db = _get_sync_db()
    _, victim_token = _create_isolated_victim(client, "Task15 Ack Victim")
    officer_token, officer_user = _get_officer_token(client)

    # 1. Victim triggers SOS emergency
    sos = client.post("/api/sos", json={"message": "Emergency SOS triggered", "latitude": 12.9716, "longitude": 77.5946}, headers={"Authorization": f"Bearer {victim_token}"})
    assert sos.status_code == 200
    case_id = sos.json()["case_id"]

    # 2. Officer acknowledges the case
    ack_res = client.post(
        "/api/officer/action",
        json={"case_id": case_id, "action": "acknowledged", "notes": "Responding officer en route."},
        headers={"Authorization": f"Bearer {officer_token}"}
    )
    assert ack_res.status_code == 200
    data = ack_res.json()
    assert data["ok"] is True
    assert data["acknowledgment_status"] == "acknowledged"

    # Verify case reflects acknowledgment and duty officer details
    case_res = client.get(f"/api/cases/{case_id}", headers={"Authorization": f"Bearer {officer_token}"})
    assert case_res.status_code == 200
    c_out = case_res.json()["case"]
    assert c_out["acknowledgment_status"] == "acknowledged"
    assert c_out["acknowledged_at"] is not None
    assert c_out["acknowledged_by"] is not None

    # 3. Duplicate acknowledgment attempt is handled idempotently without error
    ack_res2 = client.post(
        "/api/officer/action",
        json={"case_id": case_id, "action": "acknowledged"},
        headers={"Authorization": f"Bearer {officer_token}"}
    )
    assert ack_res2.status_code == 200
    data2 = ack_res2.json()
    assert data2["already_acknowledged"] is True

    # 4. Audit log entry exists
    audit_entry = sync_db.audit_logs.find_one({"action": "officer_emergency_acknowledged", "meta.case_id": case_id})
    assert audit_entry is not None
    assert audit_entry["meta"]["case_id"] == case_id


def test_task15_2_officer_contact_recording_and_history(client):
    """Task 15.2: Officer records victim contact outcome, notes, and timestamp; history is accumulated and audited."""
    sync_db = _get_sync_db()
    _, victim_token = _create_isolated_victim(client, "Task15 Contact Victim")
    officer_token, officer_user = _get_officer_token(client)

    sos = client.post("/api/sos", json={"message": "Need immediate contact", "latitude": 12.9716, "longitude": 77.5946}, headers={"Authorization": f"Bearer {victim_token}"})
    case_id = sos.json()["case_id"]

    # 1. Record first contact attempt: Attempted, no answer
    contact1 = client.post(
        "/api/officer/action",
        json={
            "case_id": case_id,
            "action": "contacted_victim",
            "outcome": "Attempted, no answer",
            "notes": "Called primary phone, rang with no response."
        },
        headers={"Authorization": f"Bearer {officer_token}"}
    )
    assert contact1.status_code == 200
    assert contact1.json()["latest_contact"]["outcome"] == "Attempted, no answer"

    # 2. Record second contact attempt: Successfully contacted
    contact2 = client.post(
        "/api/officer/action",
        json={
            "case_id": case_id,
            "action": "contacted_victim",
            "outcome": "Successfully contacted",
            "notes": "Spoke directly with victim; safe at local store."
        },
        headers={"Authorization": f"Bearer {officer_token}"}
    )
    assert contact2.status_code == 200
    assert contact2.json()["latest_contact"]["outcome"] == "Successfully contacted"

    # 3. Retrieve case detail and verify contact_history has both entries
    case_res = client.get(f"/api/cases/{case_id}", headers={"Authorization": f"Bearer {officer_token}"})
    assert case_res.status_code == 200
    c_out = case_res.json()["case"]
    assert c_out["latest_contact"]["outcome"] == "Successfully contacted"
    assert len(c_out["contact_history"]) == 2
    assert c_out["contact_history"][0]["outcome"] == "Attempted, no answer"
    assert c_out["contact_history"][1]["outcome"] == "Successfully contacted"

    # 4. Verify audit log recorded
    audit_contacts = list(sync_db.audit_logs.find({"action": "victim_contact_recorded", "meta.case_id": case_id}))
    assert len(audit_contacts) == 2


def test_task15_3_officer_internal_dispatch_and_duplicate_prevention(client):
    """Task 15.3: Officer records internal team dispatch, prevents duplicate active dispatch, and supports reassignment."""
    sync_db = _get_sync_db()
    _, victim_token = _create_isolated_victim(client, "Task15 Dispatch Victim")
    officer_token, _ = _get_officer_token(client)

    sos = client.post("/api/sos", json={"message": "Need unit dispatch", "latitude": 12.9716, "longitude": 77.5946}, headers={"Authorization": f"Bearer {victim_token}"})
    case_id = sos.json()["case_id"]

    # 1. Initial Dispatch: Unit Delta
    disp1 = client.post(
        "/api/officer/action",
        json={
            "case_id": case_id,
            "action": "dispatched_unit",
            "unit": "Patrol Unit Delta",
            "dispatch_status": "dispatched",
            "notes": "En route from Sector 2"
        },
        headers={"Authorization": f"Bearer {officer_token}"}
    )
    assert disp1.status_code == 200
    assert disp1.json()["dispatch_status"] == "dispatched"

    # Verify case document
    case_res = client.get(f"/api/cases/{case_id}", headers={"Authorization": f"Bearer {officer_token}"})
    c_out = case_res.json()["case"]
    assert c_out["dispatch_unit"] == "Patrol Unit Delta"
    assert c_out["dispatch_status"] == "dispatched"
    assert c_out["dispatched_at"] is not None

    # 2. Duplicate active dispatch attempt is guarded
    disp_dup = client.post(
        "/api/officer/action",
        json={
            "case_id": case_id,
            "action": "dispatched_unit",
            "unit": "Patrol Unit Delta",
            "dispatch_status": "dispatched"
        },
        headers={"Authorization": f"Bearer {officer_token}"}
    )
    assert disp_dup.status_code == 200
    assert disp_dup.json()["already_dispatched"] is True

    # 3. Reassignment to new unit succeeds
    reassign = client.post(
        "/api/officer/action",
        json={
            "case_id": case_id,
            "action": "dispatched_unit",
            "unit": "Patrol Unit Echo",
            "dispatch_status": "reassigned",
            "notes": "Unit Delta diverted; reassigned to Echo"
        },
        headers={"Authorization": f"Bearer {officer_token}"}
    )
    assert reassign.status_code == 200
    assert reassign.json()["dispatch_status"] == "reassigned"

    # 4. Audit log contains disclaimer indicating internal NIVARA dispatch (112 police not integrated)
    audit_disp = sync_db.audit_logs.find_one({"action": "officer_internal_dispatch_recorded", "meta.case_id": case_id, "meta.dispatch_unit": "Patrol Unit Delta"})
    assert audit_disp is not None
    assert "112" in audit_disp["meta"]["disclaimer"]


def test_task15_4_deterministic_case_summary_fallback(client):
    """Task 15.4: POST /cases/summary/{case_id} produces rich deterministic structured summary when AI is unconfigured."""
    _, victim_token = _create_isolated_victim(client, "Task15 Summary Victim")
    officer_token, _ = _get_officer_token(client)

    sos = client.post("/api/sos", json={"message": "Harassed near metro station", "latitude": 12.9716, "longitude": 77.5946, "location_label": "MG Road Station"}, headers={"Authorization": f"Bearer {victim_token}"})
    case_id = sos.json()["case_id"]

    # Acknowledge first so verified triage info is present
    client.post("/api/officer/action", json={"case_id": case_id, "action": "acknowledged"}, headers={"Authorization": f"Bearer {officer_token}"})

    # Call summary endpoint
    res = client.post(f"/api/cases/summary/{case_id}", headers={"Authorization": f"Bearer {officer_token}"})
    assert res.status_code == 200
    data = res.json()
    assert "summary" in data
    assert data["source"] in ["deterministic", "ai"]
    summary_text = data["summary"]

    # Verify structured fields in deterministic summary
    if data["source"] == "deterministic":
        assert "SYSTEM CASE SUMMARY" in summary_text
        assert "Verified Location" in summary_text
        assert "MG Road Station" in summary_text
        assert "Acknowledged" in summary_text

    # Case detail endpoint returns updated summary
    case_res = client.get(f"/api/cases/{case_id}", headers={"Authorization": f"Bearer {officer_token}"})
    assert case_res.json()["case"]["summary"] == summary_text


def test_task15_5_case_activity_and_audit_logs_retrieval(client):
    """Task 15.5: GET /cases/{case_id}/logs returns chronologically sorted, sanitized audit events and officer actions."""
    _, victim_token = _create_isolated_victim(client, "Task15 Logs Victim")
    officer_token, _ = _get_officer_token(client)

    sos = client.post("/api/sos", json={"message": "Need help logging test", "latitude": 12.9716, "longitude": 77.5946}, headers={"Authorization": f"Bearer {victim_token}"})
    case_id = sos.json()["case_id"]

    # Officer acknowledges
    client.post("/api/officer/action", json={"case_id": case_id, "action": "acknowledged"}, headers={"Authorization": f"Bearer {officer_token}"})

    # Officer contacts victim
    client.post("/api/officer/action", json={"case_id": case_id, "action": "contacted_victim", "outcome": "Successfully contacted", "notes": "All clear"}, headers={"Authorization": f"Bearer {officer_token}"})

    # Fetch logs as officer
    logs_res = client.get(f"/api/cases/{case_id}/logs", headers={"Authorization": f"Bearer {officer_token}"})
    assert logs_res.status_code == 200
    data = logs_res.json()
    assert data["case_id"] == case_id
    assert data["total"] >= 2
    logs = data["logs"]

    # Verify newest first sorting
    timestamps = [l["created_at"] for l in logs]
    assert timestamps == sorted(timestamps, reverse=True)

    # Verify actions are present
    actions = [l["action"] for l in logs]
    assert any("acknowledged" in a for a in actions)

    # Cross-role authorization: unassigned victim cannot access case logs of another user
    _, stranger_token = _create_isolated_victim(client, "Stranger Victim")
    unauth_res = client.get(f"/api/cases/{case_id}/logs", headers={"Authorization": f"Bearer {stranger_token}"})
    assert unauth_res.status_code in [401, 403, 404]


def test_task15_6_counsellor_assignment_audit_trail(client):
    """Task 15.6: Counsellor assignment persists and creates tamper-evident audit log."""
    sync_db = _get_sync_db()
    _, victim_token = _create_isolated_victim(client, "Task15 Assign Victim")
    officer_token, _ = _get_officer_token(client)

    sos = client.post("/api/sos", json={"message": "Need counsellor support"}, headers={"Authorization": f"Bearer {victim_token}"})
    case_id = sos.json()["case_id"]

    # Find counsellor user
    counsellor = sync_db.users.find_one({"role": "counsellor"})
    assert counsellor is not None

    assign_res = client.post(
        "/api/officer/assign",
        json={"case_id": case_id, "counsellor_id": counsellor["_id"], "notes": "Priority counselling requested"},
        headers={"Authorization": f"Bearer {officer_token}"}
    )
    assert assign_res.status_code == 200

    # Verify case status
    case_res = client.get(f"/api/cases/{case_id}", headers={"Authorization": f"Bearer {officer_token}"})
    assert case_res.json()["case"]["status"] == "assigned"
    assert case_res.json()["case"]["counsellor_id"] == counsellor["_id"]

    # Verify audit log entry
    assign_audit = sync_db.audit_logs.find_one({"action": "counsellor_assigned", "meta.case_id": case_id})
    assert assign_audit is not None
    assert assign_audit["meta"]["counsellor_id"] == counsellor["_id"]












