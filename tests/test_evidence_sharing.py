import pytest
import io
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
    email = f"victim_ev_{ts}_{name_suffix.lower().replace(' ', '_')}@example.com"
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


def test_1_saving_evidence_privately_without_sharing(client):
    """1. Evidence uploaded by victim is private by default and not exposed to officers."""
    _, victim_token = _create_isolated_victim(client, "Private Vault Victim")
    officer_token, _ = _get_officer_token(client)

    # Create case
    chat_res = client.post("/api/chat", json={"message": "I need to document an incident"}, headers={"Authorization": f"Bearer {victim_token}"})
    assert chat_res.status_code == 200
    case_id = chat_res.json()["case_id"]

    # Upload text snapshot
    snap_res = client.post(
        "/api/evidence/upload",
        json={"case_id": case_id, "title": "Secret Audio Notes", "content": "Suspect made threats on 29 Oct"},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert snap_res.status_code == 200
    assert snap_res.json()["sharing_status"] == "private"
    snap_id = snap_res.json()["id"]

    # Victim sees private record in list
    v_list = client.get(f"/api/evidence/{case_id}", headers={"Authorization": f"Bearer {victim_token}"})
    assert v_list.status_code == 200
    ev_items = v_list.json()["evidence"]
    assert len(ev_items) >= 1
    matched = next(e for e in ev_items if e["id"] == snap_id)
    assert matched["sharing_status"] == "private"

    # Officer querying evidence list sees 0 unshared records
    off_list = client.get(f"/api/evidence/{case_id}", headers={"Authorization": f"Bearer {officer_token}"})
    assert off_list.status_code == 200
    # No unshared private evidence exposed to officer
    assert not any(e["id"] == snap_id for e in off_list.json()["evidence"])

    # Officer attempting direct item retrieval on private record -> 403 Forbidden
    off_item = client.get(f"/api/evidence/item/{snap_id}", headers={"Authorization": f"Bearer {officer_token}"})
    assert off_item.status_code == 403
    assert "private" in off_item.json()["detail"].lower()


def test_2_sharing_requires_case_with_assigned_officer(client):
    """2. Sharing rejects if the selected case has no assigned officer yet."""
    _, victim_token = _create_isolated_victim(client, "Unassigned Case Victim")

    # Case created via chat has no officer assigned yet
    chat_res = client.post("/api/chat", json={"message": "Case without officer"}, headers={"Authorization": f"Bearer {victim_token}"})
    case_id = chat_res.json()["case_id"]

    snap_res = client.post(
        "/api/evidence/upload",
        json={"case_id": case_id, "title": "Stalking Log", "content": "Car parked outside"},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    evidence_id = snap_res.json()["id"]

    # Attempt to share to unassigned case -> 400 Bad Request
    share_res = client.post(
        f"/api/evidence/{evidence_id}/share",
        json={"case_id": case_id},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert share_res.status_code == 400
    assert "assigned officer" in share_res.json()["detail"].lower()


def test_3_explicit_sharing_with_authorized_officer(client):
    """3. Victim explicitly shares evidence with officer after case is acknowledged by officer."""
    sync_db = pymongo.MongoClient("mongodb://127.0.0.1:27017")["nivara"]
    _, victim_token = _create_isolated_victim(client, "Sharing Owner Victim")
    officer_token, officer_id = _get_officer_token(client)

    # 1. Victim creates emergency SOS case
    sos_res = client.post(
        "/api/sos",
        json={"message": "Immediate help needed", "latitude": 12.9716, "longitude": 77.5946},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert sos_res.status_code == 200
    case_id = sos_res.json()["case_id"]

    # 2. Officer acknowledges the case (assigns officer to case)
    ack_res = client.post(
        "/api/officer/action",
        json={"case_id": case_id, "action": "acknowledged", "notes": "Duty officer acknowledged emergency"},
        headers={"Authorization": f"Bearer {officer_token}"}
    )
    assert ack_res.status_code == 200

    # 3. Victim uploads media evidence to vault
    jpeg_bytes = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" + b"\xCC" * 64 + b"\xFF\xD9"
    files = {"file": ("damage_photo.jpg", io.BytesIO(jpeg_bytes), "image/jpeg")}
    upload_res = client.post(
        "/api/evidence/upload-file",
        data={"case_id": case_id, "title": "Property Damage Photo", "notes": "Broken door latch"},
        files=files,
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert upload_res.status_code == 200
    evidence_id = upload_res.json()["id"]

    # Verify officer CANNOT view evidence in case evidence list prior to explicit sharing
    unshared_list = client.get(f"/api/evidence/{case_id}", headers={"Authorization": f"Bearer {officer_token}"})
    assert unshared_list.status_code == 200
    assert not any(e["id"] == evidence_id for e in unshared_list.json()["evidence"])

    # 4. Victim explicitly shares evidence with assigned officer
    share_res = client.post(
        f"/api/evidence/{evidence_id}/share",
        json={"case_id": case_id},
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert share_res.status_code == 200
    share_data = share_res.json()
    assert share_data["ok"] is True
    assert share_data["sharing_status"] == "shared"
    assert share_data["shared_case_id"] == case_id
    assert share_data["shared_officer_id"] == officer_id

    # Verify audit log was recorded
    share_log = sync_db.audit_logs.find_one({"action": "evidence_shared_with_officer", "meta.evidence_id": evidence_id})
    assert share_log is not None
    assert share_log["meta"]["case_id"] == case_id
    assert share_log["meta"]["officer_id"] == officer_id

    # 5. Officer now successfully accesses shared evidence
    off_list = client.get(f"/api/evidence/{case_id}", headers={"Authorization": f"Bearer {officer_token}"})
    assert off_list.status_code == 200
    shared_items = off_list.json()["evidence"]
    matched = next(e for e in shared_items if e["id"] == evidence_id)
    assert matched["sharing_status"] == "shared"
    assert matched["integrity_verified"] is True

    # 6. Officer downloads media file
    media_res = client.get(f"/api/evidence/media/{evidence_id}", headers={"Authorization": f"Bearer {officer_token}"})
    assert media_res.status_code == 200
    assert media_res.content == jpeg_bytes

    # Verify audit log for officer access
    access_log = sync_db.audit_logs.find_one({"action": "evidence_accessed_by_officer", "meta.evidence_id": evidence_id})
    assert access_log is not None


def test_4_rejecting_attempts_to_share_another_victim_case_or_evidence(client):
    """4. Security checks: victim cannot share another victim's evidence or link to another victim's case."""
    _, victim_a_token = _create_isolated_victim(client, "Victim Alpha")
    _, victim_b_token = _create_isolated_victim(client, "Victim Beta")
    officer_token, _ = _get_officer_token(client)

    # Victim A creates case A and officer acknowledges it
    sos_a = client.post("/api/sos", json={"message": "SOS A"}, headers={"Authorization": f"Bearer {victim_a_token}"})
    case_a_id = sos_a.json()["case_id"]
    client.post("/api/officer/action", json={"case_id": case_a_id, "action": "acknowledged"}, headers={"Authorization": f"Bearer {officer_token}"})

    # Victim A creates evidence A
    ev_a = client.post("/api/evidence/upload", json={"case_id": case_a_id, "content": "Notes A"}, headers={"Authorization": f"Bearer {victim_a_token}"})
    ev_a_id = ev_a.json()["id"]

    # Victim B creates case B and officer acknowledges it
    sos_b = client.post("/api/sos", json={"message": "SOS B"}, headers={"Authorization": f"Bearer {victim_b_token}"})
    case_b_id = sos_b.json()["case_id"]
    client.post("/api/officer/action", json={"case_id": case_b_id, "action": "acknowledged"}, headers={"Authorization": f"Bearer {officer_token}"})

    # Attack 1: Victim B tries to share Victim A's evidence -> 403 Forbidden
    attack_1 = client.post(f"/api/evidence/{ev_a_id}/share", json={"case_id": case_b_id}, headers={"Authorization": f"Bearer {victim_b_token}"})
    assert attack_1.status_code == 403

    # Attack 2: Victim A tries to share own evidence into Victim B's case -> 403 Forbidden
    attack_2 = client.post(f"/api/evidence/{ev_a_id}/share", json={"case_id": case_b_id}, headers={"Authorization": f"Bearer {victim_a_token}"})
    assert attack_2.status_code == 403


def test_5_revoking_evidence_sharing_enforces_immediate_cutoff(client):
    """5. Revoking evidence sharing enforces 403 Forbidden on subsequent officer requests."""
    sync_db = pymongo.MongoClient("mongodb://127.0.0.1:27017")["nivara"]
    _, victim_token = _create_isolated_victim(client, "Revocation Test Victim")
    officer_token, _ = _get_officer_token(client)

    # 1. Setup case with officer
    sos = client.post("/api/sos", json={"message": "Emergency SOS"}, headers={"Authorization": f"Bearer {victim_token}"})
    case_id = sos.json()["case_id"]
    client.post("/api/officer/action", json={"case_id": case_id, "action": "acknowledged"}, headers={"Authorization": f"Bearer {officer_token}"})

    # 2. Upload media and share it
    jpeg_bytes = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" + b"\xDD" * 64 + b"\xFF\xD9"
    files = {"file": ("threat_letter.jpg", io.BytesIO(jpeg_bytes), "image/jpeg")}
    up = client.post("/api/evidence/upload-file", data={"case_id": case_id, "title": "Threat Letter"}, files=files, headers={"Authorization": f"Bearer {victim_token}"})
    evidence_id = up.json()["id"]

    client.post(f"/api/evidence/{evidence_id}/share", json={"case_id": case_id}, headers={"Authorization": f"Bearer {victim_token}"})

    # Verify officer has access
    assert client.get(f"/api/evidence/media/{evidence_id}", headers={"Authorization": f"Bearer {officer_token}"}).status_code == 200

    # 3. Victim revokes access
    revoke_res = client.post(f"/api/evidence/{evidence_id}/revoke", headers={"Authorization": f"Bearer {victim_token}"})
    assert revoke_res.status_code == 200
    assert revoke_res.json()["ok"] is True
    assert revoke_res.json()["sharing_status"] == "revoked"

    # Verify audit log
    rev_log = sync_db.audit_logs.find_one({"action": "evidence_share_revoked", "meta.evidence_id": evidence_id})
    assert rev_log is not None

    # 4. Immediate enforcement: Officer media request -> 403 Forbidden
    revoked_media = client.get(f"/api/evidence/media/{evidence_id}", headers={"Authorization": f"Bearer {officer_token}"})
    assert revoked_media.status_code == 403
    assert "revoked" in revoked_media.json()["detail"].lower()

    # Officer item request -> 403 Forbidden
    revoked_item = client.get(f"/api/evidence/item/{evidence_id}", headers={"Authorization": f"Bearer {officer_token}"})
    assert revoked_item.status_code == 403
    assert "revoked" in revoked_item.json()["detail"].lower()

    # Officer evidence list no longer displays revoked record
    off_list = client.get(f"/api/evidence/{case_id}", headers={"Authorization": f"Bearer {officer_token}"})
    assert off_list.status_code == 200
    assert not any(e["id"] == evidence_id for e in off_list.json()["evidence"])

    # Victim still sees record with status "revoked"
    v_list = client.get(f"/api/evidence/{case_id}", headers={"Authorization": f"Bearer {victim_token}"})
    assert v_list.status_code == 200
    v_item = next(e for e in v_list.json()["evidence"] if e["id"] == evidence_id)
    assert v_item["sharing_status"] == "revoked"


def test_6_encryption_at_rest_and_hash_integrity_preserved(client):
    """6. Sensitive notes remain AES-256-GCM encrypted in database while hash integrity is verified."""
    sync_db = pymongo.MongoClient("mongodb://127.0.0.1:27017")["nivara"]
    _, victim_token = _create_isolated_victim(client, "Crypto Verification Victim")

    chat = client.post("/api/chat", json={"message": "Need encrypted vault case"}, headers={"Authorization": f"Bearer {victim_token}"})
    case_id = chat.json()["case_id"]

    secret_content = "Extremely sensitive stalker incident details stored in stealth vault"
    up = client.post("/api/evidence/upload", json={"case_id": case_id, "title": "Encrypted Test", "content": secret_content}, headers={"Authorization": f"Bearer {victim_token}"})
    evidence_id = up.json()["id"]

    # Verify raw MongoDB audit_logs document: notes MUST start with enc:v1:
    raw_log = sync_db.audit_logs.find_one({"_id": evidence_id})
    assert raw_log is not None
    assert "notes" in raw_log["meta"]
    assert raw_log["meta"]["notes"].startswith("enc:v1:")
    assert secret_content not in raw_log["meta"]["notes"]
    assert "integrity_hash" in raw_log["meta"]
    assert raw_log["meta"]["integrity_hash"].startswith("SHA256:")

    # Transparent decryption on GET for authenticated victim
    item_res = client.get(f"/api/evidence/item/{evidence_id}", headers={"Authorization": f"Bearer {victim_token}"})
    assert item_res.status_code == 200
    assert item_res.json()["notes"] == secret_content
    assert item_res.json()["integrity_verified"] is True


def test_7_counsellor_permissions_preserved_without_unauthorized_expansion(client):
    """7. Counsellor access remains strictly governed by case assignment and cannot share or bypass."""
    _, victim_token = _create_isolated_victim(client, "Counsellor Isolation Victim")
    counsellor_token, _ = _get_counsellor_token(client)

    chat = client.post("/api/chat", json={"message": "Case for counsellor isolation"}, headers={"Authorization": f"Bearer {victim_token}"})
    case_id = chat.json()["case_id"]

    up = client.post("/api/evidence/upload", json={"case_id": case_id, "title": "Diary", "content": "Personal diary"}, headers={"Authorization": f"Bearer {victim_token}"})
    evidence_id = up.json()["id"]

    # Counsellor cannot call /share or /revoke -> 403 Forbidden (victim only)
    coun_share = client.post(f"/api/evidence/{evidence_id}/share", json={"case_id": case_id}, headers={"Authorization": f"Bearer {counsellor_token}"})
    assert coun_share.status_code == 403

    coun_revoke = client.post(f"/api/evidence/{evidence_id}/revoke", headers={"Authorization": f"Bearer {counsellor_token}"})
    assert coun_revoke.status_code == 403
