import os
import time
import pytest
import pymongo
from starlette.testclient import TestClient
from server import app

@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c

def _create_isolated_user(client, role, name_suffix, email_override=None, status=None, is_active=None):
    ts = int(time.time() * 1000)
    email = email_override or f"user_{role}_{ts}_{name_suffix.lower().replace(' ', '_')}@example.com"
    reg = client.post("/api/auth/register", json={
        "email": email,
        "password": "Password123",
        "name": f"Counsellor {name_suffix}",
        "role": "victim"
    })
    assert reg.status_code == 200, f"Registration failed: {reg.text}"
    user_id = reg.json()["user"]["id"]

    mongo_client = pymongo.MongoClient(os.environ.get("MONGO_URI", "mongodb://127.0.0.1:27017"))
    db_name = os.environ.get("MONGO_DB", "nivara")
    update_doc = {"role": role}
    if status is not None:
        update_doc["status"] = status
    if is_active is not None:
        update_doc["is_active"] = is_active
    mongo_client[db_name].users.update_one({"_id": user_id}, {"$set": update_doc})

    login_res = client.post("/api/auth/login", json={"email": email, "password": "Password123"})
    assert login_res.status_code == 200
    return user_id, login_res.json()["token"]

def _get_officer_token(client):
    res = client.post("/api/auth/login", json={"email": "officer@nivara.app", "password": "Password123"})
    assert res.status_code == 200
    return res.json()["token"], res.json()["user"]["id"]

def _get_demo_counsellor_token(client):
    res = client.post("/api/auth/login", json={"email": "counsellor@nivara.app", "password": "Password123"})
    assert res.status_code == 200
    return res.json()["token"], res.json()["user"]["id"]


class TestCounsellorListDeduplication:
    """Test Issue 2: Counsellor dropdown list deduplication and filtering."""

    def test_counsellor_list_unique_ids(self, client):
        officer_token, _ = _get_officer_token(client)
        res = client.get("/api/users/counsellors", headers={"Authorization": f"Bearer {officer_token}"})
        assert res.status_code == 200
        counsellors = res.json()
        assert len(counsellors) > 0

        # Verify no duplicate user IDs are returned
        ids = [c["id"] for c in counsellors]
        assert len(ids) == len(set(ids)), f"Duplicate counsellor IDs found: {ids}"

    def test_counsellors_with_identical_names_retained_with_distinct_ids(self, client):
        officer_token, _ = _get_officer_token(client)
        # Create two distinct counsellor accounts with identical display names
        shared_name = "Shared Twin"
        cid1, _ = _create_isolated_user(client, "counsellor", shared_name)
        cid2, _ = _create_isolated_user(client, "counsellor", shared_name)

        res = client.get("/api/users/counsellors", headers={"Authorization": f"Bearer {officer_token}"})
        assert res.status_code == 200
        counsellors = res.json()

        id_map = {c["id"]: c for c in counsellors}
        assert cid1 in id_map, "First twin counsellor missing"
        assert cid2 in id_map, "Second twin counsellor missing"
        assert id_map[cid1]["name"] == id_map[cid2]["name"]
        assert id_map[cid1]["email"] != id_map[cid2]["email"]

    def test_inactive_and_suspended_counsellors_filtered_out(self, client):
        officer_token, _ = _get_officer_token(client)
        # Inactive counsellor
        inactive_id, _ = _create_isolated_user(client, "counsellor", "Inactive Person", is_active=False)
        # Suspended counsellor
        suspended_id, _ = _create_isolated_user(client, "counsellor", "Suspended Person", status="suspended")

        res = client.get("/api/users/counsellors", headers={"Authorization": f"Bearer {officer_token}"})
        assert res.status_code == 200
        counsellor_ids = [c["id"] for c in res.json()]

        assert inactive_id not in counsellor_ids, "Inactive counsellor was not filtered out"
        assert suspended_id not in counsellor_ids, "Suspended counsellor was not filtered out"

    def test_live_data_filter_excludes_test_accounts(self, client):
        officer_token, _ = _get_officer_token(client)
        # Create test account with example.com
        test_id, _ = _create_isolated_user(client, "counsellor", "Test Probe Account")

        res_all = client.get("/api/users/counsellors?data_filter=all", headers={"Authorization": f"Bearer {officer_token}"})
        assert res_all.status_code == 200
        all_ids = [c["id"] for c in res_all.json()]
        assert test_id in all_ids

        res_live = client.get("/api/users/counsellors?data_filter=live", headers={"Authorization": f"Bearer {officer_token}"})
        assert res_live.status_code == 200
        live_ids = [c["id"] for c in res_live.json()]
        assert test_id not in live_ids, "Test account should be filtered when data_filter=live"


class TestAuthoritativeTimestamps:
    """Test Issue 1: Server-authoritative timestamps for case lifecycle & assignment."""

    def test_case_creation_and_initial_assigned_at(self, client):
        victim_id, victim_token = _create_isolated_user(client, "victim", "Time Case Victim")
        # Trigger SOS to create case
        sos_res = client.post("/api/sos", json={
            "latitude": 12.9716,
            "longitude": 77.5946,
            "location_label": "MG Road"
        }, headers={"Authorization": f"Bearer {victim_token}"})
        assert sos_res.status_code == 200
        case_id = sos_res.json()["case_id"]

        officer_token, _ = _get_officer_token(client)
        case_res = client.get(f"/api/cases/{case_id}", headers={"Authorization": f"Bearer {officer_token}"})
        assert case_res.status_code == 200
        case_data = case_res.json()["case"]

        # Verify created_at is valid ISO timestamp
        assert case_data["created_at"] is not None
        # Before assignment, assigned_at must be None
        assert case_data["assigned_at"] is None

    def test_officer_assign_persists_assigned_at_in_utc(self, client):
        victim_id, victim_token = _create_isolated_user(client, "victim", "Assign Time Victim")
        sos_res = client.post("/api/sos", json={"latitude": 13.0827, "longitude": 80.2707}, headers={"Authorization": f"Bearer {victim_token}"})
        case_id = sos_res.json()["case_id"]

        counsellor_id, counsellor_token = _create_isolated_user(client, "counsellor", "Assigned Clock Counsellor")
        officer_token, _ = _get_officer_token(client)

        assign_res = client.post("/api/officer/assign", json={
            "case_id": case_id,
            "counsellor_id": counsellor_id,
            "notes": "Assigning for psychological support"
        }, headers={"Authorization": f"Bearer {officer_token}"})
        assert assign_res.status_code == 200
        assign_body = assign_res.json()
        assert assign_body["ok"] is True
        assert "assigned_at" in assign_body
        assert assign_body["assigned_at"] is not None

        # Verify case detail now contains assigned_at
        detail_res = client.get(f"/api/cases/{case_id}", headers={"Authorization": f"Bearer {officer_token}"})
        assert detail_res.status_code == 200
        case_detail = detail_res.json()["case"]
        assert case_detail["assigned_at"] is not None
        assert case_detail["counsellor_id"] == counsellor_id
        # Verify created_at was NOT overwritten
        assert case_detail["created_at"] != case_detail["assigned_at"]


class TestCounsellorAssignmentSynchronization:
    """Test Issue 3: Case assignment synchronization, reassignment, and access isolation."""

    def test_case_assignment_appears_in_assigned_counsellor_mine(self, client):
        victim_id, victim_token = _create_isolated_user(client, "victim", "Sync Victim")
        sos_res = client.post("/api/sos", json={"latitude": 12.9716, "longitude": 77.5946}, headers={"Authorization": f"Bearer {victim_token}"})
        case_id = sos_res.json()["case_id"]

        c1_id, c1_token = _create_isolated_user(client, "counsellor", "Sync Target 1")
        c2_id, c2_token = _create_isolated_user(client, "counsellor", "Sync Target 2")
        officer_token, _ = _get_officer_token(client)

        # Before assignment: neither counsellor sees the case
        c1_mine = client.get("/api/cases/mine", headers={"Authorization": f"Bearer {c1_token}"}).json()
        assert case_id not in [c["id"] for c in c1_mine]

        # Officer assigns to Counsellor 1
        assign_res = client.post("/api/officer/assign", json={
            "case_id": case_id,
            "counsellor_id": c1_id
        }, headers={"Authorization": f"Bearer {officer_token}"})
        assert assign_res.status_code == 200

        # Counsellor 1 immediately sees the case in /cases/mine
        c1_mine = client.get("/api/cases/mine", headers={"Authorization": f"Bearer {c1_token}"}).json()
        c1_case_ids = [c["id"] for c in c1_mine]
        assert case_id in c1_case_ids

        matched = next(c for c in c1_mine if c["id"] == case_id)
        assert matched["assigned_at"] is not None
        assert matched["counsellor_id"] == c1_id

        # Counsellor 1 can access /cases/{case_id}
        c1_detail = client.get(f"/api/cases/{case_id}", headers={"Authorization": f"Bearer {c1_token}"})
        assert c1_detail.status_code == 200

        # Counsellor 2 does NOT see the case
        c2_mine = client.get("/api/cases/mine", headers={"Authorization": f"Bearer {c2_token}"}).json()
        assert case_id not in [c["id"] for c in c2_mine]

        # Counsellor 2 gets 403 Forbidden on /cases/{case_id}
        c2_detail = client.get(f"/api/cases/{case_id}", headers={"Authorization": f"Bearer {c2_token}"})
        assert c2_detail.status_code == 403

    def test_reassignment_transfers_case_and_revokes_previous_counsellor(self, client):
        victim_id, victim_token = _create_isolated_user(client, "victim", "Reassign Victim")
        sos_res = client.post("/api/sos", json={"latitude": 19.0760, "longitude": 72.8777}, headers={"Authorization": f"Bearer {victim_token}"})
        case_id = sos_res.json()["case_id"]

        c1_id, c1_token = _create_isolated_user(client, "counsellor", "Initial Assigned Counsellor")
        c2_id, c2_token = _create_isolated_user(client, "counsellor", "New Replacement Counsellor")
        officer_token, _ = _get_officer_token(client)

        # 1. First assignment to Counsellor 1
        client.post("/api/officer/assign", json={"case_id": case_id, "counsellor_id": c1_id}, headers={"Authorization": f"Bearer {officer_token}"})

        c1_mine = client.get("/api/cases/mine", headers={"Authorization": f"Bearer {c1_token}"}).json()
        assert case_id in [c["id"] for c in c1_mine]

        # 2. Officer reassigns case to Counsellor 2
        time.sleep(0.01)  # small delta to guarantee distinct timestamp
        reassign_res = client.post("/api/officer/assign", json={
            "case_id": case_id,
            "counsellor_id": c2_id,
            "notes": "Reassigning due to shift rotation"
        }, headers={"Authorization": f"Bearer {officer_token}"})
        assert reassign_res.status_code == 200

        # 3. Verify Counsellor 2 now sees the case in /cases/mine
        c2_mine = client.get("/api/cases/mine", headers={"Authorization": f"Bearer {c2_token}"}).json()
        assert case_id in [c["id"] for c in c2_mine]

        # 4. Verify Counsellor 1 NO LONGER sees the case in /cases/mine
        c1_mine_after = client.get("/api/cases/mine", headers={"Authorization": f"Bearer {c1_token}"}).json()
        assert case_id not in [c["id"] for c in c1_mine_after]

        # 5. Verify Counsellor 1 receives 403 Forbidden on direct access
        c1_direct = client.get(f"/api/cases/{case_id}", headers={"Authorization": f"Bearer {c1_token}"})
        assert c1_direct.status_code == 403
        assert "Forbidden: Not your assigned case" in c1_direct.json()["detail"]

        # 6. Verify Counsellor 2 can access full detail
        c2_direct = client.get(f"/api/cases/{case_id}", headers={"Authorization": f"Bearer {c2_token}"})
        assert c2_direct.status_code == 200
        assert c2_direct.json()["case"]["counsellor_id"] == c2_id
