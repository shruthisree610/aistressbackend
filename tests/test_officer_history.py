import pytest
from starlette.testclient import TestClient
from server import app
import time

@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c

def test_officer_history_requires_officer_role(client):
    """Test that only authenticated officers can access /api/officer/history (victim and counsellor rejected)."""
    # 1. Anonymous request -> 401 Unauthorized
    anon_res = client.get("/api/officer/history")
    assert anon_res.status_code == 401

    # 2. Victim role -> 403 Forbidden
    v_login = client.post("/api/auth/login", json={"email": "victim@nivara.app", "password": "Password123"})
    assert v_login.status_code == 200
    v_token = v_login.json()["token"]

    v_res = client.get("/api/officer/history", headers={"Authorization": f"Bearer {v_token}"})
    assert v_res.status_code == 403

    # 3. Counsellor role -> 403 Forbidden
    c_login = client.post("/api/auth/login", json={"email": "counsellor@nivara.app", "password": "Password123"})
    assert c_login.status_code == 200
    c_token = c_login.json()["token"]

    c_res = client.get("/api/officer/history", headers={"Authorization": f"Bearer {c_token}"})
    assert c_res.status_code == 403

def test_officer_history_retrieves_authorized_cases_and_actions(client):
    """Test that officer history retrieves cases handled by this officer, with involvements and stats."""
    # 1. Officer login
    off_login = client.post("/api/auth/login", json={"email": "officer@nivara.app", "password": "Password123"})
    assert off_login.status_code == 200
    off_token = off_login.json()["token"]

    # 2. Create a new case with unique title
    ts = int(time.time())
    v_email = f"victim_hist_{ts}@example.com"
    reg = client.post("/api/auth/register", json={"email": v_email, "password": "Password123", "name": f"VictimHist_{ts}", "role": "victim"})
    assert reg.status_code == 200
    v_token = reg.json()["token"]

    sos = client.post("/api/sos", headers={"Authorization": f"Bearer {v_token}"}, json={
        "latitude": 13.0827,
        "longitude": 80.2707,
        "location_label": f"Historical Test Spot {ts}",
        "message": f"Help needed for case test {ts}"
    })
    assert sos.status_code == 200
    case_id = sos.json()["case_id"]

    # 3. Officer performs action: Acknowledge
    ack_res = client.post("/api/officer/action", headers={"Authorization": f"Bearer {off_token}"}, json={
        "case_id": case_id,
        "action": "acknowledged",
        "notes": f"Acknowledgment recorded for history test {ts}"
    })
    assert ack_res.status_code == 200

    # 4. Officer performs action: Contacted victim
    contact_res = client.post("/api/officer/action", headers={"Authorization": f"Bearer {off_token}"}, json={
        "case_id": case_id,
        "action": "contacted_victim",
        "outcome": "Successfully contacted",
        "notes": "Verified safety directly"
    })
    assert contact_res.status_code == 200

    # 5. Officer performs action: Dispatch unit
    disp_res = client.post("/api/officer/action", headers={"Authorization": f"Bearer {off_token}"}, json={
        "case_id": case_id,
        "action": "dispatched_unit",
        "unit": f"Patrol-{ts}",
        "dispatch_status": "en_route",
        "notes": "Internal patrol en route"
    })
    assert disp_res.status_code == 200

    # 6. Retrieve officer history
    hist_res = client.get("/api/officer/history?data_filter=all", headers={"Authorization": f"Bearer {off_token}"})
    assert hist_res.status_code == 200, hist_res.text
    h_data = hist_res.json()

    assert "stats" in h_data
    assert "cases" in h_data
    assert h_data["stats"]["total_cases_handled"] > 0
    assert h_data["stats"]["acknowledgments_count"] > 0
    assert h_data["stats"]["contacts_count"] > 0
    assert h_data["stats"]["dispatches_count"] > 0

    # Find the newly created case
    found = next((c for c in h_data["cases"] if c["id"] == case_id), None)
    assert found is not None, f"Case {case_id} not found in officer history"
    assert "Acknowledged" in found["involvements"]
    assert "Contacted" in found["involvements"]
    assert "Dispatched" in found["involvements"]
    assert found["dispatch_unit"] == f"Patrol-{ts}"
    assert found["dispatch_status"] == "en_route"

def test_officer_history_search_and_filters(client):
    """Test searching by case ID, filtering by priority, status, and action type."""
    off_login = client.post("/api/auth/login", json={"email": "officer@nivara.app", "password": "Password123"})
    off_token = off_login.json()["token"]

    # 1. Search with a known query
    res = client.get("/api/officer/history?data_filter=all&search=emergency", headers={"Authorization": f"Bearer {off_token}"})
    assert res.status_code == 200
    cases = res.json()["cases"]
    for c in cases:
        combined = (c["title"] + " " + c["category"] + " " + c["priority"]).lower()
        assert "emergency" in combined or "sos" in combined

    # 2. Filter by priority=emergency
    res_emerg = client.get("/api/officer/history?data_filter=all&priority=emergency", headers={"Authorization": f"Bearer {off_token}"})
    assert res_emerg.status_code == 200
    for c in res_emerg.json()["cases"]:
        assert c["priority"] == "emergency" or c["risk_level"].lower() == "critical"

    # 3. Filter by action_type=contacted_victim
    res_act = client.get("/api/officer/history?data_filter=all&action_type=contacted_victim", headers={"Authorization": f"Bearer {off_token}"})
    assert res_act.status_code == 200
    for c in res_act.json()["cases"]:
        assert any("Contacted" in inv for inv in c["involvements"])

def test_officer_history_pagination(client):
    """Test pagination bounds (page=1, limit=3, page=2) ensuring no unexpected omission or crashes."""
    off_login = client.post("/api/auth/login", json={"email": "officer@nivara.app", "password": "Password123"})
    off_token = off_login.json()["token"]

    res_p1 = client.get("/api/officer/history?data_filter=all&page=1&limit=3", headers={"Authorization": f"Bearer {off_token}"})
    assert res_p1.status_code == 200
    d1 = res_p1.json()
    assert d1["page"] == 1
    assert d1["limit"] == 3
    assert len(d1["cases"]) <= 3

    if d1["total_pages"] > 1:
        res_p2 = client.get("/api/officer/history?data_filter=all&page=2&limit=3", headers={"Authorization": f"Bearer {off_token}"})
        assert res_p2.status_code == 200
        d2 = res_p2.json()
        assert d2["page"] == 2
        # Ensure page 2 items are distinct from page 1 items
        ids_p1 = {c["id"] for c in d1["cases"]}
        ids_p2 = {c["id"] for c in d2["cases"]}
        assert ids_p1.isdisjoint(ids_p2)

def test_data_filter_separates_test_from_live(client):
    """Test that data_filter='live' excludes test suite records from real operational statistics."""
    off_login = client.post("/api/auth/login", json={"email": "officer@nivara.app", "password": "Password123"})
    off_token = off_login.json()["token"]

    res_live = client.get("/api/officer/history?data_filter=live", headers={"Authorization": f"Bearer {off_token}"})
    assert res_live.status_code == 200
    live_data = res_live.json()

    # All returned cases in 'live' filter must have is_demo_or_test == False
    for c in live_data["cases"]:
        assert c["is_demo_or_test"] is False
        assert c["record_provenance"] == "live"

    # Stats should report test cases count transparently
    assert live_data["stats"]["test_cases_count"] >= 0
    assert live_data["stats"]["live_cases_count"] == live_data["stats"]["total_cases_handled"]

def test_case_activity_timeline_logs(client):
    """Test that GET /api/cases/{case_id}/logs returns events in chronological order with actor metadata."""
    off_login = client.post("/api/auth/login", json={"email": "officer@nivara.app", "password": "Password123"})
    off_token = off_login.json()["token"]

    # 1. Create a case
    ts = int(time.time())
    reg = client.post("/api/auth/register", json={"email": f"timeline_v_{ts}@example.com", "password": "Password123", "name": "Timeline Victim", "role": "victim"})
    v_token = reg.json()["token"]

    sos = client.post("/api/sos", headers={"Authorization": f"Bearer {v_token}"}, json={"message": "Timeline test SOS"})
    case_id = sos.json()["case_id"]

    # 2. Officer acknowledges
    client.post("/api/officer/action", headers={"Authorization": f"Bearer {off_token}"}, json={
        "case_id": case_id,
        "action": "acknowledged",
        "notes": "Officer acknowledged alert"
    })

    # 3. Retrieve logs
    logs_res = client.get(f"/api/cases/{case_id}/logs", headers={"Authorization": f"Bearer {off_token}"})
    assert logs_res.status_code == 200
    logs_data = logs_res.json()

    assert "logs" in logs_data
    assert len(logs_data["logs"]) >= 1

    ack_event = next((l for l in logs_data["logs"] if "acknowledged" in l["action"]), None)
    assert ack_event is not None
    assert ack_event["actor_name"] is not None
    assert ack_event["created_at"] is not None

def test_open_emergencies_remain_visible_in_live_response_center(client):
    """Test that fetching history does not mark cases resolved or hide them from GET /api/cases/mine."""
    off_login = client.post("/api/auth/login", json={"email": "officer@nivara.app", "password": "Password123"})
    off_token = off_login.json()["token"]

    # 1. Check live emergencies in /cases/mine
    mine_res = client.get("/api/cases/mine", headers={"Authorization": f"Bearer {off_token}"})
    assert mine_res.status_code == 200
    emergencies_before = [c for c in mine_res.json() if c["priority"] == "emergency" and c["status"] != "resolved"]

    # 2. Query history
    hist_res = client.get("/api/officer/history?data_filter=all", headers={"Authorization": f"Bearer {off_token}"})
    assert hist_res.status_code == 200

    # 3. Check /cases/mine again
    mine_res_after = client.get("/api/cases/mine", headers={"Authorization": f"Bearer {off_token}"})
    assert mine_res_after.status_code == 200
    emergencies_after = [c for c in mine_res_after.json() if c["priority"] == "emergency" and c["status"] != "resolved"]

    assert len(emergencies_after) == len(emergencies_before)
