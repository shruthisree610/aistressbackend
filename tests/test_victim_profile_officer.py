import pytest
from starlette.testclient import TestClient
from server import app
import time

@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c

def test_victim_profile_registration_and_update(client):
    """Test victim profile creation with phone, gender, blood group, saved location, and updating via PUT /api/auth/me."""
    ts = int(time.time())
    email = f"victim_profile_{ts}@example.com"
    pwd = "TestPassword123!"

    # 1. Register with profile data
    reg_res = client.post("/api/auth/register", json={
        "email": email,
        "password": pwd,
        "name": "Priya Sharma",
        "role": "victim",
        "phone": "+91 98765 43210",
        "gender": "Female",
        "blood_group": "O+",
        "saved_location": "Apartment 4B, Green Meadows, Bengaluru"
    })
    assert reg_res.status_code == 200, reg_res.text
    reg_data = reg_res.json()
    token = reg_data["token"]
    user = reg_data["user"]

    assert user["phone"] == "+919876543210"
    assert user["gender"] == "Female"
    assert user["blood_group"] == "O+"
    assert user["saved_location"] == "Apartment 4B, Green Meadows, Bengaluru"

    # 2. Check /api/auth/me GET returns profile fields
    me_res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_res.status_code == 200
    me_data = me_res.json()
    assert me_data["phone"] == "+919876543210"
    assert me_data["blood_group"] == "O+"
    assert me_data["saved_location"] == "Apartment 4B, Green Meadows, Bengaluru"

    # 3. Update profile via PUT /api/auth/me
    update_res = client.put("/api/auth/me", headers={"Authorization": f"Bearer {token}"}, json={
        "name": "Priya S. Kumar",
        "phone": "+91 91234 56789",
        "gender": "Female",
        "blood_group": "A+",
        "saved_location": "Villa 12, Palm Residency, Chennai",
        "language": "ta"
    })
    assert update_res.status_code == 200, update_res.text
    updated = update_res.json()
    assert updated["name"] == "Priya S. Kumar"
    assert updated["phone"] == "+919123456789"
    assert updated["blood_group"] == "A+"
    assert updated["saved_location"] == "Villa 12, Palm Residency, Chennai"
    assert updated["language"] == "ta"

def test_officer_retrieves_victim_profile_in_case(client):
    """Test that an authorized officer sees victim's phone, gender, blood group, and saved residence in case details."""
    ts = int(time.time())
    victim_email = f"victim_case_{ts}@example.com"
    pwd = "TestPassword123!"

    # 1. Register victim with blood group & phone
    reg_v = client.post("/api/auth/register", json={
        "email": victim_email,
        "password": pwd,
        "name": "Ananya Sen",
        "role": "victim",
        "phone": "+91 99887 76655",
        "gender": "Female",
        "blood_group": "B+",
        "saved_location": "Flat 302, Sunrise Towers, Siruseri"
    })
    assert reg_v.status_code == 200
    v_token = reg_v.json()["token"]

    # 2. Victim triggers SOS with GPS and accuracy
    sos_res = client.post("/api/sos", headers={"Authorization": f"Bearer {v_token}"}, json={
        "latitude": 12.8352,
        "longitude": 80.2189,
        "accuracy": 14.5,
        "location_label": "Siruseri IT Corridor",
        "message": "Emergency assistance required immediately"
    })
    assert sos_res.status_code == 200
    case_id = sos_res.json()["case_id"]

    # 3. Officer login
    off_login = client.post("/api/auth/login", json={"email": "officer@nivara.app", "password": "Password123"})
    assert off_login.status_code == 200
    off_token = off_login.json()["token"]

    # 4. Officer views case detail
    case_res = client.get(f"/api/cases/{case_id}", headers={"Authorization": f"Bearer {off_token}"})
    assert case_res.status_code == 200
    case_data = case_res.json()
    case_obj = case_data["case"]

    # Verify authorized officer sees victim profile information
    assert case_obj["victim_phone"] == "+919988776655"
    assert case_obj["victim_blood_group"] == "B+"
    assert case_obj["victim_gender"] == "Female"
    assert case_obj["victim_saved_location"] == "Flat 302, Sunrise Towers, Siruseri"
    assert case_obj["latitude"] == 12.8352
    assert case_obj["longitude"] == 80.2189
    assert case_obj["gps_accuracy"] == 14.5
    assert case_obj["location_source"] == "gps"

def test_missing_victim_phone_handled_safely(client):
    """Test that victim registering without phone has victim_phone=None and no fake numbers are invented."""
    ts = int(time.time())
    victim_email = f"victim_nophone_{ts}@example.com"
    pwd = "TestPassword123!"

    # 1. Register victim without phone
    reg_v = client.post("/api/auth/register", json={
        "email": victim_email,
        "password": pwd,
        "name": "Kavitha R",
        "role": "victim"
    })
    assert reg_v.status_code == 200
    v_token = reg_v.json()["token"]
    assert reg_v.json()["user"].get("phone") is None

    # 2. Trigger SOS
    sos_res = client.post("/api/sos", headers={"Authorization": f"Bearer {v_token}"}, json={
        "location_label": "Location unavailable",
        "message": "SOS without phone"
    })
    assert sos_res.status_code == 200
    case_id = sos_res.json()["case_id"]

    # 3. Officer view
    off_login = client.post("/api/auth/login", json={"email": "officer@nivara.app", "password": "Password123"})
    off_token = off_login.json()["token"]

    case_res = client.get(f"/api/cases/{case_id}", headers={"Authorization": f"Bearer {off_token}"})
    assert case_res.status_code == 200
    case_obj = case_res.json()["case"]
    assert case_obj["victim_phone"] is None

def test_unauthorized_victim_cannot_see_other_victim_phone(client):
    """Test privacy: another victim cannot access or see victim profile details of another victim's case."""
    ts = int(time.time())
    v1_email = f"v1_{ts}@example.com"
    v2_email = f"v2_{ts}@example.com"
    pwd = "TestPassword123!"

    reg1 = client.post("/api/auth/register", json={"email": v1_email, "password": pwd, "name": "V1", "role": "victim", "phone": "+91 99999 11111"})
    v1_token = reg1.json()["token"]

    reg2 = client.post("/api/auth/register", json={"email": v2_email, "password": pwd, "name": "V2", "role": "victim", "phone": "+91 88888 22222"})
    v2_token = reg2.json()["token"]

    # V1 creates case
    sos = client.post("/api/sos", headers={"Authorization": f"Bearer {v1_token}"}, json={"message": "Help"})
    case_id = sos.json()["case_id"]

    # V2 attempts to fetch V1's case
    v2_res = client.get(f"/api/cases/{case_id}", headers={"Authorization": f"Bearer {v2_token}"})
    # Should be 403 Forbidden because V2 is not owner, officer, or counsellor
    assert v2_res.status_code == 403

def test_manual_location_confirmation_preserves_original_gps(client):
    """Test that victim confirming a manual map location does NOT overwrite original live GPS."""
    ts = int(time.time())
    v_email = f"v_manual_loc_{ts}@example.com"
    pwd = "TestPassword123!"

    reg = client.post("/api/auth/register", json={"email": v_email, "password": pwd, "name": "Meera", "role": "victim"})
    v_token = reg.json()["token"]

    # 1. SOS with initial GPS
    sos_res = client.post("/api/sos", headers={"Authorization": f"Bearer {v_token}"}, json={
        "latitude": 12.8350,
        "longitude": 80.2180,
        "accuracy": 8.0,
        "location_label": "Initial GPS fix",
        "message": "Testing GPS vs Manual Pin"
    })
    case_id = sos_res.json()["case_id"]

    # 2. Confirm manual location pin
    confirm_res = client.post(f"/api/cases/{case_id}/confirm-location", headers={"Authorization": f"Bearer {v_token}"}, json={
        "latitude": 12.8375,
        "longitude": 80.2210,
        "location_label": "Opposite SIPCOT Gate 2",
        "notes": "Near pharmacy entrance"
    })
    assert confirm_res.status_code == 200, confirm_res.text
    cdata = confirm_res.json()
    assert cdata["ok"] is True
    assert cdata["manual_latitude"] == 12.8375
    assert cdata["manual_longitude"] == 80.2210
    assert cdata["manual_location_label"] == "Opposite SIPCOT Gate 2"

    # 3. Check case in DB via officer view
    off_login = client.post("/api/auth/login", json={"email": "officer@nivara.app", "password": "Password123"})
    off_token = off_login.json()["token"]

    case_res = client.get(f"/api/cases/{case_id}", headers={"Authorization": f"Bearer {off_token}"})
    assert case_res.status_code == 200
    case_obj = case_res.json()["case"]

    # Verify original GPS was preserved intact
    assert case_obj["latitude"] == 12.8350
    assert case_obj["longitude"] == 80.2180
    assert case_obj["gps_accuracy"] == 8.0
    # And manual location is saved separately
    assert case_obj["manual_latitude"] == 12.8375
    assert case_obj["manual_longitude"] == 80.2210
    assert case_obj["manual_location_label"] == "Opposite SIPCOT Gate 2"
    assert case_obj["manual_location_confirmed_at"] is not None

def test_officer_contact_standardized_outcomes(client):
    """Test that officer recording contact supports all 5 standardized outcomes and logs them in case history."""
    ts = int(time.time())
    v_email = f"v_contact_test_{ts}@example.com"
    pwd = "TestPassword123!"

    reg = client.post("/api/auth/register", json={
        "email": v_email,
        "password": pwd,
        "name": "Deepa K",
        "role": "victim",
        "phone": "+91 94444 33333"
    })
    v_token = reg.json()["token"]

    sos = client.post("/api/sos", headers={"Authorization": f"Bearer {v_token}"}, json={"message": "Need officer contact"})
    case_id = sos.json()["case_id"]

    off_login = client.post("/api/auth/login", json={"email": "officer@nivara.app", "password": "Password123"})
    off_token = off_login.json()["token"]

    standard_outcomes = [
        ("Attempted — no answer", "Ringing but victim did not pick up"),
        ("Unreachable", "Network unreachable error tone"),
        ("Contact not possible", "No phone signal in area"),
        ("Other", "Spoke briefly with neighbour on scene"),
        ("Successfully contacted", "Victim verified safe, patrol dispatch confirmed")
    ]

    for outcome, note in standard_outcomes:
        action_res = client.post("/api/officer/action", headers={"Authorization": f"Bearer {off_token}"}, json={
            "case_id": case_id,
            "action": "contacted_victim",
            "outcome": outcome,
            "notes": note
        })
        assert action_res.status_code == 200, f"Failed on {outcome}: {action_res.text}"

    # Verify case detail reflects latest contact and cumulative history
    case_res = client.get(f"/api/cases/{case_id}", headers={"Authorization": f"Bearer {off_token}"})
    assert case_res.status_code == 200
    case_obj = case_res.json()["case"]

    assert case_obj["latest_contact"]["outcome"] == "Successfully contacted"
    assert "Patrol dispatch confirmed" in case_obj["latest_contact"]["notes"] or "Victim verified safe" in case_obj["latest_contact"]["notes"]
    assert len(case_obj["contact_history"]) >= 5

def test_coordinate_validation_bounds(client):
    """Test that out-of-bounds or infinite coordinates are rejected properly."""
    ts = int(time.time())
    v_email = f"v_coord_bounds_{ts}@example.com"
    pwd = "TestPassword123!"

    reg = client.post("/api/auth/register", json={"email": v_email, "password": pwd, "name": "Test Bounds", "role": "victim"})
    v_token = reg.json()["token"]

    # Invalid latitude > 90
    bad_res1 = client.post("/api/sos", headers={"Authorization": f"Bearer {v_token}"}, json={
        "latitude": 95.0,
        "longitude": 80.0,
        "message": "Invalid latitude"
    })
    assert bad_res1.status_code == 400

    # Invalid longitude > 180
    bad_res2 = client.post("/api/sos", headers={"Authorization": f"Bearer {v_token}"}, json={
        "latitude": 12.0,
        "longitude": 190.0,
        "message": "Invalid longitude"
    })
    assert bad_res2.status_code == 400
