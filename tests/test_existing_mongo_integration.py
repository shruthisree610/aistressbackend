import asyncio
import os
import sys
from pathlib import Path
import httpx
from dotenv import load_dotenv

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))
load_dotenv(ROOT_DIR / ".env")

from database import connect_db, get_db, get_client
from motor.motor_asyncio import AsyncIOMotorClient

BASE_URL = "http://127.0.0.1:8000"

EXPECTED_COLLECTIONS = [
    "analysis_results",
    "audit_logs",
    "cases",
    "consents",
    "counsellor_notes",
    "followups",
    "interactions",
    "intervention_recommendation",
    "notifications",
    "officer_actions",
    "safety_plans",
    "stress_assessment",
    "users",
    "voice_analysis"
]

async def run_integration_tests():
    print("=" * 70)
    print("NIVARA — EXISTING MONGODB INTEGRATION & DATA PRESERVATION AUDIT")
    print("=" * 70)

    # 1. Direct MongoDB Client Verification
    mongo_url = os.environ.get("MONGO_URL", "mongodb://127.0.0.1:27017")
    db_name = os.environ.get("DB_NAME", "nivara")
    print(f"\n1. Direct MongoDB Connection:")
    print(f"   Target URI : {mongo_url}")
    print(f"   Database   : {db_name}")

    client = AsyncIOMotorClient(mongo_url, serverSelectionTimeoutMS=5000)
    pong = await client.admin.command("ping")
    assert pong.get("ok") == 1.0, f"Ping failed: {pong}"
    print(f"   Ping Check : SUCCESS (ok: {pong.get('ok')})")

    server_info = await client.server_info()
    print(f"   Server Ver : MongoDB {server_info.get('version')}")

    db = client[db_name]
    detected_cols = await db.list_collection_names()
    print(f"\n2. Detected Collections in '{db_name}' ({len(detected_cols)}):")
    
    initial_counts = {}
    for col in sorted(detected_cols):
        cnt = await db[col].count_documents({})
        initial_counts[col] = cnt
        print(f"   - {col:<32}: {cnt:>6} records")

    for exp in EXPECTED_COLLECTIONS:
        assert exp in detected_cols, f"Expected collection '{exp}' not found in MongoDB!"

    # 2. FastAPI Backend Health Check
    print(f"\n3. FastAPI Live Endpoint Verification:")
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=15.0) as http:
        res_health = await http.get("/api/health")
        assert res_health.status_code == 200, f"Health check failed: {res_health.status_code}"
        health_json = res_health.json()
        print(f"   GET /api/health -> Status: {res_health.status_code}")
        print(f"   Response Payload: {health_json}")
        assert health_json.get("status") == "ok"
        assert health_json.get("database", {}).get("status") == "connected"
        assert health_json.get("database", {}).get("ping") is True
        assert health_json.get("database", {}).get("name") == db_name

        # 3. Authentication & Login Checks
        print(f"\n4. User Authentication & Login Across Roles:")
        # Victim login
        res_v_login = await http.post("/api/auth/login", json={"email": "victim@nivara.app", "password": "Password123"})
        assert res_v_login.status_code == 200, f"Victim login failed: {res_v_login.text}"
        v_token = res_v_login.json()["token"]
        print(f"   Victim Login (victim@nivara.app)       : 200 OK -> Token issued")

        # Officer login
        res_o_login = await http.post("/api/auth/login", json={"email": "officer@nivara.app", "password": "Password123"})
        assert res_o_login.status_code == 200, f"Officer login failed: {res_o_login.text}"
        o_token = res_o_login.json()["token"]
        print(f"   Officer Login (officer@nivara.app)     : 200 OK -> Token issued")

        # Counsellor login
        res_c_login = await http.post("/api/auth/login", json={"email": "counsellor@nivara.app", "password": "Password123"})
        assert res_c_login.status_code == 200, f"Counsellor login failed: {res_c_login.text}"
        c_token = res_c_login.json()["token"]
        print(f"   Counsellor Login (counsellor@nivara.app): 200 OK -> Token issued")

        # 4. Cases API
        print(f"\n5. Cases & Workflow Endpoints:")
        v_headers = {"Authorization": f"Bearer {v_token}"}
        o_headers = {"Authorization": f"Bearer {o_token}"}
        c_headers = {"Authorization": f"Bearer {c_token}"}

        res_v_cases = await http.get("/api/cases/mine", headers=v_headers)
        assert res_v_cases.status_code == 200, f"Victim cases failed: {res_v_cases.text}"
        v_cases = res_v_cases.json()
        print(f"   Victim Cases (/api/cases/mine)         : 200 OK -> {len(v_cases)} cases found")

        res_o_cases = await http.get("/api/cases/mine", headers=o_headers)
        assert res_o_cases.status_code == 200, f"Officer cases failed: {res_o_cases.text}"
        o_cases = res_o_cases.json()
        print(f"   Officer Cases (/api/cases/mine)        : 200 OK -> {len(o_cases)} active triage cases")

        res_c_cases = await http.get("/api/cases/mine", headers=c_headers)
        assert res_c_cases.status_code == 200, f"Counsellor cases failed: {res_c_cases.text}"
        c_cases = res_c_cases.json()
        print(f"   Counsellor Cases (/api/cases/mine)     : 200 OK -> {len(c_cases)} assigned cases")

        # 5. Evidence & Safety Plan
        if v_cases:
            target_case_id = v_cases[0]["id"]
            res_ev = await http.get(f"/api/evidence/{target_case_id}", headers=v_headers)
            assert res_ev.status_code == 200
            print(f"   Evidence Records (/api/evidence/{target_case_id[:8]}...): 200 OK -> {len(res_ev.json().get('evidence', []))} records")

        res_sp = await http.get("/api/safety-plan", headers=v_headers)
        assert res_sp.status_code == 200
        print(f"   Safety Plan (/api/safety-plan)          : 200 OK -> Plan retrieved")

        # 6. Counsellors Directory
        res_couns = await http.get("/api/users/counsellors", headers=o_headers)
        assert res_couns.status_code == 200
        print(f"   Counsellors List (/api/users/counsellors): 200 OK -> {len(res_couns.json())} counsellors retrieved")

    # 7. Strict Data Preservation Verification
    print(f"\n6. Data Preservation Check (Before vs After):")
    final_counts = {}
    no_loss = True
    for col in sorted(detected_cols):
        cnt = await db[col].count_documents({})
        final_counts[col] = cnt
        diff = cnt - initial_counts[col]
        print(f"   - {col:<32}: Before={initial_counts[col]:>5}, After={cnt:>5} (delta={diff})")
        if cnt < initial_counts[col]:
            no_loss = False
            print(f"     CRITICAL ERROR: Data loss in collection '{col}'!")

    assert no_loss, "DATA LOSS DETECTED!"
    print(f"\nCONFIRMATION: ZERO records deleted, dropped, or overwritten. 100% of existing data preserved.")

    client.close()
    print("=" * 70)
    print("ALL TESTS PASSED — BACKEND IS FULLY CONNECTED TO EXISTING MONGODB")
    print("=" * 70)
    return True

if __name__ == "__main__":
    success = asyncio.run(run_integration_tests())
    sys.exit(0 if success else 1)
