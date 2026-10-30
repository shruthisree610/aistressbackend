import asyncio
import os
import sys
import httpx
from datetime import datetime
from dotenv import load_dotenv

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
load_dotenv(os.path.join(ROOT_DIR, ".env"))

from database import connect_db, get_db
from auth import make_token
import security_crypto

BASE_URL = "http://127.0.0.1:8000"

async def run_workflow_test():
    print("=== STARTING NIVARA COMPLAINT -> OFFICER DASHBOARD VISIBILITY TEST ===")
    await connect_db()
    db = get_db()

    # 1. Identify users
    victim = await db.users.find_one({"email": "victim@nivara.app"})
    if not victim:
        victim = await db.users.find_one({"role": "victim"})
    officer = await db.users.find_one({"email": "shruthi1234@gmail.com"})
    if not officer:
        officer = await db.users.find_one({"role": "officer"})

    assert victim is not None, "Victim must exist in database"
    assert officer is not None, "Officer must exist in database"
    print(f"Victim User: {victim['name']} ({victim['email']}) [ID: {victim['_id']}]")
    print(f"Officer User: {officer['name']} ({officer['email']}) [ID: {officer['_id']}]")

    victim_token = make_token(victim["_id"], victim["role"])
    officer_token = make_token(officer["_id"], officer["role"])

    v_headers = {"Authorization": f"Bearer {victim_token}"}
    o_headers = {"Authorization": f"Bearer {officer_token}"}

    async with httpx.AsyncClient(base_url=BASE_URL, timeout=30.0) as client:
        # -------------------------------------------------------------
        # STEP 1: Victim submits a new test complaint
        # -------------------------------------------------------------
        print("\n--- STEP 1: Victim submits new complaint ---")
        complaint_payload = {
            "category": "stalking",
            "title": "Stalker following me near metro station",
            "description": "A suspicious male wearing a dark hooded jacket followed me from the metro station to my apartment building. This has happened three nights in a row.",
            "incident_date": "2026-10-30",
            "incident_location": "Indiranagar Metro Station Exit B, Bangalore",
            "suspect_details": "Male, ~5ft 10in, dark hood, black backpack",
            "priority": "high",
            "latitude": 12.9784,
            "longitude": 77.6408
        }
        res = await client.post("/api/complaints", json=complaint_payload, headers=v_headers)
        assert res.status_code == 200, f"Complaint submission failed: {res.status_code} - {res.text}"
        comp_data = res.json()
        case_id = comp_data.get("case_id")
        ref_num = comp_data.get("reference_number")
        print(f"  Victim submission SUCCESS: case_id={case_id}, ref={ref_num}, status={comp_data.get('status')}")
        assert case_id is not None, "Returned case_id must not be None"
        assert ref_num.startswith("CMP-"), f"Reference number should start with CMP-, got {ref_num}"

        # -------------------------------------------------------------
        # STEP 2: Inspect MongoDB persistence
        # -------------------------------------------------------------
        print("\n--- STEP 2: Inspect MongoDB persistence ---")
        stored_case = await db.cases.find_one({"_id": case_id})
        assert stored_case is not None, f"Case {case_id} not found in MongoDB cases collection!"
        print(f"  MongoDB Document Verified: ID={stored_case['_id']}")
        print(f"    title={stored_case.get('title')}")
        print(f"    status={stored_case.get('status')}")
        print(f"    priority={stored_case.get('priority')}")
        print(f"    category={stored_case.get('category')}")
        print(f"    acknowledgment_status={stored_case.get('acknowledgment_status')}")
        print(f"    officer_id={stored_case.get('officer_id')}")
        print(f"    created_at={stored_case.get('created_at')}")
        assert stored_case.get("status") == "open", "Status must be open"
        assert stored_case.get("acknowledgment_status") == "unassigned", "Acknowledgment status must be unassigned"
        assert stored_case.get("officer_id") is None, "New complaint officer_id must be None (unassigned)"
        assert stored_case.get("is_complaint") is True, "is_complaint flag must be True"

        # Verify suspect details encryption at rest
        raw_suspect = stored_case.get("suspect_details")
        assert raw_suspect != "Male, ~5ft 10in, dark hood, black backpack", "Suspect details must be encrypted at rest!"
        decrypted_suspect = security_crypto.decrypt_value(raw_suspect)
        assert decrypted_suspect == "Male, ~5ft 10in, dark hood, black backpack", f"Decryption failed: {decrypted_suspect}"
        print(f"    Suspect details encrypted at rest and verified intact.")

        # Verify interaction created
        interaction = await db.interactions.find_one({"case_id": case_id})
        assert interaction is not None, "Interaction record must exist"
        print(f"    Interaction recorded: role={interaction['role']}, content length={len(interaction['content'])}")

        # Verify audit log created
        audit = await db.audit_logs.find_one({"meta.case_id": case_id, "action": "complaint_filed"})
        assert audit is not None, "Audit log for complaint_filed must exist"
        print(f"    Audit log created: action={audit['action']}")

        # -------------------------------------------------------------
        # STEP 3: Officer Dashboard Visibility in Unassigned Queue
        # -------------------------------------------------------------
        print("\n--- STEP 3: Officer Dashboard Visibility ---")
        officer_res = await client.get("/api/cases/mine", headers=o_headers)
        assert officer_res.status_code == 200, f"Officer cases retrieval failed: {officer_res.status_code}"
        officer_cases = officer_res.json()
        print(f"  Total cases returned to officer: {len(officer_cases)}")

        # Find the specific submitted case
        target_case = next((c for c in officer_cases if c["id"] == case_id), None)
        assert target_case is not None, f"Submitted complaint {case_id} NOT FOUND in officer /cases/mine!"
        print(f"  Case {case_id} FOUND in Officer case list:")
        print(f"    title: {target_case['title']}")
        print(f"    acknowledgment_status: {target_case.get('acknowledgment_status')}")
        print(f"    officer_id: {target_case.get('officer_id')}")
        print(f"    is_demo_or_test: {target_case.get('is_demo_or_test')}")
        print(f"    record_provenance: {target_case.get('record_provenance')}")
        print(f"    is_complaint: {target_case.get('is_complaint')}")
        print(f"    reference_number: {target_case.get('reference_number')}")

        assert target_case.get("acknowledgment_status") == "unassigned", "Acknowledgment status must be unassigned"
        assert target_case.get("officer_id") is None, "Officer ID must be None before claiming"
        assert target_case.get("is_demo_or_test") is False, "Complaint must not be suppressed as test run"
        assert target_case.get("record_provenance") == "live", "Complaint provenance must be live"

        # Check ranking: complaint should be in unassigned/triage tier near the top (before assigned active cases)
        index_in_list = next(i for i, c in enumerate(officer_cases) if c["id"] == case_id)
        print(f"  Case rank in officer list: #{index_in_list + 1} of {len(officer_cases)}")
        # Verify it's within the top tier of cases
        assert index_in_list < 15, f"Unassigned complaint should be near top of officer list, got rank #{index_in_list + 1}"

        # Test officer detail endpoint
        detail_res = await client.get(f"/api/cases/{case_id}", headers=o_headers)
        assert detail_res.status_code == 200, f"Officer detail retrieval failed: {detail_res.status_code}"
        detail_data = detail_res.json()
        assert detail_data["case"]["id"] == case_id
        assert detail_data["case"]["victim_name"] == victim["name"]
        print(f"  Officer Case Detail SUCCESS: victim={detail_data['case']['victim_name']}, phone={detail_data['case'].get('victim_phone')}")

        # -------------------------------------------------------------
        # STEP 4: Officer Claims / Acknowledges Case
        # -------------------------------------------------------------
        print("\n--- STEP 4: Officer Claims & Acknowledges Case ---")
        claim_payload = {
            "case_id": case_id,
            "action": "acknowledged",
            "notes": f"Duty Officer {officer['name']} claimed complaint for active response"
        }
        ack_res = await client.post("/api/officer/action", json=claim_payload, headers=o_headers)
        assert ack_res.status_code == 200, f"Claim action failed: {ack_res.status_code} - {ack_res.text}"
        ack_data = ack_res.json()
        print(f"  Claim Response: {ack_data}")
        assert ack_data.get("acknowledgment_status") == "acknowledged", "Status should be acknowledged"

        # Verify in MongoDB that officer is assigned and status is in_progress
        updated_db_case = await db.cases.find_one({"_id": case_id})
        print(f"  MongoDB Updated State:")
        print(f"    officer_id: {updated_db_case.get('officer_id')}")
        print(f"    acknowledgment_status: {updated_db_case.get('acknowledgment_status')}")
        print(f"    status: {updated_db_case.get('status')}")
        print(f"    acknowledged_by: {updated_db_case.get('acknowledged_by')}")
        assert updated_db_case.get("officer_id") == officer["_id"], f"Case officer_id should be {officer['_id']}"
        assert updated_db_case.get("acknowledgment_status") == "acknowledged", "acknowledgment_status should be acknowledged"
        assert updated_db_case.get("status") == "in_progress", "status should be in_progress"

        # -------------------------------------------------------------
        # STEP 5: Verify Case Transitioned to Assigned Active Cases
        # -------------------------------------------------------------
        print("\n--- STEP 5: Verify Transition to Assigned Active Cases ---")
        refreshed_res = await client.get("/api/cases/mine", headers=o_headers)
        refreshed_cases = refreshed_res.json()
        refreshed_case = next(c for c in refreshed_cases if c["id"] == case_id)
        print(f"  Refreshed Officer View for Case {case_id}:")
        print(f"    officer_id: {refreshed_case.get('officer_id')}")
        print(f"    acknowledgment_status: {refreshed_case.get('acknowledgment_status')}")
        print(f"    status: {refreshed_case.get('status')}")
        assert refreshed_case.get("officer_id") == officer["_id"]
        assert refreshed_case.get("acknowledgment_status") == "acknowledged"
        assert refreshed_case.get("status") == "in_progress"
        print("  SUCCESS: Case moved from Unassigned/Triage to Assigned Active View!")

        # -------------------------------------------------------------
        # STEP 6: Confirm Victim Data & Evidence Sharing Workflow Unlocked
        # -------------------------------------------------------------
        print("\n--- STEP 6: Confirm Victim Data Intact & Evidence Sharing Unlocked ---")
        victim_cases_res = await client.get("/api/cases/mine", headers=v_headers)
        victim_cases = victim_cases_res.json()
        victim_case = next(c for c in victim_cases if c["id"] == case_id)
        assert victim_case is not None, "Case must exist on victim's dashboard"
        print(f"  Victim dashboard view: status={victim_case['status']}, officer_assigned={bool(victim_case.get('officer_id'))}")

        # Now test evidence sharing with the assigned officer!
        evidence_payload = {
            "case_id": case_id,
            "title": "Stalker photo outside apartment",
            "notes": "Snapped photo of stalker waiting near gate",
            "location": "Indiranagar Metro Exit B"
        }
        ev_res = await client.post("/api/evidence/upload", json=evidence_payload, headers=v_headers)
        assert ev_res.status_code == 200, f"Evidence upload failed: {ev_res.status_code}"
        evidence_id = ev_res.json().get("id")
        print(f"  Victim uploaded evidence: id={evidence_id}")

        # Share evidence with assigned officer
        share_res = await client.post(f"/api/evidence/{evidence_id}/share", json={"case_id": case_id}, headers=v_headers)
        assert share_res.status_code == 200, f"Evidence share failed: {share_res.status_code} - {share_res.text}"
        print(f"  Evidence shared with assigned officer: {share_res.json().get('message')}")

        # Verify officer can view shared evidence
        officer_detail = await client.get(f"/api/cases/{case_id}", headers=o_headers)
        shared_evidence_list = officer_detail.json().get("evidence", [])
        assert any(e["id"] == evidence_id for e in shared_evidence_list), "Officer detail must include shared evidence"
        print(f"  Officer successfully accesses shared evidence: {len(shared_evidence_list)} record(s)")

    print("\n================== ALL TESTS PASSED SUCCESSFULLY! ==================")

if __name__ == "__main__":
    asyncio.run(run_workflow_test())
