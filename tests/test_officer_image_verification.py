import asyncio
import os
import sys
import hashlib
import io
import httpx
from dotenv import load_dotenv

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
load_dotenv(os.path.join(ROOT_DIR, ".env"))

from database import connect_db, get_db
from auth import make_token
import security_crypto

BASE_URL = "http://127.0.0.1:8000"

# Minimal valid file byte generators
def make_minimal_jpeg():
    # 2x2 red pixel JPEG
    return (
        b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00"
        b"\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t"
        b"\x08\n\x0c\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a"
        b"\x1f\x1e\x1d\x1a\x1c\x1c $.' \",#\x1c\x1c(7),01444\x1f'9=82<.342"
        b"\xff\xc0\x00\x0b\x08\x00\x02\x00\x02\x01\x01\x11\x00"
        b"\xff\xc4\x00\x1f\x00\x00\x01\x05\x01\x01\x01\x01\x01\x01\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b"
        b"\xff\xda\x00\x08\x01\x01\x00\x00?\x00\xbf\x80\xff\xd9"
    )

def make_minimal_png():
    # 1x1 transparent PNG
    return (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
        b"\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\rIDATx\x9cc`\x00\x00\x00"
        b"\x02\x00\x01H\xaf\xa4q\x00\x00\x00\x00IEND\xaeB`\x82"
    )

def make_minimal_webp():
    # 1x1 lossy WEBP
    header = b"RIFF\x1a\x00\x00\x00WEBPVP8 "
    chunk_data = b"\x0e\x00\x00\x00\xb0\x01\x00\x9d\x01*\x01\x00\x01\x00\x00"
    return header + chunk_data


async def run_verification():
    print("=== STARTING NIVARA OFFICER EVIDENCE PREVIEW & DOWNLOAD VERIFICATION ===")
    await connect_db()
    db = get_db()

    # 1. Identify test users
    victim = await db.users.find_one({"email": "priya@example.com"})
    if not victim:
        victim = await db.users.find_one({"role": "victim"})
    officer = await db.users.find_one({"email": "shruthi1234@gmail.com"})
    if not officer:
        officer = await db.users.find_one({"role": "officer"})

    assert victim is not None, "Victim user must exist"
    assert officer is not None, "Officer user must exist"
    print(f"Victim: {victim['name']} ({victim['email']}) [ID: {victim['_id']}]")
    print(f"Officer: {officer['name']} ({officer['email']}) [ID: {officer['_id']}]")

    victim_token = make_token(victim["_id"], victim["role"])
    officer_token = make_token(officer["_id"], officer["role"])

    v_headers = {"Authorization": f"Bearer {victim_token}"}
    o_headers = {"Authorization": f"Bearer {officer_token}"}

    results = {}

    async with httpx.AsyncClient(base_url=BASE_URL, timeout=30.0) as client:
        # TEST 1: Existing Record 1 ("Workshop poster-clg.jpeg", ID 120d2bac-6c33-4d31-bb71-d182e511ff2a)
        print("\n--- TEST 1: Existing Record 1 ('Workshop poster-clg.jpeg') ---")
        ev1_id = "120d2bac-6c33-4d31-bb71-d182e511ff2a"
        ev1_case = "a1d0952b-f140-4b17-83f3-db60c2070626"

        res_case = await client.get(f"/api/cases/{ev1_case}", headers=o_headers)
        assert res_case.status_code == 200, f"Case detail failed: {res_case.text}"
        case_data = res_case.json()
        ev1_meta = next((e for e in case_data.get("evidence", []) if e["id"] == ev1_id), None)
        assert ev1_meta is not None, "Record 1 must appear in shared evidence for case"
        print(f"  Record found in case: title='{ev1_meta['title']}', original_name='{ev1_meta['original_name']}', is_media={ev1_meta['is_media']}")
        print(f"  Integrity verified: {ev1_meta['integrity_verified']} ({ev1_meta['integrity_detail']})")
        assert ev1_meta["is_media"] is True
        assert ev1_meta["original_name"] == "Workshop poster-clg.jpeg"
        assert ev1_meta["integrity_verified"] is True

        # Preview Record 1
        res_prev = await client.get(f"/api/evidence/media/{ev1_id}", headers=o_headers)
        assert res_prev.status_code == 200, f"Preview failed: {res_prev.text}"
        assert res_prev.headers["content-type"] == "image/jpeg"
        assert 'filename="Workshop poster-clg.jpeg"' in res_prev.headers.get("content-disposition", "")
        assert "inline" in res_prev.headers.get("content-disposition", "")
        assert res_prev.headers.get("x-evidence-integrity") == "SHA256-Verified-Intact"
        assert len(res_prev.content) == 133265, f"Expected 133265 bytes, got {len(res_prev.content)}"
        calc_hash = hashlib.sha256(res_prev.content).hexdigest()
        assert calc_hash == "28635140b30a4435a82d18f753ab728cf2e9d81cb27aae6edd74793e97972f2e"
        print(f"  Preview SUCCESS: 200 OK, {len(res_prev.content)} bytes, exact SHA-256 match!")

        # Download Record 1
        res_down = await client.get(f"/api/evidence/media/{ev1_id}?download=true", headers=o_headers)
        assert res_down.status_code == 200, f"Download failed: {res_down.text}"
        assert res_down.headers["content-type"] == "image/jpeg"
        assert "attachment" in res_down.headers.get("content-disposition", "")
        assert 'filename="Workshop poster-clg.jpeg"' in res_down.headers.get("content-disposition", "")
        assert len(res_down.content) == 133265
        print(f"  Download SUCCESS: 200 OK, Content-Disposition: attachment, filename preserved!")
        results["test1_existing_record"] = "PASS"

        # TEST 2: Existing Text Snapshot Records (Record 2 & 3: 6e976c22... and 1e2e0762...)
        print("\n--- TEST 2: Existing Text Snapshot Honest Handling ---")
        ev2_id = "6e976c22-1652-4a70-801c-2e26bceca5c3"
        res_t2 = await client.get(f"/api/evidence/media/{ev2_id}", headers=o_headers)
        print(f"  Media request on text snapshot returns: {res_t2.status_code} ({res_t2.json().get('detail')})")
        assert res_t2.status_code == 400
        assert "does not contain media" in res_t2.json().get("detail", "")
        results["test2_text_snapshot_rejection"] = "PASS"

        # TEST 3: New JPEG Upload -> Seal -> Share -> Officer Preview -> Officer Download
        print("\n--- TEST 3: Full End-to-End JPEG Workflow ---")
        # Ensure victim has an active case assigned to officer
        case = await db.cases.find_one({"victim_id": victim["_id"], "officer_id": officer["_id"]})
        if not case:
            # Update a case or assign
            case = await db.cases.find_one({"victim_id": victim["_id"]})
            if case:
                await db.cases.update_one({"_id": case["_id"]}, {"$set": {"officer_id": officer["_id"]}})
                case = await db.cases.find_one({"_id": case["_id"]})
        assert case is not None, "Need a case for testing"
        target_case_id = case["_id"]

        jpeg_bytes = make_minimal_jpeg()
        upload_files = {"file": ("threat_photo.jpeg", io.BytesIO(jpeg_bytes), "image/jpeg")}
        upload_data = {
            "case_id": target_case_id,
            "title": "Threat Incident Evidence Photo",
            "notes": "Suspect left vehicle outside at 11:30 PM",
            "location": "12.9716, 77.5946"
        }
        res_up = await client.post("/api/evidence/upload-file", files=upload_files, data=upload_data, headers=v_headers)
        assert res_up.status_code == 200, f"Upload failed: {res_up.text}"
        up_data = res_up.json()
        new_ev_id = up_data["id"]
        expected_hash = hashlib.sha256(jpeg_bytes).hexdigest()
        assert up_data["hash"] == f"SHA256:{expected_hash}"
        print(f"  Victim uploaded JPEG: id={new_ev_id}, hash={up_data['hash']}")

        # Victim shares with officer
        res_share = await client.post(f"/api/evidence/{new_ev_id}/share", json={"case_id": target_case_id}, headers=v_headers)
        assert res_share.status_code == 200, f"Share failed: {res_share.text}"
        print(f"  Victim shared evidence: {res_share.json().get('message')}")

        # Officer previews new JPEG
        res_prev_jpeg = await client.get(f"/api/evidence/media/{new_ev_id}", headers=o_headers)
        assert res_prev_jpeg.status_code == 200
        assert res_prev_jpeg.headers["content-type"] == "image/jpeg"
        assert 'filename="threat_photo.jpeg"' in res_prev_jpeg.headers.get("content-disposition", "")
        assert res_prev_jpeg.content == jpeg_bytes
        print(f"  Officer preview JPEG SUCCESS: exact byte match ({len(res_prev_jpeg.content)} bytes)")

        # Officer downloads new JPEG
        res_down_jpeg = await client.get(f"/api/evidence/media/{new_ev_id}?download=true", headers=o_headers)
        assert res_down_jpeg.status_code == 200
        assert "attachment" in res_down_jpeg.headers.get("content-disposition", "")
        assert 'filename="threat_photo.jpeg"' in res_down_jpeg.headers.get("content-disposition", "")
        assert res_down_jpeg.content == jpeg_bytes
        print(f"  Officer download JPEG SUCCESS: Content-Disposition attachment, filename='threat_photo.jpeg'")
        results["test3_jpeg_workflow"] = "PASS"

        # TEST 4: PNG Upload & Retrieval
        print("\n--- TEST 4: PNG Support ---")
        png_bytes = make_minimal_png()
        up_png = await client.post(
            "/api/evidence/upload-file",
            files={"file": ("screenshot_evidence.png", io.BytesIO(png_bytes), "image/png")},
            data={"case_id": target_case_id, "title": "Stalking DM Screenshot", "notes": "Instagram direct message"},
            headers=v_headers
        )
        assert up_png.status_code == 200
        png_ev_id = up_png.json()["id"]
        await client.post(f"/api/evidence/{png_ev_id}/share", json={"case_id": target_case_id}, headers=v_headers)
        res_png_prev = await client.get(f"/api/evidence/media/{png_ev_id}", headers=o_headers)
        assert res_png_prev.status_code == 200
        assert res_png_prev.headers["content-type"] == "image/png"
        assert res_png_prev.content == png_bytes
        print(f"  PNG preview SUCCESS: MIME=image/png, {len(png_bytes)} bytes match")
        results["test4_png_support"] = "PASS"

        # TEST 5: WEBP Support
        print("\n--- TEST 5: WEBP Support ---")
        webp_bytes = make_minimal_webp()
        up_webp = await client.post(
            "/api/evidence/upload-file",
            files={"file": ("cctv_frame.webp", io.BytesIO(webp_bytes), "image/webp")},
            data={"case_id": target_case_id, "title": "CCTV Frame Evidence", "notes": "Corridor camera capture"},
            headers=v_headers
        )
        assert up_webp.status_code == 200
        webp_ev_id = up_webp.json()["id"]
        await client.post(f"/api/evidence/{webp_ev_id}/share", json={"case_id": target_case_id}, headers=v_headers)
        res_webp_prev = await client.get(f"/api/evidence/media/{webp_ev_id}", headers=o_headers)
        assert res_webp_prev.status_code == 200
        assert res_webp_prev.headers["content-type"] == "image/webp"
        assert res_webp_prev.content == webp_bytes
        print(f"  WEBP preview SUCCESS: MIME=image/webp, {len(webp_bytes)} bytes match")
        results["test5_webp_support"] = "PASS"

        # TEST 6: Unshared Evidence Access Rejection (403)
        print("\n--- TEST 6: Unshared Evidence Rejection ---")
        up_priv = await client.post(
            "/api/evidence/upload-file",
            files={"file": ("private_vault_doc.jpg", io.BytesIO(jpeg_bytes), "image/jpeg")},
            data={"case_id": target_case_id, "title": "Private Diary Entry", "notes": "Personal only"},
            headers=v_headers
        )
        assert up_priv.status_code == 200
        priv_id = up_priv.json()["id"]
        # Officer tries to access unshared evidence
        res_priv = await client.get(f"/api/evidence/media/{priv_id}", headers=o_headers)
        assert res_priv.status_code == 403, f"Expected 403, got {res_priv.status_code}"
        print(f"  Officer access to unshared evidence correctly REJECTED with 403: {res_priv.json().get('detail')}")
        results["test6_unshared_rejection"] = "PASS"

        # TEST 7: Revoked Evidence Access Rejection (403)
        print("\n--- TEST 7: Revoked Evidence Rejection ---")
        # Revoke access to png_ev_id
        res_rev = await client.post(f"/api/evidence/{png_ev_id}/revoke", headers=v_headers)
        assert res_rev.status_code == 200
        # Officer tries to access revoked evidence
        res_rev_access = await client.get(f"/api/evidence/media/{png_ev_id}", headers=o_headers)
        assert res_rev_access.status_code == 403
        assert "revoked" in res_rev_access.json().get("detail", "").lower()
        print(f"  Officer access to revoked evidence correctly REJECTED with 403: {res_rev_access.json().get('detail')}")
        results["test7_revoked_rejection"] = "PASS"

        # TEST 8: Unauthorized / Unauthenticated Access Rejection (401 / 403)
        print("\n--- TEST 8: Unauthenticated / Wrong Role Access Rejection ---")
        res_no_auth = await client.get(f"/api/evidence/media/{new_ev_id}")
        assert res_no_auth.status_code in [401, 403], f"Expected 401/403, got {res_no_auth.status_code}"
        print(f"  Unauthenticated access correctly REJECTED with {res_no_auth.status_code}")
        results["test8_unauthenticated_rejection"] = "PASS"

        # TEST 9: Non-existent Evidence ID (404)
        print("\n--- TEST 9: Non-existent Record Rejection ---")
        res_404 = await client.get("/api/evidence/media/00000000-0000-0000-0000-000000000000", headers=o_headers)
        assert res_404.status_code == 404
        print(f"  Non-existent ID correctly returned 404: {res_404.json().get('detail')}")
        results["test9_404_rejection"] = "PASS"

        # TEST 10: Missing Disk File Rejection (404)
        print("\n--- TEST 10: Missing Disk File Handling ---")
        # Insert a simulated shared record whose disk file does not exist
        fake_id = "test-missing-file-id-999"
        await db.audit_logs.insert_one({
            "_id": fake_id,
            "user_id": victim["_id"],
            "action": "evidence_snapshot",
            "created_at": (await db.audit_logs.find_one())["created_at"],
            "meta": {
                "case_id": target_case_id,
                "victim_id": victim["_id"],
                "title": "Missing Media Record",
                "notes": security_crypto.encrypt_value("test notes"),
                "integrity_hash": "SHA256:0000000000000000000000000000000000000000000000000000000000000000",
                "is_media": True,
                "media_type": "image/jpeg",
                "file_name": "non_existent_file_12345.jpg",
                "original_name": security_crypto.encrypt_value("lost_photo.jpg"),
                "sharing_status": "shared",
                "shared_case_id": target_case_id,
                "shared_officer_id": officer["_id"],
                "revoked_at": None,
            }
        })
        res_missing = await client.get(f"/api/evidence/media/{fake_id}", headers=o_headers)
        print(f"  Missing disk file response: {res_missing.status_code} ({res_missing.json().get('detail')})")
        assert res_missing.status_code in [400, 404]
        # Clean up fake record
        await db.audit_logs.delete_one({"_id": fake_id})
        results["test10_missing_file_handling"] = "PASS"

        # TEST 11: Corrupted File / Hash Mismatch (400)
        print("\n--- TEST 11: Corrupted File / Integrity Hash Mismatch ---")
        tamper_id = "test-tamper-record-888"
        tamper_disk_name = "tamper_test_disk.jpg"
        tamper_path = os.path.join(ROOT_DIR, "vault_media", tamper_disk_name)
        with open(tamper_path, "wb") as f:
            f.write(b"TAMPERED_BYTES_NOT_MATCHING_HASH")
        await db.audit_logs.insert_one({
            "_id": tamper_id,
            "user_id": victim["_id"],
            "action": "evidence_snapshot",
            "created_at": (await db.audit_logs.find_one())["created_at"],
            "meta": {
                "case_id": target_case_id,
                "victim_id": victim["_id"],
                "title": "Tampered Evidence File",
                "notes": security_crypto.encrypt_value("test notes"),
                "integrity_hash": "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "is_media": True,
                "media_type": "image/jpeg",
                "file_name": tamper_disk_name,
                "original_name": security_crypto.encrypt_value("tampered.jpg"),
                "sharing_status": "shared",
                "shared_case_id": target_case_id,
                "shared_officer_id": officer["_id"],
                "revoked_at": None,
            }
        })
        res_tamper = await client.get(f"/api/evidence/media/{tamper_id}", headers=o_headers)
        print(f"  Tampered file response: {res_tamper.status_code} ({res_tamper.json().get('detail')})")
        assert res_tamper.status_code == 400
        assert "integrity check failed" in res_tamper.json().get("detail", "").lower()
        # Clean up tamper test
        await db.audit_logs.delete_one({"_id": tamper_id})
        if os.path.exists(tamper_path):
            os.remove(tamper_path)
        results["test11_tamper_rejection"] = "PASS"

    print("\n================== VERIFICATION SUMMARY ==================")
    all_passed = True
    for test_name, status in results.items():
        print(f"  {test_name:<35}: {status}")
        if status != "PASS":
            all_passed = False
    print(f"\nOVERALL RESULT: {'ALL TESTS PASSED (100%)' if all_passed else 'FAILURES DETECTED'}")
    return all_passed

if __name__ == "__main__":
    success = asyncio.run(run_verification())
    sys.exit(0 if success else 1)
