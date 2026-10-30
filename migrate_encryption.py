"""
NIVARA Encryption Migration Utility — Task 8
Idempotent migration of legacy plaintext records to AES-256-GCM authenticated encryption at rest.

Target fields:
- safety_plans: emergency_notes, trusted_contacts, safe_places
- audit_logs (action="evidence_snapshot"): meta.notes, meta.geo

Modes:
  python migrate_encryption.py --dry-run   (Analyze without modifying data)
  python migrate_encryption.py --apply     (Perform authenticated in-place encryption)
  python migrate_encryption.py --verify    (Scan and confirm 100% encryption compliance)
"""

import os
import sys
import argparse
import logging
from typing import Dict, Any, Tuple
import pymongo
from dotenv import load_dotenv

# Load environment configuration
load_dotenv()

import security_crypto

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("nivara_migration")


def get_mongo_db(uri: str = None, db_name: str = None):
    """Obtains a synchronous pymongo Database instance."""
    mongo_uri = uri or os.environ.get("MONGO_URL", "mongodb://127.0.0.1:27017")
    database_name = db_name or os.environ.get("DB_NAME", "nivara")
    client = pymongo.MongoClient(mongo_uri)
    return client[database_name]


def migrate_database(db, dry_run: bool = True, batch_size: int = 100) -> Dict[str, Any]:
    """
    Safely migrates legacy plaintext fields in MongoDB to AES-256-GCM authenticated encryption.
    - Idempotent: Never double-encrypts existing 'enc:v1:' records.
    - Preserves all other document fields, IDs, timestamps, and metadata.
    - Never prints sensitive plaintext values in logs.
    """
    # 1. Pre-flight verification: Ensure valid encryption key is configured
    try:
        security_crypto.get_encryption_key()
    except security_crypto.EncryptionConfigError as e:
        logger.error(f"Migration aborted: Encryption key error: {e}")
        raise

    stats = {
        "dry_run": dry_run,
        "safety_plans_scanned": 0,
        "safety_plans_migrated": 0,
        "safety_plans_already_encrypted": 0,
        "evidence_scanned": 0,
        "evidence_migrated": 0,
        "evidence_already_encrypted": 0,
        "fields_encrypted": 0,
        "errors": []
    }

    # -------------------------------------------------------------
    # Collection 1: safety_plans
    # -------------------------------------------------------------
    cursor = db.safety_plans.find()
    batch_updates = []

    for doc in cursor:
        stats["safety_plans_scanned"] += 1
        plan_id = doc.get("_id")
        fields_to_update = {}

        # Check emergency_notes
        raw_notes = doc.get("emergency_notes")
        if raw_notes is not None:
            if isinstance(raw_notes, str) and raw_notes.startswith(security_crypto.PREFIX_V1):
                pass
            else:
                fields_to_update["emergency_notes"] = security_crypto.encrypt_value(raw_notes)
        else:
            fields_to_update["emergency_notes"] = security_crypto.encrypt_value("")

        # Check trusted_contacts
        raw_contacts = doc.get("trusted_contacts")
        if raw_contacts is not None:
            if isinstance(raw_contacts, str) and raw_contacts.startswith(security_crypto.PREFIX_V1):
                pass
            else:
                fields_to_update["trusted_contacts"] = security_crypto.encrypt_value(raw_contacts)
        else:
            fields_to_update["trusted_contacts"] = security_crypto.encrypt_value([])

        # Check safe_places
        raw_places = doc.get("safe_places")
        if raw_places is not None:
            if isinstance(raw_places, str) and raw_places.startswith(security_crypto.PREFIX_V1):
                pass
            else:
                fields_to_update["safe_places"] = security_crypto.encrypt_value(raw_places)
        else:
            fields_to_update["safe_places"] = security_crypto.encrypt_value([])

        if fields_to_update:
            stats["safety_plans_migrated"] += 1
            stats["fields_encrypted"] += len(fields_to_update)
            if not dry_run:
                batch_updates.append(
                    pymongo.UpdateOne({"_id": plan_id}, {"$set": fields_to_update})
                )
        else:
            stats["safety_plans_already_encrypted"] += 1

        # Execute in batches
        if not dry_run and len(batch_updates) >= batch_size:
            db.safety_plans.bulk_write(batch_updates, ordered=False)
            batch_updates = []

    if not dry_run and batch_updates:
        db.safety_plans.bulk_write(batch_updates, ordered=False)
        batch_updates = []

    # -------------------------------------------------------------
    # Collection 2: audit_logs (evidence_snapshot records)
    # -------------------------------------------------------------
    evidence_cursor = db.audit_logs.find({"action": "evidence_snapshot"})

    for log in evidence_cursor:
        stats["evidence_scanned"] += 1
        log_id = log.get("_id")
        meta = log.get("meta") or {}
        fields_to_update = {}

        # Check notes
        notes = meta.get("notes")
        if notes is not None:
            if isinstance(notes, str) and notes.startswith(security_crypto.PREFIX_V1):
                pass
            else:
                fields_to_update["meta.notes"] = security_crypto.encrypt_value(notes)

        # Check geo
        geo = meta.get("geo")
        if geo is not None:
            if isinstance(geo, str) and geo.startswith(security_crypto.PREFIX_V1):
                pass
            else:
                fields_to_update["meta.geo"] = security_crypto.encrypt_value(geo)

        if fields_to_update:
            stats["evidence_migrated"] += 1
            stats["fields_encrypted"] += len(fields_to_update)
            if not dry_run:
                batch_updates.append(
                    pymongo.UpdateOne({"_id": log_id}, {"$set": fields_to_update})
                )
        else:
            stats["evidence_already_encrypted"] += 1

        if not dry_run and len(batch_updates) >= batch_size:
            db.audit_logs.bulk_write(batch_updates, ordered=False)
            batch_updates = []

    if not dry_run and batch_updates:
        db.audit_logs.bulk_write(batch_updates, ordered=False)

    return stats


def verify_database_encryption(db) -> Dict[str, Any]:
    """
    Scans safety_plans and audit_logs to verify that 100% of sensitive fields are encrypted
    with AES-256-GCM and authenticable with the configured key.
    """
    try:
        security_crypto.get_encryption_key()
    except security_crypto.EncryptionConfigError as e:
        return {"status": "error", "message": f"Encryption key error: {e}", "compliant": False}

    results = {
        "safety_plans_checked": 0,
        "safety_plans_compliant": 0,
        "safety_plans_plaintext_remaining": 0,
        "evidence_checked": 0,
        "evidence_compliant": 0,
        "evidence_plaintext_remaining": 0,
        "tampered_records": 0,
        "compliant": True,
        "details": []
    }

    # Verify safety_plans
    for p in db.safety_plans.find():
        results["safety_plans_checked"] += 1
        plan_id = p["_id"]
        is_plan_ok = True

        for field in ["emergency_notes", "trusted_contacts", "safe_places"]:
            val = p.get(field)
            if val is not None:
                if not (isinstance(val, str) and val.startswith(security_crypto.PREFIX_V1)):
                    is_plan_ok = False
                    results["safety_plans_plaintext_remaining"] += 1
                    results["compliant"] = False
                    results["details"].append(f"Plan {plan_id}: field '{field}' is unencrypted plaintext")
                else:
                    # Test authenticable decryption
                    try:
                        security_crypto.decrypt_value(val, fallback_to_raw_on_unencrypted=False)
                    except security_crypto.DecryptionError:
                        is_plan_ok = False
                        results["tampered_records"] += 1
                        results["compliant"] = False
                        results["details"].append(f"Plan {plan_id}: field '{field}' failed authentication check (tampered/invalid key)")

        if is_plan_ok:
            results["safety_plans_compliant"] += 1

    # Verify evidence in audit_logs
    for l in db.audit_logs.find({"action": "evidence_snapshot"}):
        results["evidence_checked"] += 1
        log_id = l["_id"]
        meta = l.get("meta") or {}
        is_evidence_ok = True

        for field in ["notes", "geo"]:
            val = meta.get(field)
            if val is not None:
                if not (isinstance(val, str) and val.startswith(security_crypto.PREFIX_V1)):
                    is_evidence_ok = False
                    results["evidence_plaintext_remaining"] += 1
                    results["compliant"] = False
                    results["details"].append(f"Evidence {log_id}: meta field '{field}' is unencrypted plaintext")
                else:
                    try:
                        security_crypto.decrypt_value(val, fallback_to_raw_on_unencrypted=False)
                    except security_crypto.DecryptionError:
                        is_evidence_ok = False
                        results["tampered_records"] += 1
                        results["compliant"] = False
                        results["details"].append(f"Evidence {log_id}: meta field '{field}' failed authentication check")

        if is_evidence_ok:
            results["evidence_compliant"] += 1

    return results


def main():
    parser = argparse.ArgumentParser(description="NIVARA Sensitive Data Encryption Migration")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--dry-run", action="store_true", help="Inspect and report without modifying data (default)")
    group.add_argument("--apply", action="store_true", help="Perform in-place encryption of legacy records")
    group.add_argument("--verify", action="store_true", help="Verify 100% encryption compliance across records")

    args = parser.parse_args()
    db = get_mongo_db()

    if args.verify:
        print("\n=======================================================")
        print("  NIVARA SENSITIVE DATA ENCRYPTION VERIFICATION")
        print("=======================================================\n")
        report = verify_database_encryption(db)
        print(f"Safety Plans Checked:      {report['safety_plans_checked']}")
        print(f"  Compliant:               {report['safety_plans_compliant']}")
        print(f"  Plaintext Remaining:     {report['safety_plans_plaintext_remaining']}")
        print(f"Evidence Records Checked:  {report['evidence_checked']}")
        print(f"  Compliant:               {report['evidence_compliant']}")
        print(f"  Plaintext Remaining:     {report['evidence_plaintext_remaining']}")
        print(f"Tampered / Corrupted:      {report['tampered_records']}")
        print(f"\nOverall Compliant:         {'YES (100% Protected)' if report['compliant'] else 'NO (Plaintext/Issues Detected)'}")
        if report["details"]:
            print(f"Issues detected ({len(report['details'])}):")
            for d in report["details"][:10]:
                print(f"  - {d}")
        sys.exit(0 if report["compliant"] else 1)

    is_dry_run = not args.apply
    mode_label = "DRY-RUN (No changes applied)" if is_dry_run else "LIVE MIGRATION (Applying AES-256-GCM encryption)"

    print("\n=======================================================")
    print(f"  NIVARA DATA MIGRATION: {mode_label}")
    print("=======================================================\n")

    stats = migrate_database(db, dry_run=is_dry_run)

    print(f"Mode:                          {'DRY RUN (Preview Only)' if is_dry_run else 'APPLIED'}")
    print(f"Safety Plans Scanned:          {stats['safety_plans_scanned']}")
    print(f"  Needing Encryption:          {stats['safety_plans_migrated']}")
    print(f"  Already Encrypted:           {stats['safety_plans_already_encrypted']}")
    print(f"Evidence Records Scanned:      {stats['evidence_scanned']}")
    print(f"  Needing Encryption:          {stats['evidence_migrated']}")
    print(f"  Already Encrypted:           {stats['evidence_already_encrypted']}")
    print(f"Total Fields Encrypted:        {stats['fields_encrypted']}")

    if is_dry_run:
        print("\n[NOTE] Dry run complete. No database changes were made.")
        print("To apply this migration, run: python migrate_encryption.py --apply\n")
    else:
        print("\n[SUCCESS] Migration applied successfully.")
        print("To verify encryption compliance, run: python migrate_encryption.py --verify\n")


if __name__ == "__main__":
    main()
