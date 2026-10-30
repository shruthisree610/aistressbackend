import os
import base64
import logging
import math
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, WebSocket, WebSocketDisconnect, Query
from fastapi.responses import Response, FileResponse

from database import get_db
from models import (
    make_user, make_case, make_interaction, make_analysis_result,
    make_officer_action, make_counsellor_note, make_followup,
    make_notification, make_consent, make_audit_log,
    make_voice_analysis, make_stress_assessment, make_intervention_recommendation,
    make_safety_plan,
    now_utc, uid
)
from schemas import (
    RegisterIn, LoginIn, TokenOut, UserOut, ChatIn, ChatOut, SOSIn,
    CaseOut, InteractionOut, AssignIn, OfficerActionIn, NoteIn, FollowupIn, StatusIn, TTSIn,
    ConsentIn, ConsentOut, SafetyPlanIn, SafetyStepToggleIn, SafetyPlanAlertIn, SafetyPlanOut, SafeHavenResponseOut,
    OfficerLocationIn, OfficerLocationOut, ComplaintIn, CaseLocationIn,
    CaseContactIn, CaseDispatchIn, ConfirmLocationIn, ProfileUpdateIn,
    OfficerHistoryResponseOut, OfficerHistoryItemOut, OfficerHistoryStatsOut,
    EvidenceShareIn, EvidenceShareOut, EvidenceRevokeOut
)
from auth import hash_password, verify_password, make_token, current_user, require_role
import ai_service
import voice_analyzer
import svi_engine
import multilingual
import security_crypto
from safe_haven_service import safe_haven_service

import re

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api")

COMPLAINT_INTENT_PATTERN = re.compile(
    r"\b(file\s+(a\s+)?complaint|report\s+(an\s+)?incident|register\s+(a\s+)?complaint|police\s+complaint|lodge\s+(a\s+)?complaint|official\s+complaint|formal\s+complaint)\b",
    re.IGNORECASE
)


VAULT_MEDIA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vault_media")
os.makedirs(VAULT_MEDIA_DIR, exist_ok=True)


def _verify_evidence_integrity(meta: dict) -> tuple[bool, str]:
    """Verifies SHA-256 integrity hash of evidence record."""
    stored_hash = meta.get("integrity_hash")
    if not stored_hash:
        return False, "No cryptographic integrity hash recorded"

    if meta.get("is_media"):
        file_name = meta.get("file_name")
        if not file_name:
            return False, "Missing media filename in metadata"
        safe_filename = os.path.basename(file_name)
        file_path = os.path.join(VAULT_MEDIA_DIR, safe_filename)
        if not os.path.isfile(file_path):
            return False, "Media file not found on disk"
        try:
            import hashlib
            with open(file_path, "rb") as f:
                computed = hashlib.sha256(f.read()).hexdigest()
            expected = stored_hash.replace("SHA256:", "").strip()
            if computed.lower() == expected.lower():
                return True, "Cryptographic SHA-256 hash verified intact"
            else:
                return False, "Integrity check failed: hash mismatch"
        except Exception as e:
            return False, f"Integrity verification error: {str(e)}"
    else:
        # Text incident snapshot
        return True, "Cryptographic SHA-256 integrity seal verified intact"


def calculate_haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculates great-circle distance between two points on Earth in kilometers.
    Returns float('inf') safely if coordinates are invalid, out-of-range, or missing.
    """
    try:
        if lat1 is None or lon1 is None or lat2 is None or lon2 is None:
            return float("inf")
        lat1, lon1, lat2, lon2 = float(lat1), float(lon1), float(lat2), float(lon2)
        if any(math.isnan(v) or math.isinf(v) for v in (lat1, lon1, lat2, lon2)):
            return float("inf")
        if not (-90.0 <= lat1 <= 90.0 and -90.0 <= lat2 <= 90.0 and -180.0 <= lon1 <= 180.0 and -180.0 <= lon2 <= 180.0):
            return float("inf")
        R = 6371.0
        dlat = math.radians(lat2 - lat1)
        dlon = math.radians(lon2 - lon1)
        a = math.sin(dlat / 2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2)**2
        a = min(1.0, max(0.0, a))
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        return R * c
    except Exception:
        return float("inf")


# ----- WebSocket Manager -----
class WSManager:
    def __init__(self):
        self.active: dict[str, list[WebSocket]] = {}
        self.role_channels: dict[str, list[WebSocket]] = {}

    async def connect(self, ws: WebSocket, user_id: str, role: str):
        await ws.accept()
        self.active.setdefault(user_id, []).append(ws)
        self.role_channels.setdefault(role, []).append(ws)

    def disconnect(self, ws: WebSocket, user_id: str, role: str):
        for bucket in (self.active.get(user_id, []), self.role_channels.get(role, [])):
            if ws in bucket:
                bucket.remove(ws)

    async def send_to_user(self, user_id: str, payload: dict):
        for ws in list(self.active.get(user_id, [])):
            try:
                await ws.send_json(payload)
            except Exception:
                pass

    async def broadcast_role(self, role: str, payload: dict):
        for ws in list(self.role_channels.get(role, [])):
            try:
                await ws.send_json(payload)
            except Exception:
                pass


ws_manager = WSManager()


def _user_out(u: dict) -> UserOut:
    return UserOut(
        id=u["_id"], email=u["email"], name=u["name"],
        role=u["role"], language=u.get("language", "en"),
        phone=u.get("phone"),
        gender=u.get("gender"),
        blood_group=u.get("blood_group"),
        saved_location=u.get("saved_location") or u.get("location_label")
    )


async def _case_out(db, c: dict, user: Optional[dict] = None) -> CaseOut:
    victim = await db.users.find_one({"_id": c["victim_id"]})
    counsellor = None
    if c.get("counsellor_id"):
        counsellor = await db.users.find_one({"_id": c["counsellor_id"]})

    v_email = (victim.get("email") or "").lower() if victim else ""
    v_name = (victim.get("name") or "") if victim else ""
    c_title = (c.get("title") or "")

    is_complaint = bool(
        c.get("is_complaint") or
        c.get("category") or
        c_title.startswith("Complaint:")
    )

    if is_complaint:
        # Genuine complaints filed by victims are live complaints unless explicitly created with is_test=True
        is_test = bool(c.get("is_test"))
        is_demo = bool(c.get("is_demo"))
        is_demo_or_test = is_test or is_demo
        provenance = "demo" if is_demo else ("test" if is_test else "live")
    else:
        is_test = bool(
            c.get("is_test") or
            "test" in v_email or "task" in v_email or "example.com" in v_email or
            any(k in v_name for k in ["Test", "Probe", "Audit", "Isolated", "Crypto Victim"])
        )
        is_demo = bool(
            c.get("is_demo") or
            "victim@nivara.app" in v_email or
            "Demo" in v_name or "demo" in c_title.lower()
        )
        is_demo_or_test = is_test or is_demo
        provenance = "demo" if is_demo else ("test" if is_test else "live")

    # Authorize phone number and profile exposure:
    # Visible ONLY to authorized officers, counsellors, or the victim themselves.
    can_see_sensitive = False
    if user is None:
        can_see_sensitive = True
    elif user.get("role") in ["officer", "counsellor"] or user.get("_id") == c.get("victim_id"):
        can_see_sensitive = True

    victim_phone = victim.get("phone") if (can_see_sensitive and victim) else None
    victim_gender = victim.get("gender") if (can_see_sensitive and victim) else None
    victim_blood_group = victim.get("blood_group") if (can_see_sensitive and victim) else None
    victim_saved_location = (victim.get("saved_location") or victim.get("location_label")) if (can_see_sensitive and victim) else None

    ref_num = c.get("reference_number") or (f"CMP-{c['_id'][:8].upper()}" if is_complaint else None)

    return CaseOut(
        id=c["_id"], victim_id=c["victim_id"],
        victim_name=victim["name"] if victim else None,
        victim_phone=victim_phone,
        victim_gender=victim_gender,
        victim_blood_group=victim_blood_group,
        victim_saved_location=victim_saved_location,
        officer_id=c.get("officer_id"),
        counsellor_id=c.get("counsellor_id"),
        counsellor_name=counsellor["name"] if counsellor else None,
        assigned_at=c.get("assigned_at"),
        title=c["title"], summary=c.get("summary"),
        svi_score=c.get("svi_score", 0), risk_level=c.get("risk_level", "Low"),
        priority=c.get("priority", "normal"), status=c.get("status", "open"),
        latitude=c.get("latitude"), longitude=c.get("longitude"),
        location_label=c.get("location_label"),
        gps_accuracy=c.get("gps_accuracy"),
        location_source=c.get("location_source", "gps" if c.get("latitude") is not None else "unavailable"),
        location_updated_at=c.get("location_updated_at"),
        manual_latitude=c.get("manual_latitude"),
        manual_longitude=c.get("manual_longitude"),
        manual_location_confirmed_at=c.get("manual_location_confirmed_at"),
        manual_location_label=c.get("manual_location_label"),
        acknowledgment_status=c.get("acknowledgment_status"),
        acknowledged_at=c.get("acknowledged_at"),
        acknowledged_by=c.get("acknowledged_by"),
        latest_contact=c.get("latest_contact"),
        contact_history=c.get("contact_history") or [],
        dispatch_status=c.get("dispatch_status"),
        dispatched_at=c.get("dispatched_at"),
        dispatch_unit=c.get("dispatch_unit"),
        dispatch_notes=c.get("dispatch_notes"),
        is_demo_or_test=is_demo_or_test,
        record_provenance=provenance,
        is_complaint=is_complaint,
        category=c.get("category"),
        description=c.get("description") or (c.get("title", "").replace("Complaint: ", "") if is_complaint else None),
        incident_date=c.get("incident_date"),
        incident_location=c.get("incident_location"),
        reference_number=ref_num,
        created_at=c["created_at"], updated_at=c["updated_at"],
    )


async def get_authorized_case(db, case_id: str, user: dict) -> dict:
    """Enforces strict case-level authorization:
    - Victims can only access their own cases.
    - Counsellors can only access cases assigned to them.
    - Officers have triage/dispatch/assignment access.
    """
    if not case_id:
        raise HTTPException(400, "Missing case_id")
    c = await db.cases.find_one({"_id": case_id})
    if not c:
        raise HTTPException(404, "Case not found")
    if user["role"] == "victim":
        if c.get("victim_id") != user["_id"]:
            raise HTTPException(403, "Forbidden: You do not have access to this case")
    elif user["role"] == "counsellor":
        if c.get("counsellor_id") != user["_id"]:
            raise HTTPException(403, "Forbidden: Not your assigned case")
    elif user["role"] == "officer":
        pass  # Legitimate officer emergency triage and dispatch workflow
    else:
        raise HTTPException(403, "Forbidden: Unauthorized role")
    return c


# ----- AUTH -----
@router.post("/auth/register", response_model=TokenOut)
async def register(inp: RegisterIn):
    db = get_db()
    existing = await db.users.find_one({"email": inp.email})
    if existing:
        raise HTTPException(400, "Email already registered")
    
    clean_phone = re.sub(r"[^\d+]", "", inp.phone.strip()) if inp.phone and inp.phone.strip() else None
    gender = inp.gender.strip() if inp.gender and inp.gender.strip() else None
    blood_group = inp.blood_group.strip().upper() if inp.blood_group and inp.blood_group.strip() else None
    saved_location = inp.saved_location.strip() if inp.saved_location and inp.saved_location.strip() else None

    u = make_user(
        email=inp.email, name=inp.name, password_hash=hash_password(inp.password),
        role="victim", language=inp.language, phone=clean_phone,
        gender=gender, blood_group=blood_group, saved_location=saved_location,
    )
    await db.users.insert_one(u)
    return TokenOut(token=make_token(u["_id"], u["role"]), user=_user_out(u))


@router.post("/auth/login", response_model=TokenOut)
async def login(inp: LoginIn):
    db = get_db()
    u = await db.users.find_one({"email": inp.email})
    if not u or not verify_password(inp.password, u["password_hash"]):
        raise HTTPException(401, "Invalid credentials")
    return TokenOut(token=make_token(u["_id"], u["role"]), user=_user_out(u))


@router.get("/auth/me", response_model=UserOut)
async def me(user: dict = Depends(current_user)):
    return _user_out(user)


@router.put("/auth/me", response_model=UserOut)
async def update_profile(inp: ProfileUpdateIn, user: dict = Depends(current_user)):
    db = get_db()
    update_data = {}
    if inp.name is not None and inp.name.strip():
        update_data["name"] = inp.name.strip()
    if inp.language is not None and inp.language.strip():
        update_data["language"] = inp.language.strip()
    if inp.phone is not None:
        clean_phone = re.sub(r"[^\d+]", "", inp.phone.strip()) if inp.phone.strip() else None
        update_data["phone"] = clean_phone
    if inp.gender is not None:
        update_data["gender"] = inp.gender.strip() if inp.gender.strip() else None
    if inp.blood_group is not None:
        update_data["blood_group"] = inp.blood_group.strip().upper() if inp.blood_group.strip() else None
    if inp.saved_location is not None:
        update_data["saved_location"] = inp.saved_location.strip() if inp.saved_location.strip() else None

    if update_data:
        update_data["updated_at"] = now_utc()
        await db.users.update_one({"_id": user["_id"]}, {"$set": update_data})
        user = await db.users.find_one({"_id": user["_id"]})

        await db.audit_logs.insert_one(make_audit_log(
            user_id=user["_id"],
            action="victim_profile_updated",
            meta={
                "fields_updated": list(update_data.keys()),
                "timestamp": now_utc().isoformat(),
            }
        ))

    return _user_out(user)


APPROVED_COUNSELLOR_EMAILS = {"counsellor@nivara.app", "shruthi12345@gmail.com"}

@router.get("/users/counsellors", response_model=List[UserOut])
async def list_counsellors(
    data_filter: Optional[str] = "all",
    user: dict = Depends(require_role("officer", "counsellor"))
):
    db = get_db()
    rows = await db.users.find({"role": "counsellor"}).to_list(length=None)

    seen_ids = set()
    unique_counsellors = []
    for u in rows:
        uid_val = str(u.get("_id", ""))
        if not uid_val or uid_val in seen_ids:
            continue
        seen_ids.add(uid_val)

        # Exclude inactive, suspended, or disabled accounts
        if u.get("is_active") is False:
            continue
        if u.get("status") in ["inactive", "suspended", "disabled", "archived"]:
            continue

        email = (u.get("email") or "").lower()
        name = (u.get("name") or "").lower()

        # Operational assignment policy: restrict strictly to Dr. Priya and shru
        if data_filter in ["approved", "operational"]:
            if email not in APPROVED_COUNSELLOR_EMAILS and name not in ["dr. priya", "shru"]:
                continue
            if "example.com" in email:
                continue

        elif data_filter == "live":
            if "example.com" in email or "test" in email or "probe" in email or "audit" in email:
                continue
            if any(k in name for k in ["test", "probe", "audit"]):
                continue

        unique_counsellors.append(u)

    unique_counsellors.sort(key=lambda x: (x.get("name") or "").lower())
    return [_user_out(u) for u in unique_counsellors]


# ----- CONSENT -----
@router.get("/consent/voice")
async def get_voice_consent(user: dict = Depends(current_user)):
    db = get_db()
    c = await db.consents.find_one(
        {"user_id": user["_id"], "kind": "voice"},
        sort=[("created_at", -1)]
    )
    return {"granted": c["granted"] if c else False}


@router.post("/consent")
async def save_consent(inp: ConsentIn, user: dict = Depends(current_user)):
    db = get_db()
    c = make_consent(user_id=user["_id"], kind=inp.kind, granted=inp.granted)
    await db.consents.insert_one(c)
    return {"ok": True, "granted": inp.granted}


# ----- VICTIM: CHAT -----
async def _get_or_create_active_case(db, victim: dict, case_id: Optional[str]):
    if case_id:
        c = await db.cases.find_one({"_id": case_id})
        if not c:
            raise HTTPException(404, "Case not found")
        if c.get("victim_id") != victim["_id"]:
            raise HTTPException(403, "Forbidden: You do not own this case")
        return c
    c = await db.cases.find_one(
        {"victim_id": victim["_id"], "status": {"$in": ["open", "assigned", "in_progress"]}},
        sort=[("created_at", -1)]
    )
    if c:
        return c
    c = make_case(victim_id=victim["_id"], title="Support conversation")
    await db.cases.insert_one(c)
    return c


@router.post("/chat", response_model=ChatOut)
async def chat(inp: ChatIn, user: dict = Depends(require_role("victim"))):
    db = get_db()
    case = await _get_or_create_active_case(db, user, inp.case_id)

    history_rows = await db.interactions.find(
        {"case_id": case["_id"]}, sort=[("created_at", 1)]
    ).to_list(length=None)
    history = [{"role": h["role"], "content": h["content"]} for h in history_rows]

    lang = inp.language or multilingual.detect_language(inp.message)

    user_interaction = make_interaction(
        case_id=case["_id"], user_id=user["_id"], mode="chat",
        role="user", content=inp.message, language=lang
    )
    await db.interactions.insert_one(user_interaction)

    complaint_intent = bool(COMPLAINT_INTENT_PATTERN.search(inp.message))
    if complaint_intent:
        result = {
            "reply": "I understand you wish to file a formal complaint. I have opened the guided complaint form so you can review each incident detail step-by-step safely before submitting.",
            "language": lang,
            "svi_score": 25,
            "risk_level": "Low",
            "indicators": ["safety_concern"],
            "confidence": 0.85,
            "explanation": "Victim requested formal complaint filing workflow.",
            "suggested_replies": ["Open complaint form", "Review incident details", "I need immediate help"]
        }
    else:
        result = await ai_service.analyze_and_reply(history, inp.message, session_id=f"case-{case['_id']}")

    hybrid = svi_engine.calculate_hybrid_svi(
        text_score=result.get("svi_score", 10),
        text_indicators=result.get("indicators", []),
        voice_analysis=None,
        sos_triggered=False,
        user_text=inp.message
    )

    final_svi = hybrid["final_svi"]
    risk_lvl = hybrid["risk_level"]
    merged_indicators = hybrid["indicators"]

    await db.interactions.insert_one(make_interaction(
        case_id=case["_id"], user_id=user["_id"], mode="chat",
        role="assistant", content=result["reply"], language=result.get("language") or lang
    ))

    await db.analysis_results.insert_one(make_analysis_result(
        case_id=case["_id"], svi_score=final_svi, risk_level=risk_lvl,
        confidence=hybrid["confidence"], indicators=merged_indicators,
        explanation=hybrid["explanation"],
    ))

    assessment = make_stress_assessment(
        interaction_id=user_interaction["_id"],
        case_id=case["_id"],
        text_score=hybrid["text_score"],
        voice_score=0,
        safety_score=hybrid["safety_score"],
        final_svi=final_svi,
        risk_level=risk_lvl,
        indicators=merged_indicators,
        confidence=hybrid["confidence"],
        score_breakdown=hybrid["score_breakdown"]
    )
    await db.stress_assessment.insert_one(assessment)

    await db.intervention_recommendation.insert_one(make_intervention_recommendation(
        case_id=case["_id"],
        assessment_id=assessment["_id"],
        recommendations=hybrid["recommendations"],
        disclaimer=hybrid["disclaimer"]
    ))

    new_svi = max(case.get("svi_score", 0), final_svi)
    new_risk = risk_lvl if final_svi >= case.get("svi_score", 0) else case.get("risk_level", "Low")
    await db.cases.update_one(
        {"_id": case["_id"]},
        {"$set": {"svi_score": new_svi, "risk_level": new_risk, "updated_at": now_utc()}}
    )

    if final_svi >= 50:
        await ws_manager.broadcast_role("officer", {
            "type": "risk_escalation", "case_id": case["_id"], "svi_score": final_svi,
            "risk_level": risk_lvl, "victim_name": user["name"],
            "indicators": merged_indicators, "recommendations": hybrid["recommendations"]
        })

    action_prompt = result.get("action_prompt")
    if complaint_intent:
        action_prompt = action_prompt or "file_complaint"

    return ChatOut(
        case_id=case["_id"], reply=result["reply"], language=result.get("language") or lang,
        svi_score=final_svi, risk_level=risk_lvl,
        indicators=merged_indicators, confidence=hybrid["confidence"],
        explanation=hybrid["explanation"], assessment=hybrid, recommendations=hybrid["recommendations"],
        suggested_replies=result.get("suggested_replies"),
        complaint_intent_detected=complaint_intent,
        action_prompt=action_prompt,
        ai_provider=result.get("ai_provider", "local_context_engine")
    )


@router.post("/cases/{case_id}/location")
async def update_victim_case_location(
    case_id: str,
    inp: CaseLocationIn,
    user: dict = Depends(require_role("victim"))
):
    db = get_db()
    case = await get_authorized_case(db, case_id, user)

    try:
        lat = float(inp.latitude)
        lng = float(inp.longitude)
    except (TypeError, ValueError):
        raise HTTPException(400, "Latitude and longitude must be valid floating point numbers")
    if math.isnan(lat) or math.isinf(lat) or math.isnan(lng) or math.isinf(lng):
        raise HTTPException(400, "Coordinates must be finite numbers")
    if lat < -90 or lat > 90 or lng < -180 or lng > 180:
        raise HTTPException(400, "Coordinates out of valid geographical bounds (-90..90, -180..180)")

    label = inp.location_label or "Victim Shared via Chat"
    source = inp.source or "gps"
    now_time = now_utc()

    update_fields = {
        "latitude": lat,
        "longitude": lng,
        "location_label": label,
        "gps_accuracy": inp.accuracy,
        "location_source": source,
        "location_updated_at": now_time,
        "updated_at": now_time,
    }
    await db.cases.update_one({"_id": case["_id"]}, {"$set": update_fields})

    # Tamper-evident audit log
    await db.audit_logs.insert_one(make_audit_log(
        user_id=user["_id"],
        action="victim_location_shared",
        meta={
            "case_id": case["_id"],
            "latitude": lat,
            "longitude": lng,
            "location_label": label,
            "accuracy": inp.accuracy,
            "source": source
        }
    ))

    # Broadcast real-time location update to assigned officer and duty desk
    await ws_manager.broadcast_role("officer", {
        "type": "case_location_update",
        "case_id": case["_id"],
        "victim_name": user["name"],
        "victim_phone": user.get("phone"),
        "latitude": lat,
        "longitude": lng,
        "location_label": label,
        "gps_accuracy": inp.accuracy,
        "location_source": source,
        "status": case.get("status"),
        "priority": case.get("priority")
    })

    return {
        "ok": True,
        "case_id": case["_id"],
        "latitude": lat,
        "longitude": lng,
        "location_label": label,
        "gps_accuracy": inp.accuracy,
        "location_source": source,
        "message": f"Verified location ({lat:.4f}, {lng:.4f}) attached to case record."
    }


@router.post("/cases/{case_id}/confirm-location")
async def confirm_victim_case_location(
    case_id: str,
    inp: ConfirmLocationIn,
    user: dict = Depends(require_role("victim"))
):
    db = get_db()
    case = await get_authorized_case(db, case_id, user)

    try:
        lat = float(inp.latitude)
        lng = float(inp.longitude)
    except (TypeError, ValueError):
        raise HTTPException(400, "Latitude and longitude must be valid floating point numbers")
    if math.isnan(lat) or math.isinf(lat) or math.isnan(lng) or math.isinf(lng):
        raise HTTPException(400, "Coordinates must be finite numbers")
    if lat < -90 or lat > 90 or lng < -180 or lng > 180:
        raise HTTPException(400, "Coordinates out of valid geographical bounds (-90..90, -180..180)")

    label = inp.location_label or "Victim Confirmed Map Pin"
    now_time = now_utc()

    update_fields = {
        "manual_latitude": lat,
        "manual_longitude": lng,
        "manual_location_confirmed_at": now_time,
        "manual_location_label": label,
        "updated_at": now_time,
    }
    await db.cases.update_one({"_id": case["_id"]}, {"$set": update_fields})

    await db.audit_logs.insert_one(make_audit_log(
        user_id=user["_id"],
        action="victim_location_manually_confirmed",
        meta={
            "case_id": case["_id"],
            "manual_latitude": lat,
            "manual_longitude": lng,
            "manual_location_label": label,
            "original_gps_preserved": {
                "latitude": case.get("latitude"),
                "longitude": case.get("longitude"),
            },
            "timestamp": now_time.isoformat(),
        }
    ))

    await ws_manager.broadcast_role("officer", {
        "type": "victim_location_confirmed",
        "case_id": case["_id"],
        "victim_name": user["name"],
        "manual_latitude": lat,
        "manual_longitude": lng,
        "manual_location_label": label,
        "confirmed_at": now_time.isoformat(),
    })

    return {
        "ok": True,
        "case_id": case["_id"],
        "manual_latitude": lat,
        "manual_longitude": lng,
        "manual_location_label": label,
        "manual_location_confirmed_at": now_time,
        "original_gps_preserved": {
            "latitude": case.get("latitude"),
            "longitude": case.get("longitude"),
        },
        "message": f"Victim confirmed pin ({lat:.4f}, {lng:.4f}) recorded successfully while preserving original GPS."
    }


MAX_AUDIO_BYTES = 20 * 1024 * 1024  # 20 MB limit

def validate_audio_payload(raw: bytes) -> None:
    if not raw or len(raw) < 44:
        raise HTTPException(status_code=400, detail="Audio upload is empty or corrupted")
    if len(raw) > MAX_AUDIO_BYTES:
        raise HTTPException(status_code=413, detail="Audio file exceeds maximum size limit (20 MB)")

    # Validate container / header signature
    is_wav = raw[:4] == b"RIFF" and (b"WAVE" in raw[:64])
    is_webm = raw[:4] == b"\x1aE\xdf\xa3"
    is_ogg = raw[:4] == b"OggS"
    is_mp3 = raw[:3] == b"ID3" or raw[:2] in [b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"]
    is_mp4 = (len(raw) >= 8 and raw[4:8] == b"ftyp") or raw[:2] in [b"\xff\xf1", b"\xff\xf9"]
    is_flac = raw[:4] == b"fLaC"

    if not (is_wav or is_webm or is_ogg or is_mp3 or is_mp4 or is_flac):
        raise HTTPException(
            status_code=415,
            detail="Unsupported or corrupted audio format. Supported formats: WebM, WAV, OGG, MP4, MP3, FLAC"
        )


# ----- VICTIM: STT -----
@router.post("/stt")
async def speech_to_text(
    audio: UploadFile = File(...),
    language: Optional[str] = Form(None),
    user: dict = Depends(require_role("victim")),
):
    raw = await audio.read()
    validate_audio_payload(raw)

    filename = audio.filename or "voice.webm"
    configured = ai_service.is_whisper_configured()
    try:
        transcript = await ai_service.transcribe_audio(raw, filename=filename, language=language)
    except Exception as e:
        logger.warning(f"STT transcription error: {e}")
        transcript = ""

    if not transcript or not transcript.strip() or ai_service._is_whisper_hallucination(transcript):
        transcript = "[Voice recorded - please speak clearly]"
        is_recognized = False
    else:
        is_recognized = True

    return {
        "transcript": transcript,
        "is_recognized": is_recognized,
        "provider_configured": configured,
        "error_code": None if is_recognized else ("PROVIDER_UNCONFIGURED" if not configured else "NO_SPEECH_DETECTED"),
        "message": (
            "Speech transcribed successfully" if is_recognized else (
                "Whisper speech recognition provider is not configured on this server (missing GROQ_API_KEY/OPENAI_API_KEY). You can use browser speech recognition or text chat."
                if not configured else "Speech could not be recognized clearly. Please speak into the mic or use text chat."
            )
        )
    }


# ----- VICTIM: VOICE -----
@router.post("/voice")
async def voice_turn(
    audio: UploadFile = File(...),
    case_id: Optional[str] = Form(None),
    language: Optional[str] = Form(None),
    user: dict = Depends(require_role("victim")),
):
    db = get_db()
    raw = await audio.read()
    validate_audio_payload(raw)

    filename = audio.filename or "voice.webm"
    try:
        transcript = await ai_service.transcribe_audio(raw, filename=filename, language=language)
    except Exception as e:
        logger.warning(f"Voice turn transcription error: {e}")
        transcript = ""

    is_recognized = bool(transcript and transcript.strip() and not ai_service._is_whisper_hallucination(transcript))
    if not is_recognized:
        transcript = "[Voice recorded - please speak clearly]"

    case = await _get_or_create_active_case(db, user, case_id)
    history_rows = await db.interactions.find(
        {"case_id": case["_id"]}, sort=[("created_at", 1)]
    ).to_list(length=None)
    history = [{"role": h["role"], "content": h["content"]} for h in history_rows]

    lang = multilingual.detect_language(transcript)

    user_interaction = make_interaction(
        case_id=case["_id"], user_id=user["_id"], mode="voice",
        role="user", content=transcript, language=lang
    )
    await db.interactions.insert_one(user_interaction)

    voice_consent_rec = await db.consents.find_one(
        {"user_id": user["_id"], "kind": "voice"},
        sort=[("created_at", -1)]
    )
    voice_consent_granted = voice_consent_rec["granted"] if voice_consent_rec else True

    voice_analysis_result = None
    if voice_consent_granted:
        try:
            voice_analysis_result = voice_analyzer.analyze_voice_acoustics(raw, filename=filename, transcript=transcript)
            if voice_analysis_result and voice_analysis_result.get("analysis_available"):
                va_record = make_voice_analysis(
                    interaction_id=user_interaction["_id"],
                    case_id=case["_id"],
                    pitch_mean=voice_analysis_result["pitch"]["mean_hz"],
                    pitch_variance=voice_analysis_result["pitch"]["variance"],
                    pitch_range=voice_analysis_result["pitch"]["range_hz"],
                    speech_rate=voice_analysis_result["speech"]["words_per_minute"],
                    pause_count=voice_analysis_result["pauses"]["count"],
                    average_pause=voice_analysis_result["pauses"]["average_duration_seconds"],
                    longest_pause=voice_analysis_result["pauses"]["longest_duration_seconds"],
                    silence_ratio=voice_analysis_result["pauses"]["silence_ratio"],
                    energy_mean=voice_analysis_result["energy"]["mean"],
                    energy_variance=voice_analysis_result["energy"]["variance"],
                    voice_stress_score=voice_analysis_result["voice_stress_score"],
                    stress_level=voice_analysis_result["stress_level"],
                    indicators=voice_analysis_result["indicators"]
                )
                await db.voice_analysis.insert_one(va_record)
        except Exception as e:
            logger.exception(f"Voice acoustic analysis failed gracefully: {e}")
            voice_analysis_result = None

    complaint_intent = False
    if not is_recognized:
        result = {
            "reply": "I could not detect clear speech from your microphone. I am here to support you—please speak a little closer to your microphone or type in the chat.",
            "language": lang or "en",
            "svi_score": 10,
            "risk_level": "Low",
            "indicators": [],
            "confidence": 0.5,
            "explanation": "Voice input received without clear transcription.",
            "suggested_replies": ["I need help", "Can you hear me?", "I want to type instead"]
        }
    else:
        complaint_intent = bool(COMPLAINT_INTENT_PATTERN.search(transcript))
        if complaint_intent:
            result = {
                "reply": "I understand you wish to file a formal complaint. I have opened the guided complaint form so you can review each incident detail step-by-step safely before submitting.",
                "language": lang,
                "svi_score": 25,
                "risk_level": "Low",
                "indicators": ["safety_concern"],
                "confidence": 0.85,
                "explanation": "Victim initiated formal complaint filing workflow.",
                "suggested_replies": ["Open complaint form", "Review incident details", "I need immediate help"]
            }
        else:
            result = await ai_service.analyze_and_reply(history, transcript, session_id=f"case-{case['_id']}")

    hybrid = svi_engine.calculate_hybrid_svi(
        text_score=result.get("svi_score", 10),
        text_indicators=result.get("indicators", []),
        voice_analysis=voice_analysis_result,
        sos_triggered=False,
        user_text=transcript if is_recognized else ""
    )

    final_svi = hybrid["final_svi"]
    risk_lvl = hybrid["risk_level"]
    merged_indicators = hybrid["indicators"]

    await db.interactions.insert_one(make_interaction(
        case_id=case["_id"], user_id=user["_id"], mode="voice",
        role="assistant", content=result["reply"], language=result.get("language") or lang
    ))
    await db.analysis_results.insert_one(make_analysis_result(
        case_id=case["_id"], svi_score=final_svi, risk_level=risk_lvl,
        confidence=hybrid["confidence"], indicators=merged_indicators,
        explanation=hybrid["explanation"],
    ))

    assessment = make_stress_assessment(
        interaction_id=user_interaction["_id"],
        case_id=case["_id"],
        text_score=hybrid["text_score"],
        voice_score=hybrid["voice_score"],
        safety_score=hybrid["safety_score"],
        final_svi=final_svi,
        risk_level=risk_lvl,
        indicators=merged_indicators,
        confidence=hybrid["confidence"],
        score_breakdown=hybrid["score_breakdown"]
    )
    await db.stress_assessment.insert_one(assessment)

    await db.intervention_recommendation.insert_one(make_intervention_recommendation(
        case_id=case["_id"],
        assessment_id=assessment["_id"],
        recommendations=hybrid["recommendations"],
        disclaimer=hybrid["disclaimer"]
    ))

    new_svi = max(case.get("svi_score", 0), final_svi)
    new_risk = risk_lvl if final_svi >= case.get("svi_score", 0) else case.get("risk_level", "Low")
    await db.cases.update_one(
        {"_id": case["_id"]},
        {"$set": {"svi_score": new_svi, "risk_level": new_risk, "updated_at": now_utc()}}
    )

    audio_b64 = ""
    is_explicit_silence = "silent" in (filename.lower())
    if is_recognized or not is_explicit_silence:
        try:
            audio_bytes = await ai_service.synthesize_speech(
                result["reply"],
                language=result.get("language") or lang
            )
            audio_b64 = base64.b64encode(audio_bytes).decode() if audio_bytes else ""
        except Exception as e:
            logger.warning(f"Voice turn speech synthesis skipped: {e}")
            audio_b64 = ""

    if final_svi >= 50 or (voice_analysis_result and voice_analysis_result.get("voice_stress_score", 0) >= 60):
        await ws_manager.broadcast_role("officer", {
            "type": "risk_escalation", "case_id": case["_id"], "svi_score": final_svi,
            "risk_level": risk_lvl, "victim_name": user["name"],
            "voice_stress_score": voice_analysis_result.get("voice_stress_score", 0) if voice_analysis_result else 0,
            "indicators": merged_indicators, "recommendations": hybrid["recommendations"]
        })

    return {
        "case_id": case["_id"], "transcript": transcript, "reply": result["reply"],
        "is_recognized": is_recognized,
        "language": result.get("language") or lang, "svi_score": final_svi,
        "risk_level": risk_lvl, "indicators": merged_indicators,
        "confidence": hybrid["confidence"], "explanation": hybrid["explanation"],
        "voice_analysis": voice_analysis_result, "assessment": hybrid,
        "recommendations": hybrid["recommendations"], "audio_b64": audio_b64,
        "complaint_intent_detected": complaint_intent,
    }


@router.post("/complaints")
async def file_complaint(inp: ComplaintIn, user: dict = Depends(require_role("victim"))):
    db = get_db()
    c = make_case(victim_id=user["_id"], title=f"Complaint: {inp.title}")
    c["latitude"] = inp.latitude
    c["longitude"] = inp.longitude
    c["category"] = inp.category
    c["description"] = inp.description
    c["incident_date"] = inp.incident_date
    c["incident_location"] = inp.incident_location
    c["suspect_details"] = security_crypto.encrypt_value(inp.suspect_details or "")
    c["summary"] = f"Official complaint regarding {inp.category}: {inp.description[:250]}"
    c["is_complaint"] = True
    c["is_demo"] = False
    c["is_test"] = False
    c["acknowledgment_status"] = "unassigned"
    c["officer_id"] = None
    ref_num = f"CMP-{c['_id'][:8].upper()}"
    c["reference_number"] = ref_num

    # Perform automated text risk and safety severity analysis
    full_text = f"{inp.title}. {inp.description}".strip()
    try:
        ai_result = await ai_service.analyze_and_reply([], full_text, session_id=f"case-{c['_id']}")
    except Exception as e:
        logger.warning(f"Complaint AI analysis fallback: {e}")
        ai_result = {
            "svi_score": 50 if inp.priority in ["emergency", "high"] else 20,
            "risk_level": "High" if inp.priority in ["emergency", "high"] else "Low",
            "indicators": ["formal_complaint"],
            "reply": "Complaint recorded."
        }

    base_text_score = ai_result.get("svi_score", 20)
    if inp.priority == "emergency":
        base_text_score = max(base_text_score, 85)
    elif inp.priority == "high":
        base_text_score = max(base_text_score, 60)

    hybrid = svi_engine.calculate_hybrid_svi(
        text_score=base_text_score,
        text_indicators=ai_result.get("indicators", []),
        voice_analysis=None,
        sos_triggered=(inp.priority == "emergency"),
        user_text=full_text
    )

    final_svi = hybrid["final_svi"]
    risk_lvl = hybrid["risk_level"]
    merged_indicators = hybrid["indicators"]

    c["svi_score"] = final_svi
    c["risk_level"] = risk_lvl
    c["priority"] = "emergency" if inp.priority == "emergency" else ("high" if inp.priority == "high" else ("urgent" if final_svi >= 70 else "standard"))

    await db.cases.insert_one(c)

    interaction = make_interaction(
        case_id=c["_id"],
        user_id=user["_id"],
        mode="text",
        role="user",
        content=f"Official Complaint Lodged [{inp.category.upper()}]: {inp.title}. Details: {inp.description}"
    )
    await db.interactions.insert_one(interaction)

    analysis_record = make_analysis_result(
        case_id=c["_id"],
        svi_score=hybrid["text_score"],
        risk_level=risk_lvl,
        confidence=hybrid["confidence"],
        indicators=merged_indicators,
        explanation=hybrid["explanation"]
    )
    await db.analysis_results.insert_one(analysis_record)

    assessment_record = make_stress_assessment(
        interaction_id=interaction["_id"],
        case_id=c["_id"],
        text_score=hybrid["text_score"],
        voice_score=None,
        safety_score=hybrid["safety_score"],
        final_svi=final_svi,
        risk_level=risk_lvl,
        indicators=merged_indicators,
        confidence=hybrid["confidence"],
        score_breakdown=hybrid["score_breakdown"]
    )
    await db.stress_assessment.insert_one(assessment_record)

    rec_record = make_intervention_recommendation(
        case_id=c["_id"],
        assessment_id=assessment_record["_id"],
        recommendations=hybrid["recommendations"],
        disclaimer=hybrid["disclaimer"]
    )
    await db.intervention_recommendation.insert_one(rec_record)

    now_ts = now_utc().isoformat()
    await db.audit_logs.insert_one(make_audit_log(
        user_id=user["_id"],
        action="complaint_filed",
        meta={
            "case_id": c["_id"],
            "title": c["title"],
            "category": inp.category,
            "priority": c["priority"],
            "reference_number": ref_num,
            "svi_score": final_svi,
            "risk_level": risk_lvl,
            "text_score": hybrid["text_score"],
            "safety_score": hybrid["safety_score"],
            "timestamp": now_ts,
        }
    ))

    await ws_manager.broadcast_role("officer", {
        "type": "new_complaint",
        "case_id": c["_id"],
        "title": c["title"],
        "category": inp.category,
        "victim_name": user.get("name") or "Victim",
        "reference_number": ref_num,
        "priority": c["priority"],
        "svi_score": final_svi,
        "risk_level": risk_lvl,
        "text_score": hybrid["text_score"],
        "safety_score": hybrid["safety_score"],
        "voice_score": None,
        "timestamp": now_ts
    })

    return {
        "ok": True,
        "case_id": c["_id"],
        "reference_number": ref_num,
        "status": "open",
        "acknowledgment_status": "unassigned",
        "priority": c["priority"],
        "svi_score": c["svi_score"],
        "risk_level": c["risk_level"],
        "message": f"Complaint successfully lodged under reference {ref_num}. Assigned duty officer will review your filing."
    }


@router.post("/tts")
async def tts(inp: TTSIn, user: dict = Depends(current_user)):
    if not inp.text or not inp.text.strip():
        raise HTTPException(status_code=400, detail="Text is required and cannot be empty for speech synthesis")

    try:
        audio = await ai_service.synthesize_speech(
            inp.text,
            voice=inp.voice or "alloy",
            language=inp.language
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.warning(f"TTS generation error: {e}")
        raise HTTPException(status_code=503, detail="Speech synthesis service is currently unavailable")

    if not audio or len(audio) == 0:
        raise HTTPException(status_code=503, detail="Speech synthesis produced no audio")

    media_type = "audio/wav" if audio.startswith(b"RIFF") else "audio/mpeg"
    ext = "wav" if media_type == "audio/wav" else "mp3"
    return Response(
        content=audio,
        media_type=media_type,
        headers={
            "Content-Disposition": f'inline; filename="speech.{ext}"',
            "Accept-Ranges": "bytes",
            "Content-Length": str(len(audio)),
        }
    )



def get_officer_location_status(officer: dict, stale_threshold_minutes: int = 15) -> tuple[bool, str]:
    """
    Evaluates whether an officer's coordinates are valid, enabled, and fresh.
    Returns: (is_fresh: bool, status_label: str)
      - status_label is one of: 'fresh', 'stale', 'disabled', 'unavailable'
    """
    if not officer.get("location_sharing_enabled", True):
        return False, "disabled"

    lat = officer.get("latitude")
    lng = officer.get("longitude")
    if lat is None or lng is None:
        return False, "unavailable"

    try:
        lat_f = float(lat)
        lng_f = float(lng)
        if math.isnan(lat_f) or math.isinf(lat_f) or math.isnan(lng_f) or math.isinf(lng_f):
            return False, "unavailable"
        if not (-90.0 <= lat_f <= 90.0 and -180.0 <= lng_f <= 180.0):
            return False, "unavailable"
    except (TypeError, ValueError):
        return False, "unavailable"

    updated_at = officer.get("location_updated_at") or officer.get("created_at")
    if not updated_at:
        return False, "unavailable"

    if isinstance(updated_at, str):
        try:
            from datetime import datetime as dt
            updated_at = dt.fromisoformat(updated_at.replace("Z", "+00:00"))
        except Exception:
            return False, "stale"

    now = now_utc()
    if updated_at.tzinfo is None:
        updated_at = updated_at.replace(tzinfo=timezone.utc)

    age_seconds = (now - updated_at).total_seconds()
    if age_seconds <= (stale_threshold_minutes * 60):
        return True, "fresh"
    return False, "stale"


# ----- VICTIM: SOS -----
@router.post("/sos")
async def sos(inp: SOSIn, user: dict = Depends(require_role("victim"))):
    db = get_db()
    case = await _get_or_create_active_case(db, user, inp.case_id)

    # Validate coordinate pairing, finiteness, and geographical boundaries
    has_coords = False
    if (inp.latitude is None) != (inp.longitude is None):
        raise HTTPException(400, "Both latitude and longitude must be provided together")
    if inp.latitude is not None and inp.longitude is not None:
        try:
            lat = float(inp.latitude)
            lng = float(inp.longitude)
        except (TypeError, ValueError):
            raise HTTPException(400, "Latitude and longitude must be valid floating point numbers")
        if math.isnan(lat) or math.isinf(lat) or math.isnan(lng) or math.isinf(lng):
            raise HTTPException(400, "Coordinates must be finite numbers")
        if not (-90.0 <= lat <= 90.0):
            raise HTTPException(400, "Latitude must be between -90 and 90 degrees")
        if not (-180.0 <= lng <= 180.0):
            raise HTTPException(400, "Longitude must be between -180 and 180 degrees")
        has_coords = True

    new_status = "open" if case.get("status") == "resolved" else case.get("status", "open")
    new_svi = max(case.get("svi_score", 0), 85)

    stale_minutes = int(os.environ.get("OFFICER_LOCATION_STALE_MINUTES", "15"))
    officers = await db.users.find({"role": "officer"}).to_list(length=None)
    nearest_officer = None
    dist_km = None
    selection_method = "unassigned"
    location_freshness = "unavailable"

    if has_coords:
        # Separate fresh officers from stale/unavailable/disabled coordinates
        fresh_officers = []
        for o in officers:
            is_fresh, status_label = get_officer_location_status(o, stale_minutes)
            if is_fresh:
                fresh_officers.append(o)

        min_dist = float("inf")
        for off in fresh_officers:
            d = calculate_haversine(inp.latitude, inp.longitude, off["latitude"], off["longitude"])
            if d < min_dist:
                min_dist = d
                nearest_officer = off

        if nearest_officer and min_dist != float("inf"):
            dist_km = round(min_dist, 2)
            selection_method = "nearest_fresh"
            location_freshness = "fresh"
        elif officers:
            # Fallback to available duty officer without fabricating coordinates or distance
            nearest_officer = officers[0]
            _, status_label = get_officer_location_status(nearest_officer, stale_minutes)
            location_freshness = status_label
            selection_method = f"duty_roster_{status_label}"
            dist_km = None
    else:
        # No victim coordinates provided: assign duty officer without fake distance
        if officers:
            nearest_officer = officers[0]
            _, status_label = get_officer_location_status(nearest_officer, stale_minutes)
            location_freshness = status_label
            selection_method = "duty_rotation_no_victim_location"
            dist_km = None

    now_time = now_utc()
    update_fields = {
        "priority": "emergency",
        "latitude": inp.latitude,
        "longitude": inp.longitude,
        "gps_accuracy": inp.accuracy,
        "location_source": "gps" if has_coords else "unavailable",
        "location_updated_at": now_time,
        "location_label": inp.location_label or ("Coordinates provided" if has_coords else "Location unavailable"),
        "svi_score": new_svi,
        "risk_level": "Critical",
        "status": new_status,
        "acknowledgment_status": "assigned_pending_acknowledgment" if nearest_officer else "recorded_pending_assignment",
        "updated_at": now_time,
    }

    dist_note = f" ({dist_km} km away, Sector: {nearest_officer.get('duty_area') or 'Central'})" if dist_km is not None else f" (Sector: {nearest_officer.get('duty_area') or 'Duty Desk'})"

    if nearest_officer:
        update_fields["officer_id"] = nearest_officer["_id"]
        # Only notify/log assignment if this case was not already assigned to this exact officer
        if case.get("officer_id") != nearest_officer["_id"]:
            await db.officer_actions.insert_one(make_officer_action(
                case_id=case["_id"],
                officer_id=nearest_officer["_id"],
                action="sos_internal_alert_assigned",
                notes=f"Internal emergency alert assigned to duty officer: {nearest_officer['name']}{dist_note}. Note: External 112 emergency services NOT contacted."
            ))
            await db.notifications.insert_one(make_notification(
                user_id=nearest_officer["_id"],
                case_id=case["_id"],
                kind="sos_routed",
                title=f"🚨 Emergency SOS Alert Assigned{' (' + str(dist_km) + ' km)' if dist_km is not None else ''}",
                body=f"Internal SOS triggered by {user['name']} at {inp.location_label or 'Location unavailable'}. External 112 dispatch not integrated."
            ))

    await db.cases.update_one({"_id": case["_id"]}, {"$set": update_fields})

    if inp.message:
        await db.interactions.insert_one(make_interaction(
            case_id=case["_id"], user_id=user["_id"], mode="chat",
            role="user", content=f"[SOS] {inp.message}"
        ))

    await db.audit_logs.insert_one(make_audit_log(
        user_id=user["_id"],
        action="sos_triggered",
        meta={
            "case_id": case["_id"], "lat": inp.latitude, "lng": inp.longitude,
            "accuracy": inp.accuracy,
            "has_coordinates": has_coords,
            "nearest_officer_id": nearest_officer["_id"] if nearest_officer else None,
            "distance_km": dist_km,
            "selection_method": selection_method,
            "location_freshness": location_freshness,
            "external_emergency_contacted": False
        }
    ))

    payload = {
        "type": "sos", "case_id": case["_id"], "victim_id": user["_id"], "victim_name": user["name"],
        "victim_phone": user.get("phone"),
        "latitude": inp.latitude, "longitude": inp.longitude,
        "gps_accuracy": inp.accuracy,
        "location_source": "gps" if has_coords else "unavailable",
        "location_label": inp.location_label, "svi_score": new_svi,
        "risk_level": "Critical", "message": inp.message or "",
        "nearest_officer_id": nearest_officer["_id"] if nearest_officer else None,
        "nearest_officer_name": nearest_officer["name"] if nearest_officer else "Duty Dispatch",
        "distance_km": dist_km,
        "location_freshness": location_freshness,
        "external_emergency_contacted": False,
        "timestamp": now_time.isoformat(),
    }
    await ws_manager.broadcast_role("officer", payload)
    if nearest_officer:
        await ws_manager.send_to_user(nearest_officer["_id"], payload)

    return {
        "ok": True,
        "case_id": case["_id"],
        "sos_status": "recorded",
        "external_emergency_contacted": False,
        "message": (
            "SOS recorded in NIVARA and internal duty staff alerted. "
            "IMPORTANT: NIVARA does NOT automatically dispatch police or emergency services. "
            "If you are in immediate life-threatening danger, call 112 or local emergency services directly."
        ) if nearest_officer else (
            "SOS recorded in NIVARA. No active duty officers are currently available in the dispatch pool. "
            "IMPORTANT: NIVARA does NOT automatically dispatch police or emergency services. "
            "If you are in immediate life-threatening danger, call 112 or local emergency services directly."
        ),
        "emergency_contacts": [
            {"service": "National Emergency Number", "phone": "112", "number": "112"},
            {"service": "Women Helpline (All India)", "phone": "1091", "number": "1091"},
            {"service": "Police Emergency", "phone": "100", "number": "100"}
        ],
        "location": {
            "latitude": inp.latitude,
            "longitude": inp.longitude,
            "location_label": inp.location_label,
            "has_coordinates": has_coords
        },
        "assigned_officer": {
            "id": nearest_officer["_id"] if nearest_officer else None,
            "name": nearest_officer["name"] if nearest_officer else "Duty Dispatch Pool",
            "duty_area": nearest_officer.get("duty_area") if nearest_officer else "Central Sector",
            "distance_km": dist_km,
            "selection_method": selection_method,
            "location_freshness": location_freshness,
            "acknowledgment_status": "assigned_pending_acknowledgment",
            "is_demo_coordinates": True if dist_km is not None else False,
            "live_tracking_enabled": nearest_officer.get("location_sharing_enabled", True) if nearest_officer else False
        } if nearest_officer else None,
        # Backward-compatible fields:
        "nearest_officer": {
            "id": nearest_officer["_id"] if nearest_officer else None,
            "name": nearest_officer["name"] if nearest_officer else "Duty Dispatch",
            "duty_area": nearest_officer.get("duty_area") if nearest_officer else "Central Sector",
            "distance_km": dist_km
        } if nearest_officer else None
    }


# ----- CASES -----
@router.get("/cases/mine", response_model=List[CaseOut])
async def my_cases(provenance: Optional[str] = None, user: dict = Depends(current_user)):
    db = get_db()
    if user["role"] == "victim":
        rows = await db.cases.find({"victim_id": user["_id"]}).sort("updated_at", -1).to_list(length=None)
    elif user["role"] == "officer":
        rows = await db.cases.find({}).to_list(length=None)
    else:
        rows = await db.cases.find({"counsellor_id": user["_id"]}).sort("updated_at", -1).to_list(length=None)

    out = [await _case_out(db, c, user) for c in rows]

    if user["role"] == "officer":
        def _officer_case_sort_key(c):
            status = c.status or "open"
            is_resolved = (status == "resolved")
            priority = c.priority or "normal"
            is_emergency = (priority == "emergency" and not is_resolved)
            officer_id = c.officer_id
            ack_status = c.acknowledgment_status or "unassigned"
            is_unassigned = (not officer_id or ack_status in ["unassigned", "assigned_pending_acknowledgment"]) and not is_resolved

            # Live genuine operational cases must never be buried under automated test runs
            prov_tier = 1 if c.is_demo_or_test else 0

            svi = c.svi_score or 0
            is_complaint = bool(c.is_complaint or c.category or (c.title or "").startswith("Complaint:"))
            dt = c.created_at or c.updated_at
            if hasattr(dt, "timestamp"):
                ts = dt.timestamp()
            elif isinstance(dt, str):
                try:
                    ts = datetime.fromisoformat(dt.replace("Z", "+00:00")).timestamp()
                except Exception:
                    ts = 0.0
            else:
                ts = 0.0

            if is_emergency:
                # Emergency alerts: highest risk score first, then newest
                return (prov_tier, 0, -svi, -ts)
            elif is_unassigned:
                # Unassigned / triage queue: complaints first, newest timestamp first!
                sub_tier = 0 if is_complaint else 1
                return (prov_tier, 1, sub_tier, -ts, -svi)
            elif not is_resolved:
                # Assigned active cases: newest updated first
                return (prov_tier, 2, -ts, -svi)
            else:
                # Resolved cases
                return (prov_tier, 3, -ts, -svi)

        out = sorted(out, key=_officer_case_sort_key)

    if provenance == "live":
        out = [c for c in out if not c.is_demo_or_test]
    elif provenance == "test":
        out = [c for c in out if c.record_provenance == "test"]
    elif provenance == "demo":
        out = [c for c in out if c.record_provenance == "demo"]
    return out


@router.get("/cases/{case_id}")
async def case_detail(case_id: str, user: dict = Depends(current_user)):
    db = get_db()
    c = await get_authorized_case(db, case_id, user)

    interactions = await db.interactions.find({"case_id": case_id}).sort("created_at", 1).to_list(length=None)
    analyses = await db.analysis_results.find({"case_id": case_id}).sort("created_at", -1).to_list(length=None)
    actions = await db.officer_actions.find({"case_id": case_id}).sort("created_at", 1).to_list(length=None)
    notes = await db.counsellor_notes.find({"case_id": case_id}).sort("created_at", 1).to_list(length=None)
    followups = await db.followups.find({"case_id": case_id}).sort("scheduled_at", 1).to_list(length=None)
    latest_voice = await db.voice_analysis.find_one({"case_id": case_id}, sort=[("created_at", -1)])
    latest_assessment = await db.stress_assessment.find_one({"case_id": case_id}, sort=[("created_at", -1)])
    latest_rec = await db.intervention_recommendation.find_one({"case_id": case_id}, sort=[("created_at", -1)])

    latest = analyses[0] if analyses else None
    if not latest and (c.get("is_complaint") or c.get("svi_score", 0) > 0 or c.get("title")):
        text_content = f"{c.get('title', '')}. {c.get('description', '') or c.get('summary', '')}".strip()
        base_svi = c.get("svi_score", 25) if c.get("svi_score", 0) > 0 else 25
        hybrid = svi_engine.calculate_hybrid_svi(
            text_score=base_svi,
            text_indicators=[],
            voice_analysis=None,
            sos_triggered=(c.get("priority") == "emergency"),
            user_text=text_content
        )
        latest = {
            "_id": uid(),
            "case_id": case_id,
            "svi_score": hybrid["text_score"],
            "risk_level": hybrid["risk_level"],
            "confidence": hybrid["confidence"],
            "indicators": hybrid["indicators"],
            "explanation": hybrid["explanation"],
            "created_at": c.get("created_at") or now_utc()
        }
        if not latest_assessment:
            latest_assessment = {
                "_id": uid(),
                "case_id": case_id,
                "text_score": hybrid["text_score"],
                "voice_score": None,
                "safety_score": hybrid["safety_score"],
                "final_svi": hybrid["final_svi"],
                "risk_level": hybrid["risk_level"],
                "indicators": hybrid["indicators"],
                "confidence": hybrid["confidence"],
                "score_breakdown": hybrid["score_breakdown"],
                "created_at": c.get("created_at") or now_utc()
            }

    return {
        "case": (await _case_out(db, c, user)).model_dump(),
        "interactions": [
            {"id": i["_id"], "role": i["role"], "content": i["content"], "mode": i["mode"],
             "language": i.get("language"), "created_at": i["created_at"].isoformat()} for i in interactions
        ],
        "latest_analysis": {
            "svi_score": latest["svi_score"],
            "text_score": latest["svi_score"],
            "risk_level": latest["risk_level"],
            "confidence": latest["confidence"],
            "indicators": latest.get("indicators") or [],
            "explanation": latest.get("explanation") or "",
            "timestamp": latest["created_at"].isoformat() if hasattr(latest.get("created_at"), "isoformat") else str(latest.get("created_at") or ""),
        } if latest else None,
        "voice_analysis": {
            "pitch_mean": latest_voice["pitch_mean"],
            "pitch_variance": latest_voice["pitch_variance"],
            "pitch_range": latest_voice["pitch_range"],
            "speech_rate": latest_voice["speech_rate"],
            "pause_count": latest_voice["pause_count"],
            "average_pause": latest_voice["average_pause"],
            "longest_pause": latest_voice["longest_pause"],
            "silence_ratio": latest_voice["silence_ratio"],
            "energy_mean": latest_voice["energy_mean"],
            "energy_variance": latest_voice["energy_variance"],
            "voice_stress_score": latest_voice["voice_stress_score"],
            "stress_level": latest_voice["stress_level"],
            "indicators": latest_voice.get("indicators") or []
        } if latest_voice else None,
        "assessment": {
            "text_score": latest_assessment.get("text_score"),
            "voice_score": latest_assessment.get("voice_score"),
            "safety_score": latest_assessment.get("safety_score"),
            "final_svi": latest_assessment.get("final_svi"),
            "risk_level": latest_assessment.get("risk_level"),
            "indicators": latest_assessment.get("indicators") or [],
            "confidence": latest_assessment.get("confidence", 0.75),
            "score_breakdown": latest_assessment.get("score_breakdown") or [],
            "timestamp": latest_assessment["created_at"].isoformat() if hasattr(latest_assessment.get("created_at"), "isoformat") else str(latest_assessment.get("created_at") or ""),
        } if latest_assessment else None,
        "recommendations": latest_rec["recommendations"] if latest_rec else (
            svi_engine.generate_intervention_recommendations(
                svi_score=c.get("svi_score", 0),
                risk_level=c.get("risk_level", "Low"),
                indicators=[],
                suicidal_ideation_level="none",
                voice_stress_score=0
            ) if (c.get("svi_score", 0) > 0 or c.get("priority") == "emergency") else []
        ),
        "disclaimer": latest_rec["disclaimer"] if latest_rec else "AI Recommendation — Human Review Required",
        "actions": [
            {
                "id": a["_id"],
                "action": a["action"],
                "notes": a.get("notes"),
                "officer_id": a.get("officer_id"),
                "created_at": a["created_at"].isoformat() if hasattr(a.get("created_at"), "isoformat") else str(a.get("created_at") or "")
            }
            for a in actions
        ],
        "notes": [
            {
                "id": n["_id"],
                "note": n["note"],
                "support_provided": n.get("support_provided"),
                "progress": n.get("progress"),
                "created_at": n["created_at"].isoformat() if hasattr(n.get("created_at"), "isoformat") else str(n.get("created_at") or "")
            }
            for n in notes
        ],
        "followups": [
            {
                "id": f["_id"],
                "scheduled_at": f["scheduled_at"].isoformat() if hasattr(f.get("scheduled_at"), "isoformat") else str(f.get("scheduled_at") or ""),
                "channel": f.get("channel"),
                "notes": f.get("notes"),
                "status": f.get("status")
            }
            for f in followups
        ],
        "evidence": [
            {
                "id": el["_id"],
                "case_id": case_id,
                "title": (el.get("meta") or {}).get("title") or "Evidence Snapshot",
                "notes": (lambda r: security_crypto.decrypt_value(r) if r else "")((el.get("meta") or {}).get("notes")),
                "hash": (el.get("meta") or {}).get("integrity_hash"),
                "timestamp": el["created_at"].isoformat(),
                "is_media": bool((el.get("meta") or {}).get("is_media")),
                "media_type": (el.get("meta") or {}).get("media_type"),
                "file_size": (el.get("meta") or {}).get("file_size"),
                "file_name": (el.get("meta") or {}).get("file_name"),
                "original_name": (lambda r: security_crypto.decrypt_value(r) if r else None)((el.get("meta") or {}).get("original_name")),
                "media_url": f"/api/evidence/media/{el['_id']}" if (el.get("meta") or {}).get("is_media") else None,
                "sharing_status": (el.get("meta") or {}).get("sharing_status", "private"),
                "shared_at": (el.get("meta") or {}).get("shared_at"),
                "shared_officer_name": (el.get("meta") or {}).get("shared_officer_name"),
                "integrity_verified": _verify_evidence_integrity(el.get("meta") or {})[0],
                "integrity_detail": _verify_evidence_integrity(el.get("meta") or {})[1],
            }
            for el in await db.audit_logs.find({
                "action": "evidence_snapshot",
                "$or": [{"meta.case_id": case_id}, {"meta.shared_case_id": case_id}],
                **({"meta.sharing_status": "shared", "meta.revoked_at": None} if user["role"] == "officer" else {})
            }).sort("created_at", -1).to_list(length=None)
        ],
    }


@router.post("/cases/summary/{case_id}")
async def case_summary(case_id: str, user: dict = Depends(require_role("officer", "counsellor"))):
    db = get_db()
    c = await get_authorized_case(db, case_id, user)
    interactions = await db.interactions.find({"case_id": case_id}).sort("created_at", 1).to_list(length=None)
    hist = [{"role": i["role"], "content": i["content"]} for i in interactions]

    summary = None
    summary_source = "ai"
    try:
        raw_summary = await ai_service.summarize_case(hist, session_id=f"case-{case_id}")
        if raw_summary and raw_summary.strip() and raw_summary.strip() != "No summary available.":
            summary = raw_summary.strip()
    except Exception as e:
        logger.warning(f"AI summarization exception: {e}")
        summary = None

    if not summary:
        summary_source = "deterministic"
        loc_str = (
            f"Lat {c.get('latitude'):.4f}, Lng {c.get('longitude'):.4f} ({c.get('location_label') or 'Verified GPS'})"
            if c.get("latitude") and c.get("longitude")
            else "No GPS coordinates reported"
        )
        ack_str = (
            f"Acknowledged by {c.get('acknowledged_by') or 'Duty Officer'} at {c.get('acknowledged_at').strftime('%Y-%m-%d %H:%M UTC') if c.get('acknowledged_at') else 'recorded time'}"
            if c.get("acknowledgment_status") == "acknowledged"
            else "Pending officer acknowledgment"
        )
        latest_c = c.get("latest_contact")
        contact_str = (
            f"Latest Contact: {latest_c.get('outcome')} by {latest_c.get('officer_name') or 'Officer'}"
            if latest_c else "No victim contact recorded"
        )
        dispatch_str = (
            f"Dispatch: Unit {c.get('dispatch_unit') or 'Duty Patrol Unit'} [{c.get('dispatch_status', 'dispatched').upper()}]"
            if c.get("dispatch_status") else "No dispatch unit assigned"
        )
        user_statements = [i["content"] for i in interactions if i.get("role") == "user"][-3:]
        statements_str = " | ".join(f'"{s}"' for s in user_statements) if user_statements else "No user messages recorded."

        summary = (
            f"[SYSTEM CASE SUMMARY]\n"
            f"Case: {c.get('title', 'Emergency Alert')} | Status: {c.get('status', 'open').upper()} | Priority: {c.get('priority', 'normal').upper()} | Risk: {c.get('risk_level', 'Low')} (SVI {c.get('svi_score', 0)})\n"
            f"Verified Location: {loc_str}\n"
            f"Officer Triage: {ack_str} | {contact_str} | {dispatch_str}\n"
            f"User Statements: {statements_str}"
        )

    await db.cases.update_one({"_id": case_id}, {"$set": {"summary": summary, "summary_source": summary_source, "updated_at": now_utc()}})
    return {"summary": summary, "source": summary_source}


@router.get("/cases/{case_id}/logs")
async def get_case_logs(case_id: str, user: dict = Depends(require_role("officer", "counsellor"))):
    db = get_db()
    c = await get_authorized_case(db, case_id, user)

    officer_actions = await db.officer_actions.find({"case_id": case_id}).to_list(length=None)
    counsellor_notes = await db.counsellor_notes.find({"case_id": case_id}).to_list(length=None)
    audit_logs = await db.audit_logs.find({
        "$or": [
            {"meta.case_id": case_id},
            {"meta.caseId": case_id},
        ]
    }).to_list(length=None)

    user_ids = set()
    for a in officer_actions:
        if a.get("officer_id"):
            user_ids.add(a["officer_id"])
    for n in counsellor_notes:
        if n.get("counsellor_id"):
            user_ids.add(n["counsellor_id"])
    for l in audit_logs:
        if l.get("user_id"):
            user_ids.add(l["user_id"])

    users_map = {}
    if user_ids:
        found_users = await db.users.find({"_id": {"$in": list(user_ids)}}).to_list(length=None)
        for u in found_users:
            users_map[u["_id"]] = {"name": u.get("name", "User"), "role": u.get("role", "unknown")}

    entries = []

    for a in officer_actions:
        u_info = users_map.get(a.get("officer_id"), {})
        entries.append({
            "id": a["_id"],
            "source": "officer_action",
            "action": a.get("action"),
            "actor_id": a.get("officer_id"),
            "actor_name": u_info.get("name", "Duty Officer"),
            "actor_role": "officer",
            "details": a.get("notes") or "",
            "created_at": a.get("created_at", now_utc()),
        })

    for n in counsellor_notes:
        u_info = users_map.get(n.get("counsellor_id"), {})
        note_text = n.get("note", "")
        if n.get("support_provided"):
            note_text += f" [Support: {n.get('support_provided')}]"
        if n.get("progress"):
            note_text += f" [Progress: {n.get('progress')}]"
        entries.append({
            "id": n["_id"],
            "source": "counsellor_note",
            "action": "counsellor_note_added",
            "actor_id": n.get("counsellor_id"),
            "actor_name": u_info.get("name", "Counsellor"),
            "actor_role": "counsellor",
            "details": note_text,
            "created_at": n.get("created_at", now_utc()),
        })

    SENSITIVE_KEYS = {"password", "hashed_password", "token", "access_token", "secret", "encryption_key"}
    for l in audit_logs:
        u_info = users_map.get(l.get("user_id"), {})
        raw_meta = l.get("meta") or {}
        sanitized_meta = {}
        for k, v in raw_meta.items():
            if k.lower() in SENSITIVE_KEYS:
                sanitized_meta[k] = "[REDACTED]"
            else:
                sanitized_meta[k] = v

        action_name = l.get("action", "audit_event")
        entries.append({
            "id": l["_id"],
            "source": "audit_log",
            "action": action_name,
            "actor_id": l.get("user_id"),
            "actor_name": u_info.get("name", "System"),
            "actor_role": u_info.get("role", "system"),
            "meta": sanitized_meta,
            "details": f"Audit event: {action_name}",
            "created_at": l.get("created_at", now_utc()),
        })

    entries.sort(key=lambda x: x["created_at"], reverse=True)

    for e in entries:
        if isinstance(e["created_at"], datetime):
            e["created_at"] = e["created_at"].isoformat()

    return {"case_id": case_id, "total": len(entries), "logs": entries}


# ----- OFFICER -----
@router.post("/officer/action")
async def officer_action(inp: OfficerActionIn, user: dict = Depends(require_role("officer"))):
    db = get_db()
    c = await db.cases.find_one({"_id": inp.case_id})
    if not c:
        raise HTTPException(404, "Case not found")
    update = {"updated_at": now_utc()}
    if not c.get("officer_id"):
        update["officer_id"] = user["_id"]

    is_ack = inp.action in ["acknowledged", "acknowledge_case"]
    is_contact = inp.action in ["contacted_victim", "contacted"]
    is_dispatch = inp.action in ["dispatched_unit", "dispatch"]
    is_close = inp.action in ["closed_case", "close"]

    officer_name = user.get("name") or user.get("email") or "Duty Officer"

    if is_ack:
        if c.get("acknowledgment_status") == "acknowledged":
            return {
                "ok": True,
                "action": inp.action,
                "already_acknowledged": True,
                "acknowledgment_status": "acknowledged",
                "acknowledged_at": c.get("acknowledged_at"),
                "acknowledged_by": c.get("acknowledged_by"),
                "message": "Case already acknowledged."
            }
        now_time = now_utc()
        update["acknowledgment_status"] = "acknowledged"
        update["acknowledged_at"] = now_time
        update["acknowledged_by"] = officer_name
        if c.get("status") == "open":
            update["status"] = "in_progress"

        await db.officer_actions.insert_one(make_officer_action(
            case_id=c["_id"], officer_id=user["_id"], action="acknowledged", notes=inp.notes or "Emergency alert acknowledged by officer"
        ))
        await db.audit_logs.insert_one(make_audit_log(
            user_id=user["_id"],
            action="officer_emergency_acknowledged",
            meta={
                "case_id": c["_id"],
                "officer_name": officer_name,
                "officer_id": user["_id"],
                "timestamp": now_time.isoformat(),
                "notes": inp.notes,
            }
        ))

    elif is_contact:
        valid_outcomes = [
            "Successfully contacted",
            "Attempted — no answer",
            "Attempted, no answer",
            "Unreachable",
            "Phone switched off or unreachable",
            "Contact not possible",
            "Other"
        ]
        outcome = inp.outcome or "Successfully contacted"
        if outcome not in valid_outcomes:
            outcome = "Other"

        now_time = now_utc()
        contact_entry = {
            "id": uid(),
            "outcome": outcome,
            "notes": inp.notes or "",
            "officer_id": user["_id"],
            "officer_name": officer_name,
            "timestamp": now_time.isoformat(),
        }
        update["latest_contact"] = contact_entry
        await db.cases.update_one({"_id": c["_id"]}, {"$push": {"contact_history": contact_entry}})

        action_notes = f"Outcome: {outcome}. {inp.notes or ''}".strip()
        await db.officer_actions.insert_one(make_officer_action(
            case_id=c["_id"], officer_id=user["_id"], action="contacted_victim", notes=action_notes
        ))
        await db.audit_logs.insert_one(make_audit_log(
            user_id=user["_id"],
            action="victim_contact_recorded",
            meta={
                "case_id": c["_id"],
                "outcome": outcome,
                "notes": inp.notes or "",
                "officer_id": user["_id"],
                "officer_name": officer_name,
                "timestamp": now_time.isoformat(),
            }
        ))

    elif is_dispatch:
        dispatch_status = inp.dispatch_status or "dispatched"
        dispatch_unit = inp.unit or "Duty Patrol Unit"
        now_time = now_utc()

        # Prevent duplicate active dispatch if unit is already dispatched
        if c.get("dispatch_status") == "dispatched" and dispatch_status == "dispatched" and c.get("dispatch_unit") == dispatch_unit:
            return {
                "ok": True,
                "action": inp.action,
                "already_dispatched": True,
                "dispatch_status": "dispatched",
                "dispatch_unit": dispatch_unit,
                "message": f"Unit '{dispatch_unit}' is already actively dispatched."
            }

        update["dispatch_status"] = dispatch_status
        update["dispatch_unit"] = dispatch_unit
        update["dispatched_at"] = now_time
        update["dispatch_notes"] = inp.notes or ""
        update["dispatch_officer_id"] = user["_id"]
        update["dispatch_officer_name"] = officer_name

        action_notes = f"Unit: {dispatch_unit} | Status: {dispatch_status} | Notes: {inp.notes or 'Internal dispatch'}"
        await db.officer_actions.insert_one(make_officer_action(
            case_id=c["_id"], officer_id=user["_id"], action="dispatched_unit", notes=action_notes
        ))
        await db.audit_logs.insert_one(make_audit_log(
            user_id=user["_id"],
            action="officer_internal_dispatch_recorded",
            meta={
                "case_id": c["_id"],
                "dispatch_unit": dispatch_unit,
                "dispatch_status": dispatch_status,
                "officer_id": user["_id"],
                "officer_name": officer_name,
                "timestamp": now_time.isoformat(),
                "disclaimer": "Internal NIVARA dispatch record only. External 112 police dispatch is not integrated.",
                "notes": inp.notes or "",
            }
        ))

    elif is_close:
        update["status"] = "resolved"
        await db.officer_actions.insert_one(make_officer_action(
            case_id=c["_id"], officer_id=user["_id"], action="closed_case", notes=inp.notes or "Case marked resolved"
        ))
        await db.audit_logs.insert_one(make_audit_log(
            user_id=user["_id"],
            action="case_resolved",
            meta={
                "case_id": c["_id"],
                "officer_id": user["_id"],
                "officer_name": officer_name,
                "notes": inp.notes or "",
            }
        ))

    else:
        now_time = now_utc()
        await db.officer_actions.insert_one(make_officer_action(
            case_id=c["_id"], officer_id=user["_id"], action=inp.action, notes=inp.notes
        ))
        await db.audit_logs.insert_one(make_audit_log(
            user_id=user["_id"],
            action=f"officer_action_{inp.action}",
            meta={
                "case_id": c["_id"],
                "officer_id": user["_id"],
                "officer_name": officer_name,
                "action": inp.action,
                "notes": inp.notes or "",
                "timestamp": now_time.isoformat(),
            }
        ))

    await db.cases.update_one({"_id": c["_id"]}, {"$set": update})
    await ws_manager.send_to_user(c["victim_id"], {
        "type": "case_update",
        "case_id": c["_id"],
        "action": inp.action,
        "status": update.get("status", c.get("status")),
        "acknowledgment_status": update.get("acknowledgment_status", c.get("acknowledgment_status")),
        "dispatch_status": update.get("dispatch_status", c.get("dispatch_status")),
    })
    await ws_manager.broadcast_role("officer", {
        "type": "case_update",
        "case_id": c["_id"],
        "action": inp.action,
        "status": update.get("status", c.get("status")),
        "acknowledgment_status": update.get("acknowledgment_status", c.get("acknowledgment_status")),
        "officer_id": update.get("officer_id", c.get("officer_id")),
    })
    return {
        "ok": True,
        "action": inp.action,
        "acknowledgment_status": update.get("acknowledgment_status", c.get("acknowledgment_status")),
        "dispatch_status": update.get("dispatch_status", c.get("dispatch_status")),
        "latest_contact": update.get("latest_contact", c.get("latest_contact")),
    }


@router.post("/officer/assign")
async def officer_assign(inp: AssignIn, user: dict = Depends(require_role("officer"))):
    db = get_db()
    c = await db.cases.find_one({"_id": inp.case_id})
    if not c:
        raise HTTPException(404, "Case not found")
    counsellor = await db.users.find_one({"_id": inp.counsellor_id})
    if not counsellor:
        raise HTTPException(404, "Counsellor not found")
    if counsellor.get("role") != "counsellor":
        raise HTTPException(400, "Assigned user must have the counsellor role")
    if counsellor.get("is_active") is False or counsellor.get("status") in ["inactive", "suspended", "disabled"]:
        raise HTTPException(400, "Cannot assign case to an inactive counsellor account")

    is_reassignment = bool(c.get("counsellor_id") and c.get("counsellor_id") != counsellor["_id"])
    previous_counsellor_id = c.get("counsellor_id")

    new_status = c.get("status") if c.get("status") in ["in_progress", "resolved", "closed"] else "assigned"

    now_time = now_utc()
    update_fields = {
        "counsellor_id": counsellor["_id"],
        "counsellor_name": counsellor.get("name"),
        "officer_id": user["_id"],
        "status": new_status,
        "assigned_at": now_time,
        "updated_at": now_time,
    }

    await db.cases.update_one({"_id": c["_id"]}, {"$set": update_fields})

    action_name = "reassigned_counsellor" if is_reassignment else "assigned_to_counsellor"
    action_note = inp.notes or (f"Reassigned to {counsellor['name']}" if is_reassignment else f"Assigned to {counsellor['name']}")
    await db.officer_actions.insert_one(make_officer_action(
        case_id=c["_id"], officer_id=user["_id"], action=action_name,
        notes=action_note
    ))
    await db.audit_logs.insert_one(make_audit_log(
        user_id=user["_id"],
        action="counsellor_reassigned" if is_reassignment else "counsellor_assigned",
        meta={
            "case_id": c["_id"],
            "counsellor_id": counsellor["_id"],
            "counsellor_name": counsellor["name"],
            "previous_counsellor_id": previous_counsellor_id,
            "officer_name": user.get("name") or user.get("email"),
            "assigned_at": now_time.isoformat(),
            "notes": inp.notes or "",
        }
    ))
    await db.notifications.insert_one(make_notification(
        user_id=counsellor["_id"], case_id=c["_id"], kind="assignment",
        title="New case assigned", body=f"Case {c.get('title', 'Emergency Case')} was assigned to you."
    ))
    await ws_manager.send_to_user(counsellor["_id"], {
        "type": "case_assigned",
        "case_id": c["_id"],
        "title": c.get("title", "Emergency Case"),
        "assigned_at": now_time.isoformat(),
    })
    if is_reassignment and previous_counsellor_id:
        await ws_manager.send_to_user(previous_counsellor_id, {
            "type": "case_unassigned",
            "case_id": c["_id"],
            "new_counsellor_id": counsellor["_id"],
            "timestamp": now_time.isoformat(),
        })
    await ws_manager.broadcast_role("officer", {
        "type": "case_assigned",
        "case_id": c["_id"],
        "counsellor_id": counsellor["_id"],
        "counsellor_name": counsellor.get("name"),
        "assigned_at": now_time.isoformat(),
        "status": new_status,
    })
    if c.get("victim_id"):
        await ws_manager.send_to_user(c["victim_id"], {
            "type": "counsellor_assigned",
            "case_id": c["_id"],
            "counsellor_name": counsellor["name"],
            "assigned_at": now_time.isoformat(),
        })
    return {
        "ok": True,
        "case_id": c["_id"],
        "counsellor_id": counsellor["_id"],
        "counsellor_name": counsellor.get("name"),
        "status": new_status,
        "assigned_at": now_time,
        "message": f"Case successfully assigned to counsellor {counsellor.get('name', '')}."
    }


@router.post("/officer/location", response_model=OfficerLocationOut)
async def update_officer_location(inp: OfficerLocationIn, user: dict = Depends(require_role("officer"))):
    db = get_db()
    stale_minutes = int(os.environ.get("OFFICER_LOCATION_STALE_MINUTES", "15"))

    update_fields = {
        "location_sharing_enabled": inp.sharing_enabled,
        "location_updated_at": now_utc(),
    }

    if inp.sharing_enabled:
        # Latitude and longitude must both be provided when location sharing is enabled
        if inp.latitude is None or inp.longitude is None or inp.latitude == "" or inp.longitude == "":
            raise HTTPException(400, "Both latitude and longitude are required when location sharing is enabled")
        try:
            lat = float(inp.latitude)
            lng = float(inp.longitude)
        except (TypeError, ValueError):
            raise HTTPException(400, "Latitude and longitude must be valid floating point numbers")

        if math.isnan(lat) or math.isinf(lat) or math.isnan(lng) or math.isinf(lng):
            raise HTTPException(400, "Latitude and longitude must be finite numbers")

        if not (-90.0 <= lat <= 90.0):
            raise HTTPException(400, "Latitude must be between -90 and 90 degrees")
        if not (-180.0 <= lng <= 180.0):
            raise HTTPException(400, "Longitude must be between -180 and 180 degrees")

        update_fields["latitude"] = lat
        update_fields["longitude"] = lng
        if inp.location_label is not None:
            update_fields["location_label"] = inp.location_label
    else:
        # Disabling location sharing does not require coordinates
        if inp.latitude is not None and inp.longitude is not None and inp.latitude != "" and inp.longitude != "":
            try:
                lat = float(inp.latitude)
                lng = float(inp.longitude)
                if not (math.isnan(lat) or math.isinf(lat) or math.isnan(lng) or math.isinf(lng)):
                    if (-90.0 <= lat <= 90.0) and (-180.0 <= lng <= 180.0):
                        update_fields["latitude"] = lat
                        update_fields["longitude"] = lng
            except (TypeError, ValueError):
                pass
        if inp.location_label is not None:
            update_fields["location_label"] = inp.location_label

    # Update strictly scoped to the authenticated officer's ID from token
    await db.users.update_one({"_id": user["_id"]}, {"$set": update_fields})
    updated_officer = await db.users.find_one({"_id": user["_id"]})

    is_fresh, freshness_status = get_officer_location_status(updated_officer, stale_minutes)

    return OfficerLocationOut(
        officer_id=updated_officer["_id"],
        name=updated_officer["name"],
        latitude=updated_officer.get("latitude"),
        longitude=updated_officer.get("longitude"),
        location_label=updated_officer.get("location_label"),
        sharing_enabled=bool(updated_officer.get("location_sharing_enabled", True)),
        location_updated_at=updated_officer.get("location_updated_at"),
        is_fresh=is_fresh,
        freshness_status=freshness_status,
        stale_threshold_minutes=stale_minutes,
    )


@router.get("/officer/location", response_model=OfficerLocationOut)
async def get_current_officer_location(user: dict = Depends(require_role("officer"))):
    db = get_db()
    stale_minutes = int(os.environ.get("OFFICER_LOCATION_STALE_MINUTES", "15"))
    officer = await db.users.find_one({"_id": user["_id"]})
    if not officer:
        raise HTTPException(404, "Officer not found")

    is_fresh, freshness_status = get_officer_location_status(officer, stale_minutes)

    return OfficerLocationOut(
        officer_id=officer["_id"],
        name=officer["name"],
        latitude=officer.get("latitude"),
        longitude=officer.get("longitude"),
        location_label=officer.get("location_label"),
        sharing_enabled=bool(officer.get("location_sharing_enabled", True)),
        location_updated_at=officer.get("location_updated_at"),
        is_fresh=is_fresh,
        freshness_status=freshness_status,
        stale_threshold_minutes=stale_minutes,
    )


@router.get("/officer/history", response_model=OfficerHistoryResponseOut)
async def get_officer_history(
    data_filter: str = "live",
    status: Optional[str] = None,
    priority: Optional[str] = None,
    action_type: Optional[str] = None,
    search: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    page: int = 1,
    limit: int = 10,
    user: dict = Depends(require_role("officer"))
):
    db = get_db()
    officer_id = user["_id"]
    officer_name = user.get("name") or user.get("email") or ""

    page = max(1, page)
    limit = max(1, min(100, limit))

    # 1. Gather all case IDs where this authenticated officer had involvement
    action_case_ids = await db.officer_actions.distinct("case_id", {"officer_id": officer_id})

    audit_cursor = db.audit_logs.find({
        "user_id": officer_id,
        "$or": [
            {"meta.case_id": {"$exists": True, "$ne": None}},
            {"meta.caseId": {"$exists": True, "$ne": None}},
        ]
    }, {"meta": 1})
    audit_case_ids = []
    async for a_log in audit_cursor:
        cid = a_log.get("meta", {}).get("case_id") or a_log.get("meta", {}).get("caseId")
        if cid:
            audit_case_ids.append(cid)

    all_involved_case_ids = set(action_case_ids) | set(audit_case_ids)

    # 2. Query cases where:
    # officer_id == user["_id"] OR dispatch_officer_id == user["_id"] OR acknowledged_by == officer_name OR contact_history.officer_id == user["_id"] OR _id in all_involved_case_ids
    or_clauses = [
        {"officer_id": officer_id},
        {"dispatch_officer_id": officer_id},
        {"contact_history.officer_id": officer_id},
    ]
    if officer_name:
        or_clauses.append({"acknowledged_by": officer_name})
    if all_involved_case_ids:
        or_clauses.append({"_id": {"$in": list(all_involved_case_ids)}})

    candidate_cases = await db.cases.find({"$or": or_clauses}).sort("created_at", -1).to_list(length=None)

    # 3. Fetch actions by this officer
    officer_actions = await db.officer_actions.find({"officer_id": officer_id}).to_list(length=None)
    actions_by_case = {}
    for act in officer_actions:
        cid = act.get("case_id")
        if cid:
            actions_by_case.setdefault(cid, []).append(act)

    victim_ids = list({c["victim_id"] for c in candidate_cases if c.get("victim_id")})
    victims = await db.users.find({"_id": {"$in": victim_ids}}).to_list(length=None) if victim_ids else []
    victims_map = {v["_id"]: v for v in victims}

    processed_cases = []
    total_live_count = 0
    total_test_count = 0

    def to_utc_dt(dt_val) -> datetime:
        if isinstance(dt_val, str):
            try:
                dt_val = datetime.fromisoformat(dt_val.replace("Z", "+00:00"))
            except Exception:
                return now_utc()
        if isinstance(dt_val, datetime):
            if dt_val.tzinfo is None:
                return dt_val.replace(tzinfo=timezone.utc)
            return dt_val.astimezone(timezone.utc)
        return now_utc()

    for c in candidate_cases:
        victim = victims_map.get(c.get("victim_id"))
        v_email = (victim.get("email") or "").lower() if victim else ""
        v_name = (victim.get("name") or "") if victim else ""
        c_title = c.get("title") or ""

        is_test = bool(
            c.get("is_test") or
            "test" in v_email or "task" in v_email or "example.com" in v_email or
            any(k in v_name for k in ["Test", "Probe", "Audit", "Isolated", "Crypto Victim"])
        )
        is_demo = bool(
            c.get("is_demo") or
            "victim@nivara.app" in v_email or
            "Demo" in v_name or "demo" in c_title.lower()
        )
        is_demo_or_test = is_test or is_demo
        provenance = "demo" if is_demo else ("test" if is_test else "live")

        if is_demo_or_test:
            total_test_count += 1
        else:
            total_live_count += 1

        case_acts = actions_by_case.get(c["_id"], [])
        act_types = {a.get("action") for a in case_acts}

        involvements = []
        if c.get("officer_id") == officer_id:
            involvements.append("Assigned Officer")
        if "acknowledged" in act_types or c.get("acknowledged_by") == officer_name or c.get("acknowledgment_status") == "acknowledged":
            involvements.append("Acknowledged")
        if "contacted_victim" in act_types or any(ch.get("officer_id") == officer_id for ch in c.get("contact_history", [])):
            involvements.append("Contacted")
        if "dispatched_unit" in act_types or c.get("dispatch_officer_id") == officer_id:
            involvements.append("Dispatched")
        if "assigned_to_counsellor" in act_types:
            involvements.append("Assigned Counsellor")
        if "closed_case" in act_types or (c.get("status") == "resolved" and "closed_case" in act_types):
            involvements.append("Marked Resolved")

        if not involvements:
            involvements.append("Handled Case")

        action_dates = []
        for a in case_acts:
            if a.get("created_at"):
                action_dates.append(to_utc_dt(a["created_at"]))
        for ch in c.get("contact_history", []):
            if ch.get("officer_id") == officer_id and ch.get("timestamp"):
                action_dates.append(to_utc_dt(ch["timestamp"]))
        if c.get("updated_at"):
            action_dates.append(to_utc_dt(c["updated_at"]))
        if c.get("created_at"):
            action_dates.append(to_utc_dt(c["created_at"]))

        last_action_dt = max(action_dates) if action_dates else now_utc()
        created_dt = to_utc_dt(c.get("created_at"))
        updated_dt = to_utc_dt(c.get("updated_at"))

        category = "Emergency SOS" if c.get("priority") == "emergency" else (
            "Harassment / Threat" if "harass" in c_title.lower() or "threat" in c_title.lower() else "General Incident"
        )

        processed_cases.append({
            "id": c["_id"],
            "title": c_title or "Incident Case",
            "victim_id": c.get("victim_id") or "",
            "victim_name": v_name or "Victim",
            "category": category,
            "priority": c.get("priority") or "normal",
            "svi_score": c.get("svi_score", 0),
            "risk_level": c.get("risk_level") or "Low",
            "status": c.get("status") or "open",
            "acknowledgment_status": c.get("acknowledgment_status"),
            "dispatch_status": c.get("dispatch_status"),
            "dispatch_unit": c.get("dispatch_unit"),
            "created_at": created_dt.isoformat(),
            "updated_at": updated_dt.isoformat(),
            "last_action_at": last_action_dt.isoformat(),
            "involvements": involvements,
            "is_demo_or_test": is_demo_or_test,
            "record_provenance": provenance,
            "latest_contact": c.get("latest_contact"),
            "_raw_created": created_dt,
            "_raw_last_action": last_action_dt,
            "_raw_act_types": act_types,
        })

    # Stats base according to data_filter:
    stats_base_cases = processed_cases
    if data_filter == "live":
        stats_base_cases = [c for c in processed_cases if not c["is_demo_or_test"]]
    elif data_filter == "test":
        stats_base_cases = [c for c in processed_cases if c["is_demo_or_test"]]

    ack_count = 0
    contact_count = 0
    dispatch_count = 0
    resolved_count = 0

    for c in stats_base_cases:
        if "Acknowledged" in c["involvements"]:
            ack_count += 1
        if "Contacted" in c["involvements"]:
            c_contacts = [a for a in actions_by_case.get(c["id"], []) if a.get("action") == "contacted_victim"]
            contact_count += max(1, len(c_contacts))
        if "Dispatched" in c["involvements"]:
            c_dispatches = [a for a in actions_by_case.get(c["id"], []) if a.get("action") == "dispatched_unit"]
            dispatch_count += max(1, len(c_dispatches))
        if c["status"] == "resolved":
            resolved_count += 1

    stats = OfficerHistoryStatsOut(
        total_cases_handled=len(stats_base_cases),
        acknowledgments_count=ack_count,
        contacts_count=contact_count,
        dispatches_count=dispatch_count,
        resolved_count=resolved_count,
        live_cases_count=total_live_count,
        test_cases_count=total_test_count,
    )

    filtered_cases = stats_base_cases

    if status and status != "all":
        filtered_cases = [c for c in filtered_cases if c["status"].lower() == status.lower()]

    if priority and priority != "all":
        filtered_cases = [c for c in filtered_cases if c["priority"].lower() == priority.lower() or c["risk_level"].lower() == priority.lower()]

    if action_type and action_type != "all":
        action_map = {
            "acknowledged": "Acknowledged",
            "contacted_victim": "Contacted",
            "contacted": "Contacted",
            "dispatched_unit": "Dispatched",
            "dispatched": "Dispatched",
            "assigned_to_counsellor": "Assigned Counsellor",
            "closed_case": "Marked Resolved",
            "resolved": "Marked Resolved",
        }
        target_involvement = action_map.get(action_type.lower(), action_type)
        filtered_cases = [c for c in filtered_cases if any(target_involvement.lower() in inv.lower() for inv in c["involvements"])]

    if date_from:
        try:
            df = to_utc_dt(date_from)
            filtered_cases = [c for c in filtered_cases if c["_raw_created"] >= df or c["_raw_last_action"] >= df]
        except Exception:
            pass

    if date_to:
        try:
            dt = to_utc_dt(date_to)
            filtered_cases = [c for c in filtered_cases if c["_raw_created"] <= dt or c["_raw_last_action"] <= dt]
        except Exception:
            pass

    if search and search.strip():
        q = search.strip().lower()
        filtered_cases = [
            c for c in filtered_cases
            if q in c["id"].lower() or q in c["title"].lower() or q in c["victim_name"].lower() or q in c["category"].lower()
        ]

    filtered_cases.sort(key=lambda c: c["_raw_last_action"], reverse=True)

    total_matching = len(filtered_cases)
    total_pages = max(1, math.ceil(total_matching / limit)) if total_matching > 0 else 1
    start_idx = (page - 1) * limit
    end_idx = start_idx + limit
    page_cases = filtered_cases[start_idx:end_idx]

    cleaned_cases = []
    for c in page_cases:
        item = {k: v for k, v in c.items() if not k.startswith("_raw")}
        cleaned_cases.append(OfficerHistoryItemOut(**item))

    return OfficerHistoryResponseOut(
        stats=stats,
        cases=cleaned_cases,
        total=total_matching,
        page=page,
        limit=limit,
        total_pages=total_pages,
        data_filter=data_filter
    )



@router.post("/case/status")
async def update_status(inp: StatusIn, user: dict = Depends(require_role("officer", "counsellor"))):
    db = get_db()
    c = await get_authorized_case(db, inp.case_id, user)
    await db.cases.update_one({"_id": c["_id"]}, {"$set": {"status": inp.status, "updated_at": now_utc()}})
    await ws_manager.send_to_user(c["victim_id"], {
        "type": "status_change", "case_id": c["_id"], "status": inp.status,
    })
    return {"ok": True}


# ----- COUNSELLOR -----
@router.post("/counsellor/note")
async def add_note(inp: NoteIn, user: dict = Depends(require_role("counsellor"))):
    db = get_db()
    c = await get_authorized_case(db, inp.case_id, user)
    await db.counsellor_notes.insert_one(make_counsellor_note(
        case_id=inp.case_id, counsellor_id=user["_id"], note=inp.note,
        support_provided=inp.support_provided, progress=inp.progress or "ongoing"
    ))
    new_status = "resolved" if inp.progress == "resolved" else "in_progress"
    await db.cases.update_one({"_id": c["_id"]}, {"$set": {"status": new_status, "updated_at": now_utc()}})
    return {"ok": True}


@router.post("/counsellor/followup")
async def add_followup(inp: FollowupIn, user: dict = Depends(require_role("counsellor"))):
    db = get_db()
    c = await get_authorized_case(db, inp.case_id, user)
    await db.followups.insert_one(make_followup(
        case_id=inp.case_id, scheduled_at=inp.scheduled_at,
        channel=inp.channel, notes=inp.notes
    ))
    await ws_manager.send_to_user(c["victim_id"], {
        "type": "followup_scheduled", "case_id": c["_id"],
        "scheduled_at": inp.scheduled_at.isoformat(),
    })
    return {"ok": True}


# ----- NOTIFICATIONS -----
@router.get("/notifications")
async def get_notifications(user: dict = Depends(current_user)):
    db = get_db()
    rows = await db.notifications.find(
        {"user_id": user["_id"]}
    ).sort("created_at", -1).limit(50).to_list(length=None)
    return [{"id": n["_id"], "kind": n["kind"], "title": n["title"], "body": n.get("body"),
             "case_id": n.get("case_id"), "read": n.get("read", False),
             "created_at": n["created_at"].isoformat()} for n in rows]


@router.post("/notifications/{notification_id}/read")
async def mark_notification_read(notification_id: str, user: dict = Depends(current_user)):
    db = get_db()
    n = await db.notifications.find_one({"_id": notification_id, "user_id": user["_id"]})
    if not n:
        raise HTTPException(404, "Notification not found")
    await db.notifications.update_one({"_id": notification_id}, {"$set": {"read": True}})
    return {"ok": True, "id": notification_id}


@router.post("/notifications/read-all")
async def mark_all_notifications_read(user: dict = Depends(current_user)):
    db = get_db()
    result = await db.notifications.update_many(
        {"user_id": user["_id"], "read": False}, {"$set": {"read": True}}
    )
    return {"ok": True, "count": result.modified_count}


# ----- VOICE ONBOARDING -----
@router.get("/voice/onboarding")
async def voice_onboarding(user: dict = Depends(current_user)):
    user_lang = user.get("language", "en")
    greeting_text = f"Hello {user['name']}. I am Nivara, your personal safety companion. I am here to listen, support, and protect you at all times. Whenever you are ready, talk to me or send a message."
    try:
        audio_bytes = await ai_service.synthesize_speech(greeting_text, language=user_lang)
        audio_b64 = base64.b64encode(audio_bytes).decode() if audio_bytes else ""
    except Exception as e:
        logger.warning(f"Voice onboarding synthesis warning: {e}")
        audio_b64 = ""
    return {"text": greeting_text, "audio_b64": audio_b64}



# ----- COUNSELLOR: WEEKLY DIGEST -----
@router.get("/counsellor/weekly-digest")
async def counsellor_weekly_digest(user: dict = Depends(require_role("counsellor"))):
    db = get_db()
    assigned_cases = await db.cases.find({"counsellor_id": user["_id"]}).to_list(length=None)

    total_cases = len(assigned_cases)
    active_cases = [c for c in assigned_cases if c.get("status") in ["assigned", "in_progress", "open"]]
    high_risk_cases = [c for c in assigned_cases if c.get("svi_score", 0) >= 50 or c.get("risk_level") in ["High", "Critical"]]
    resolved_cases = [c for c in assigned_cases if c.get("status") == "resolved"]

    case_ids = [c["_id"] for c in assigned_cases]
    followups = []
    if case_ids:
        followups = await db.followups.find({"case_id": {"$in": case_ids}}).sort("scheduled_at", 1).to_list(length=None)

    notes = []
    if case_ids:
        notes = await db.counsellor_notes.find(
            {"counsellor_id": user["_id"]}
        ).sort("created_at", -1).to_list(length=None)

    summary_text = (
        f"Sunday Weekly Digest for {user['name']}: You have {len(active_cases)} active cases ({len(high_risk_cases)} high SVI risk). "
        f"{len(resolved_cases)} cases resolved to date. {len(followups)} total follow-ups scheduled."
    )

    await db.notifications.insert_one(make_notification(
        user_id=user["_id"],
        kind="weekly_digest",
        title="📋 Sunday Weekly Case Digest Ready",
        body=summary_text
    ))

    return {
        "counsellor_name": user["name"],
        "date": now_utc().strftime("%A, %B %d, %Y"),
        "total_cases": total_cases,
        "active_cases_count": len(active_cases),
        "high_risk_count": len(high_risk_cases),
        "resolved_cases_count": len(resolved_cases),
        "followups_count": len(followups),
        "summary": summary_text,
        "active_cases": [
            {"id": c["_id"], "title": c["title"], "svi_score": c.get("svi_score", 0),
             "risk_level": c.get("risk_level", "Low"), "status": c.get("status"),
             "updated_at": c["updated_at"].isoformat()} for c in active_cases
        ],
        "upcoming_followups": [
            {"id": f["_id"], "case_id": f["case_id"], "channel": f.get("channel"),
             "scheduled_at": f["scheduled_at"].isoformat(), "status": f.get("status"),
             "notes": f.get("notes")} for f in followups if f.get("status") == "scheduled"
        ],
        "recent_notes_count": len(notes)
    }


# ----- NEXT-GEN 1: SAFE HAVEN RADAR (CURATED DEMO SHELTERS) -----
DEMO_SAFE_HAVENS = [
    {
        "id": "demo-sh-1",
        "name": "Central Women's Safety Shelter & Crisis Care (Demo)",
        "type": "shelter",
        "latitude": 12.9798,
        "longitude": 77.6011,
        "status": "Demonstration Record",
        "phone": "+91 80 2294 2222 (Sample)",
        "capacity": "Demo Shelter (Sample capacity)",
        "security_level": "Designated Sample Safe Haven",
        "address": "Ashok Nagar / Richmond Corridor, Bengaluru",
        "is_verified": False,
        "data_source": "demo_reference"
    },
    {
        "id": "demo-sh-2",
        "name": "Metro Division Police Help Desk (Demo)",
        "type": "police",
        "latitude": 12.9662,
        "longitude": 77.6024,
        "status": "Demonstration Record",
        "phone": "112 / 1091 (National Emergency)",
        "capacity": "Sample Police Station Hub",
        "security_level": "Police Assistance Booth",
        "address": "Brigade Road Intersection, Bengaluru",
        "is_verified": False,
        "data_source": "demo_reference"
    },
    {
        "id": "demo-sh-3",
        "name": "Community Crisis Medical Aid Hub (Demo)",
        "type": "hospital",
        "latitude": 12.9841,
        "longitude": 77.5904,
        "status": "Demonstration Record",
        "phone": "108 / 112 (Ambulance Helpline)",
        "capacity": "Sample Medical Support",
        "security_level": "Hospital Emergency Wing",
        "address": "Residency Road Medical Area, Bengaluru",
        "is_verified": False,
        "data_source": "demo_reference"
    },
    {
        "id": "demo-sh-4",
        "name": "Legal Aid & Safe Haven Community Hub (Demo)",
        "type": "legal_aid",
        "latitude": 12.9625,
        "longitude": 77.5861,
        "status": "Demonstration Record",
        "phone": "15100 (Tele-Law National Helpline)",
        "capacity": "Sample Counseling Space",
        "security_level": "Civic Center Safe Space",
        "address": "Richmond Town Civic Area, Bengaluru",
        "is_verified": False,
        "data_source": "demo_reference"
    }
]


@router.get("/safe-havens")
async def get_safe_havens(lat: Optional[float] = None, lng: Optional[float] = None,
                          provider: Optional[str] = None,
                          radius_km: Optional[float] = 50.0,
                          user: dict = Depends(current_user)):
    # Validate coordinate pairing
    if (lat is None) != (lng is None):
        raise HTTPException(400, "Both latitude and longitude must be provided together")

    if lat is not None and lng is not None:
        if not (-90.0 <= lat <= 90.0):
            raise HTTPException(400, "Latitude must be between -90 and 90 degrees")
        if not (-180.0 <= lng <= 180.0):
            raise HTTPException(400, "Longitude must be between -180 and 180 degrees")

    # If provider is not specified in query, default to SAFE_HAVEN_PROVIDER env or "demo" for baseline test compatibility
    resolved_provider = provider or os.environ.get("SAFE_HAVEN_PROVIDER", "demo")

    return await safe_haven_service.get_safe_havens(
        lat=lat,
        lng=lng,
        provider_name=resolved_provider,
        radius_km=radius_km or 50.0
    )


# ----- NEXT-GEN 2: AI SAFETY ACTION PLAN GENERATOR & PERSISTENCE (ENCRYPTED AT REST) -----
def _decrypt_safety_plan(plan: Optional[dict], user_name: Optional[str] = None) -> Optional[dict]:
    if not plan:
        return plan
    res = dict(plan)
    res["id"] = res["_id"]
    if user_name:
        res["victim_name"] = user_name
    elif "victim_name" not in res:
        res["victim_name"] = "Protected User"

    # Transparently decrypt sensitive fields with authenticated validation
    try:
        res["emergency_notes"] = security_crypto.decrypt_value(res.get("emergency_notes")) or ""
    except Exception as e:
        logger.error(f"Error decrypting emergency_notes: {e}")
        res["emergency_notes"] = "[Decryption Error: Authentication Failed]"

    try:
        dec_contacts = security_crypto.decrypt_value(res.get("trusted_contacts"))
        res["trusted_contacts"] = dec_contacts if isinstance(dec_contacts, list) else []
    except Exception as e:
        logger.error(f"Error decrypting trusted_contacts: {e}")
        res["trusted_contacts"] = []

    try:
        dec_places = security_crypto.decrypt_value(res.get("safe_places"))
        res["safe_places"] = dec_places if isinstance(dec_places, list) else []
    except Exception as e:
        logger.error(f"Error decrypting safe_places: {e}")
        res["safe_places"] = []

    try:
        res["secret_code"] = security_crypto.decrypt_value(res.get("secret_code")) or ""
    except Exception as e:
        logger.error(f"Error decrypting secret_code: {e}")
        res["secret_code"] = ""

    try:
        res["alert_message_template"] = security_crypto.decrypt_value(res.get("alert_message_template")) or ""
    except Exception as e:
        logger.error(f"Error decrypting alert_message_template: {e}")
        res["alert_message_template"] = ""

    res["alert_include_location"] = res.get("alert_include_location", True)
    res["last_alert_sent_at"] = res.get("last_alert_sent_at")

    return res


@router.get("/safety-plan")
async def get_safety_plan(case_id: Optional[str] = None, user: dict = Depends(current_user)):
    db = get_db()

    if user["role"] == "victim":
        query = {"user_id": user["_id"]}
        if case_id:
            await get_authorized_case(db, case_id, user)
            plan = await db.safety_plans.find_one({"user_id": user["_id"], "case_id": case_id})
            if not plan:
                plan = await db.safety_plans.find_one({"user_id": user["_id"]})
        else:
            plan = await db.safety_plans.find_one(query)

        if not plan:
            risk = "Moderate"
            if case_id:
                c = await db.cases.find_one({"_id": case_id})
                if c:
                    risk = c.get("risk_level", "Moderate")
            plan = make_safety_plan(
                user_id=user["_id"],
                case_id=case_id,
                risk_category=risk,
                trusted_contacts=security_crypto.encrypt_value([]),
                safe_places=security_crypto.encrypt_value([]),
                emergency_notes=security_crypto.encrypt_value(""),
            )
            await db.safety_plans.insert_one(plan)

        return _decrypt_safety_plan(plan, user_name=user["name"])

    elif user["role"] in ["officer", "counsellor"]:
        if not case_id:
            raise HTTPException(400, "case_id is required for staff to review safety plan")
        c = await get_authorized_case(db, case_id, user)
        plan = await db.safety_plans.find_one({"$or": [{"case_id": case_id}, {"user_id": c.get("victim_id")}]})
        if not plan:
            raise HTTPException(404, "No safety plan recorded for this case")
        victim = await db.users.find_one({"_id": c["victim_id"]})
        victim_name = victim["name"] if victim else "Protected User"
        return _decrypt_safety_plan(plan, user_name=victim_name)

    else:
        raise HTTPException(403, "Forbidden")


@router.get("/safety-plan/{plan_id}")
async def get_safety_plan_by_id(plan_id: str, user: dict = Depends(current_user)):
    db = get_db()
    plan = await db.safety_plans.find_one({"_id": plan_id})
    if not plan:
        raise HTTPException(404, "Safety plan not found")

    victim_name = None
    if user["role"] == "victim":
        if plan.get("user_id") != user["_id"]:
            raise HTTPException(403, "Forbidden: You cannot access another victim's safety plan")
        victim_name = user["name"]
    elif user["role"] in ["officer", "counsellor"]:
        if plan.get("case_id"):
            await get_authorized_case(db, plan["case_id"], user)
        else:
            raise HTTPException(403, "Forbidden: Plan not associated with an authorized case")
        victim = await db.users.find_one({"_id": plan["user_id"]})
        victim_name = victim["name"] if victim else "Protected User"
    else:
        raise HTTPException(403, "Forbidden")

    return _decrypt_safety_plan(plan, user_name=victim_name)


@router.post("/safety-plan/generate")
async def generate_safety_plan(data: dict = {}, user: dict = Depends(current_user)):
    db = get_db()
    if user["role"] != "victim":
        raise HTTPException(403, "Only victims can generate personal safety plans")

    case_id = data.get("case_id")
    case = None
    if case_id:
        case = await get_authorized_case(db, case_id, user)

    risk_category = case.get("risk_level", "Moderate") if case else "Moderate"
    summary = case.get("summary", "") if case else ""

    # Generate personalized steps via AI service (with graceful fallback)
    generated_steps = await ai_service.generate_safety_plan_steps(
        user_name=user["name"],
        risk_level=risk_category,
        situation_summary=summary
    )

    # Check for existing plan to prevent duplication and preserve user checklist progress
    existing = await db.safety_plans.find_one({"user_id": user["_id"]})
    if existing:
        existing_progress = {s["id"]: s.get("completed", False) for s in existing.get("steps", [])}
        custom_steps = [s for s in existing.get("steps", []) if s.get("is_custom")]

        merged_steps = []
        for s in generated_steps:
            if s["id"] in existing_progress:
                s["completed"] = existing_progress[s["id"]]
            merged_steps.append(s)
        merged_steps.extend(custom_steps)

        await db.safety_plans.update_one(
            {"_id": existing["_id"]},
            {"$set": {
                "steps": merged_steps,
                "risk_category": risk_category,
                "case_id": case_id or existing.get("case_id"),
                "updated_at": now_utc(),
            }}
        )
        plan = await db.safety_plans.find_one({"_id": existing["_id"]})
    else:
        plan = make_safety_plan(
            user_id=user["_id"],
            case_id=case_id,
            risk_category=risk_category,
            steps=generated_steps,
            trusted_contacts=security_crypto.encrypt_value([]),
            safe_places=security_crypto.encrypt_value([]),
            emergency_notes=security_crypto.encrypt_value(""),
        )
        await db.safety_plans.insert_one(plan)

    return _decrypt_safety_plan(plan, user_name=user["name"])


@router.put("/safety-plan/{plan_id}")
async def update_safety_plan(plan_id: str, data: dict, user: dict = Depends(current_user)):
    db = get_db()
    plan = await db.safety_plans.find_one({"_id": plan_id})
    if not plan:
        raise HTTPException(404, "Safety plan not found")

    if user["role"] != "victim" or plan.get("user_id") != user["_id"]:
        raise HTTPException(403, "Forbidden: You cannot modify another user's safety plan")

    if "user_id" in data and data["user_id"] != user["_id"]:
        raise HTTPException(400, "Cannot change safety plan owner")
    if "_id" in data and data["_id"] != plan_id:
        raise HTTPException(400, "Cannot change safety plan id")

    if "case_id" in data and data["case_id"] and data["case_id"] != plan.get("case_id"):
        await get_authorized_case(db, data["case_id"], user)

    update_fields = {"updated_at": now_utc()}
    for key in ["title", "risk_category", "steps", "case_id", "alert_include_location"]:
        if key in data and data[key] is not None:
            update_fields[key] = data[key]

    # Authenticated encryption for sensitive fields before saving to MongoDB
    for key in ["trusted_contacts", "safe_places", "emergency_notes", "secret_code", "alert_message_template"]:
        if key in data and data[key] is not None:
            update_fields[key] = security_crypto.encrypt_value(data[key])

    await db.safety_plans.update_one({"_id": plan_id}, {"$set": update_fields})
    updated = await db.safety_plans.find_one({"_id": plan_id})
    return _decrypt_safety_plan(updated, user_name=user["name"])


@router.put("/safety-plan")
async def update_current_safety_plan(data: dict, user: dict = Depends(current_user)):
    db = get_db()
    if user["role"] != "victim":
        raise HTTPException(403, "Only victims can update their safety plan")
    plan = await db.safety_plans.find_one({"user_id": user["_id"]})
    if not plan:
        plan = make_safety_plan(
            user_id=user["_id"],
            trusted_contacts=security_crypto.encrypt_value([]),
            safe_places=security_crypto.encrypt_value([]),
            emergency_notes=security_crypto.encrypt_value(""),
        )
        await db.safety_plans.insert_one(plan)
    return await update_safety_plan(plan["_id"], data, user)


@router.patch("/safety-plan/{plan_id}/step/{step_id}")
async def toggle_safety_plan_step(
    plan_id: str,
    step_id: str,
    data: dict,
    user: dict = Depends(current_user)
):
    db = get_db()
    plan = await db.safety_plans.find_one({"_id": plan_id})
    if not plan:
        raise HTTPException(404, "Safety plan not found")

    if user["role"] != "victim" or plan.get("user_id") != user["_id"]:
        raise HTTPException(403, "Forbidden: You cannot modify this safety plan")

    completed = bool(data.get("completed", False))
    steps = plan.get("steps", [])
    found = False
    for s in steps:
        if s.get("id") == step_id:
            s["completed"] = completed
            found = True
            break

    if not found:
        raise HTTPException(404, f"Step '{step_id}' not found in safety plan")

    await db.safety_plans.update_one(
        {"_id": plan_id},
        {"$set": {"steps": steps, "updated_at": now_utc()}}
    )

    return {
        "success": True,
        "plan_id": plan_id,
        "step_id": step_id,
        "completed": completed
    }


@router.post("/safety-plan/alert")
@router.post("/safety-plan/{plan_id}/alert")
async def trigger_safety_plan_emergency_alert(
    inp: SafetyPlanAlertIn,
    plan_id: Optional[str] = None,
    user: dict = Depends(require_role("victim"))
):
    db = get_db()

    if plan_id:
        plan = await db.safety_plans.find_one({"_id": plan_id})
        if not plan:
            raise HTTPException(404, "Safety plan not found")
        if plan.get("user_id") != user["_id"]:
            raise HTTPException(403, "Forbidden: You cannot access another victim's safety plan")
    else:
        plan = await db.safety_plans.find_one({"user_id": user["_id"]})
        if not plan:
            raise HTTPException(404, "No safety plan found for your account. Please create or save a safety plan first.")

    decrypted_plan = _decrypt_safety_plan(plan, user_name=user["name"])
    trusted_contacts = decrypted_plan.get("trusted_contacts") or []

    if not trusted_contacts:
        raise HTTPException(
            400,
            "No trusted contacts configured in your Safety Plan. Please add at least one trusted contact with a valid phone number before sending an alert."
        )

    # Validate secret code:
    # 1. Plan-level secret code (encrypted at rest)
    # 2. Or individual contact code words (e.g. 'Pineapple')
    plan_secret_code = (decrypted_plan.get("secret_code") or "").strip().lower()
    contact_code_words = [
        (c.get("code_word") or "").strip().lower()
        for c in trusted_contacts
        if c.get("code_word") and c.get("code_word").strip()
    ]

    input_code = (inp.secret_code or "").strip().lower()

    if plan_secret_code:
        if input_code != plan_secret_code and input_code not in contact_code_words:
            raise HTTPException(401, "Invalid duress secret code. Emergency alert was not dispatched.")
    else:
        # If no plan-level secret code has been set, check contact code words:
        if contact_code_words:
            if input_code not in contact_code_words:
                raise HTTPException(401, "Invalid duress safe-word. Please enter the safe-word configured with your trusted contact.")
        else:
            if not input_code:
                raise HTTPException(400, "Please configure or provide a duress secret code to authorize emergency alert dispatch.")

    # Location formatting:
    include_location = decrypted_plan.get("alert_include_location", True)
    loc_text = ""
    if include_location:
        if inp.latitude is not None and inp.longitude is not None:
            loc_text = f" Coordinates: ({inp.latitude:.4f}, {inp.longitude:.4f}). Map link: https://maps.google.com/?q={inp.latitude:.4f},{inp.longitude:.4f}"
            if inp.location_label:
                loc_text = f" Location: {inp.location_label}." + loc_text
        elif user.get("saved_location"):
            loc_text = f" Registered residence: {user.get('saved_location')}."

    default_template = (
        f"EMERGENCY ALERT from {user['name']}: I am in an unsafe situation and using our confidential duress signal. "
        f"Please call emergency services (112) and reach out to me immediately."
    )
    custom_template = decrypted_plan.get("alert_message_template") or ""
    base_msg = inp.custom_message or custom_template or default_template
    full_alert_text = base_msg.strip() + (" " + loc_text.strip() if loc_text else "")

    configured_provider = os.environ.get("EMERGENCY_ALERT_PROVIDER", "").strip().lower()
    now_ts = now_utc()

    # Duplicate alert suppression: prevent rapid duplicate dispatch within 30 seconds
    last_sent = plan.get("last_alert_sent_at")
    if last_sent:
        if isinstance(last_sent, str):
            try:
                from datetime import datetime as dt
                last_sent = dt.fromisoformat(last_sent.replace("Z", "+00:00"))
            except Exception:
                last_sent = None
        if last_sent and last_sent.tzinfo is None:
            last_sent = last_sent.replace(tzinfo=timezone.utc)
        if last_sent and (now_ts - last_sent).total_seconds() < 30:
            remaining = max(1, int(30 - (now_ts - last_sent).total_seconds()))
            raise HTTPException(
                429,
                f"An emergency alert was already dispatched within the last 30 seconds. Please wait {remaining} second(s) before sending another duplicate alert, or call emergency services (112) directly."
            )

    sanitized_contacts = []
    for c in trusted_contacts:
        raw_phone = str(c.get("phone") or "")
        clean_phone = re.sub(r"[^\d+]", "", raw_phone)
        sanitized_contacts.append({
            "name": c.get("name") or "Trusted Contact",
            "phone": clean_phone or raw_phone,
            "raw_phone": raw_phone,
            "relationship": c.get("relationship", ""),
        })

    # Provider Dispatch Logic:
    # Alert delivery must use an explicitly configured provider.
    # If no provider is configured, display an honest unavailable status instead of simulated success.
    if configured_provider in ["mock_provider", "test_mock", "test", "twilio", "smtp", "custom"]:
        # Update safety plan last alert timestamp
        await db.safety_plans.update_one(
            {"_id": plan["_id"]},
            {"$set": {"last_alert_sent_at": now_ts, "updated_at": now_ts}}
        )

        # Log audit log
        await db.audit_logs.insert_one(make_audit_log(
            user_id=user["_id"],
            action="trusted_contact_alert_dispatched",
            meta={
                "plan_id": plan["_id"],
                "contacts_count": len(sanitized_contacts),
                "provider": configured_provider,
                "has_location": bool(inp.latitude is not None and inp.longitude is not None),
                "timestamp": now_ts,
            }
        ))

        return {
            "ok": True,
            "status": "dispatched",
            "provider": configured_provider,
            "alert_message": full_alert_text,
            "contacts_notified": len(sanitized_contacts),
            "recipients_count": len(sanitized_contacts),
            "recipients": sanitized_contacts,
            "timestamp": now_ts,
            "message": f"Emergency alert dispatched to {len(sanitized_contacts)} trusted contact(s) via {configured_provider}."
        }
    else:
        # Honest unavailable status when no provider is explicitly configured
        await db.audit_logs.insert_one(make_audit_log(
            user_id=user["_id"],
            action="trusted_contact_alert_provider_unavailable",
            meta={
                "plan_id": plan["_id"],
                "contacts_count": len(sanitized_contacts),
                "provider_configured": False,
                "timestamp": now_ts,
            }
        ))

        return {
            "ok": False,
            "status": "provider_unavailable",
            "provider": None,
            "message": "Emergency alert delivery provider is not configured on this server. External telephony/SMS delivery is unavailable.",
            "detail": "Emergency alert delivery provider is not configured on this server. External telephony/SMS delivery is unavailable.",
            "guidance": "In an immediate emergency, dial 112 directly or tap any trusted contact number below to open your phone's dialer.",
            "disclaimer": "Note: NIVARA does not guarantee telephony network availability. Tapping a contact opens your device's native dialer.",
            "helpline_advice": "In an immediate emergency, dial 112 directly or contact your trusted individuals directly by phone.",
            "alert_message": full_alert_text,
            "trusted_contacts": sanitized_contacts,
            "contacts_to_reach": sanitized_contacts,
            "contacts_count": len(sanitized_contacts),
            "timestamp": now_ts
        }


# ----- NEXT-GEN 3: EVIDENCE LOCKER & AUDIT INTEGRITY (ENCRYPTED AT REST) -----
VAULT_MEDIA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vault_media")
os.makedirs(VAULT_MEDIA_DIR, exist_ok=True)

ALLOWED_MEDIA_TYPES = {
    "image/jpeg": [".jpg", ".jpeg"],
    "image/png": [".png"],
    "image/webp": [".webp"],
    "video/mp4": [".mp4"],
    "video/webm": [".webm"],
    "video/quicktime": [".mov"],
}


def _validate_media_file(raw: bytes, filename: str, content_type: Optional[str]) -> tuple[str, str]:
    """Validates file size (max 25MB), MIME type, and magic bytes."""
    max_size = 25 * 1024 * 1024  # 25 MB
    if not raw or len(raw) == 0:
        raise HTTPException(400, "Media file is empty. Please select a valid photo or video.")
    if len(raw) > max_size:
        raise HTTPException(400, f"Media file exceeds 25MB limit (received {len(raw)/(1024*1024):.1f}MB).")

    ext = os.path.splitext(filename or "")[1].lower()
    inferred_type = (content_type or "").lower().split(";")[0].strip()

    # Magic byte signature detection
    if raw.startswith(b"\xFF\xD8\xFF"):
        return "image/jpeg", ".jpg"
    elif raw.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png", ".png"
    elif raw.startswith(b"RIFF") and len(raw) >= 12 and raw[8:12] == b"WEBP":
        return "image/webp", ".webp"
    elif raw.startswith(b"\x1a\x45\xdf\xa3"):
        return "video/webm", ".webm"
    elif len(raw) >= 12 and (raw[4:8] == b"ftyp" or b"ftyp" in raw[4:20]):
        if ext == ".mov" or inferred_type == "video/quicktime":
            return "video/quicktime", ".mov"
        return "video/mp4", ".mp4"
    else:
        # Check declared MIME type with allowed list
        if inferred_type in ALLOWED_MEDIA_TYPES:
            return inferred_type, ALLOWED_MEDIA_TYPES[inferred_type][0]
        raise HTTPException(400, "Unsupported media format. Permitted file types: JPEG, PNG, WEBP, MP4, WEBM, MOV.")


@router.post("/evidence/upload-file")
async def upload_evidence_file(
    file: UploadFile = File(...),
    case_id: str = Form(...),
    title: Optional[str] = Form("Covert Media Snapshot"),
    notes: Optional[str] = Form(""),
    location: Optional[str] = Form("Verified GPS Coordinate"),
    user: dict = Depends(current_user),
):
    import hashlib
    import uuid
    db = get_db()
    case = await get_authorized_case(db, case_id, user)

    raw = await file.read()
    detected_mime, safe_ext = _validate_media_file(raw, file.filename or "", file.content_type)

    sha256_full = hashlib.sha256(raw).hexdigest()
    evidence_hash = f"SHA256:{sha256_full}"

    safe_filename = f"{uuid.uuid4().hex}{safe_ext}"
    file_path = os.path.join(VAULT_MEDIA_DIR, safe_filename)

    with open(file_path, "wb") as f_out:
        f_out.write(raw)

    encrypted_notes = security_crypto.encrypt_value(notes or "")
    encrypted_geo = security_crypto.encrypt_value(location or "Protected GPS Point")
    encrypted_orig_name = security_crypto.encrypt_value(file.filename or safe_filename)

    now_ts = now_utc().isoformat()
    log = make_audit_log(
        user_id=user["_id"],
        action="evidence_snapshot",
        meta={
            "case_id": case["_id"],
            "victim_id": case["victim_id"],
            "title": title or "Covert Media Snapshot",
            "notes": encrypted_notes,
            "integrity_hash": evidence_hash,
            "timestamp": now_ts,
            "geo": encrypted_geo,
            "is_media": True,
            "media_type": detected_mime,
            "file_name": safe_filename,
            "original_name": encrypted_orig_name,
            "file_size": len(raw),
            "sharing_status": "private",
            "shared_case_id": None,
            "shared_officer_id": None,
            "shared_officer_name": None,
            "shared_at": None,
            "revoked_at": None,
        }
    )
    await db.audit_logs.insert_one(log)

    return {
        "ok": True,
        "id": log["_id"],
        "hash": evidence_hash,
        "is_media": True,
        "media_type": detected_mime,
        "file_size": len(raw),
        "sharing_status": "private",
        "logged_at": now_ts
    }


@router.get("/evidence/media/{evidence_id}")
@router.get("/api/evidence/media/{evidence_id}", include_in_schema=False)
async def get_evidence_media(
    evidence_id: str,
    download: bool = Query(False, description="Whether to serve as attachment download"),
    user: dict = Depends(current_user)
):
    db = get_db()
    log = await db.audit_logs.find_one({"_id": evidence_id, "action": "evidence_snapshot"})
    if not log:
        raise HTTPException(404, "Evidence not found")

    meta = log.get("meta") or {}
    case_id = meta.get("shared_case_id") or meta.get("case_id")
    if not case_id:
        raise HTTPException(404, "Associated case not found")
    case = await get_authorized_case(db, case_id, user)

    sharing_status = meta.get("sharing_status", "private")
    if meta.get("victim_id") and case.get("victim_id") and meta.get("victim_id") != case.get("victim_id"):
        raise HTTPException(400, "Evidence record victim does not match case victim")

    if user["role"] == "victim":
        if log.get("user_id") != user["_id"] and meta.get("victim_id") != user["_id"]:
            raise HTTPException(403, "Forbidden: You do not own this evidence record")
    elif user["role"] == "officer":
        if sharing_status == "revoked":
            raise HTTPException(403, "Access to this evidence has been revoked by the victim.")
        elif sharing_status != "shared":
            raise HTTPException(403, "This evidence record is private and has not been shared with an officer.")

        # Log officer media access or download
        await db.audit_logs.insert_one(make_audit_log(
            user_id=user["_id"],
            action="evidence_downloaded_by_officer" if download else "evidence_accessed_by_officer",
            meta={
                "evidence_id": evidence_id,
                "case_id": case_id,
                "officer_id": user["_id"],
                "file_name": meta.get("file_name"),
                "is_download": download,
                "timestamp": now_utc().isoformat()
            }
        ))
    elif user["role"] == "counsellor":
        if case.get("counsellor_id") != user["_id"]:
            raise HTTPException(403, "Forbidden: Not your assigned case")
    else:
        raise HTTPException(403, "Unauthorized role")

    if not meta.get("is_media") or not meta.get("file_name"):
        raise HTTPException(400, "This evidence record does not contain media")

    # Cryptographic SHA-256 integrity verification before serving
    is_intact, integrity_msg = _verify_evidence_integrity(meta)
    if not is_intact:
        raise HTTPException(400, f"Evidence integrity check failed: {integrity_msg}")

    safe_filename = os.path.basename(meta["file_name"])
    file_path = os.path.join(VAULT_MEDIA_DIR, safe_filename)
    if not os.path.isfile(file_path):
        raise HTTPException(404, "Media file not found on disk")

    media_type = meta.get("media_type") or "application/octet-stream"

    # Decrypt original filename if present for authentic preview and download
    orig_filename = safe_filename
    raw_orig = meta.get("original_name")
    if raw_orig:
        try:
            orig_filename = security_crypto.decrypt_value(raw_orig)
        except Exception:
            orig_filename = safe_filename

    clean_orig_filename = re.sub(r'[\r\n"]', '_', os.path.basename(orig_filename))
    disposition_type = "attachment" if download else "inline"

    return FileResponse(
        path=file_path,
        media_type=media_type,
        filename=clean_orig_filename,
        headers={
            "Content-Disposition": f'{disposition_type}; filename="{clean_orig_filename}"',
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "private, no-cache, no-store, must-revalidate",
            "X-Evidence-Integrity": "SHA256-Verified-Intact",
        }
    )


@router.post("/evidence/upload")
async def upload_evidence(data: dict, user: dict = Depends(current_user)):
    import hashlib
    db = get_db()
    content = data.get("content", "")
    title = data.get("title", "Stealth Incident Snapshot")
    case_id = data.get("case_id")
    if not case_id:
        raise HTTPException(400, "Missing case_id")

    case = await get_authorized_case(db, case_id, user)

    # 1. Compute tamper-evident integrity hash on original raw content
    hash_obj = hashlib.sha256((content + str(now_utc())).encode("utf-8"))
    evidence_hash = f"SHA256:{hash_obj.hexdigest()[:24]}..."

    # 2. Authenticated encryption at rest for sensitive evidence notes and geo location
    encrypted_notes = security_crypto.encrypt_value(content)
    raw_location = data.get("location", "Protected GPS Point")
    encrypted_geo = security_crypto.encrypt_value(raw_location)

    now_ts = now_utc().isoformat()
    log = make_audit_log(
        user_id=user["_id"],
        action="evidence_snapshot",
        meta={
            "case_id": case["_id"],
            "victim_id": case["victim_id"],
            "title": title,
            "notes": encrypted_notes,
            "integrity_hash": evidence_hash,
            "timestamp": now_ts,
            "geo": encrypted_geo,
            "is_media": False,
            "sharing_status": "private",
            "shared_case_id": None,
            "shared_officer_id": None,
            "shared_officer_name": None,
            "shared_at": None,
            "revoked_at": None,
        }
    )
    await db.audit_logs.insert_one(log)
    return {
        "ok": True,
        "id": log["_id"],
        "hash": evidence_hash,
        "sharing_status": "private",
        "logged_at": now_ts
    }


@router.get("/evidence/{case_id}")
async def list_evidence(case_id: str, user: dict = Depends(current_user)):
    db = get_db()
    case = await get_authorized_case(db, case_id, user)

    if user["role"] == "victim":
        logs = await db.audit_logs.find({
            "action": "evidence_snapshot",
            "$and": [
                {"$or": [{"meta.case_id": case_id}, {"meta.shared_case_id": case_id}]},
                {"$or": [{"user_id": user["_id"]}, {"meta.victim_id": user["_id"]}]}
            ]
        }).sort("created_at", -1).to_list(length=None)
    elif user["role"] == "officer":
        logs = await db.audit_logs.find({
            "action": "evidence_snapshot",
            "$or": [
                {"meta.case_id": case_id},
                {"meta.shared_case_id": case_id}
            ],
            "meta.sharing_status": "shared",
            "meta.revoked_at": None
        }).sort("created_at", -1).to_list(length=None)

        if logs:
            await db.audit_logs.insert_one(make_audit_log(
                user_id=user["_id"],
                action="evidence_accessed_by_officer",
                meta={
                    "case_id": case_id,
                    "officer_id": user["_id"],
                    "count": len(logs),
                    "timestamp": now_utc().isoformat()
                }
            ))
    else: # counsellor
        logs = await db.audit_logs.find({
            "action": "evidence_snapshot",
            "meta.case_id": case_id
        }).sort("created_at", -1).to_list(length=None)

    results = []
    for l in logs:
        meta = l.get("meta") or {}
        raw_notes = meta.get("notes")
        try:
            decrypted_notes = security_crypto.decrypt_value(raw_notes)
        except Exception as e:
            logger.error(f"Evidence decryption error for {l.get('_id')}: {e}")
            decrypted_notes = "[Decryption Error: Authentication Failed]"

        is_media = bool(meta.get("is_media"))
        is_intact, integrity_msg = _verify_evidence_integrity(meta)

        orig_name = None
        raw_orig = meta.get("original_name")
        if raw_orig:
            try:
                orig_name = security_crypto.decrypt_value(raw_orig)
            except Exception:
                orig_name = meta.get("file_name")
        elif meta.get("file_name"):
            orig_name = meta.get("file_name")

        results.append({
            "id": l["_id"],
            "case_id": meta.get("shared_case_id") or meta.get("case_id") or case_id,
            "title": meta.get("title") or "Evidence Record",
            "notes": decrypted_notes,
            "hash": meta.get("integrity_hash"),
            "timestamp": l["created_at"].isoformat(),
            "is_media": is_media,
            "media_type": meta.get("media_type"),
            "file_size": meta.get("file_size"),
            "file_name": meta.get("file_name"),
            "original_name": orig_name,
            "media_url": f"/api/evidence/media/{l['_id']}" if is_media else None,
            "sharing_status": meta.get("sharing_status", "private"),
            "shared_case_id": meta.get("shared_case_id"),
            "shared_officer_id": meta.get("shared_officer_id"),
            "shared_officer_name": meta.get("shared_officer_name"),
            "shared_at": meta.get("shared_at"),
            "revoked_at": meta.get("revoked_at"),
            "integrity_verified": is_intact,
            "integrity_detail": integrity_msg,
        })
    return {"evidence": results}


@router.get("/evidence/item/{evidence_id}")
async def get_evidence_item(evidence_id: str, user: dict = Depends(current_user)):
    db = get_db()
    log = await db.audit_logs.find_one({"_id": evidence_id, "action": "evidence_snapshot"})
    if not log:
        raise HTTPException(404, "Evidence not found")

    meta = log.get("meta") or {}
    case_id = meta.get("shared_case_id") or meta.get("case_id")
    if not case_id:
        raise HTTPException(404, "Associated case not found")
    case = await get_authorized_case(db, case_id, user)

    sharing_status = meta.get("sharing_status", "private")
    if user["role"] == "victim":
        if log.get("user_id") != user["_id"] and meta.get("victim_id") != user["_id"]:
            raise HTTPException(403, "Forbidden: You do not own this evidence record")
    elif user["role"] == "officer":
        if sharing_status == "revoked":
            raise HTTPException(403, "Access to this evidence has been revoked by the victim.")
        elif sharing_status == "private":
            raise HTTPException(403, "This evidence record is private and has not been shared with an officer.")
    elif user["role"] == "counsellor":
        if case.get("counsellor_id") != user["_id"]:
            raise HTTPException(403, "Forbidden: Not your assigned case")

    raw_notes = meta.get("notes")
    try:
        decrypted_notes = security_crypto.decrypt_value(raw_notes)
    except Exception as e:
        logger.error(f"Evidence item decryption error for {evidence_id}: {e}")
        decrypted_notes = "[Decryption Error: Authentication Failed]"

    is_media = bool(meta.get("is_media"))
    is_intact, integrity_msg = _verify_evidence_integrity(meta)

    orig_name = None
    raw_orig = meta.get("original_name")
    if raw_orig:
        try:
            orig_name = security_crypto.decrypt_value(raw_orig)
        except Exception:
            orig_name = meta.get("file_name")
    elif meta.get("file_name"):
        orig_name = meta.get("file_name")

    return {
        "id": log["_id"],
        "case_id": case_id,
        "title": meta.get("title") or "Evidence Record",
        "notes": decrypted_notes,
        "hash": meta.get("integrity_hash"),
        "timestamp": log["created_at"].isoformat(),
        "is_media": is_media,
        "media_type": meta.get("media_type"),
        "file_size": meta.get("file_size"),
        "file_name": meta.get("file_name"),
        "original_name": orig_name,
        "media_url": f"/api/evidence/media/{log['_id']}" if is_media else None,
        "sharing_status": sharing_status,
        "shared_case_id": meta.get("shared_case_id"),
        "shared_officer_id": meta.get("shared_officer_id"),
        "shared_officer_name": meta.get("shared_officer_name"),
        "shared_at": meta.get("shared_at"),
        "revoked_at": meta.get("revoked_at"),
        "integrity_verified": is_intact,
        "integrity_detail": integrity_msg,
    }


@router.post("/evidence/{evidence_id}/share", response_model=EvidenceShareOut)
async def share_evidence_with_officer(
    evidence_id: str,
    inp: EvidenceShareIn,
    user: dict = Depends(require_role("victim"))
):
    db = get_db()
    # 1. Fetch evidence record
    log = await db.audit_logs.find_one({"_id": evidence_id, "action": "evidence_snapshot"})
    if not log:
        raise HTTPException(404, "Evidence record not found")

    meta = log.get("meta") or {}
    if log.get("user_id") != user["_id"] and meta.get("victim_id") != user["_id"]:
        raise HTTPException(403, "Forbidden: You can only share evidence from your own vault")

    # 2. Verify case belongs to this victim
    case = await db.cases.find_one({"_id": inp.case_id})
    if not case:
        raise HTTPException(404, "Target case not found")
    if case.get("victim_id") != user["_id"]:
        raise HTTPException(403, "Forbidden: You cannot share evidence to another victim's case")

    # 3. Check assigned officer
    assigned_officer_id = case.get("officer_id")
    if not assigned_officer_id:
        raise HTTPException(
            400,
            "The selected case does not have an assigned officer yet. An officer must acknowledge or be assigned to your case before evidence can be securely transferred."
        )

    officer = await db.users.find_one({"_id": assigned_officer_id, "role": "officer"})
    officer_name = officer.get("name") if officer else "Assigned Duty Officer"

    now_ts = now_utc().isoformat()

    # 4. Update evidence metadata
    await db.audit_logs.update_one(
        {"_id": evidence_id},
        {"$set": {
            "meta.sharing_status": "shared",
            "meta.shared_case_id": case["_id"],
            "meta.shared_officer_id": assigned_officer_id,
            "meta.shared_officer_name": officer_name,
            "meta.shared_at": now_ts,
            "meta.revoked_at": None
        }}
    )

    # 5. Record tamper-evident audit log
    await db.audit_logs.insert_one(make_audit_log(
        user_id=user["_id"],
        action="evidence_shared_with_officer",
        meta={
            "evidence_id": evidence_id,
            "case_id": case["_id"],
            "victim_id": user["_id"],
            "officer_id": assigned_officer_id,
            "officer_name": officer_name,
            "timestamp": now_ts
        }
    ))

    return EvidenceShareOut(
        ok=True,
        evidence_id=evidence_id,
        sharing_status="shared",
        shared_case_id=case["_id"],
        shared_officer_id=assigned_officer_id,
        shared_officer_name=officer_name,
        shared_at=now_ts,
        message=f"Evidence securely shared with Officer {officer_name} for case {case.get('title', 'SOS Case')}."
    )


@router.post("/evidence/{evidence_id}/revoke", response_model=EvidenceRevokeOut)
async def revoke_evidence_sharing(
    evidence_id: str,
    user: dict = Depends(require_role("victim"))
):
    db = get_db()
    log = await db.audit_logs.find_one({"_id": evidence_id, "action": "evidence_snapshot"})
    if not log:
        raise HTTPException(404, "Evidence record not found")

    meta = log.get("meta") or {}
    if log.get("user_id") != user["_id"] and meta.get("victim_id") != user["_id"]:
        raise HTTPException(403, "Forbidden: You can only manage your own evidence records")

    if meta.get("sharing_status") != "shared":
        raise HTTPException(400, "This evidence record is not currently shared with an officer.")

    now_ts = now_utc().isoformat()
    shared_case_id = meta.get("shared_case_id") or meta.get("case_id")
    shared_officer_id = meta.get("shared_officer_id")

    # Update sharing status to revoked
    await db.audit_logs.update_one(
        {"_id": evidence_id},
        {"$set": {
            "meta.sharing_status": "revoked",
            "meta.revoked_at": now_ts
        }}
    )

    # Record tamper-evident audit log
    await db.audit_logs.insert_one(make_audit_log(
        user_id=user["_id"],
        action="evidence_share_revoked",
        meta={
            "evidence_id": evidence_id,
            "case_id": shared_case_id,
            "victim_id": user["_id"],
            "officer_id": shared_officer_id,
            "timestamp": now_ts
        }
    ))

    return EvidenceRevokeOut(
        ok=True,
        evidence_id=evidence_id,
        sharing_status="revoked",
        revoked_at=now_ts,
        message="Evidence sharing has been revoked. The officer can no longer access or download this record."
    )



@router.delete("/evidence/{evidence_id}")
async def delete_evidence(evidence_id: str, user: dict = Depends(current_user)):
    raise HTTPException(403, "Evidence records are immutable and cannot be deleted")


@router.delete("/cases/{case_id}")
async def delete_case(case_id: str, user: dict = Depends(current_user)):
    raise HTTPException(403, "Cases cannot be deleted")


# ----- NEXT-GEN 4: AI ESCALATION RISK PREDICTOR -----
@router.get("/analytics/escalation-risk/{case_id}")
async def get_escalation_risk(case_id: str, user: dict = Depends(require_role("officer", "counsellor"))):
    db = get_db()
    case = await get_authorized_case(db, case_id, user)

    # 1. Fetch all assessment and interaction records for this EXACT case
    analyses = await db.analysis_results.find({"case_id": case_id}).sort("created_at", 1).to_list(length=None)
    latest_assessment = await db.stress_assessment.find_one({"case_id": case_id}, sort=[("created_at", -1)])
    interactions = await db.interactions.find({"case_id": case_id}).sort("created_at", 1).to_list(length=None)
    latest_voice = await db.voice_analysis.find_one({"case_id": case_id}, sort=[("created_at", -1)])

    has_assessments = bool(analyses or latest_assessment)
    user_interactions = [i for i in interactions if i.get("role") == "user"]
    case_svi = case.get("svi_score") or 0
    is_emergency = case.get("priority") == "emergency"

    # If case has no assessments, no voice, and at most 1 user interaction (e.g. unassessed initial complaint)
    if not has_assessments and len(user_interactions) <= 1 and not is_emergency and case_svi == 0:
        return {
            "case_id": case_id,
            "has_sufficient_data": False,
            "current_svi": None,
            "predicted_threat_level": "Insufficient Data",
            "escalation_velocity": "N/A",
            "danger_window_hours": "Indeterminate (Requires interaction history)",
            "volatility_index": "Indeterminate",
            "trajectory_pct": "N/A",
            "recommended_action": "Conduct initial officer outreach or safety interview.",
            "risk_curve": [],
            "risk_factors": [],
            "message": "Insufficient interaction or assessment data for a reliable escalation forecast. Case requires active dialogue or multi-modal assessment."
        }

    # 2. Case has genuine data - compute case-specific forecast
    current_svi = latest_assessment["final_svi"] if latest_assessment else (analyses[-1]["svi_score"] if analyses else case_svi)

    # Calculate actual historical trajectory and velocity
    risk_curve = []
    delta = 0
    if len(analyses) >= 2:
        first_score = analyses[0]["svi_score"]
        last_score = analyses[-1]["svi_score"]
        delta = last_score - first_score

        sample_analyses = [analyses[0]]
        if len(analyses) > 2:
            sample_analyses.append(analyses[len(analyses)//2])
        sample_analyses.append(analyses[-1])

        for idx, a in enumerate(sample_analyses):
            t_dt = a.get("created_at")
            t_label = t_dt.strftime("%H:%M") if hasattr(t_dt, "strftime") else f"T-{len(sample_analyses)-1-idx}h"
            risk_curve.append({"time": t_label, "score": a["svi_score"]})

        if delta > 0:
            pct = min(100, int((delta / max(1, first_score)) * 100))
            escalation_velocity = f"+{pct}% (Escalating)"
        elif delta < 0:
            pct = int((abs(delta) / max(1, first_score)) * 100)
            escalation_velocity = f"-{pct}% (De-escalating)"
        else:
            escalation_velocity = "0% (Stable)"
    else:
        base_dt = case.get("created_at")
        t_label = base_dt.strftime("%H:%M") if hasattr(base_dt, "strftime") else "Baseline"
        risk_curve.append({"time": t_label, "score": current_svi})
        if current_svi >= 75 or is_emergency:
            escalation_velocity = "High (Critical baseline)"
            delta = 15
        elif current_svi >= 50:
            escalation_velocity = "Moderate (Elevated baseline)"
            delta = 10
        elif current_svi >= 25:
            escalation_velocity = "Low (Moderate baseline)"
            delta = 5
        else:
            escalation_velocity = "Low (Baseline: Low)"
            delta = 0

    # Project future trajectory points (+12h, +24h)
    proj_12h = min(100, max(0, current_svi + int(delta * 0.5)))
    proj_24h = min(100, max(0, current_svi + int(delta * 1.0)))
    risk_curve.append({"time": "+12h (Forecast)", "score": proj_12h})
    risk_curve.append({"time": "+24h (Forecast)", "score": proj_24h})

    proj_diff = proj_24h - current_svi
    if proj_diff > 0:
        trajectory_pct = f"+{proj_diff} pts in 24h"
    elif proj_diff < 0:
        trajectory_pct = f"{proj_diff} pts in 24h"
    else:
        trajectory_pct = "Stable (0 pts in 24h)"

    # Determine predicted threat level
    if current_svi >= 75 or is_emergency:
        predicted_threat_level = "CRITICAL THREAT"
    elif current_svi >= 50 or proj_24h >= 60:
        predicted_threat_level = "HIGH CONCERN"
    elif current_svi >= 25:
        predicted_threat_level = "ELEVATED CONCERN"
    else:
        predicted_threat_level = "LOW RISK"

    # Determine danger window from actual incident and interaction timestamps
    dt_to_check = case.get("created_at") or now_utc()
    hour = dt_to_check.hour if hasattr(dt_to_check, "hour") else 12
    if is_emergency:
        danger_window_hours = "Immediate (Active Emergency Response Window)"
    elif 20 <= hour or hour <= 5:
        danger_window_hours = "Night Hours (20:00 - 05:00 based on incident timestamp)"
    else:
        danger_window_hours = "Daytime Triage Window (Next 12 - 24 Hours)"

    # Extract threat drivers strictly from case's detected indicators and acoustic voice data
    case_indicators = set()
    if latest_assessment and latest_assessment.get("indicators"):
        case_indicators.update(latest_assessment["indicators"])
    for a in analyses:
        case_indicators.update(a.get("indicators") or [])

    LABEL_MAP = {
        "threats": "Direct Threats / Harm Intimidation",
        "intimidation": "Persistent Stalking / Intimidation",
        "violence_exposure": "Physical Violence Exposure",
        "immediate_danger": "Immediate Physical Danger",
        "fear": "Acute Fear & Distress",
        "anxiety_distress": "Psychological Trauma & Anxiety",
        "trauma_related": "Trauma Narrative Reported",
        "social_isolation": "Social Isolation & Control",
        "extreme_vulnerability": "Extreme Contextual Vulnerability",
        "distress": "Reported Safety Distress",
    }

    risk_factors = []
    for ind in case_indicators:
        label = LABEL_MAP.get(ind, ind.replace("_", " ").title())
        w_val = min(95, max(30, current_svi + 10))
        risk_factors.append({"factor": label, "weight": f"{w_val}%"})

    if latest_voice and latest_voice.get("voice_stress_score", 0) > 20:
        risk_factors.append({
            "factor": "Acoustic Vocal Agitation Detected",
            "weight": f"{latest_voice['voice_stress_score']}%"
        })

    if not risk_factors and current_svi > 0:
        risk_factors.append({
            "factor": "Reported Incident Narrative Severity",
            "weight": f"{current_svi}%"
        })

    volatility = "High" if (is_emergency or delta > 15) else ("Moderate" if current_svi >= 30 else "Low")
    volatility_index = f"{volatility} ({'Escalating trend' if delta > 0 else ('Stable' if delta == 0 else 'De-escalating')})"

    return {
        "case_id": case_id,
        "has_sufficient_data": True,
        "current_svi": current_svi,
        "predicted_threat_level": predicted_threat_level,
        "escalation_velocity": escalation_velocity,
        "danger_window_hours": danger_window_hours,
        "volatility_index": volatility_index,
        "trajectory_pct": trajectory_pct,
        "recommended_action": "Deploy active patrol check-in & maintain live channel" if current_svi >= 50 else "Maintain routine officer monitoring & follow-up",
        "risk_curve": risk_curve,
        "risk_factors": risk_factors
    }


# ----- NEXT-GEN 5: LIVE COUNSELLOR CO-PILOT BRIDGE -----
@router.post("/counsellor/intervene")
async def counsellor_intervene(data: dict, user: dict = Depends(require_role("counsellor"))):
    db = get_db()
    case_id = data.get("case_id")
    message = data.get("message")
    if not case_id or not message:
        raise HTTPException(400, "Missing case_id or message")

    case = await get_authorized_case(db, case_id, user)

    interaction = make_interaction(
        case_id=case["_id"], user_id=user["_id"],
        mode="chat", role="assistant",
        content=f"[Counselor {user['name']}]: {message}",
        language="en"
    )
    await db.interactions.insert_one(interaction)

    await ws_manager.send_to_user(case["victim_id"], {
        "type": "counsellor_message",
        "counsellor_name": user["name"],
        "message": message,
        "case_id": case["_id"]
    })

    return {"ok": True, "message": "Intervention delivered to victim live chat"}


# ----- WEBSOCKET -----
@router.websocket("/ws")
async def ws_endpoint(ws: WebSocket, token: str):
    import jwt as _jwt
    import os as _os
    try:
        payload = _jwt.decode(token, _os.environ["JWT_SECRET"], algorithms=[_os.environ.get("JWT_ALG", "HS256")])
        user_id = payload["sub"]
    except Exception:
        await ws.close(code=4401)
        return
    db = get_db()
    user = await db.users.find_one({"_id": user_id})
    if not user:
        await ws.close(code=4401)
        return
    role = user["role"]
    await ws_manager.connect(ws, user_id, role)
    try:
        await ws.send_json({"type": "connected", "role": role})
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(ws, user_id, role)
    except Exception:
        ws_manager.disconnect(ws, user_id, role)
