"""
MongoDB document helpers — replaces SQLAlchemy ORM models.
All collections use string UUIDs as '_id' for easy interop.
"""
import uuid
from datetime import datetime, timezone


def uid() -> str:
    return str(uuid.uuid4())


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


# ---- Document factory helpers ----

def make_user(email: str, name: str, password_hash: str, role: str,
              language: str = "en", phone: str = None,
              gender: str = None, blood_group: str = None, saved_location: str = None,
              latitude: float = None, longitude: float = None,
              duty_area: str = None, location_sharing_enabled: bool = True,
              location_updated_at: datetime = None) -> dict:
    now = now_utc()
    return {
        "_id": uid(),
        "email": email,
        "name": name,
        "password_hash": password_hash,
        "role": role,
        "language": language,
        "phone": phone,
        "gender": gender,
        "blood_group": blood_group,
        "saved_location": saved_location,
        "latitude": latitude,
        "longitude": longitude,
        "duty_area": duty_area,
        "location_sharing_enabled": location_sharing_enabled,
        "location_updated_at": location_updated_at if location_updated_at is not None else (now if latitude is not None and longitude is not None else None),
        "created_at": now,
    }


def make_case(victim_id: str, title: str = "New Case") -> dict:
    now = now_utc()
    return {
        "_id": uid(),
        "victim_id": victim_id,
        "officer_id": None,
        "counsellor_id": None,
        "counsellor_name": None,
        "assigned_at": None,
        "title": title,
        "summary": None,
        "svi_score": 0,
        "risk_level": "Low",
        "priority": "normal",
        "status": "open",
        "latitude": None,
        "longitude": None,
        "location_label": None,
        "acknowledgment_status": "unassigned",
        "acknowledged_at": None,
        "created_at": now,
        "updated_at": now,
    }


def make_interaction(case_id: str, user_id: str, mode: str, role: str,
                     content: str, language: str = None, audio_url: str = None) -> dict:
    return {
        "_id": uid(),
        "case_id": case_id,
        "user_id": user_id,
        "mode": mode,
        "role": role,
        "content": content,
        "language": language,
        "audio_url": audio_url,
        "created_at": now_utc(),
    }


def make_analysis_result(case_id: str, svi_score: int, risk_level: str,
                         confidence: float = 0.7, indicators=None, explanation: str = None) -> dict:
    return {
        "_id": uid(),
        "case_id": case_id,
        "svi_score": svi_score,
        "risk_level": risk_level,
        "confidence": confidence,
        "indicators": indicators or [],
        "explanation": explanation,
        "created_at": now_utc(),
    }


def make_officer_action(case_id: str, officer_id: str, action: str, notes: str = None) -> dict:
    return {
        "_id": uid(),
        "case_id": case_id,
        "officer_id": officer_id,
        "action": action,
        "notes": notes,
        "created_at": now_utc(),
    }


def make_counsellor_note(case_id: str, counsellor_id: str, note: str,
                         support_provided: str = None, progress: str = "ongoing") -> dict:
    return {
        "_id": uid(),
        "case_id": case_id,
        "counsellor_id": counsellor_id,
        "note": note,
        "support_provided": support_provided,
        "progress": progress,
        "created_at": now_utc(),
    }


def make_followup(case_id: str, scheduled_at: datetime, channel: str = "in-app",
                  notes: str = None) -> dict:
    return {
        "_id": uid(),
        "case_id": case_id,
        "scheduled_at": scheduled_at,
        "channel": channel,
        "notes": notes,
        "status": "scheduled",
        "created_at": now_utc(),
    }


def make_notification(user_id: str, kind: str, title: str, body: str = None,
                      case_id: str = None) -> dict:
    return {
        "_id": uid(),
        "user_id": user_id,
        "case_id": case_id,
        "kind": kind,
        "title": title,
        "body": body,
        "read": False,
        "created_at": now_utc(),
    }


def make_consent(user_id: str, kind: str, granted: bool = True) -> dict:
    return {
        "_id": uid(),
        "user_id": user_id,
        "kind": kind,
        "granted": granted,
        "created_at": now_utc(),
    }


def make_audit_log(user_id: str, action: str, meta: dict = None) -> dict:
    return {
        "_id": uid(),
        "user_id": user_id,
        "action": action,
        "meta": meta or {},
        "created_at": now_utc(),
    }


def make_voice_analysis(case_id: str, interaction_id: str = None, **fields) -> dict:
    return {
        "_id": uid(),
        "interaction_id": interaction_id,
        "case_id": case_id,
        "pitch_mean": fields.get("pitch_mean", 0.0),
        "pitch_variance": fields.get("pitch_variance", 0.0),
        "pitch_range": fields.get("pitch_range", 0.0),
        "speech_rate": fields.get("speech_rate", 0.0),
        "pause_count": fields.get("pause_count", 0),
        "average_pause": fields.get("average_pause", 0.0),
        "longest_pause": fields.get("longest_pause", 0.0),
        "silence_ratio": fields.get("silence_ratio", 0.0),
        "energy_mean": fields.get("energy_mean", 0.0),
        "energy_variance": fields.get("energy_variance", 0.0),
        "voice_stress_score": fields.get("voice_stress_score", 0),
        "stress_level": fields.get("stress_level", "LOW"),
        "indicators": fields.get("indicators", []),
        "created_at": now_utc(),
    }


def make_stress_assessment(case_id: str, interaction_id: str = None, **fields) -> dict:
    return {
        "_id": uid(),
        "interaction_id": interaction_id,
        "case_id": case_id,
        "text_score": fields.get("text_score", 0),
        "voice_score": fields.get("voice_score", None),
        "safety_score": fields.get("safety_score", 0),
        "final_svi": fields.get("final_svi", 0),
        "risk_level": fields.get("risk_level", "Low"),
        "indicators": fields.get("indicators", []),
        "confidence": fields.get("confidence", 0.7),
        "score_breakdown": fields.get("score_breakdown", []),
        "created_at": now_utc(),
    }


def make_intervention_recommendation(case_id: str, assessment_id: str = None,
                                     recommendations=None, disclaimer: str = None) -> dict:
    return {
        "_id": uid(),
        "case_id": case_id,
        "assessment_id": assessment_id,
        "recommendations": recommendations or [],
        "disclaimer": disclaimer or "AI Recommendation — Human Review Required",
        "created_at": now_utc(),
    }


def make_safety_plan(
    user_id: str,
    case_id: str = None,
    title: str = "Personalized High-Security Safety Strategy",
    risk_category: str = "Moderate",
    steps: list = None,
    trusted_contacts: list = None,
    safe_places: list = None,
    emergency_notes: str = None,
    secret_code: str = None,
    alert_message_template: str = None,
    alert_include_location: bool = True,
    last_alert_sent_at: str = None,
) -> dict:
    now = now_utc()
    default_steps = [
        {
            "id": "step-1",
            "category": "Immediate Signal",
            "title": "Establish Silent Duress Code Words",
            "desc": "Share a pre-agreed safe word ('Pineapple' or 'Red') with 2 trusted contacts to silently summon help without alerting perpetrator.",
            "completed": False,
            "priority": "High",
            "is_custom": False,
        },
        {
            "id": "step-2",
            "category": "Physical Escape",
            "title": "Designate 2 Primary Safe Havens",
            "desc": "Confirm nearest 24/7 shelter or police desk with accessible transportation route and key emergency cash stash.",
            "completed": False,
            "priority": "Critical",
            "is_custom": False,
        },
        {
            "id": "step-3",
            "category": "Digital Privacy",
            "title": "Activate Stealth Browser & Masking",
            "desc": "Use Disguise View in public, enable two-factor authentication on personal emails, and revoke location sharing permissions on unverified apps.",
            "completed": False,
            "priority": "High",
            "is_custom": False,
        },
        {
            "id": "step-4",
            "category": "Evidence Security",
            "title": "Auto-Sync Secure Cloud Vault",
            "desc": "Snapshot threatening messages, timestamps, and audio notes directly to Nivara's evidence vault.",
            "completed": False,
            "priority": "Medium",
            "is_custom": False,
        },
        {
            "id": "step-5",
            "category": "Legal & Support",
            "title": "Connect with Dedicated Protection Officer",
            "desc": "Review legal protection options (Restraining Order / Protection under Domestic Violence Act) with assigned counselor.",
            "completed": False,
            "priority": "High",
            "is_custom": False,
        },
    ]

    return {
        "_id": uid(),
        "user_id": user_id,
        "case_id": case_id,
        "title": title,
        "risk_category": risk_category,
        "steps": steps if steps is not None else default_steps,
        "trusted_contacts": trusted_contacts or [],
        "safe_places": safe_places or [],
        "emergency_notes": emergency_notes or "",
        "secret_code": secret_code or "",
        "alert_message_template": alert_message_template or "",
        "alert_include_location": alert_include_location,
        "last_alert_sent_at": last_alert_sent_at,
        "disclaimer": "NIVARA Safety Plans are personal safety planning guides and do not automatically contact emergency services. In an immediate life-threatening emergency, call 112 directly.",
        "created_at": now,
        "updated_at": now,
    }

