from datetime import datetime
from typing import Optional, List, Any
from pydantic import BaseModel, EmailStr, Field


class RegisterIn(BaseModel):
    email: EmailStr
    name: str
    password: str = Field(min_length=6)
    role: Optional[str] = "victim"
    language: str = "en"
    phone: Optional[str] = None
    gender: Optional[str] = None
    blood_group: Optional[str] = None
    saved_location: Optional[str] = None


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class UserOut(BaseModel):
    id: str
    email: str
    name: str
    role: str
    language: str
    phone: Optional[str] = None
    gender: Optional[str] = None
    blood_group: Optional[str] = None
    saved_location: Optional[str] = None


class TokenOut(BaseModel):
    token: str
    user: UserOut


class ChatIn(BaseModel):
    case_id: Optional[str] = None
    message: str
    language: Optional[str] = None


class ChatOut(BaseModel):
    case_id: str
    reply: str
    language: str
    svi_score: int
    risk_level: str
    indicators: List[str]
    confidence: Optional[float] = 0.7
    explanation: Optional[str] = None
    voice_analysis: Optional[Any] = None
    assessment: Optional[Any] = None
    recommendations: Optional[List[Any]] = None
    suggested_replies: Optional[List[str]] = None
    complaint_intent_detected: Optional[bool] = False
    action_prompt: Optional[str] = None
    ai_provider: Optional[str] = None


class CaseLocationIn(BaseModel):
    latitude: float
    longitude: float
    location_label: Optional[str] = None
    accuracy: Optional[float] = None
    source: Optional[str] = "gps"
    is_manual_confirmation: Optional[bool] = False


class ConfirmLocationIn(BaseModel):
    latitude: float
    longitude: float
    location_label: Optional[str] = "Victim Confirmed Map Location"
    notes: Optional[str] = None


class ProfileUpdateIn(BaseModel):
    name: Optional[str] = None
    phone: Optional[str] = None
    gender: Optional[str] = None
    blood_group: Optional[str] = None
    saved_location: Optional[str] = None
    language: Optional[str] = None


class ComplaintIn(BaseModel):
    category: str
    title: str
    description: str
    incident_date: Optional[str] = None
    incident_location: Optional[str] = None
    suspect_details: Optional[str] = None
    priority: Optional[str] = "standard"
    latitude: Optional[float] = None
    longitude: Optional[float] = None


class ConsentIn(BaseModel):
    kind: str  # voice | location | video
    granted: bool


class ConsentOut(BaseModel):
    id: str
    kind: str
    granted: bool
    created_at: datetime



class SOSIn(BaseModel):
    case_id: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    location_label: Optional[str] = None
    accuracy: Optional[float] = None
    message: Optional[str] = None


class CaseOut(BaseModel):
    id: str
    victim_id: str
    victim_name: Optional[str] = None
    victim_phone: Optional[str] = None
    victim_gender: Optional[str] = None
    victim_blood_group: Optional[str] = None
    victim_saved_location: Optional[str] = None
    officer_id: Optional[str] = None
    counsellor_id: Optional[str] = None
    counsellor_name: Optional[str] = None
    title: str
    summary: Optional[str] = None
    svi_score: int
    risk_level: str
    priority: str
    status: str
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    location_label: Optional[str] = None
    gps_accuracy: Optional[float] = None
    location_source: Optional[str] = "gps"
    location_updated_at: Optional[datetime] = None
    manual_latitude: Optional[float] = None
    manual_longitude: Optional[float] = None
    manual_location_confirmed_at: Optional[datetime] = None
    manual_location_label: Optional[str] = None
    acknowledgment_status: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    acknowledged_by: Optional[str] = None
    latest_contact: Optional[dict] = None
    contact_history: Optional[List[dict]] = None
    dispatch_status: Optional[str] = None
    dispatched_at: Optional[datetime] = None
    dispatch_unit: Optional[str] = None
    dispatch_notes: Optional[str] = None
    is_demo_or_test: Optional[bool] = False
    record_provenance: Optional[str] = "live"
    assigned_at: Optional[datetime] = None
    is_complaint: Optional[bool] = False
    category: Optional[str] = None
    description: Optional[str] = None
    incident_date: Optional[str] = None
    incident_location: Optional[str] = None
    reference_number: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class InteractionOut(BaseModel):
    id: str
    role: str
    content: str
    mode: str
    language: Optional[str] = None
    created_at: datetime


class AssignIn(BaseModel):
    case_id: str
    counsellor_id: str
    notes: Optional[str] = None


class OfficerActionIn(BaseModel):
    case_id: str
    action: str
    notes: Optional[str] = None
    outcome: Optional[str] = None
    unit: Optional[str] = None
    dispatch_status: Optional[str] = None


class CaseContactIn(BaseModel):
    case_id: str
    outcome: str
    notes: Optional[str] = None


class CaseDispatchIn(BaseModel):
    case_id: str
    unit: Optional[str] = "Duty Patrol Unit"
    dispatch_status: Optional[str] = "dispatched"
    notes: Optional[str] = None


class NoteIn(BaseModel):
    case_id: str
    note: str
    support_provided: Optional[str] = None
    progress: Optional[str] = "ongoing"


class FollowupIn(BaseModel):
    case_id: str
    scheduled_at: datetime
    channel: str = "in-app"
    notes: Optional[str] = None


class StatusIn(BaseModel):
    case_id: str
    status: str


class TTSIn(BaseModel):
    text: str
    voice: Optional[str] = "alloy"
    language: Optional[str] = None


class SafetyStepSchema(BaseModel):
    id: str
    category: str = "General"
    title: str
    desc: str
    completed: bool = False
    priority: str = "Medium"
    is_custom: bool = False


class TrustedContactSchema(BaseModel):
    name: str
    phone: str
    relationship: Optional[str] = None
    code_word: Optional[str] = None


class SafePlaceSchema(BaseModel):
    name: str
    address: Optional[str] = None
    transport_route: Optional[str] = None
    notes: Optional[str] = None


class SafetyPlanIn(BaseModel):
    case_id: Optional[str] = None
    title: Optional[str] = "Personalized High-Security Safety Strategy"
    risk_category: Optional[str] = "Moderate"
    steps: Optional[List[SafetyStepSchema]] = None
    trusted_contacts: Optional[List[TrustedContactSchema]] = None
    safe_places: Optional[List[SafePlaceSchema]] = None
    emergency_notes: Optional[str] = None
    secret_code: Optional[str] = None
    alert_message_template: Optional[str] = None
    alert_include_location: Optional[bool] = None


class SafetyStepToggleIn(BaseModel):
    completed: bool


class SafetyPlanAlertIn(BaseModel):
    secret_code: Optional[str] = None
    custom_message: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    location_label: Optional[str] = None


class SafetyPlanOut(BaseModel):
    id: str
    user_id: str
    case_id: Optional[str] = None
    title: str
    risk_category: str
    steps: List[dict]
    trusted_contacts: List[dict] = []
    safe_places: List[dict] = []
    emergency_notes: Optional[str] = None
    secret_code: Optional[str] = None
    alert_message_template: Optional[str] = None
    alert_include_location: Optional[bool] = True
    last_alert_sent_at: Optional[str] = None
    disclaimer: str
    created_at: datetime
    updated_at: datetime


class SafeHavenItemOut(BaseModel):
    id: str
    name: str
    type: str
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    address: Optional[str] = None
    district: Optional[str] = None
    state: Optional[str] = None
    phone: Optional[str] = None
    helpline: Optional[str] = None
    operating_hours: Optional[str] = "unknown"
    services: List[str] = []
    source_name: str
    source_type: str
    is_verified_source: bool
    is_location_verified: bool
    bed_availability: str
    last_updated: Optional[str] = None
    distance_km: Optional[float] = None
    distance_type: Optional[str] = None
    disclaimer: str


class SafeHavenResponseOut(BaseModel):
    verified_provider_configured: bool
    provider_id: str
    provider_name: str
    provider_notice: str
    user_location: Optional[dict] = None
    has_user_location: bool
    emergency_hotlines: List[dict]
    havens: List[SafeHavenItemOut]


class OfficerLocationIn(BaseModel):
    latitude: Optional[Any] = None
    longitude: Optional[Any] = None
    location_label: Optional[str] = None
    accuracy: Optional[float] = None
    sharing_enabled: bool = True


class OfficerLocationOut(BaseModel):
    officer_id: str
    name: str
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    location_label: Optional[str] = None
    sharing_enabled: bool
    location_updated_at: Optional[datetime] = None
    is_fresh: bool
    freshness_status: str
    stale_threshold_minutes: int


class OfficerHistoryStatsOut(BaseModel):
    total_cases_handled: int
    acknowledgments_count: int
    contacts_count: int
    dispatches_count: int
    resolved_count: int
    live_cases_count: int
    test_cases_count: int


class OfficerHistoryItemOut(BaseModel):
    id: str
    title: str
    victim_id: str
    victim_name: Optional[str] = "Victim"
    category: Optional[str] = "Emergency / Incident"
    priority: str
    svi_score: int
    risk_level: str
    status: str
    acknowledgment_status: Optional[str] = None
    dispatch_status: Optional[str] = None
    dispatch_unit: Optional[str] = None
    created_at: str
    updated_at: str
    last_action_at: str
    involvements: List[str] = []
    is_demo_or_test: bool = False
    record_provenance: str = "live"
    latest_contact: Optional[dict] = None


class OfficerHistoryResponseOut(BaseModel):
    stats: OfficerHistoryStatsOut
    cases: List[OfficerHistoryItemOut]
    total: int
    page: int
    limit: int
    total_pages: int
    data_filter: str


class EvidenceShareIn(BaseModel):
    case_id: str


class EvidenceShareOut(BaseModel):
    ok: bool
    evidence_id: str
    sharing_status: str
    shared_case_id: str
    shared_officer_id: Optional[str] = None
    shared_officer_name: Optional[str] = None
    shared_at: Optional[str] = None
    message: Optional[str] = None


class EvidenceRevokeOut(BaseModel):
    ok: bool
    evidence_id: str
    sharing_status: str
    revoked_at: str
    message: str
