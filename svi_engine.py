from typing import Dict, Any, List, Optional
import math


def evaluate_suicidal_ideation(text: str, detected_indicators: List[str]) -> Dict[str, Any]:
    """
    Evaluates suicidal ideation and self-harm risk levels:
    1. No indication
    2. Passive ideation
    3. Active ideation
    4. Immediate danger
    """
    lower = text.lower()
    
    immediate_danger_kw = [
        "going to kill myself now", "have a gun to my head", "took all the pills",
        "ending it right now", "goodbye forever", "hanging myself", "blade to my wrist"
    ]
    active_ideation_kw = [
        "want to die", "kill myself", "suicide", "end my life", "better off dead",
        "planning to die", "can't go on living", "don't want to live"
    ]
    passive_ideation_kw = [
        "wish I was never born", "wish I wouldn't wake up", "no reason to live",
        "tired of living", "hopeless", "disappear"
    ]

    for kw in immediate_danger_kw:
        if kw in lower:
            return {
                "level": "immediate_danger",
                "label": "Immediate Danger (Self-Harm / Suicidal Risk)",
                "risk_bonus": 40,
                "critical_flag": True
            }

    for kw in active_ideation_kw:
        if kw in lower:
            return {
                "level": "active_ideation",
                "label": "Active Suicidal Ideation",
                "risk_bonus": 30,
                "critical_flag": False
            }

    for kw in passive_ideation_kw:
        if kw in lower:
            return {
                "level": "passive_ideation",
                "label": "Passive Suicidal Ideation",
                "risk_bonus": 15,
                "critical_flag": False
            }

    if "self_harm_risk" in detected_indicators:
        return {
            "level": "passive_ideation",
            "label": "Self-Harm Risk Detected",
            "risk_bonus": 15,
            "critical_flag": False
        }

    return {
        "level": "no_indication",
        "label": "No Indication",
        "risk_bonus": 0,
        "critical_flag": False
    }


def compute_safety_indicators(text: str, existing_indicators: List[str]) -> List[Dict[str, Any]]:
    """
    Analyzes safety and trauma indicators with context:
    fear, anxiety/distress, trauma-related, depression, suicidal ideation,
    self-harm, intimidation, threats, violence exposure, social isolation, extreme vulnerability, immediate danger.
    """
    lower = text.lower()
    indicators = []

    # Map existing basic indicators if present
    for ind in existing_indicators:
        indicators.append(ind)

    # Contextual keywords & patterns
    indicator_rules = [
        ("fear", ["afraid", "scared", "terrified", "frightened", "fear", "dread", "panicked"], "Fear & Anxiety"),
        ("anxiety_distress", ["anxious", "panic", "overwhelmed", "trembling", "crying", "distress", "helpless"], "Anxiety / Distress"),
        ("trauma_related", ["nightmares", "flashbacks", "trauma", "abused", "assaulted", "beaten", "ptsd"], "Trauma-Related Narrative"),
        ("depression_related", ["depressed", "worthless", "numb", "empty", "deep sadness", "hopeless"], "Depression Indicators"),
        ("intimidation", ["blackmail", "extort", "controlling", "stalking", "following me", "tracking me"], "Intimidation / Stalking"),
        ("threats", ["kill you", "hurt you", "threatened", "weapon", "knife", "gun", "warned me"], "Threat / Harm Indicator"),
        ("violence_exposure", ["hit me", "slapped", "punched", "bleeding", "physical violence", "domestic abuse"], "Violence Exposure"),
        ("social_isolation", ["alone", "no one to help", "locked inside", "isolated", "nobody believes me"], "Social Isolation"),
        ("extreme_vulnerability", ["pregnant", "elderly", "disabled", "no money", "homeless", "infant"], "Extreme Vulnerability"),
        ("immediate_danger", ["outside my door", "breaking in", "chasing me", "in immediate danger", "sos"], "Immediate Danger")
    ]

    for code, keywords, label in indicator_rules:
        if any(kw in lower for kw in keywords):
            if code not in indicators:
                indicators.append(code)

    return list(set(indicators))


def generate_intervention_recommendations(
    svi_score: int,
    risk_level: str,
    indicators: List[str],
    suicidal_ideation_level: str,
    voice_stress_score: int
) -> List[Dict[str, Any]]:
    """
    Generates deterministic automated intervention recommendations based on risk score and indicators.
    All recommendations carry 'AI Recommendation — Human Review Required'.
    """
    recs = []

    # LOW (0-24)
    if risk_level == "Low":
        recs.append({
            "type": "General Support & Information",
            "priority": "Standard",
            "description": "Provide general emotional support, informational resources, and self-care materials."
        })
        recs.append({
            "type": "Optional Counselling",
            "priority": "Optional",
            "description": "Offer voluntary counselling sessions with a certified social worker."
        })

    # MODERATE (25-49)
    elif risk_level == "Moderate":
        recs.append({
            "type": "Counselling Referral",
            "priority": "Recommended",
            "description": "Schedule a dedicated mental health counselling session within 24–48 hours."
        })
        recs.append({
            "type": "Follow-up Check-in",
            "priority": "Recommended",
            "description": "Schedule an automated or counsellor follow-up check-in."
        })
        if "intimidation" in indicators or "threats" in indicators:
            recs.append({
                "type": "Legal Information & Guidance",
                "priority": "Recommended",
                "description": "Provide legal rights information regarding protection orders and complaint filing."
            })

    # HIGH (50-74)
    elif risk_level == "High":
        recs.append({
            "type": "Mental Health Counselling",
            "priority": "High",
            "description": "Immediate assignment to a qualified counsellor for psychological first aid."
        })
        recs.append({
            "type": "Officer Case Review",
            "priority": "High",
            "description": "Assign case to an on-duty officer for active monitoring and safety evaluation."
        })
        recs.append({
            "type": "Legal Aid Services",
            "priority": "High",
            "description": "Connect victim with free legal aid counsel for filing protection petitions."
        })
        if "trauma_related" in indicators or "violence_exposure" in indicators:
            recs.append({
                "type": "Medical Assistance Referral",
                "priority": "High",
                "description": "Offer referral to medical facilities for physical trauma assessment."
            })

    # CRITICAL (75-100)
    else:  # Critical
        recs.append({
            "type": "Immediate Human Review",
            "priority": "CRITICAL",
            "description": "Urgent human officer review required. Escalate immediately to response team."
        })
        recs.append({
            "type": "Emergency Support & Dispatch",
            "priority": "CRITICAL",
            "description": "Alert nearby duty response units for immediate location check."
        })
        recs.append({
            "type": "Police Intervention",
            "priority": "CRITICAL",
            "description": "Initiate police protection protocol and immediate safety dispatch."
        })
        recs.append({
            "type": "Counsellor & Trauma Support",
            "priority": "CRITICAL",
            "description": "Urgent crisis counselling and trauma support hotline referral."
        })

    # Specific indicator additions
    if "intimidation" in indicators or "threats" in indicators or svi_score >= 70:
        if not any(r["type"] == "Witness Protection Recommendation" for r in recs):
            recs.append({
                "type": "Witness Protection Recommendation",
                "priority": "Special Protection",
                "description": "Evaluate case for witness protection measures due to severe intimidation/threat indicators."
            })

    if suicidal_ideation_level in ["active_ideation", "immediate_danger"]:
        recs.insert(0, {
            "type": "Crisis Helpline & Suicide Prevention",
            "priority": "IMMEDIATE",
            "description": "Provide 24/7 crisis helpline numbers (e.g. Tele-MANAS 14416 / 1800 891 4416) and activate immediate human safety review."
        })

    return recs


def calculate_hybrid_svi(
    text_score: int,
    text_indicators: List[str],
    voice_analysis: Optional[Dict[str, Any]] = None,
    sos_triggered: bool = False,
    user_text: str = ""
) -> Dict[str, Any]:
    """
    Computes a hybrid multimodal Stress Vulnerability Index (SVI):
    Text/NLP score + Voice acoustic stress score + Safety severity score.
    Returns deterministic final SVI, risk level, breakdown, indicators, and intervention recommendations.
    """
    breakdown = []
    
    # 1. Base Text NLP Score
    base_text = max(0, min(100, text_score))
    breakdown.append({"factor": "Text Content Risk Analysis", "points": int(base_text * 0.5)})

    # 2. Voice Acoustic Score (if voice analysis available)
    voice_score = 0
    if voice_analysis and "voice_stress_score" in voice_analysis:
        voice_score = int(voice_analysis["voice_stress_score"])
        voice_contrib = int(voice_score * 0.3)
        breakdown.append({"factor": "Voice Acoustic Stress", "points": voice_contrib})
        for ind in voice_analysis.get("indicators", []):
            breakdown.append({"factor": f"Acoustic: {ind}", "points": 4})
    else:
        # Re-weight text if no voice analysis present
        voice_contrib = 0

    # 3. Safety & Trauma Indicators
    safety_indicators = compute_safety_indicators(user_text, text_indicators)
    safety_points = 0

    if "immediate_danger" in safety_indicators or sos_triggered:
        safety_points += 35
        breakdown.append({"factor": "Immediate Safety / Danger Alert", "points": 35})
    if "threats" in safety_indicators:
        safety_points += 20
        breakdown.append({"factor": "Threat / Intimidation Indicator", "points": 20})
    if "violence_exposure" in safety_indicators:
        safety_points += 20
        breakdown.append({"factor": "Violence Exposure", "points": 20})
    if "fear" in safety_indicators or "anxiety_distress" in safety_indicators:
        safety_points += 12
        breakdown.append({"factor": "Fear & Severe Anxiety", "points": 12})
    if "trauma_related" in safety_indicators:
        safety_points += 15
        breakdown.append({"factor": "Trauma Narrative", "points": 15})
    if "social_isolation" in safety_indicators:
        safety_points += 10
        breakdown.append({"factor": "Social Isolation", "points": 10})
    if "extreme_vulnerability" in safety_indicators:
        safety_points += 10
        breakdown.append({"factor": "Extreme Vulnerability Context", "points": 10})

    # 4. Suicidal Ideation & Self-Harm Evaluation
    suicide_eval = evaluate_suicidal_ideation(user_text, safety_indicators)
    if suicide_eval["risk_bonus"] > 0:
        safety_points += suicide_eval["risk_bonus"]
        breakdown.append({"factor": suicide_eval["label"], "points": suicide_eval["risk_bonus"]})

    # Hybrid Weighted Formula
    if voice_analysis and "voice_stress_score" in voice_analysis and voice_analysis["voice_stress_score"] > 0:
        # 45% Text + 25% Voice + 30% Safety Points
        raw_svi = (base_text * 0.45) + (voice_score * 0.25) + (min(100, safety_points * 1.5) * 0.30)
    else:
        # 60% Text + 40% Safety Points
        raw_svi = (base_text * 0.60) + (min(100, safety_points * 1.5) * 0.40)

    # Force Critical level if immediate danger or active suicide ideation or SOS
    if suicide_eval["critical_flag"] or sos_triggered or "immediate_danger" in safety_indicators:
        raw_svi = max(78.0, raw_svi)

    final_svi = int(max(0, min(100, round(raw_svi))))

    if final_svi >= 75:
        risk_level = "Critical"
    elif final_svi >= 50:
        risk_level = "High"
    elif final_svi >= 25:
        risk_level = "Moderate"
    else:
        risk_level = "Low"

    # Merge all indicators
    all_indicators = list(set(safety_indicators + text_indicators))
    if voice_analysis and "indicators" in voice_analysis:
        all_indicators.extend(voice_analysis["indicators"])
    all_indicators = list(set(all_indicators))

    # Recommendations
    recommendations = generate_intervention_recommendations(
        svi_score=final_svi,
        risk_level=risk_level,
        indicators=all_indicators,
        suicidal_ideation_level=suicide_eval["level"],
        voice_stress_score=voice_score
    )

    explanation = (
        f"Hybrid SVI score of {final_svi} ({risk_level}). "
        f"Key factors: {', '.join([b['factor'] for b in breakdown[:3]])}."
    )

    return {
        "final_svi": final_svi,
        "risk_level": risk_level,
        "text_score": base_text,
        "voice_score": voice_score,
        "safety_score": min(100, safety_points),
        "confidence": 0.85 if voice_analysis else 0.75,
        "indicators": all_indicators,
        "score_breakdown": breakdown,
        "suicidal_ideation_level": suicide_eval["level"],
        "recommendations": recommendations,
        "explanation": explanation,
        "disclaimer": "AI Recommendation — Human Review Required"
    }
