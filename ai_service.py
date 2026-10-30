import os
import re
import json
import uuid
import logging
import sys
import io
import asyncio
from typing import List, Dict, Tuple, Optional

from groq import AsyncGroq
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

load_dotenv()


def _get_groq_client() -> AsyncGroq:
    key = os.environ.get("GROQ_API_KEY", "")
    return AsyncGroq(api_key=key) if key else None


SYSTEM_PROMPT = """You are Nivara — a warm, calm, empathetic, and context-aware AI safety companion for individuals facing harassment, distress, domestic violence, stalking, threats, or safety concerns.

CORE PRINCIPLES & CONTEXTUAL AWARENESS:
1. MULTI-TURN CONVERSATION AWARENESS:
   - Carefully review the preceding conversation history before responding.
   - Do NOT repeat questions the victim has already answered or repeat generic introductory lines.
   - When the victim provides new details (e.g., location, escalate from harassment to active following/stalking), directly acknowledge the new details and escalate your guidance accordingly.

2. SITUATION-SPECIFIC GUIDANCE:
   - Active Danger / Stalking in progress (e.g., being followed, someone outside their door/college, immediate threats):
     * Give concise, tactical safety guidance immediately: head towards a well-lit, crowded place, campus security desk, or staffed shop.
     * Instruct them to contact local emergency services immediately: In India, dial 112.
     * Offer emergency SOS dispatch and location sharing with duty officers.
   - Harassment / Reporting:
     * Acknowledge the situation empathetically. Check if they are safe right now.
     * Offer practical steps: move to a safe public area, alert a trusted person, preserve evidence safely without engaging.
     * Introduce NIVARA support (Safe Haven Radar, Evidence Vault) and offer to help file an official complaint.
   - Evidence Preservation:
     * Provide clear, actionable advice: capture uncropped screenshots showing date, timestamp, URLs, sender handles; export chat histories; do not delete or confront.
     * Advise storing evidence securely in NIVARA's encrypted Evidence Vault. Remind them never to put themselves at risk to gather evidence.
   - Emotional Distress without Immediate Danger:
     * Respond with warmth, deep empathy, and grounding techniques (steady breathing, focusing on immediate surroundings).
     * Ask a clarifying question to assess their physical safety.
     * Avoid automatically classifying situation as a confirmed emergency based on emotion alone.

3. MULTILINGUAL SUPPORT:
   - Detect and reply in the EXACT same language, script, or dialect mix used by the user:
     English ("en"), Tamil ("ta"), Hindi ("hi"), Tanglish ("tanglish"), or Hinglish ("hinglish").
   - Keep replies concise (2-4 sentences).

4. ACTION PROMPT & QUICK REPLIES:
   - Provide an optional "action_prompt": "file_complaint" | "share_location" | "call_112" | "vault_upload" | "open_safe_haven" | null
   - Include 2-3 short, natural suggested quick-replies.

OUTPUT FORMAT (STRICT):
Return ONLY a valid JSON object with NO markdown or extra text:
{
  "reply": "your empathetic, context-aware interactive reply",
  "language": "en" | "ta" | "hi" | "tanglish" | "hinglish",
  "svi_score": integer 0-100,
  "risk_level": "Low" | "Moderate" | "High" | "Critical",
  "indicators": ["fear", "threat", "intimidation", "distress", "urgency", "safety_concern"],
  "confidence": 0.85,
  "explanation": "one sentence explanation for the SVI score",
  "suggested_replies": ["short option 1", "short option 2", "short option 3"],
  "action_prompt": "file_complaint" | "share_location" | "call_112" | "vault_upload" | "open_safe_haven" | null
}
"""


def _extract_json(text: str) -> Dict:
    """Robust JSON extraction from LLM output."""
    if not text:
        return {}
    text = text.strip()

    # Remove markdown code blocks if present (e.g. ```json ... ```)
    if "```" in text:
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\s*```$", "", text)
        text = text.strip()

    # Try direct parse
    try:
        return json.loads(text)
    except Exception:
        pass

    # Find first {...} block
    m = re.search(r"\{[\s\S]*\}", text)
    if m:
        candidate = m.group(0)
        try:
            return json.loads(candidate)
        except Exception:
            # Fix trailing commas inside JSON arrays/objects
            cleaned = re.sub(r",\s*([\]}])", r"\1", candidate)
            try:
                return json.loads(cleaned)
            except Exception:
                pass
    return {}


def _risk_from_score(s: int) -> str:
    if s >= 75:
        return "Critical"
    if s >= 50:
        return "High"
    if s >= 25:
        return "Moderate"
    return "Low"


def generate_context_aware_reply(
    history: List[Dict[str, str]],
    user_msg: str,
    session_id: str = ""
) -> Dict:
    """
    Context-aware, multi-turn expert support system for when LLM is unavailable or offline.
    Understands preceding conversation context, handles escalating details, provides
    practical safety advice, and guides victim towards complaints, evidence, and location sharing.
    """
    lower = user_msg.lower().strip()

    # Determine user language
    import multilingual
    lang = multilingual.detect_language(user_msg)

    # Analyze history context
    recent_user_turns = [h["content"].lower() for h in history if h.get("role") == "user"][-5:]
    recent_assistant_turns = [h["content"].lower() for h in history if h.get("role") == "assistant"][-3:]

    history_has_harassment = any("harass" in t or "stalk" in t or "follow" in t or "threat" in t for t in recent_user_turns)
    history_has_college_or_location = any("college" in t or "outside" in t or "office" in t or "campus" in t for t in recent_user_turns)
    history_has_evidence = any("evidence" in t or "screenshot" in t or "proof" in t for t in recent_user_turns)

    # 1. IMMEDIATE CRITICAL DANGER / WEAPON / DIRECT PHYSICAL VIOLENCE
    critical_danger_kw = ["kill", "weapon", "knife", "gun", "bleeding", "choking", "attacking me", "rape", "breaking in", "in immediate danger"]
    if any(k in lower for k in critical_danger_kw):
        return {
            "reply": "This is a critical emergency situation. Your immediate safety is paramount. Please call emergency services immediately by dialing 112 (Emergency Services in India). If you cannot speak out loud, press the red Emergency SOS button below to alert duty officers with your coordinates. Seek a secure, locked space away from danger immediately.",
            "language": lang,
            "svi_score": 88,
            "risk_level": "Critical",
            "indicators": ["immediate_danger", "threat", "violence_exposure", "urgency"],
            "confidence": 0.95,
            "explanation": "Critical life-safety emergency detected with immediate threat indicators.",
            "suggested_replies": ["Call 112", "Trigger Emergency SOS", "Share my location"],
            "action_prompt": "call_112",
            "ai_provider": "local_context_engine"
        }

    # 2. ACTIVE STALKING / FOLLOWING IN PUBLIC OR OUTSIDE COLLEGE/HOME (EXAMPLE B & ESCALATION)
    stalking_kw = ["following me", "chasing me", "outside my", "outside the", "behind me", "stalker", "stalking me", "waiting for me", "outside college", "outside campus"]
    followup_stalking_terms = ["following", "outside", "nearby", "standing", "college", "campus", "chasing", "stalking"]
    is_stalking_in_progress = any(k in lower for k in stalking_kw) or (history_has_harassment and any(k in lower for k in followup_stalking_terms))

    if is_stalking_in_progress:
        return {
            "reply": "I hear you, and this is an urgent safety situation. Please head immediately towards a well-lit, populated area, a campus security office, a reception desk, or an open shop with staff. Do not remain isolated. If you feel in immediate danger, please dial 112 (Emergency Services in India) right away. Would you like me to share your location with duty officers or prepare an emergency SOS dispatch?",
            "language": lang,
            "svi_score": 78,
            "risk_level": "Critical",
            "indicators": ["intimidation", "threat", "safety_concern", "urgency", "immediate_danger"],
            "confidence": 0.90,
            "explanation": "Active following/stalking in public space detected requiring immediate tactical safety steps.",
            "suggested_replies": ["I am reaching security now", "Trigger Emergency SOS", "Share my location"],
            "action_prompt": "call_112",
            "ai_provider": "local_context_engine"
        }

    # 3. EVIDENCE PRESERVATION / DIGITAL HARASSMENT (EXAMPLE D)
    evidence_kw = ["preserve evidence", "evidence", "screenshot", "screenshots", "proof", "record harassment", "cyber", "online harassment", "whatsapp", "messages as proof"]
    if any(k in lower for k in evidence_kw):
        return {
            "reply": "To preserve evidence safely: 1) Take uncropped screenshots clearly displaying the sender's username, profile handle, phone number, and timestamps. 2) Export full chat histories and save copies in an external drive or cloud. 3) Do not delete messages or confront the harasser. You can securely store photos, videos, and notes in NIVARA's Evidence Vault, which locks them with tamper-evident SHA-256 integrity hashes and AES-256 encryption. Crucially, never put yourself in physical danger to gather evidence. Would you like to open the Vault or prepare an incident complaint?",
            "language": lang,
            "svi_score": 25,
            "risk_level": "Moderate",
            "indicators": ["distress", "safety_concern"],
            "confidence": 0.85,
            "explanation": "Practical guidance on legal and technical digital evidence preservation.",
            "suggested_replies": ["Open Evidence Vault", "File a complaint", "How to block them safely?"],
            "action_prompt": "vault_upload",
            "ai_provider": "local_context_engine"
        }

    # 4. HARASSMENT / GENERAL INCIDENT REPORTING (EXAMPLE A)
    harassment_kw = ["harass", "harassing", "harassment", "bothering me", "troubling me", "intimidating", "blackmail", "abusive", "uncomfortable"]
    if any(k in lower for k in harassment_kw):
        return {
            "reply": "I am truly sorry you are dealing with this harassment, and I want to support you through every step. First, are you in a physically safe place right now? If possible, move towards a secure public setting, alert a trusted friend or colleague, and take screenshots of any harassing messages to preserve evidence safely without engaging the individual. NIVARA offers confidential Safe Haven shelter navigation and an encrypted Evidence Vault. Would you like to prepare an official complaint or share your current location for nearby support?",
            "language": lang,
            "svi_score": 50,
            "risk_level": "High",
            "indicators": ["fear", "intimidation", "distress", "safety_concern"],
            "confidence": 0.85,
            "explanation": "Harassment reported; initial safety assessment and support options presented.",
            "suggested_replies": ["I am in a safe place", "File a complaint", "Share my location"],
            "action_prompt": "file_complaint",
            "ai_provider": "local_context_engine"
        }

    # 5. EMOTIONAL DISTRESS / FEAR WITHOUT IMMEDIATE PHYSICAL EMERGENCY (EXAMPLE C)
    distress_kw = ["scared", "afraid", "don't know what to do", "dont know what to do", "panicking", "panic", "terrified", "crying", "helpless", "overwhelmed", "anxious", "bayam", "dar"]
    if any(k in lower for k in distress_kw):
        return {
            "reply": "I hear how frightened and overwhelmed you are feeling right now, and it is completely understandable to feel this way. You are not alone, and we can take this one step at a time together. Let's take a slow, deep breath. Can you tell me if you are in a physically safe room right now, or is someone nearby making you feel unsafe?",
            "language": lang,
            "svi_score": 35,
            "risk_level": "Moderate",
            "indicators": ["fear", "distress"],
            "confidence": 0.80,
            "explanation": "Emotional distress and fear acknowledged with grounding reassurance.",
            "suggested_replies": ["I am physically safe right now", "Someone is threatening me", "Tell me what steps to take"],
            "action_prompt": None,
            "ai_provider": "local_context_engine"
        }

    # 6. SAFE HAVEN / SHELTER INQUIRY
    shelter_kw = ["safe haven", "shelter", "where to go", "where can i go", "safe place", "stay the night", "hostel", "one stop centre", "osc"]
    if any(k in lower for k in shelter_kw):
        return {
            "reply": "If you need a secure, verified shelter, NIVARA's Safe Haven Radar connects you directly to government One Stop Centres (OSCs), women's helplines (181), and emergency shelters offering 24/7 medical, legal, and residential support. You can share your location with one click to locate the nearest verified safe haven and get direct navigation routes. Would you like to open Safe Haven Radar or share your location now?",
            "language": lang,
            "svi_score": 40,
            "risk_level": "Moderate",
            "indicators": ["distress", "safety_concern"],
            "confidence": 0.85,
            "explanation": "Verified shelter and One Stop Centre guidance provided.",
            "suggested_replies": ["Open Safe Haven Radar", "Share my location", "Tell me helpline numbers"],
            "action_prompt": "open_safe_haven",
            "ai_provider": "local_context_engine"
        }

    # 7. OFFICIAL COMPLAINT INQUIRY
    complaint_kw = ["file a complaint", "file complaint", "report incident", "police complaint", "lodge a complaint", "official complaint", "register complaint"]
    if any(k in lower for k in complaint_kw):
        return {
            "reply": "I can help you file an official incident complaint through NIVARA's guided workflow. You can document the incident category, time, location, narrative, and suspect details confidentially. You will have full opportunity to review and confirm all details before submission, and a unique tracking reference code will be generated for assigned duty officers. Shall we open the complaint form now?",
            "language": lang,
            "svi_score": 30,
            "risk_level": "Moderate",
            "indicators": ["safety_concern"],
            "confidence": 0.90,
            "explanation": "Victim guided to structured complaint filing.",
            "suggested_replies": ["Open complaint form", "Review incident details", "I need immediate help"],
            "action_prompt": "file_complaint",
            "ai_provider": "local_context_engine"
        }

    # 8. GENERAL SUPPORTIVE FALLBACK (CONTEXT-AWARE & DYNAMIC)
    # Extract substantive snippet or respond to sentiment
    clean_preview = re.sub(r"[^\w\s]", "", user_msg).strip()
    return {
        "reply": f"Thank you for sharing that with me. I am here to support you in whatever you need right now. Based on your situation, we can explore verified safe havens, document details securely in your Evidence Vault, or file a formal complaint for officer review. How can I best help you right now?",
        "language": lang,
        "svi_score": 20,
        "risk_level": "Low",
        "indicators": ["distress"],
        "confidence": 0.70,
        "explanation": "General safety consultation and tool discovery.",
        "suggested_replies": ["I need safety advice", "File a complaint", "Find nearby safe places"],
        "action_prompt": None,
        "ai_provider": "local_context_engine"
    }


def _fallback(user_msg: str) -> Dict:
    """Legacy wrapper redirecting to generate_context_aware_reply."""
    return generate_context_aware_reply([], user_msg)


CANDIDATE_CHAT_MODELS = [
    "llama-3.3-70b-versatile",
    "llama-3.1-8b-instant",
    "llama3-70b-8192",
    "mixtral-8x7b-32768",
    "gemma2-9b-it"
]


async def _create_chat_completion(client: AsyncGroq, messages: List[Dict], temperature: float = 0.5):
    """Helper to try candidate models sequentially on Groq, with fallback to OpenAI if configured."""
    last_error = None
    if client:
        for model_name in CANDIDATE_CHAT_MODELS:
            try:
                res = await client.chat.completions.create(
                    model=model_name,
                    messages=messages,
                    temperature=temperature,
                )
                return res
            except Exception as e:
                logger.warning(f"Groq model {model_name} failed: {e}")
                last_error = e

    # Fallback to OpenAI if key available
    openai_client = _get_openai_client()
    if openai_client:
        for oai_model in ["gpt-4o-mini", "gpt-3.5-turbo"]:
            try:
                res = await openai_client.chat.completions.create(
                    model=oai_model,
                    messages=messages,
                    temperature=temperature,
                )
                return res
            except Exception as e:
                logger.warning(f"OpenAI model {oai_model} failed: {e}")
                last_error = e

    if last_error:
        raise last_error
    raise RuntimeError("No AI chat models available")


async def analyze_and_reply(
    history: List[Dict[str, str]],
    user_msg: str,
    session_id: str
) -> Dict:
    """Send conversation to Groq model, get interactive reply + SVI."""

    client = _get_groq_client()
    openai_client = _get_openai_client()
    if not client and not openai_client:
        return generate_context_aware_reply(history, user_msg, session_id)

    try:
        ctx_lines = []
        for h in history[-8:]:
            ctx_lines.append(f"{h['role'].upper()}: {h['content']}")

        ctx_lines.append(f"USER: {user_msg}")

        prompt = (
            "Conversation history:\n"
            + "\n".join(ctx_lines)
            + "\n\nAnalyze the latest user message and respond in JSON as specified."
        )

        response = await _create_chat_completion(
            client=client,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=0.5,
        )

        raw_text = response.choices[0].message.content or ""
        data = _extract_json(raw_text)

        # If LLM returned text instead of structured JSON, wrap raw text as response
        if not data or "reply" not in data or not str(data.get("reply")).strip():
            clean_reply = re.sub(r"```.*", "", raw_text).strip()
            if clean_reply:
                data = {
                    "reply": clean_reply,
                    "language": "en",
                    "svi_score": 25,
                    "risk_level": "Low",
                    "indicators": ["distress"],
                    "confidence": 0.7,
                    "explanation": "Direct response from AI assistant.",
                    "suggested_replies": ["I need help", "I am feeling scared", "What should I do?"],
                    "action_prompt": None,
                    "ai_provider": "groq" if client else "openai"
                }
            else:
                return generate_context_aware_reply(history, user_msg, session_id)

        score = int(data.get("svi_score", 15))
        score = max(0, min(100, score))

        data["svi_score"] = score
        data["risk_level"] = data.get("risk_level") or _risk_from_score(score)
        data["indicators"] = data.get("indicators") or ["distress"]
        data["confidence"] = float(data.get("confidence", 0.8))
        data["language"] = data.get("language") or "en"
        data["explanation"] = data.get("explanation") or "Contextual NLP evaluation."
        data["suggested_replies"] = data.get("suggested_replies") or [
            "I need guidance", "I feel unsafe", "What steps should I take?"
        ]
        data["action_prompt"] = data.get("action_prompt")
        data["ai_provider"] = "groq" if client else "openai"

        return data

    except Exception as e:
        logger.warning(f"Cloud AI provider error ({e}); using context-aware expert system.")
        return generate_context_aware_reply(history, user_msg, session_id)


WHISPER_HALLUCINATIONS = {
    "thank you for watching", "thanks for watching",
    "subtitles by", "amara org", "like and subscribe", "subscribe to my channel",
    "please subscribe", "mbc news", "www mooji org", "coughing", "laughter",
    "cheering", "applause", "music", "silence", "blank", "thank you", "thanks",
    "bye", "you", "so", "oh", "uh"
}


def _is_whisper_hallucination(text: str) -> bool:
    if not text:
        return True
    cleaned = re.sub(r"[^\w\s]", "", text).strip().lower()
    if not cleaned:
        return True
    if cleaned in WHISPER_HALLUCINATIONS:
        return True
    if any(h in cleaned for h in ["subtitles by", "amara org", "thank you for watching", "thanks for watching", "like and subscribe"]):
        return True
    return False


from openai import AsyncOpenAI


def _get_openai_client() -> Optional[AsyncOpenAI]:
    key = os.environ.get("OPENAI_API_KEY", "")
    return AsyncOpenAI(api_key=key) if key else None


def is_whisper_configured() -> bool:
    """Returns True if either Groq or OpenAI API key is available for Whisper STT."""
    return bool(os.environ.get("GROQ_API_KEY") or os.environ.get("OPENAI_API_KEY"))


def _convert_audio_to_wav(audio_bytes: bytes, filename: str = "audio.webm") -> tuple[bytes, str, str]:
    """Converts input audio (WebM Opus, MP4 AAC, OGG, etc.) to 16kHz mono WAV for Whisper."""
    if not audio_bytes or len(audio_bytes) < 44:
        return audio_bytes, filename, "audio/webm"
    if audio_bytes[:4] == b"RIFF" and b"WAVE" in audio_bytes[:64]:
        return audio_bytes, "audio.wav", "audio/wav"
    try:
        import subprocess
        import imageio_ffmpeg
        exe = imageio_ffmpeg.get_ffmpeg_exe()
        p = subprocess.run(
            [exe, "-y", "-i", "pipe:0", "-vn", "-ar", "16000", "-ac", "1", "-f", "wav", "pipe:1"],
            input=audio_bytes,
            capture_output=True,
            timeout=10
        )
        if p.returncode == 0 and len(p.stdout) > 44:
            return p.stdout, "audio.wav", "audio/wav"
    except Exception as e:
        logger.debug(f"Audio conversion to WAV fallback: {e}")
    ext = os.path.splitext(filename)[1].lower()
    mime_map = {
        ".wav": "audio/wav",
        ".mp3": "audio/mpeg",
        ".m4a": "audio/mp4",
        ".mp4": "audio/mp4",
        ".ogg": "audio/ogg",
        ".webm": "audio/webm",
    }
    return audio_bytes, filename, mime_map.get(ext, "audio/webm")


async def transcribe_audio(
    audio_bytes: bytes,
    filename: str = "audio.webm",
    language: str = None
) -> str:
    """Transcribe audio using Groq Whisper API with fallback to OpenAI Whisper."""

    if not audio_bytes:
        return ""

    # Convert audio to clean 16kHz mono WAV to ensure format compatibility
    wav_bytes, target_filename, content_type = _convert_audio_to_wav(audio_bytes, filename)

    # 1. Try Groq Whisper models FIRST (fast, active Groq API key)
    client = _get_groq_client()
    if client:
        for whisper_model in ["whisper-large-v3-turbo", "whisper-large-v3"]:
            try:
                import io

                f = io.BytesIO(wav_bytes)
                f.name = target_filename

                kwargs = {
                    "model": whisper_model,
                    "file": (target_filename, f, content_type),
                    "prompt": "User speaking in English, Tamil, Hindi, Tanglish, or Hinglish expressing feelings, concerns, or safety situation."
                }

                if language:
                    clean_lang = language.split("-")[0].lower()
                    if clean_lang in ["en", "ta", "hi", "te", "ml", "kn", "mr", "gu", "bn"]:
                        kwargs["language"] = clean_lang

                response = await client.audio.transcriptions.create(**kwargs)
                text = (response.text or "").strip()
                if text and not _is_whisper_hallucination(text):
                    return text
            except Exception as e:
                logger.warning(f"Groq Whisper model {whisper_model} error: {e}")

    # 2. Fallback to OpenAI Whisper API if Groq is unavailable
    openai_client = _get_openai_client()
    if openai_client:
        try:
            import io
            f = io.BytesIO(audio_bytes)
            f.name = filename
            kwargs = {
                "model": "whisper-1",
                "file": (filename, f, content_type),
                "prompt": "User speaking in English, Tamil, Hindi, Tanglish, or Hinglish expressing feelings, concerns, or safety situation."
            }
            if language:
                clean_lang = language.split("-")[0].lower()
                if clean_lang in ["en", "ta", "hi", "te", "ml", "kn", "mr", "gu", "bn"]:
                    kwargs["language"] = clean_lang
            response = await openai_client.audio.transcriptions.create(**kwargs)
            text = (response.text or "").strip()
            if text and not _is_whisper_hallucination(text):
                return text
        except Exception as e:
            logger.warning(f"OpenAI Whisper error: {e}")

    # Honest handling: Do not fabricate a transcript when transcription fails or keys are unconfigured.
    return ""



async def synthesize_speech(
    text: str,
    voice: str = "alloy",
    language: Optional[str] = None
) -> bytes:
    """
    Synthesizes speech from text using a multi-tier fallback architecture:
    1. OpenAI TTS API (if OPENAI_API_KEY is configured).
    2. gTTS (Google Text-to-Speech) for high-quality multilingual neural speech.
    3. Windows System.Speech SpeechSynthesizer (offline fallback on Windows environments).

    Returns non-empty bytes of audio (MP3 or WAV).
    Raises ValueError if text is empty.
    Raises RuntimeError if all TTS engines fail.
    Never returns empty bytes.
    """
    if not text or not text.strip():
        raise ValueError("Text cannot be empty for speech synthesis")

    clean_text = text.strip()

    # Resolve language
    clean_lang = None
    if language:
        clean_lang = language.split("-")[0].lower()

    if not clean_lang or clean_lang in ["auto", "default"]:
        try:
            import multilingual
            clean_lang = multilingual.detect_language(clean_text)
        except Exception:
            clean_lang = "en"

    # Tier 1: Cloud OpenAI TTS API if key is configured
    openai_client = _get_openai_client()
    if openai_client:
        try:
            chosen_voice = voice if voice in ["alloy", "echo", "fable", "onyx", "nova", "shimmer"] else "alloy"
            response = await openai_client.audio.speech.create(
                model="tts-1",
                voice=chosen_voice,
                input=clean_text[:4096]
            )
            if hasattr(response, "aread"):
                audio_bytes = await response.aread()
            elif hasattr(response, "content"):
                audio_bytes = response.content
            elif hasattr(response, "read"):
                audio_bytes = response.read()
            else:
                audio_bytes = bytes(response)

            if audio_bytes and len(audio_bytes) > 0:
                return audio_bytes
        except Exception as e:
            logger.warning(f"OpenAI TTS synthesis error: {e}")

    # Tier 2: gTTS (Free multilingual TTS)
    try:
        from gtts import gTTS
        gtts_lang = "en"
        tld = "co.in" if clean_lang in ["en", "hinglish", "tanglish"] else "com"

        if clean_lang in ["hi", "ta", "te", "kn", "ml", "bn", "mr", "gu", "pa", "ur"]:
            gtts_lang = clean_lang
            tld = "com"

        def _generate_gtts():
            fp = io.BytesIO()
            t = gTTS(text=clean_text, lang=gtts_lang, tld=tld)
            t.write_to_fp(fp)
            return fp.getvalue()

        audio_bytes = await asyncio.to_thread(_generate_gtts)
        if audio_bytes and len(audio_bytes) > 0:
            return audio_bytes
    except Exception as e:
        logger.warning(f"gTTS speech synthesis error: {e}")

    # Tier 3: Windows System.Speech offline fallback (Windows environments)
    if sys.platform == "win32":
        try:
            def _generate_windows_sapi():
                import subprocess
                import base64
                safe_text = clean_text.replace("'", "''").replace('"', '`"')[:1000]
                ps_script = f"""
Add-Type -AssemblyName System.Speech
$s = New-Object System.Speech.Synthesis.SpeechSynthesizer
$ms = New-Object System.IO.MemoryStream
$s.SetOutputToWaveStream($ms)
$s.Speak("{safe_text}")
[Convert]::ToBase64String($ms.ToArray())
"""
                res = subprocess.run(
                    ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
                    capture_output=True,
                    text=True,
                    timeout=15
                )
                if res.returncode == 0 and res.stdout.strip():
                    return base64.b64decode(res.stdout.strip())
                return None

            audio_bytes = await asyncio.to_thread(_generate_windows_sapi)
            if audio_bytes and len(audio_bytes) > 0:
                return audio_bytes
        except Exception as e:
            logger.warning(f"Windows SpeechSynthesizer offline fallback error: {e}")

    logger.error("All speech synthesis engines failed or are unavailable.")
    raise RuntimeError("Speech synthesis engines unavailable or failed to produce audio")



async def summarize_case(
    interactions: List[Dict],
    session_id: str
) -> str:
    """Produce a 3-4 sentence case summary from transcript."""

    client = _get_groq_client()
    if not client or not interactions:
        return "No summary available."

    try:
        transcript = "\n".join(
            f"{i['role']}: {i['content']}"
            for i in interactions[-40:]
        )

        prompt = (
            "Summarize this support conversation in 3-4 sentences. "
            "Cover: what the victim shared, key concerns, apparent risk "
            "factors, and current emotional state. Avoid diagnosis.\n\n"
            + transcript
        )

        response = await _create_chat_completion(
            client=client,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You produce concise, factual, empathetic case summaries "
                        "for social workers."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,
        )

        return response.choices[0].message.content or "Summary completed."

    except Exception as e:
        logger.exception(f"Summary error: {e}")
        return "Summary unavailable."


async def generate_safety_plan_steps(
    user_name: str,
    risk_level: str = "Moderate",
    situation_summary: str = ""
) -> List[dict]:
    """Generates personalized actionable safety steps using LLM if available,
    falling back to curated high-security 5-pillar safety steps if LLM is unavailable.
    """
    default_steps = [
        {
            "id": "step-1",
            "category": "Immediate Signal",
            "title": "Establish Silent Duress Code Words",
            "desc": f"Agree on a discreet safe word ('Pineapple' or 'Red') with 2 trusted contacts so {user_name} can silently signal danger without alerting others.",
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
            "priority": "Critical" if risk_level in ["High", "Critical"] else "High",
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

    client = _get_groq_client()
    if not client:
        return default_steps

    try:
        prompt = (
            f"User Name: {user_name}\n"
            f"Risk Level: {risk_level}\n"
            f"Situation Summary: {situation_summary or 'Seeking general domestic safety precautions'}\n\n"
            "Generate 5 practical, discrete, non-escalating safety action steps across categories: "
            "Immediate Signal, Physical Escape, Digital Privacy, Evidence Security, Legal & Support. "
            "Return JSON ONLY as a list of objects with fields: id, category, title, desc, completed (always false), priority (Critical/High/Medium), is_custom (false)."
        )
        response = await _create_chat_completion(
            client=client,
            messages=[
                {"role": "system", "content": "You are a crisis intervention safety planner. Return valid JSON array only."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2
        )
        content = response.choices[0].message.content or ""
        match = re.search(r"\[.*\]", content, re.DOTALL)
        if match:
            parsed = json.loads(match.group(0))
            if isinstance(parsed, list) and len(parsed) >= 3:
                for idx, item in enumerate(parsed):
                    if not item.get("id"):
                        item["id"] = f"step-{idx + 1}"
                    item["completed"] = False
                    item["is_custom"] = False
                return parsed
    except Exception as e:
        logger.warning(f"AI safety plan step generation fallback: {e}")

    return default_steps


def gen_session_id() -> str:
    return f"nivara-{uuid.uuid4()}"