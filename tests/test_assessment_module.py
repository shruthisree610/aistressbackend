import pytest
import numpy as np
import voice_analyzer
import svi_engine
import multilingual

SYNTHETIC_TEST_CASES = [
    {
        "id": "TC01",
        "text": "Hello, I just want to ask about general support services and timings.",
        "expected_risk": "Low",
        "expected_indicators": [],
        "voice_stress": 15
    },
    {
        "id": "TC02",
        "text": "I am feeling a bit anxious because someone has been sending weird messages.",
        "expected_risk": "Moderate",
        "expected_indicators": ["anxiety_distress"],
        "voice_stress": 35
    },
    {
        "id": "TC03",
        "text": "My ex-partner is following me and threatening to hurt me if I go out alone. I am scared.",
        "expected_risk": "High",
        "expected_indicators": ["fear", "threats", "intimidation"],
        "voice_stress": 65
    },
    {
        "id": "TC04",
        "text": "Please help! Someone is outside breaking into my house with a weapon! I am in immediate danger!",
        "expected_risk": "Critical",
        "expected_indicators": ["immediate_danger", "threats", "fear"],
        "voice_stress": 85
    },
    {
        "id": "TC05",
        "text": "I feel so hopeless and I don't want to live anymore. I am going to end my life.",
        "expected_risk": "Critical",
        "expected_indicators": ["depression_related"],
        "expected_suicide_level": "active_ideation",
        "voice_stress": 75
    },
    {
        "id": "TC06",
        "text": "I have nobody to talk to, no family or friends, completely locked inside alone.",
        "expected_risk": "Moderate",
        "expected_indicators": ["social_isolation"],
        "voice_stress": 40
    },
    {
        "id": "TC07",
        "text": "Enaku romba bayam irukku, avan enna thodarnthu varan, enna panradhune theriyala.",
        "expected_lang": "tanglish",
        "expected_risk": "High",
        "expected_indicators": ["fear"],
        "voice_stress": 60
    },
    {
        "id": "TC08",
        "text": "Mujhe bohot dar lag raha hai, koi mera picha kar raha hai.",
        "expected_lang": "hinglish",
        "expected_risk": "High",
        "expected_indicators": ["fear"],
        "voice_stress": 60
    }
]


def test_language_detection():
    assert multilingual.detect_language("Hello, how are you?") == "en"
    assert multilingual.detect_language("Mujhe bohot dar lag raha hai") == "hinglish"
    assert multilingual.detect_language("Enaku romba bayam irukku") == "tanglish"
    assert multilingual.detect_language("எனக்கு உதவி வேண்டும்") == "ta"
    assert multilingual.detect_language("मुझे मदद चाहिए") == "hi"


def test_acoustic_voice_analyzer_silence_and_noise():
    res_empty = voice_analyzer.analyze_voice_acoustics(b"")
    assert res_empty["voice_stress_score"] == 0
    assert res_empty["stress_level"] == "LOW"

    sample_rate = 16000
    duration = 2.0
    t = np.linspace(0, duration, int(sample_rate * duration), False)
    tone = (np.sin(2 * np.pi * 150 * t) * 16384).astype(np.int16)
    audio_bytes = tone.tobytes()

    res_sine = voice_analyzer.analyze_voice_acoustics(audio_bytes, transcript="test voice tone")
    assert res_sine["speech"]["duration_seconds"] > 0
    assert "pitch" in res_sine
    assert "pauses" in res_sine


def test_suicidal_ideation_detection():
    eval_passive = svi_engine.evaluate_suicidal_ideation("I feel hopeless and tired of living", [])
    assert eval_passive["level"] in ["passive_ideation", "active_ideation"]

    eval_active = svi_engine.evaluate_suicidal_ideation("I want to die and end my life", [])
    assert eval_active["level"] == "active_ideation"

    eval_immediate = svi_engine.evaluate_suicidal_ideation("I am going to kill myself now with pills", [])
    assert eval_immediate["level"] == "immediate_danger"
    assert eval_immediate["critical_flag"] is True


def test_hybrid_svi_and_evaluation_metrics():
    y_true = []
    y_pred = []

    for tc in SYNTHETIC_TEST_CASES:
        voice_data = {
            "voice_stress_score": tc["voice_stress"],
            "indicators": ["Acoustic variation"] if tc["voice_stress"] > 50 else []
        }
        text_nlp_score = 15 if tc["expected_risk"] == "Low" else 40 if tc["expected_risk"] == "Moderate" else 65 if tc["expected_risk"] == "High" else 85
        
        result = svi_engine.calculate_hybrid_svi(
            text_score=text_nlp_score,
            text_indicators=tc.get("expected_indicators", []),
            voice_analysis=voice_data,
            sos_triggered=(tc["id"] == "TC04"),
            user_text=tc["text"]
        )

        y_true.append(tc["expected_risk"])
        y_pred.append(result["risk_level"])

        assert result["final_svi"] >= 0 and result["final_svi"] <= 100
        assert len(result["recommendations"]) > 0
        assert "disclaimer" in result

    correct = sum(1 for t, p in zip(y_true, y_pred) if t == p)
    accuracy = correct / len(y_true)
    assert accuracy >= 0.75
