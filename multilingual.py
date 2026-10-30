from typing import Dict, Any, Optional
import re

SUPPORTED_LANGUAGES = {
    "en": "English",
    "hi": "Hindi",
    "ta": "Tamil",
    "te": "Telugu",
    "ml": "Malayalam",
    "kn": "Kannada",
    "bn": "Bengali",
    "mr": "Marathi",
    "gu": "Gujarati",
    "pa": "Punjabi",
    "or": "Odia",
    "hinglish": "Hinglish (Hindi-English)",
    "tanglish": "Tanglish (Tamil-English)"
}

SCRIPT_PATTERNS = [
    (re.compile(r"[\u0900-\u097F]"), "hi"),  # Devanagari (Hindi / Marathi)
    (re.compile(r"[\u0B80-\u0BFF]"), "ta"),  # Tamil
    (re.compile(r"[\u0C00-\u0C7F]"), "te"),  # Telugu
    (re.compile(r"[\u0D00-\u0D7F]"), "ml"),  # Malayalam
    (re.compile(r"[\u0C80-\u0CFF]"), "kn"),  # Kannada
    (re.compile(r"[\u0980-\u09FF]"), "bn"),  # Bengali
    (re.compile(r"[\u0A80-\u0AFF]"), "gu"),  # Gujarati
    (re.compile(r"[\u0A00-\u0A7F]"), "pa"),  # Punjabi
    (re.compile(r"[\u0B00-\u0B7F]"), "or"),  # Odia
]

HINGLISH_KEYWORDS = [
    "kya", "hai", "mujhe", "dar", "lag", "raha", "rahi", "samajh", "bhai", "aaj", "kuch", "kar",
    "hoon", "hun", "ho", "picha", "baat", "mat", "karo", "kaise", "kahan", "kaun", "hoga", "madad",
    "batao", "bataen", "bolo", "chahiye", "gaya", "gayi", "karna", "aaye"
]
TANGLISH_KEYWORDS = [
    "bayam", "irukku", "iruku", "enaku", "enna", "romba", "pannu", "varatam", "illai", "theriyuma",
    "panna", "solla", "paar", "yaaro", "yaroo", "thikra", "thikuranga", "panga", "nan", "naan",
    "venum", "maram", "teriyala", "kitta", "veetula", "veettula", "thookam", "valikudhu", "solnudhu"
]


def detect_language(text: str) -> str:
    """
    Detects language code from input text.
    Handles Indic scripts, English, Hinglish, and Tanglish.
    """
    if not text or not text.strip():
        return "en"

    # Check script ranges
    for pattern, lang in SCRIPT_PATTERNS:
        if pattern.search(text):
            return lang

    lower = text.lower()
    
    # Check Tanglish
    tanglish_matches = sum(1 for kw in TANGLISH_KEYWORDS if re.search(r"\b" + kw + r"\b", lower))
    if tanglish_matches >= 1:
        return "tanglish"

    # Check Hinglish
    hinglish_matches = sum(1 for kw in HINGLISH_KEYWORDS if re.search(r"\b" + kw + r"\b", lower))
    if hinglish_matches >= 1:
        return "hinglish"

    return "en"
