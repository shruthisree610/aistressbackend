import os
import logging
from pathlib import Path

from fastapi import FastAPI
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware

import sys
ROOT_DIR = Path(__file__).parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))
load_dotenv(ROOT_DIR / ".env")

from database import connect_db, close_db, get_db, get_client
from routes import router as api_router
from auth import hash_password
from models import make_user

app = FastAPI(title="Nivara API")

_raw_cors = os.environ.get("CORS_ORIGINS", "")
_parsed_cors = [o.strip() for o in _raw_cors.split(",") if o.strip() and o.strip() != "*"]
_explicit_origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "https://aistressfrontend.vercel.app",
]
_cors_origins = list(dict.fromkeys(_parsed_cors + _explicit_origins))

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=_cors_origins,
    allow_origin_regex=r"https://.*\.vercel\.app",
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("nivara")


@app.on_event("startup")
async def on_startup():
    await connect_db()
    db = get_db()

    env = os.environ.get("ENVIRONMENT", "development").lower()

    # In production, validate critical secrets and fail safely if missing or insecure
    if env == "production":
        jwt_sec = os.environ.get("JWT_SECRET", "").strip()
        if not jwt_sec or jwt_sec in ["change-me", "secret", "default", "dev-secret", "nivara-secret"]:
            logger.critical("PRODUCTION STARTUP FAILED: Insecure or default JWT_SECRET configured.")
            raise RuntimeError("CRITICAL: Insecure or default JWT_SECRET configured in production environment.")
        
        # Verify encryption key is valid
        import security_crypto
        try:
            security_crypto.get_encryption_key()
        except security_crypto.EncryptionConfigError as e:
            logger.critical(f"PRODUCTION STARTUP FAILED: Encryption key error: {e}")
            raise RuntimeError(f"CRITICAL: DATA_ENCRYPTION_KEY missing or invalid in production: {e}")

    # Guard demo account seeding: never seed demo accounts with Password123 in production
    allow_seed = os.environ.get("SEED_DEMO_USERS", "true" if env != "production" else "false").lower() == "true"
    if allow_seed and env != "production":
        seeds = [
            ("victim@nivara.app",    "Aarti Sharma",             "victim",     "Password123", None,    None,    None),
            ("officer@nivara.app",   "Officer Ravi (Central)",   "officer",    "Password123", 12.9716, 77.5946, "Central Metro Sector"),
            ("officer2@nivara.app",  "Officer Suresh (North)",   "officer",    "Password123", 12.9910, 77.6100, "North City Sector"),
            ("officer3@nivara.app",  "Officer Anita (South)",    "officer",    "Password123", 12.9350, 77.5800, "South Suburbs Sector"),
            ("counsellor@nivara.app","Dr. Priya",                "counsellor", "Password123", None,    None,    None),
        ]

        for email, name, role, pw, lat, lng, duty in seeds:
            exists = await db.users.find_one({"email": email})
            if not exists:
                user_doc = make_user(
                    email=email, name=name, password_hash=hash_password(pw),
                    role=role, language="en", latitude=lat, longitude=lng, duty_area=duty
                )
                await db.users.insert_one(user_doc)
    else:
        logger.info("Demo user seeding skipped (production environment or SEED_DEMO_USERS=false)")

    logger.info("Nivara startup complete (MongoDB)")


@app.on_event("shutdown")
async def on_shutdown():
    await close_db()


@app.get("/api/health")
@app.get("/health", include_in_schema=False)
async def health():
    db = get_db()
    client = get_client()
    db_status = "connected"
    ping_ok = False
    try:
        if client:
            pong = await client.admin.command("ping")
            ping_ok = pong.get("ok") == 1.0
        else:
            db_status = "disconnected"
    except Exception as e:
        db_status = f"error: {str(e)}"
    return {
        "status": "ok",
        "database": {
            "status": db_status if ping_ok else "unreachable",
            "name": getattr(db, "name", None) if db is not None else None,
            "ping": ping_ok,
        }
    }
