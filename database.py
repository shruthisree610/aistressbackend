import os
import logging
from pathlib import Path
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient

logger = logging.getLogger("nivara.database")

ROOT_DIR = Path(__file__).resolve().parent
load_dotenv(ROOT_DIR / ".env")

MONGO_URL = os.environ.get("MONGO_URL") or os.environ.get("MONGODB_URI") or "mongodb://127.0.0.1:27017"
DB_NAME = os.environ.get("DB_NAME", "nivara")

client: AsyncIOMotorClient = None
db = None


def get_client() -> AsyncIOMotorClient:
    return client


def get_db():
    return db


async def connect_db():
    global client, db
    url = os.environ.get("MONGO_URL") or os.environ.get("MONGODB_URI") or MONGO_URL
    name = os.environ.get("DB_NAME") or DB_NAME
    client = AsyncIOMotorClient(url)
    db = client[name]
    # Verify live connectivity using MongoDB ping
    await client.admin.command("ping")
    logger.info(f"MongoDB connected successfully to {url} [database: {name}]")
    # Create indexes
    await db.users.create_index("email", unique=True)
    await db.cases.create_index("victim_id")
    await db.cases.create_index("officer_id")
    await db.cases.create_index("counsellor_id")
    await db.interactions.create_index("case_id")
    await db.notifications.create_index("user_id")
    await db.audit_logs.create_index("user_id")
    await db.voice_analysis.create_index("case_id")
    await db.stress_assessment.create_index("case_id")
    await db.intervention_recommendation.create_index("case_id")
    await db.consents.create_index([("user_id", 1), ("kind", 1)])
    await db.followups.create_index("case_id")
    await db.counsellor_notes.create_index("case_id")
    await db.officer_actions.create_index("case_id")


async def close_db():
    global client
    if client:
        client.close()
