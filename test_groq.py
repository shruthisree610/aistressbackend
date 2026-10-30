import asyncio
import os
import pytest
from dotenv import load_dotenv
from groq import AsyncGroq

load_dotenv()

key = os.environ.get("GROQ_API_KEY")

client = AsyncGroq(api_key=key)

@pytest.mark.asyncio
async def test():
    try:
        res = await client.chat.completions.create(
            model="qwen/qwen3.8-27b",
            messages=[{"role": "user", "content": "Hello!"}]
        )
        assert res.choices[0].message.content
    except Exception as e:
        print("Chat Error:", e)

