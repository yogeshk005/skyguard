import httpx
from .config import GEMINI_API_KEY, GEMINI_MODEL
async def ask_gemini(prompt: str) -> str:
    if not GEMINI_API_KEY:
        raise RuntimeError("Gemini is not configured. Add GEMINI_API_KEY to backend/.env and restart.")
    url=f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"
    payload={"contents":[{"parts":[{"text":prompt}]}],"generationConfig":{"temperature":0.2}}
    async with httpx.AsyncClient(timeout=45) as client:
        r=await client.post(url,params={"key":GEMINI_API_KEY},json=payload)
        r.raise_for_status()
        data=r.json()
    return data["candidates"][0]["content"]["parts"][0]["text"]
