# AI integration

Set `GEMINI_API_KEY` and optionally `GEMINI_MODEL` in `backend/.env`, then restart the API. The key remains on the backend. Finding explanation and fix suggestion routes send title, category, message, relative path and bounded snippet. Without a key, those routes return HTTP 503 with a configuration message; static scanning remains usable.

Outputs are untrusted recommendations. SkyGuard does not currently parse structured AI output, validate patches, or apply/rollback code. Review generated content manually.
