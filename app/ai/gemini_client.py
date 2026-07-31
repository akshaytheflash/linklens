import json
import re
from typing import Any, Dict, List, Optional

try:
    from google import genai
    from google.genai import types
except Exception:  # pragma: no cover
    genai = None
    types = None


class GeminiClient:
    """Thin wrapper around the Gemini API that asks for JSON back so the
    risk scores parse cleanly instead of guessing numbers from prose."""

    def __init__(self, api_key: Optional[str], model: str = "gemini-flash-latest") -> None:
        self.model = model
        self._client = None
        if api_key and genai is not None:
            try:
                self._client = genai.Client(api_key=api_key)
            except Exception:
                self._client = None

    @property
    def enabled(self) -> bool:
        return self._client is not None

    def _neutral(self, reason: str) -> Dict[str, Any]:
        return {"riskScore": 0.0, "summary": reason, "reasons": []}

    def _complete_json(self, prompt: str) -> Optional[Dict[str, Any]]:
        if not self._client:
            return None
        try:
            config = types.GenerateContentConfig(response_mime_type="application/json") if types else None
            response = self._client.models.generate_content(model=self.model, contents=prompt, config=config)
            text = getattr(response, "text", None) or ""
            start = text.find("{")
            end = text.rfind("}")
            if start != -1 and end > start:
                return json.loads(text[start : end + 1])
        except Exception:
            return None
        return None

    def _normalize(
        self,
        payload: Optional[Dict[str, Any]],
        default_reason: str,
        reason_key: str = "reason",
    ) -> Dict[str, Any]:
        if not payload:
            return self._neutral(default_reason)

        # The model is prompted to use risk_score, but older responses may
        # use riskScore or just prose. Be tolerant either way.
        score = payload.get("risk_score", payload.get("riskScore"))
        if score is None:
            score = 0.0
            for token in str(payload).split():
                try:
                    val = float(token.strip(".,"))
                    if 0.0 <= val <= 10.0:
                        score = val
                        break
                except Exception:
                    continue

        summary = payload.get("summary") or payload.get(reason_key) or default_reason
        reasons = payload.get("reasons") or []
        if not isinstance(reasons, list):
            reasons = [str(reasons)]

        return {
            "riskScore": max(0.0, min(10.0, float(score))),
            "summary": str(summary)[:500],
            "reasons": [str(r)[:200] for r in reasons][:5],
        }

    def evaluate_link(self, original_url: str, final_url: str, title: str) -> Dict[str, Any]:
        if not self._client:
            return self._neutral("AI disabled (no API key configured)")
        prompt = (
            "You are a security analyst. A user clicked a link. Original URL: "
            + original_url[:500]
            + "\nIt redirected to: "
            + final_url[:500]
            + "\nPage title: "
            + (title or "")[:200]
            + "\n\nAssess the URL for phishing: typosquatting, suspicious keywords, odd "
            "subdomains, punycode, URL shorteners, unexpected redirects.\n"
            'Respond ONLY with JSON: {"risk_score": <0-10>, "summary": "<one short sentence>", '
            '"reasons": ["<why>", ...]}'
        )
        return self._normalize(self._complete_json(prompt), "Could not assess link with AI.")

    def evaluate_content(self, snippet: str) -> Dict[str, Any]:
        if not self._client:
            return self._neutral("AI disabled (no API key configured)")
        if not snippet or not snippet.strip():
            return self._neutral("No page text to analyze.")
        prompt = (
            "You are a security analyst. Below is the visible text of a webpage a user visited.\n"
            "---\n"
            + snippet[:1200]
            + "\n---\nDoes it use urgent language, demand immediate action, impersonate a "
            "known brand, or ask for personal details? Ignore generic marketing.\n"
            'Respond ONLY with JSON: {"risk_score": <0-10>, "summary": "<one short sentence>", '
            '"reasons": ["<why>", ...]}'
        )
        return self._normalize(self._complete_json(prompt), "Could not assess content with AI.")

    def evaluate_popups(self, texts: List[str]) -> Dict[str, Any]:
        if not self._client:
            return self._neutral("AI disabled (no API key configured)")
        joined = "\n".join([t for t in texts if t][:600])
        if not joined:
            return self._neutral("No popup or dialog text to analyze.")
        prompt = (
            "You are a security analyst. These are popups/dialogs shown by a webpage:\n"
            "---\n"
            + joined
            + "\n---\nAre they social-engineering or scammy (fake virus alerts, prize wins, "
            "fake updates, urgent 'call this number' scams)?\n"
            'Respond ONLY with JSON: {"risk_score": <0-10>, "summary": "<one short sentence>", '
            '"reasons": ["<why>", ...]}'
        )
        return self._normalize(self._complete_json(prompt), "Could not assess popups with AI.")
