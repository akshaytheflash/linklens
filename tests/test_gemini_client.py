from app.ai.gemini_client import GeminiClient


def test_disabled_client_returns_neutral():
    client = GeminiClient(api_key=None)
    assert client.enabled is False
    link = client.evaluate_link("https://example.com", "https://example.com", "Hi")
    assert link["riskScore"] == 0.0
    assert "disabled" in link["summary"].lower()


def test_normalize_handles_missing_fields():
    client = GeminiClient(api_key="fake")
    normalized = client._normalize(None, "fallback reason")
    assert normalized["riskScore"] == 0.0
    assert normalized["summary"] == "fallback reason"
    assert normalized["reasons"] == []


def test_normalize_parses_risk_score():
    client = GeminiClient(api_key="fake")
    normalized = client._normalize(
        {"risk_score": 7.5, "summary": "Looks phishy", "reasons": ["brand impersonation"]},
        "fallback",
    )
    assert normalized["riskScore"] == 7.5
    assert normalized["summary"] == "Looks phishy"
    assert normalized["reasons"] == ["brand impersonation"]


def test_normalize_clamps_out_of_range_score():
    client = GeminiClient(api_key="fake")
    normalized = client._normalize({"risk_score": 42}, "fallback")
    assert normalized["riskScore"] == 10.0


def test_normalize_falls_back_to_number_in_text():
    client = GeminiClient(api_key="fake")
    normalized = client._normalize({"answer": "The risk score is 6.2 out of ten"}, "fallback")
    assert normalized["riskScore"] == 6.2
