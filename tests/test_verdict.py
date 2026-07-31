from app.scoring.verdict import compute_verdict, verdict_for


def _categories_with_score(score):
    return {key: {"score": score, "notes": []} for key in [
        "url", "brand", "redirect", "content", "ai",
        "network", "downloads", "domain", "behavior",
    ]}


def test_verdict_for_thresholds():
    assert verdict_for(2.0) == "SAFE"
    assert verdict_for(4.0) == "SUSPICIOUS"
    assert verdict_for(6.0) == "HIGH_RISK"
    assert verdict_for(8.0) == "MALICIOUS"


def test_all_zero_is_safe():
    result = compute_verdict(_categories_with_score(0.0))
    assert result["verdict"] == "SAFE"
    assert result["overallScore"] == 0.0


def test_all_ten_is_malicious():
    result = compute_verdict(_categories_with_score(10.0))
    assert result["verdict"] == "MALICIOUS"
    assert result["overallScore"] == 10.0


def test_breakdown_is_sorted_and_weighted():
    categories = _categories_with_score(0.0)
    categories["url"] = {"score": 10.0, "notes": ["raw ip"]}
    categories["downloads"] = {"score": 10.0, "notes": ["yara match"]}
    result = compute_verdict(categories)

    assert result["breakdown"][0]["key"] in ("url", "downloads")
    assert result["breakdown"][0]["contribution"] == round(
        result["breakdown"][0]["score"] * result["breakdown"][0]["weight"], 2
    )
    assert any("raw ip" in r["text"] for r in result["reasons"])


def test_ai_disabled_folds_weight():
    categories = _categories_with_score(5.0)
    with_ai = compute_verdict(categories)
    without_ai = compute_verdict(categories, ai_disabled=True)
    # With AI removed, the "ai" category isn't present in the breakdown.
    keys_with = {b["key"] for b in with_ai["breakdown"]}
    keys_without = {b["key"] for b in without_ai["breakdown"]}
    assert "ai" in keys_with
    assert "ai" not in keys_without


def test_scores_are_clamped():
    categories = _categories_with_score(99.0)
    result = compute_verdict(categories)
    assert result["overallScore"] == 10.0
