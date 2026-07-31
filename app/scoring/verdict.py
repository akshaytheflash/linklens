from typing import Any, Dict, List

# Category metadata: label + weight (fraction of the overall score).
# Weights sum to 1.0. Kept in one place so tweaking the model is trivial.
CATEGORY_DEFS: Dict[str, Dict[str, Any]] = {
    "url": {"label": "URL Structure", "weight": 0.14},
    "brand": {"label": "Brand Impersonation", "weight": 0.12},
    "redirect": {"label": "Redirects", "weight": 0.08},
    "content": {"label": "Page Content", "weight": 0.12},
    "ai": {"label": "AI Review", "weight": 0.16},
    "network": {"label": "Network Activity", "weight": 0.10},
    "downloads": {"label": "Downloads / YARA", "weight": 0.12},
    "domain": {"label": "Domain Trust", "weight": 0.10},
    "behavior": {"label": "Behavioral Flags", "weight": 0.06},
}

VERDICT_THRESHOLDS = [
    (7.5, "MALICIOUS"),
    (5.0, "HIGH_RISK"),
    (3.0, "SUSPICIOUS"),
]


def _clamp(score: float) -> float:
    return max(0.0, min(10.0, score))


def verdict_for(score: float) -> str:
    for threshold, verdict in VERDICT_THRESHOLDS:
        if score >= threshold:
            return verdict
    return "SAFE"


def compute_verdict(categories: Dict[str, Dict[str, Any]], *, ai_disabled: bool = False) -> Dict[str, Any]:
    """Combine per-category scores into an overall verdict.

    categories maps a key (e.g. "url") to {"score": 0-10, "notes": [str]}.
    Returns the overall score, a verdict label, a per-category breakdown
    (useful for the UI bars) and a flattened list of the loudest signals.
    """
    weights = {k: v["weight"] for k, v in CATEGORY_DEFS.items()}

    # If the AI key isn't set we can't score "ai" fairly, so fold its weight
    # into URL + content instead of silently counting a 0.
    if ai_disabled:
        freed = weights.pop("ai", 0.0)
        weights["url"] = weights.get("url", 0.0) + freed / 2
        weights["content"] = weights.get("content", 0.0) + freed / 2

    total = 0.0
    weight_sum = 0.0
    breakdown = []
    for key, cat in categories.items():
        if key not in weights:
            continue
        score = _clamp(float(cat.get("score", 0.0)))
        weight = weights[key]
        total += score * weight
        weight_sum += weight
        breakdown.append({
            "key": key,
            "label": CATEGORY_DEFS[key]["label"],
            "score": round(score, 2),
            "weight": round(weight, 3),
            "contribution": round(score * weight, 2),
            "notes": cat.get("notes", []),
        })

    overall = (total / weight_sum) if weight_sum else 0.0
    breakdown.sort(key=lambda b: b["contribution"], reverse=True)

    reasons = []
    for item in breakdown:
        for note in item["notes"]:
            reasons.append({"category": item["label"], "text": note})

    return {
        "overallScore": round(overall, 2),
        "verdict": verdict_for(overall),
        "breakdown": breakdown,
        "reasons": reasons,
    }
