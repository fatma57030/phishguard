"""Orchestrator: validate -> run checks -> score -> build the JSON report."""
from .risk_scoring import build_recommendations, build_summary, get_risk_level, score_checks
from .url_checks import run_all_checks
from .url_validator import validate_url

LIMITATIONS = [
    "The URL is analysed as text only. The website was never visited, so its "
    "content, redirects and downloads were not inspected.",
    "The TLS/SSL certificate was not validated because the server is never contacted.",
    "The checks are simple heuristics. They do not use blocklists, domain age, "
    "reputation data or machine learning.",
    "Look-alike spellings of brand names (e.g. 'paypa1.com') are not detected.",
    "A low score does not mean a URL is safe, and a high score does not prove it is malicious.",
]


def scan_url(raw_url) -> dict:
    """Analyse one URL string. Raises ValidationError for invalid input."""
    parsed = validate_url(raw_url)
    checks = run_all_checks(parsed)
    score, indicators = score_checks(checks)
    level = get_risk_level(score)
    return {
        "success": True,
        "url": parsed.original,
        "normalized_url": parsed.normalized,
        "risk_score": score,
        "risk_level": level,
        "summary": build_summary(score, level, indicators),
        "indicators": indicators,
        "recommendations": build_recommendations(indicators),
        "checks": [c.to_dict() for c in checks],
        "limitations": LIMITATIONS,
        "parsed": {
            "scheme": parsed.scheme,
            "hostname": parsed.host,
            "is_ip_address": parsed.is_ip,
            "port": parsed.port,
            "path": parsed.path,
        },
    }
