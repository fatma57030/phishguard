"""Step 3: ALL scoring rules live in this one file.

Scoring model (preliminary heuristic, NOT a probability of being malicious):
  * Each check can contribute points at most ONCE (see POINTS below).
  * Overlapping checks are made "not applicable" in url_checks.py (e.g. an IP
    host is not also counted for subdomains), so one problem is not counted twice.
  * Points are added, then capped at MAX_SCORE (100).
  * The score maps to a level using the thresholds below.

To tune the system later, edit POINTS, LOW_MAX or MEDIUM_MAX only.
"""

MAX_SCORE = 100
LOW_MAX = 24        # 0..24   -> Low
MEDIUM_MAX = 54     # 25..54  -> Medium ; 55..100 -> High

# check name -> {severity: points}
POINTS = {
    "https_usage":         {"medium": 20},
    "ip_hostname":         {"high": 30},
    "url_length":          {"low": 5, "medium": 10},
    "subdomain_count":     {"low": 5, "medium": 12},
    "suspicious_patterns": {"low": 8, "medium": 20, "high": 30},
    "misleading_hostname": {"medium": 20, "high": 30},
    "non_default_port":    {"low": 8},
}

GENERAL_RECOMMENDATIONS = [
    "Never enter passwords or payment details because of a link you received "
    "unexpectedly; go to the official website by typing its address yourself.",
    "For a stronger opinion, also check the URL with a dedicated reputation "
    "service (for example Google Safe Browsing or VirusTotal).",
]


def get_risk_level(score: int) -> str:
    """Map a 0-100 score to Low / Medium / High."""
    if score <= LOW_MAX:
        return "Low"
    if score <= MEDIUM_MAX:
        return "Medium"
    return "High"


def points_for(check) -> int:
    """Points one failed check contributes (0 for passed or unknown checks)."""
    if check.passed:
        return 0
    return POINTS.get(check.name, {}).get(check.severity, 0)


def score_checks(checks) -> tuple:
    """Return (score, indicators). Indicators are the failed checks plus points."""
    total = 0
    indicators = []
    for check in checks:
        pts = points_for(check)
        if not check.passed:
            total += pts
            indicators.append({
                "name": check.name,
                "title": check.title,
                "severity": check.severity,
                "points": pts,
                "message": check.message,
                "recommendation": check.recommendation,
            })
    return min(total, MAX_SCORE), indicators


def build_recommendations(indicators) -> list:
    """Per-indicator advice (no duplicates) followed by general advice."""
    recs = []
    for ind in indicators:
        if ind["recommendation"] and ind["recommendation"] not in recs:
            recs.append(ind["recommendation"])
    return recs + GENERAL_RECOMMENDATIONS


def build_summary(score: int, level: str, indicators) -> str:
    if not indicators:
        return ("The implemented checks did not identify suspicious characteristics "
                "in this URL. This does not mean the URL is safe: the checks only "
                "inspect the text of the URL.")
    return (f"Preliminary heuristic estimate: {score}/100 ({level} risk) based on "
            f"{len(indicators)} indicator(s). This is not a verified probability "
            "that the URL is malicious.")
