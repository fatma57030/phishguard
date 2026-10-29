import pytest

from analyzer import risk_scoring
from analyzer.scanner import scan_url
from analyzer.url_checks import (CheckResult, check_https_usage, check_ip_hostname,
                                 check_misleading_hostname, check_non_default_port,
                                 check_subdomain_count, check_suspicious_patterns,
                                 check_url_length)
from analyzer.url_validator import validate_url


def P(url):
    return validate_url(url)


def test_https_check():
    assert check_https_usage(P("https://example.com")).passed
    result = check_https_usage(P("http://example.com"))
    assert not result.passed and result.severity == "medium"
    assert "not validated" in result.limitation.lower()


def test_ip_check():
    assert check_ip_hostname(P("https://example.com")).passed
    result = check_ip_hostname(P("http://203.0.113.9/"))
    assert not result.passed and result.severity == "high"


def test_long_url_check():
    assert check_url_length(P("https://example.com/short")).passed
    assert check_url_length(P("https://example.com/" + "a" * 120)).severity == "low"
    assert check_url_length(P("https://example.com/" + "a" * 250)).severity == "medium"


@pytest.mark.parametrize("url,passed", [
    ("https://example.com", True),
    ("https://www.example.com", True),
    ("https://a.b.example.com", True),          # 2 subdomains is normal
    ("https://a.b.c.example.com", False),       # 3 -> low
    ("https://a.b.c.d.example.com", False),     # 4 -> medium
    ("https://a.b.example.co.uk", True),        # .co.uk counted as one suffix
])
def test_subdomain_check(url, passed):
    assert check_subdomain_count(P(url)).passed is passed


def test_subdomain_severity_levels():
    assert check_subdomain_count(P("https://a.b.c.example.com")).severity == "low"
    assert check_subdomain_count(P("https://a.b.c.d.example.com")).severity == "medium"


def test_hyphens_and_digits_are_not_suspicious_by_themselves():
    for url in ("https://my-shop-2024.example.com", "https://web3-news.org/a-b-c"):
        assert scan_url(url)["risk_score"] == 0


@pytest.mark.parametrize("url", [
    "https://example.com/login@evil.test",
    "https://example.com/a%40b",
    "https://example.com/a%252Fb",
    "https://example.com/a%00b",
    "https://example.com/a%2fb",
    "https://example.com/go?next=https://other.test",
])
def test_suspicious_patterns_detected(url):
    assert not check_suspicious_patterns(P(url)).passed


def test_plain_url_has_no_suspicious_patterns():
    assert check_suspicious_patterns(P("https://example.com/path/page.html?id=7")).passed


def test_misleading_hostname_checks():
    assert not check_misleading_hostname(P("https://paypal.com.attacker.example")).passed
    assert not check_misleading_hostname(P("https://bücher.example")).passed
    assert check_misleading_hostname(P("https://example.com")).passed
    assert check_misleading_hostname(P("https://www.example.com.eg")).passed


def test_non_default_port_check():
    assert check_non_default_port(P("https://example.com")).passed
    assert check_non_default_port(P("https://example.com:443")).passed
    assert not check_non_default_port(P("https://example.com:8443")).passed


# ---- scoring ---------------------------------------------------------------
@pytest.mark.parametrize("score,level", [
    (0, "Low"), (risk_scoring.LOW_MAX, "Low"),
    (risk_scoring.LOW_MAX + 1, "Medium"), (risk_scoring.MEDIUM_MAX, "Medium"),
    (risk_scoring.MEDIUM_MAX + 1, "High"), (100, "High"),
])
def test_risk_level_boundaries(score, level):
    assert risk_scoring.get_risk_level(score) == level


def test_score_is_capped_at_100():
    fake = [CheckResult(n, n, False, "high", "m", "l", "r") for n in ("ip_hostname",) * 1]
    many = [CheckResult("suspicious_patterns", "t", False, "high", "m", "l", "r")] * 10
    score, _ = risk_scoring.score_checks(fake + many)
    assert score == 100


def test_clean_url_scores_zero_with_honest_summary():
    report = scan_url("https://example.com")
    assert report["risk_score"] == 0 and report["risk_level"] == "Low"
    assert report["indicators"] == []
    assert "did not identify suspicious characteristics" in report["summary"]
    assert "safe" in report["summary"].lower() and "does not mean" in report["summary"]


def test_http_only_scores_20_low():
    report = scan_url("http://example.com")
    assert report["risk_score"] == 20 and report["risk_level"] == "Low"


def test_ip_host_is_not_double_counted():
    report = scan_url("https://203.0.113.9/")
    names = [i["name"] for i in report["indicators"]]
    assert names == ["ip_hostname"]
    assert report["risk_score"] == risk_scoring.POINTS["ip_hostname"]["high"]


def test_risky_url_reaches_high():
    report = scan_url("http://203.0.113.9:8080/login@x.test")
    assert report["risk_level"] == "High"
    assert report["risk_score"] >= risk_scoring.MEDIUM_MAX + 1


def test_every_indicator_has_explanation_and_recommendation():
    report = scan_url("http://paypal.com.evil.example:8080/a%40b")
    assert report["indicators"]
    for ind in report["indicators"]:
        assert ind["message"] and ind["recommendation"] and ind["points"] > 0
    assert len(report["recommendations"]) == len(set(report["recommendations"]))
