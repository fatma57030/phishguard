import pytest

from analyzer.url_validator import MAX_URL_LENGTH, ValidationError, validate_url


def test_valid_https_url():
    p = validate_url("https://example.com")
    assert p.scheme == "https" and p.host == "example.com"
    assert p.normalized == "https://example.com"
    assert p.is_ip is False


def test_valid_http_url():
    p = validate_url("http://example.com/path?x=1")
    assert p.scheme == "http"
    assert p.path == "/path" and p.query == "x=1"


def test_normalization_lowercases_scheme_and_host_only():
    assert validate_url("HTTPS://Example.COM/CaseSensitive").normalized == "https://example.com/CaseSensitive"


def test_default_port_dropped_and_custom_port_kept():
    assert validate_url("https://example.com:443/").normalized == "https://example.com/"
    p = validate_url("http://example.com:8080/")
    assert p.port == 8080 and p.normalized == "http://example.com:8080/"


def test_surrounding_whitespace_is_trimmed():
    assert validate_url("  https://example.com  ").original == "https://example.com"


def test_ipv4_and_ipv6_hosts():
    p4 = validate_url("http://192.168.1.1/login")
    assert p4.is_ip and p4.ip_version == 4
    p6 = validate_url("https://[2001:db8::1]/")
    assert p6.is_ip and p6.ip_version == 6 and "[2001:db8::1]" in p6.normalized


def test_internationalized_hostname_becomes_punycode():
    p = validate_url("https://bücher.example")
    assert p.host == "xn--bcher-kva.example" and p.is_idn


@pytest.mark.parametrize("value,code", [
    ("", "empty_url"),
    ("    ", "empty_url"),
    (123, "invalid_url_type"),
    (None, "invalid_url_type"),
    ("example.com", "missing_scheme"),
    ("ftp://example.com", "unsupported_scheme"),
    ("javascript:alert(1)", "unsupported_scheme"),
    ("file:///etc/passwd", "unsupported_scheme"),
    ("https:example.com", "malformed_url"),
    ("https://", "malformed_url"),
    ("https:///path", "malformed_url"),
    ("https://[::1", "malformed_url"),
    ("https://[example.com]/", "malformed_url"),
    ("https://user:pass@example.com", "credentials_not_allowed"),
    ("https://user@example.com", "credentials_not_allowed"),
    ("https://exa_mple.com", "invalid_hostname"),
    ("https://-bad.com", "invalid_hostname"),
    ("https://a..b.com", "invalid_hostname"),
    ("https://" + "a" * 64 + ".com", "invalid_hostname"),
    ("https://2130706433/", "invalid_hostname"),
    ("https://999.999.999.999", "invalid_hostname"),
    ("https://example.com:99999", "invalid_port"),
    ("https://example.com:abc", "invalid_port"),
    ("https://example.com:0", "invalid_port"),
    ("http://exa mple.com", "invalid_characters"),
    ("https://example.com\\evil", "invalid_characters"),
    ("https://example.com/\x00", "invalid_characters"),
    ("https://example.com/" + "a" * (MAX_URL_LENGTH + 1), "url_too_long"),
])
def test_invalid_inputs_are_rejected(value, code):
    with pytest.raises(ValidationError) as info:
        validate_url(value)
    assert info.value.code == code
