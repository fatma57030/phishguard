"""Step 2: individual, independent URL checks.

Every check takes a ParsedURL and returns a CheckResult with the same fields:
  name, title, passed, severity ("none"/"low"/"medium"/"high"),
  message, limitation, recommendation.

IMPORTANT: no check proves that a URL is malicious. They are weak hints, and
each check documents its own limitation. Nothing here touches the network.
"""
import re
from dataclasses import asdict, dataclass

from .url_validator import ParsedURL

# ---- tunable constants (easy to change) -----------------------------------
URL_LENGTH_LOW = 100        # longer than this  -> "low" severity
URL_LENGTH_MEDIUM = 200     # longer than this  -> "medium" severity
SUBDOMAINS_LOW = 3          # this many subdomains -> "low"
SUBDOMAINS_MEDIUM = 4       # this many or more    -> "medium"
LONG_HOSTNAME = 60          # hostname characters considered unusually long

# Small, hand-written list of two-part public suffixes (e.g. example.co.uk).
# The real answer is the Public Suffix List; we avoid that dependency on purpose.
TWO_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.nz", "co.jp", "co.in", "com.br", "com.eg", "edu.eg", "gov.eg",
    "org.eg", "com.sa", "com.tr", "co.za",
}
# Labels that look like a TLD but are used as a decoy in a subdomain,
# e.g. paypal.com.attacker.example
DECOY_LABELS = {"com", "net", "org", "edu", "gov", "info"}

SEVERITY_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}


@dataclass
class CheckResult:
    name: str
    title: str
    passed: bool
    severity: str
    message: str
    limitation: str
    recommendation: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _pass(name, title, message, limitation) -> CheckResult:
    return CheckResult(name, title, True, "none", message, limitation, "")


def _fail(name, title, severity, message, limitation, recommendation) -> CheckResult:
    return CheckResult(name, title, False, severity, message, limitation, recommendation)


def _subdomain_labels(host: str) -> list:
    """Labels left of the 'registered domain' (naive: last 1 or 2 labels)."""
    labels = host.split(".")
    suffix_len = 2 if ".".join(labels[-2:]) in TWO_PART_SUFFIXES else 1
    return labels[: max(len(labels) - suffix_len - 1, 0)]


# ---------------------------------------------------------------------------
def check_https_usage(p: ParsedURL) -> CheckResult:
    """Does the URL ask for an encrypted (HTTPS) connection?"""
    limitation = (
        "The server is never contacted, so the TLS certificate is NOT validated. "
        "HTTPS only means the connection would be encrypted; many phishing sites use it too."
    )
    if p.scheme == "https":
        return _pass("https_usage", "HTTPS usage",
                     "The URL uses HTTPS.", limitation)
    return _fail(
        "https_usage", "HTTPS usage", "medium",
        "The URL uses plain HTTP, so data sent to the site would not be encrypted.",
        limitation,
        "Prefer the https:// version of the site and never enter passwords or "
        "personal data on a page loaded over HTTP.",
    )


def check_ip_hostname(p: ParsedURL) -> CheckResult:
    """Is the host a raw IP address instead of a domain name?"""
    limitation = ("Routers, internal tools and test servers legitimately use IP "
                  "addresses. This is a hint, not proof.")
    if not p.is_ip:
        return _pass("ip_hostname", "IP address as hostname",
                     "The hostname is a domain name, not an IP address.", limitation)
    return _fail(
        "ip_hostname", "IP address as hostname", "high",
        f"The URL uses the IP address {p.host} instead of a domain name. "
        "Legitimate public websites rarely do this.",
        limitation,
        "Be cautious with links that use a bare IP address. Open the service "
        "through its official domain name instead.",
    )


def check_url_length(p: ParsedURL) -> CheckResult:
    """Is the (normalized) URL unusually long?"""
    length = len(p.normalized)
    limitation = ("Long URLs are common for legitimate tracking and search links. "
                  "Length is only a weak signal.")
    if length <= URL_LENGTH_LOW:
        return _pass("url_length", "URL length",
                     f"The URL length ({length} characters) is not unusual.", limitation)
    severity = "medium" if length > URL_LENGTH_MEDIUM else "low"
    return _fail(
        "url_length", "URL length", severity,
        f"The URL is {length} characters long, which is longer than usual. "
        "Long URLs can hide the real destination.",
        limitation,
        "Check the beginning of the address (the domain) carefully rather than "
        "the long part at the end.",
    )


def check_subdomain_count(p: ParsedURL) -> CheckResult:
    """Count subdomains with a simple heuristic.

    Heuristic: registered domain = last 2 labels (or last 3 for a few known
    suffixes such as .co.uk). Everything to the left is a subdomain. A leading
    'www' is not counted.
    """
    limitation = ("Uses a short hand-written suffix list, not the full Public "
                  "Suffix List, so counts can be off for unusual domains. "
                  "Many legitimate sites use several subdomains.")
    title = "Number of subdomains"
    if p.is_ip:
        return _pass("subdomain_count", title,
                     "Not applicable: the host is an IP address.", limitation)
    subs = _subdomain_labels(p.host)
    if subs and subs[0] == "www":
        subs = subs[1:]
    count = len(subs)
    if count < SUBDOMAINS_LOW:
        return _pass("subdomain_count", title,
                     f"The hostname has {count} subdomain(s), which is normal.", limitation)
    severity = "medium" if count >= SUBDOMAINS_MEDIUM else "low"
    return _fail(
        "subdomain_count", title, severity,
        f"The hostname has {count} subdomains. Attackers sometimes stack "
        "subdomains to make a hostname look familiar.",
        limitation,
        "Read the hostname from right to left: the part just before the "
        "final suffix (e.g. .com) is the real domain.",
    )


def check_suspicious_patterns(p: ParsedURL) -> CheckResult:
    """Look for suspicious text patterns after the hostname (one combined check)."""
    limitation = ("Encoded characters and embedded URLs are common in legitimate "
                  "redirects and APIs. These patterns are hints only.")
    title = "Suspicious URL patterns"
    findings = []   # (severity, text)
    rest = p.path + ("?" + p.query if p.query else "") + ("#" + p.fragment if p.fragment else "")
    lowered = rest.lower()

    if "@" in rest:
        findings.append(("medium", "an '@' character appears after the hostname "
                         "(it can be used to mislead readers about the real destination)"))
    if "%40" in lowered:
        findings.append(("medium", "an encoded '@' (%40) is present"))
    if re.search(r"%(00|0a|0d|5c)", lowered):
        findings.append(("medium", "encoded control characters or backslashes are present"))
    if re.search(r"%25[0-9a-f]{2}", lowered):
        findings.append(("medium", "double percent-encoding (e.g. %252F) is present"))
    if re.search(r"%(2f|2e)", p.path.lower()):
        findings.append(("low", "encoded slashes or dots are present in the path"))
    if re.search(r"https?(://|%3a%2f%2f)", lowered):
        findings.append(("low", "another URL is embedded in the path or query "
                         "(common in redirect links)"))
    if len(p.host) > LONG_HOSTNAME:
        findings.append(("low", f"the hostname is unusually long ({len(p.host)} characters)"))

    if not findings:
        return _pass("suspicious_patterns", title,
                     "No suspicious patterns were found in the URL text.", limitation)
    severity = max((s for s, _ in findings), key=lambda s: SEVERITY_ORDER[s])
    message = "Suspicious pattern(s) found: " + "; ".join(t for _, t in findings) + "."
    return _fail("suspicious_patterns", title, severity, message, limitation,
                 "Do not click links that hide their destination. Type the "
                 "official address yourself or use a bookmark.")


def check_misleading_hostname(p: ParsedURL) -> CheckResult:
    """Look for hostname formats that can mislead a human reader."""
    limitation = ("Internationalized domains are used legitimately all over the "
                  "world, and this check does not compare against a brand list, "
                  "so look-alike spellings (e.g. 'paypa1') are NOT detected.")
    title = "Potentially misleading hostname"
    if p.is_ip:
        return _pass("misleading_hostname", title,
                     "Not applicable: the host is an IP address.", limitation)
    findings = []
    if p.is_idn:
        findings.append(f"the hostname uses internationalized characters "
                        f"(punycode form: {p.host}), which can imitate familiar names")
    decoys = [l for l in _subdomain_labels(p.host) if l in DECOY_LABELS]
    if decoys:
        findings.append(f"the subdomain part contains the label '{decoys[0]}', which "
                        "can make the hostname look like a different domain")
    if not findings:
        return _pass("misleading_hostname", title,
                     "No misleading hostname format was detected.", limitation)
    return _fail("misleading_hostname", title, "medium",
                 "Possible misleading hostname: " + "; ".join(findings) + ".",
                 limitation,
                 "Confirm the exact domain name before trusting the site; compare "
                 "it character by character with the official one.")


def check_non_default_port(p: ParsedURL) -> CheckResult:
    """Does the URL use a port other than 80 (http) / 443 (https)?"""
    limitation = "Development servers and some admin tools legitimately use other ports."
    title = "Non-default port"
    if p.port is None:
        return _pass("non_default_port", title,
                     "The URL uses the default port for its protocol.", limitation)
    return _fail("non_default_port", title, "low",
                 f"The URL uses a non-default port ({p.port}).",
                 limitation,
                 "Public websites normally do not need a custom port. Make sure "
                 "you expect this service before continuing.")


ALL_CHECKS = (
    check_https_usage,
    check_ip_hostname,
    check_url_length,
    check_subdomain_count,
    check_suspicious_patterns,
    check_misleading_hostname,
    check_non_default_port,
)


def run_all_checks(p: ParsedURL) -> list:
    """Run every check and return a list of CheckResult."""
    return [check(p) for check in ALL_CHECKS]
