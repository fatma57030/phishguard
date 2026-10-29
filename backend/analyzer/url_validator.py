"""Step 1 of the pipeline: strict URL validation and careful normalization.

This module only looks at the *text* of the URL. It never connects to it.

Normalization rules (each one keeps the destination identical):
  * scheme and hostname are lower-cased,
  * internationalized hostnames are converted to ASCII (punycode),
  * a port equal to the scheme default (80 / 443) is dropped,
  * a single trailing dot on the hostname is dropped,
  * the path, query and fragment are left untouched.
Anything we are not sure about is rejected instead of "fixed".
"""
import ipaddress
import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

MAX_URL_LENGTH = 2048
ALLOWED_SCHEMES = ("http", "https")
DEFAULT_PORTS = {"http": 80, "https": 443}

_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
# whitespace, control characters and backslashes are never valid in a URL
_FORBIDDEN_CHARS_RE = re.compile(r"[\s\x00-\x1f\x7f\\]")
_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*):")


class ValidationError(Exception):
    """Raised for bad input. `code` is machine-readable, `message` is for humans."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class ParsedURL:
    """A validated URL broken into the parts the checks need."""

    original: str          # what the user sent (whitespace-trimmed)
    normalized: str        # safe, canonical form
    scheme: str            # "http" or "https"
    host: str              # ASCII hostname (punycode) or IP, no brackets
    unicode_host: str      # human-readable hostname (decoded punycode)
    is_ip: bool
    ip_version: Optional[int]
    port: Optional[int]    # only set when it is NOT the scheme default
    path: str
    query: str
    fragment: str

    @property
    def is_idn(self) -> bool:
        """True if any hostname label is punycode (xn--...)."""
        return any(label.startswith("xn--") for label in self.host.split("."))


def _try_ip(host: str):
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _validate_hostname(host: str) -> str:
    """Return the ASCII form of a domain name or raise ValidationError."""
    if host.endswith("."):
        host = host[:-1]
    if not host:
        raise ValidationError("invalid_hostname", "The URL has no hostname.")
    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValidationError("invalid_hostname", "The hostname is not valid.")
    if len(ascii_host) > 253:
        raise ValidationError("invalid_hostname", "The hostname is too long.")
    labels = ascii_host.split(".")
    for label in labels:
        if not _LABEL_RE.match(label):
            raise ValidationError(
                "invalid_hostname",
                "The hostname contains an invalid part. Use only letters, digits "
                "and hyphens, with no empty parts.",
            )
    if labels[-1].isdigit():
        raise ValidationError(
            "invalid_hostname",
            "The hostname looks like an IP address in a non-standard format "
            "(for example 2130706433 or 999.1.1.1). Use a normal domain or a "
            "standard IPv4/IPv6 address.",
        )
    return ascii_host


def validate_url(raw) -> ParsedURL:
    """Validate and normalize `raw`. Returns ParsedURL or raises ValidationError."""
    if not isinstance(raw, str):
        raise ValidationError("invalid_url_type", "The 'url' field must be a string.")
    url = raw.strip()
    if not url:
        raise ValidationError("empty_url", "The URL is empty.")
    if len(url) > MAX_URL_LENGTH:
        raise ValidationError(
            "url_too_long", f"The URL is longer than {MAX_URL_LENGTH} characters."
        )
    if _FORBIDDEN_CHARS_RE.search(url):
        raise ValidationError(
            "invalid_characters",
            "The URL contains spaces, control characters or backslashes.",
        )

    # --- scheme ---------------------------------------------------------
    match = _SCHEME_RE.match(url)
    if not match:
        raise ValidationError(
            "missing_scheme", "The URL must start with http:// or https://."
        )
    scheme = match.group(1).lower()
    if scheme not in ALLOWED_SCHEMES:
        raise ValidationError(
            "unsupported_scheme", "Only http:// and https:// URLs are supported."
        )
    if not url[len(scheme) + 1:].startswith("//"):
        raise ValidationError("malformed_url", "The URL is malformed.")

    # --- structure ------------------------------------------------------
    try:
        parts = urlsplit(url)
    except ValueError:
        raise ValidationError("malformed_url", "The URL is malformed.")
    if not parts.netloc:
        raise ValidationError("malformed_url", "The URL has no hostname.")
    if "@" in parts.netloc:
        raise ValidationError(
            "credentials_not_allowed",
            "URLs containing a username or password are not accepted.",
        )
    try:
        port = parts.port
    except ValueError:
        raise ValidationError("invalid_port", "The port number is not valid.")
    if port == 0:
        raise ValidationError("invalid_port", "The port number is not valid.")
    host = parts.hostname
    if not host:
        raise ValidationError("invalid_hostname", "The URL has no valid hostname.")
    if "%" in host:
        raise ValidationError("invalid_hostname", "The hostname is not valid.")

    # --- host: IP address or domain name -------------------------------
    ip = _try_ip(host)
    if "[" in parts.netloc and (ip is None or ip.version != 6):
        raise ValidationError("malformed_url", "Square brackets are only valid around an IPv6 address.")
    if ip is not None:
        is_ip, ip_version = True, ip.version
        ascii_host = str(ip)
        unicode_host = ascii_host
        host_for_url = f"[{ascii_host}]" if ip.version == 6 else ascii_host
    else:
        is_ip, ip_version = False, None
        ascii_host = _validate_hostname(host)
        try:
            unicode_host = ascii_host.encode("ascii").decode("idna")
        except UnicodeError:
            unicode_host = ascii_host
        host_for_url = ascii_host

    explicit_port = None if port is None or port == DEFAULT_PORTS[scheme] else port
    netloc = host_for_url + (f":{explicit_port}" if explicit_port else "")
    normalized = urlunsplit((scheme, netloc, parts.path, parts.query, parts.fragment))

    return ParsedURL(
        original=url,
        normalized=normalized,
        scheme=scheme,
        host=ascii_host,
        unicode_host=unicode_host,
        is_ip=is_ip,
        ip_version=ip_version,
        port=explicit_port,
        path=parts.path,
        query=parts.query,
        fragment=parts.fragment,
    )
