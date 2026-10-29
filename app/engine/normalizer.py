"""
Safe URL Input Validation and Normalizer.

Security Principles:
1. Strict Length Caps: Prevents memory exhaustion and ReDoS vulnerabilities.
2. Dangerous Scheme Blocking: Blocks pseudo-schemes like 'javascript:', 'data:', 'file:'.
3. Safe Decomposition: Uses standard urllib.parse without executing or resolving the address.
4. Zero Network Calls: Parsing is 100% offline. No DNS lookups, no HTTP requests.
"""

from dataclasses import dataclass
from typing import Optional, List
import urllib.parse
import re
import ipaddress


class ValidationError(Exception):
    """Raised when user input fails security validation or structural checks."""
    pass


# Disallowed non-web schemes that can execute code or access local files in browsers
DISALLOWED_SCHEMES = frozenset([
    "javascript", "data", "file", "vbscript", "blob", "about", "chrome",
    "resource", "filesystem", "ws", "wss"
])

ALLOWED_SCHEMES = frozenset(["http", "https"])

# Maximum reasonable URL length according to browser and RFC standards
MAX_URL_LENGTH = 2048
MIN_URL_LENGTH = 3

# Regex to check for suspicious control characters or raw newlines
CONTROL_CHARS_PATTERN = re.compile(r"[\x00-\x1f\x7f]")


@dataclass(frozen=True)
class NormalizedURL:
    """Immutable data structure representing a safely parsed and normalized URL."""
    raw_input: str
    normalized_url: str
    scheme: str
    host: str
    port: Optional[int]
    path: str
    query: str
    fragment: str
    userinfo: Optional[str]
    is_ip_address: bool
    ip_version: Optional[int]
    subdomains: List[str]
    registered_domain: str
    top_level_domain: str
    scheme_was_inferred: bool


def _is_ip(hostname: str) -> tuple[bool, Optional[int]]:
    """
    Safely determine if a hostname is an IPv4 or IPv6 address.
    Also handles integer/dword/hex representations common in evasion techniques.
    """
    cleaned_host = hostname.strip("[]")
    
    # 1. Standard IPv4/IPv6 parsing
    try:
        ip_obj = ipaddress.ip_address(cleaned_host)
        return True, ip_obj.version
    except ValueError:
        pass

    # 2. Hex/Octal/Dword representation checks (e.g. 0x7f000001 or 2130706433)
    if cleaned_host.isdigit():
        try:
            val = int(cleaned_host)
            if 0 <= val <= 0xFFFFFFFF:
                return True, 4
        except ValueError:
            pass

    if cleaned_host.lower().startswith("0x"):
        try:
            val = int(cleaned_host, 16)
            if 0 <= val <= 0xFFFFFFFF:
                return True, 4
        except ValueError:
            pass

    return False, None


def _extract_domain_parts(hostname: str, is_ip: bool) -> tuple[List[str], str, str]:
    """
    Decompose a non-IP hostname into subdomains, registered domain, and TLD.
    Example: 'login.verify.paypal.com' -> subdomains=['login', 'verify'], reg_domain='paypal.com', tld='com'
    """
    if is_ip or not hostname:
        return [], "", ""

    # Strip any trailing dot (FQDN root notation)
    clean_host = hostname.rstrip(".")
    parts = clean_host.split(".")

    if len(parts) == 1:
        return [], clean_host, ""

    # Known two-part public suffixes (e.g., .co.uk, .gov.in, .com.au, .co.nz)
    two_part_tlds = {
        "co.uk", "gov.uk", "ac.uk", "org.uk",
        "co.in", "net.in", "org.in", "gov.in",
        "com.au", "net.au", "org.au", "edu.au",
        "co.nz", "net.nz", "org.nz",
        "co.jp", "ne.jp", "ac.jp",
        "com.br", "org.br", "gov.br"
    }

    tld = parts[-1]
    reg_domain = ""
    subdomains = []

    if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}".lower() in two_part_tlds:
        tld = f"{parts[-2]}.{parts[-1]}".lower()
        reg_domain = f"{parts[-3]}.{tld}".lower()
        subdomains = parts[:-3]
    else:
        tld = parts[-1].lower()
        reg_domain = f"{parts[-2]}.{tld}".lower()
        subdomains = parts[:-2]

    return subdomains, reg_domain, tld


def normalize_url(user_input: str) -> NormalizedURL:
    """
    Validate, sanitize, and normalize user-submitted URL text.
    
    Security Guards:
    - Rejects empty, whitespace-only, or overly long inputs.
    - Strips whitespace and disallows control characters.
    - Rejects dangerous schemes ('javascript:', 'data:', etc.).
    - Defaults to 'http://' if scheme is omitted for parsing, while flagging scheme_was_inferred.
    - Performs strict offline parsing via urllib.parse.
    """
    if not isinstance(user_input, str):
        raise ValidationError("Input must be a valid text string.")

    cleaned = user_input.strip()

    if not cleaned:
        raise ValidationError("Please provide a URL to evaluate.")

    if len(cleaned) < MIN_URL_LENGTH:
        raise ValidationError(f"URL is too short (minimum {MIN_URL_LENGTH} characters).")

    if len(cleaned) > MAX_URL_LENGTH:
        raise ValidationError(
            f"URL length ({len(cleaned)} chars) exceeds maximum safety limit of {MAX_URL_LENGTH} characters."
        )

    # Reject null bytes and unprintable control characters
    if CONTROL_CHARS_PATTERN.search(cleaned):
        raise ValidationError("URL contains illegal control characters or null bytes.")

    # Check for dangerous schemes early
    lower_input = cleaned.lower()
    for bad_scheme in DISALLOWED_SCHEMES:
        if lower_input.startswith(f"{bad_scheme}:"):
            raise ValidationError(
                f"Dangerous scheme '{bad_scheme}:' is blocked. Only web addresses (http/https) are permitted."
            )

    scheme_inferred = False
    candidate = cleaned

    # If scheme is omitted (e.g. 'paypal.com/login'), prepend 'http://' to allow proper RFC parsing
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", candidate):
        candidate = f"http://{candidate}"
        scheme_inferred = True

    try:
        parsed = urllib.parse.urlsplit(candidate)
    except Exception as exc:
        raise ValidationError(f"URL parsing failed: {str(exc)}") from exc

    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise ValidationError(f"Unsupported scheme '{scheme}'. Only http and https URLs can be assessed.")

    netloc = parsed.netloc
    if not netloc:
        raise ValidationError("URL is missing a valid hostname or network location.")

    # Extract userinfo (credentials like 'user:pass@' or 'google.com@evil.com')
    userinfo = None
    host_portion = netloc
    if "@" in netloc:
        userinfo, host_portion = netloc.split("@", 1)

    # Extract hostname and port safely
    port = None
    hostname = host_portion
    if ":" in host_portion and not host_portion.startswith("["):
        # Not an IPv6 literal
        host_parts = host_portion.split(":")
        hostname = host_parts[0]
        try:
            port = int(host_parts[1])
            if not (1 <= port <= 65535):
                raise ValidationError(f"Port {port} is out of the valid range (1-65535).")
        except ValueError:
            raise ValidationError(f"Invalid port specification: '{host_parts[1]}'.")
    elif host_portion.startswith("[") and "]:" in host_portion:
        # IPv6 with port: [::1]:8080
        match = re.match(r"^\[([a-fA-F0-9:]+)\]:(\d+)$", host_portion)
        if match:
            hostname = match.group(1)
            port = int(match.group(2))
        else:
            raise ValidationError("Malformed IPv6 address format.")

    hostname = hostname.lower().strip()
    if not hostname:
        raise ValidationError("Hostname could not be identified.")

    # Check for IP address vs domain name
    is_ip, ip_ver = _is_ip(hostname)

    # Decompose domain parts if not an IP
    subdomains, reg_domain, tld = _extract_domain_parts(hostname, is_ip)

    # Normalize path: ensure at least '/'
    path = parsed.path or "/"

    # Reconstruct normalized URL string
    normalized_netloc = hostname
    if port:
        normalized_netloc = f"{normalized_netloc}:{port}"
    if userinfo:
        normalized_netloc = f"{userinfo}@{normalized_netloc}"

    normalized_full = urllib.parse.urlunsplit((
        scheme,
        normalized_netloc,
        path,
        parsed.query,
        parsed.fragment
    ))

    return NormalizedURL(
        raw_input=cleaned,
        normalized_url=normalized_full,
        scheme=scheme,
        host=hostname,
        port=port,
        path=path,
        query=parsed.query,
        fragment=parsed.fragment,
        userinfo=userinfo,
        is_ip_address=is_ip,
        ip_version=ip_ver,
        subdomains=subdomains,
        registered_domain=reg_domain,
        top_level_domain=tld,
        scheme_was_inferred=scheme_inferred
    )
