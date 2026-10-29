"""
Heuristic Rule Definitions and Explanations.

Each rule provides:
- rule_id: Unique identifier for reporting and auditing.
- name: Human-readable title.
- category: Type of indicator (Hostname, Authority, Query, Structure).
- weight: Contribution to total risk score (10 - 40 points).
- description: Concise summary of what triggered the rule.
- explanation: Clear explanation of why attackers use this tactic.
- guidance: Educational safety advice on how users should protect themselves.
"""

from dataclasses import dataclass
from typing import Dict, List, Set


@dataclass(frozen=True)
class RuleDefinition:
    rule_id: str
    name: str
    category: str
    weight: int
    description: str
    explanation: str
    guidance: str


# Well-known trusted brands often targeted by phishing kits
MONITORED_BRANDS: Dict[str, Set[str]] = {
    "paypal": {"paypal.com"},
    "google": {"google.com", "accounts.google.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "login.microsoftonline.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.in"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com"},
    "binance": {"binance.com"},
    "coinbase": {"coinbase.com"},
    "metamask": {"metamask.io"}
}

# High-risk / historically abused generic TLDs
HIGH_RISK_TLDS: Set[str] = {
    "xyz", "top", "work", "click", "buzz", "tk", "ml", "cf", "ga", "gq",
    "fit", "racing", "cam", "loan", "rest", "surf", "date", "wang", "men"
}

# Sensitive credential / account keywords
SENSITIVE_KEYWORDS: Set[str] = {
    "login", "signin", "sign-in", "log-in", "verify", "verification",
    "secure", "security", "account", "update", "banking", "wallet",
    "authenticate", "credential", "recovery", "confirm", "billing"
}

# Open redirect query parameter names
REDIRECT_PARAMS: Set[str] = {
    "redirect", "url", "next", "dest", "destination", "return_url", "r", "target"
}


# Pre-defined master rules catalog
RULES_CATALOG: Dict[str, RuleDefinition] = {
    "HR-01": RuleDefinition(
        rule_id="HR-01",
        name="IP Address Used as Hostname",
        category="Hostname",
        weight=35,
        description="The URL uses a raw IP address (IPv4 or IPv6) instead of a registered domain name.",
        explanation=(
            "Legitimate services almost exclusively use registered domain names with valid SSL certificates. "
            "Cybercriminals often deploy temporary phishing pages directly on compromised IP addresses to avoid "
            "domain registration costs or evade domain-based reputation blocklists."
        ),
        guidance="Do not enter credentials or personal information on links that use raw IP addresses in place of a standard domain."
    ),
    "HR-02": RuleDefinition(
        rule_id="HR-02",
        name="Credential '@' Symbol in Authority",
        category="Authority",
        weight=40,
        description="The URL contains an '@' character within the hostname/authority section.",
        explanation=(
            "In URL standards (RFC 3986), characters before an '@' symbol represent user credentials (username:password), "
            "and web browsers navigate exclusively to the host *following* the '@'. Attackers craft links like "
            "'https://paypal.com@evil-phishing.com' to trick users who only glance at the start of the address."
        ),
        guidance="Always look at the domain immediately following the '@' symbol. Never trust a URL with an '@' in the address bar."
    ),
    "HR-03": RuleDefinition(
        rule_id="HR-03",
        name="Excessive Subdomains",
        category="Hostname",
        weight=20,
        description="The hostname contains 3 or more nested subdomain levels.",
        explanation=(
            "Attackers frequently chain subdomains (e.g. 'paypal.com.verify.account.phish.com') so the real root domain "
            "is pushed to the right, hidden from view on mobile screens or shortened address bars."
        ),
        guidance="Focus on the registered root domain (the two words just before the final dot), not the words at the far left."
    ),
    "HR-04": RuleDefinition(
        rule_id="HR-04",
        name="Sensitive Keyword in Subdomain",
        category="Hostname",
        weight=25,
        description="A sensitive keyword (e.g., 'login', 'verify', 'bank') appears in the subdomain of an unfamiliar root domain.",
        explanation=(
            "Placing words like 'secure-login' or 'account-verify' inside a subdomain creates a false sense of legitimacy, "
            "even though the underlying domain is completely unrelated to the authentic brand."
        ),
        guidance="Verify that the root domain itself belongs to the official organization before trusting any login prompt."
    ),
    "HR-05": RuleDefinition(
        rule_id="HR-05",
        name="Historically Abused / High-Risk TLD",
        category="Hostname",
        weight=15,
        description="The domain uses a Top-Level Domain (TLD) frequently associated with disposable phishing campaigns.",
        explanation=(
            "Certain TLDs offer ultra-cheap or free domain registrations with minimal identity verification, "
            "making them attractive for disposable, short-lived phishing operations."
        ),
        guidance="Exercise extra caution when visiting domains on unfamiliar or novelty TLDs, particularly if claiming to be financial services."
    ),
    "HR-06": RuleDefinition(
        rule_id="HR-06",
        name="Punycode / Homoglyph Deception Indicator",
        category="Hostname",
        weight=35,
        description="The domain uses Punycode ('xn--') or non-ASCII characters that can visually mimic standard Latin letters.",
        explanation=(
            "Internationalized Domain Names (IDNs) allow non-Latin alphabets. In an IDN homograph attack, an attacker uses "
            "lookalike characters (such as Cyrillic 'а' in place of Latin 'a') to create an address virtually indistinguishable "
            "from a legitimate domain."
        ),
        guidance="Type reputable addresses manually into your browser's address bar rather than clicking links containing Punycode prefixes."
    ),
    "HR-07": RuleDefinition(
        rule_id="HR-07",
        name="Non-Standard Web Port",
        category="Authority",
        weight=20,
        description="The URL explicitly specifies a non-standard port number instead of default port 80 (HTTP) or 443 (HTTPS).",
        explanation=(
            "Standard consumer websites operate on ports 80 and 443. Non-standard ports (such as :8080 or :8443) are frequently "
            "seen on rogue web servers, development environments, or compromised hosts running unauthorized services."
        ),
        guidance="Commercial and banking sites rarely run on custom ports. Check the service identity before proceeding."
    ),
    "HR-08": RuleDefinition(
        rule_id="HR-08",
        name="Unusually Long URL",
        category="Structure",
        weight=15,
        description="The total URL length exceeds standard thresholds (over 100 characters).",
        explanation=(
            "While long URLs can occur with legitimate tracking links, attackers frequently pack long, encoded query parameters "
            "or deeply nested paths to obscure the destination or bury malicious payloads."
        ),
        guidance="Be cautious of excessively long links sent via SMS or unexpected emails."
    ),
    "HR-09": RuleDefinition(
        rule_id="HR-09",
        name="Excessive Hyphenation in Hostname",
        category="Hostname",
        weight=15,
        description="The hostname contains 3 or more hyphens.",
        explanation=(
            "Attackers string together multiple hyphenated keywords (e.g. 'paypal-security-account-update-center') "
            "to build domains that mimic authentic corporate portal names."
        ),
        guidance="Legitimate major brands rarely use heavily hyphenated domain names for their core customer services."
    ),
    "HR-10": RuleDefinition(
        rule_id="HR-10",
        name="Obfuscated / Hex / Dword IP Format",
        category="Hostname",
        weight=40,
        description="The hostname is encoded as a decimal dword or hexadecimal IP address.",
        explanation=(
            "Representing an IP address as a raw integer (e.g., 2130706433) or hex (0x7f000001) is a known evasion technique "
            "designed to bypass basic regex filters and mislead unsuspecting users."
        ),
        guidance="Evasive numerical addresses should be treated with extreme caution."
    ),
    "HR-11": RuleDefinition(
        rule_id="HR-11",
        name="Potential Open Redirect Parameter",
        category="Query",
        weight=20,
        description="The query string contains a redirection parameter referencing another web destination.",
        explanation=(
            "Open redirect vulnerabilities in otherwise reputable websites allow attackers to craft links starting with a trusted "
            "domain that silently forwards the victim to an attacker-controlled site upon arrival."
        ),
        guidance="Check if the link contains a 'redirect=' or 'url=' parameter pointing to a different third-party destination."
    ),
    "HR-12": RuleDefinition(
        rule_id="HR-12",
        name="Misleading Brand Name in Path or Query",
        category="Path/Query",
        weight=25,
        description="A major brand name appears in the path or parameters, but the registered domain does not belong to that brand.",
        explanation=(
            "Attackers place brand names in the URL path (e.g. 'http://unrelated-site.com/paypal/login') because users frequently "
            "read from left to right and assume the presence of the brand name indicates a legitimate page."
        ),
        guidance="Always identify the registered root domain. A brand name in the path cannot authenticate an unrelated domain."
    ),
    "HR-13": RuleDefinition(
        rule_id="HR-13",
        name="Unencrypted HTTP for Sensitive Action",
        category="Structure",
        weight=15,
        description="The URL uses unencrypted plain HTTP while referencing login or account functions.",
        explanation=(
            "Unencrypted HTTP sends all data, including credentials, in clear text over the local network, exposing users "
            "to eavesdropping and adversary-in-the-middle (AITM) attacks."
        ),
        guidance="Never enter passwords or confidential details on websites that do not utilize HTTPS encryption."
    )
}
