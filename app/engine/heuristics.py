"""
Heuristic Risk Evaluation Engine.

Evaluates NormalizedURL instances against the declarative heuristic rules catalog,
computes a cumulative risk score, classifies the risk tier, and generates
transparent, beginner-friendly educational explanations.
"""

from dataclasses import dataclass
from typing import List, Dict, Any
import urllib.parse
import re

from app.engine.normalizer import NormalizedURL
from app.engine.rules import (
    RULES_CATALOG,
    RuleDefinition,
    MONITORED_BRANDS,
    HIGH_RISK_TLDS,
    SENSITIVE_KEYWORDS,
    REDIRECT_PARAMS
)

DISCLAIMER_TEXT = (
    "Educational Disclaimer: This assessment is based exclusively on static, transparent heuristic pattern "
    "analysis of the URL structure. It DOES NOT visit the destination website, resolve DNS records, or inspect "
    "live server content. Consequently, heuristic results ARE NOT DEFINITIVE PROOF that a URL is safe or malicious. "
    "Always exercise vigilance and verify domains independently before submitting credentials."
)


@dataclass
class TriggeredRuleResult:
    rule_id: str
    name: str
    category: str
    weight: int
    description: str
    explanation: str
    guidance: str


@dataclass
class AssessmentResult:
    raw_url: str
    normalized_url: str
    host: str
    scheme: str
    risk_score: int
    risk_level: str  # LOW_RISK, SUSPICIOUS, HIGH_RISK
    color: str       # green, amber, red
    triggered_rules: List[TriggeredRuleResult]
    total_rules_evaluated: int
    disclaimer: str
    breakdown_summary: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "raw_url": self.raw_url,
            "normalized_url": self.normalized_url,
            "host": self.host,
            "scheme": self.scheme,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "color": self.color,
            "triggered_rules": [
                {
                    "rule_id": r.rule_id,
                    "name": r.name,
                    "category": r.category,
                    "weight": r.weight,
                    "description": r.description,
                    "explanation": r.explanation,
                    "guidance": r.guidance,
                }
                for r in self.triggered_rules
            ],
            "total_rules_evaluated": self.total_rules_evaluated,
            "disclaimer": self.disclaimer,
            "breakdown_summary": self.breakdown_summary
        }


def _check_ip_hostname(url: NormalizedURL) -> bool:
    # Rule HR-01: Raw IPv4 or IPv6 (standard dotted-quad or colon-hex)
    return url.is_ip_address and not (url.host.isdigit() or url.host.lower().startswith("0x"))


def _check_hex_octal_ip(url: NormalizedURL) -> bool:
    # Rule HR-10: Hostname is integer dword or hex representation
    cleaned = url.host.strip("[]")
    return cleaned.isdigit() or cleaned.lower().startswith("0x")


def _check_at_symbol(url: NormalizedURL) -> bool:
    # Rule HR-02: '@' symbol in authority/userinfo
    return url.userinfo is not None and len(url.userinfo) > 0


def _check_excessive_subdomains(url: NormalizedURL) -> bool:
    # Rule HR-03: 3 or more subdomain levels
    return len(url.subdomains) >= 3


def _check_sensitive_subdomain(url: NormalizedURL) -> bool:
    # Rule HR-04: Sensitive keyword in subdomains while registered domain is not an official domain for that keyword
    if not url.subdomains:
        return False
    
    joined_subdomains = " ".join(url.subdomains).lower()
    for kw in SENSITIVE_KEYWORDS:
        if kw in joined_subdomains:
            # Check if keyword is part of official brand
            for brand, official_domains in MONITORED_BRANDS.items():
                if kw in brand and url.registered_domain in official_domains:
                    return False
            return True
    return False


def _check_high_risk_tld(url: NormalizedURL) -> bool:
    # Rule HR-05: TLD is in high risk set
    return url.top_level_domain.lower() in HIGH_RISK_TLDS


def _check_punycode(url: NormalizedURL) -> bool:
    # Rule HR-06: Punycode or non-ASCII
    if "xn--" in url.host.lower():
        return True
    try:
        url.host.encode("ascii")
        return False
    except UnicodeEncodeError:
        return True


def _check_non_standard_port(url: NormalizedURL) -> bool:
    # Rule HR-07: Port specified and not standard 80 or 443
    return url.port is not None and url.port not in (80, 443)


def _check_long_url(url: NormalizedURL) -> bool:
    # Rule HR-08: URL length > 100 characters
    return len(url.raw_input) > 100


def _check_multiple_hyphens(url: NormalizedURL) -> bool:
    # Rule HR-09: 3 or more hyphens in the hostname
    return url.host.count("-") >= 3


def _check_open_redirect(url: NormalizedURL) -> bool:
    # Rule HR-11: Query parameter containing an external URL
    if not url.query:
        return False
    try:
        query_dict = urllib.parse.parse_qs(url.query)
        for param_name, values in query_dict.items():
            if param_name.lower() in REDIRECT_PARAMS:
                for val in values:
                    if val.lower().startswith("http://") or val.lower().startswith("https://"):
                        return True
    except Exception:
        pass
    return False


def _check_misleading_brand_in_path(url: NormalizedURL) -> bool:
    # Rule HR-12: Monitored brand appears in path or query, but registered_domain does NOT match that brand
    full_path_query = f"{url.path}?{url.query}".lower()
    for brand, official_domains in MONITORED_BRANDS.items():
        if brand in full_path_query:
            # Check if registered domain belongs to this brand
            if url.registered_domain not in official_domains:
                return True
    return False


def _check_unencrypted_sensitive(url: NormalizedURL) -> bool:
    # Rule HR-13: Scheme is http (not https) and contains sensitive auth keywords
    if url.scheme != "http":
        return False
    full_url_text = f"{url.path}?{url.query}".lower()
    return any(kw in full_url_text for kw in SENSITIVE_KEYWORDS)


def evaluate_url_risk(url: NormalizedURL) -> AssessmentResult:
    """
    Perform transparent heuristic evaluation against all defined rules.
    Calculates composite risk score and risk classification.
    """
    triggered: List[TriggeredRuleResult] = []

    # Map rule checker functions
    rule_evaluators = [
        ("HR-01", _check_ip_hostname),
        ("HR-02", _check_at_symbol),
        ("HR-03", _check_excessive_subdomains),
        ("HR-04", _check_sensitive_subdomain),
        ("HR-05", _check_high_risk_tld),
        ("HR-06", _check_punycode),
        ("HR-07", _check_non_standard_port),
        ("HR-08", _check_long_url),
        ("HR-09", _check_multiple_hyphens),
        ("HR-10", _check_hex_octal_ip),
        ("HR-11", _check_open_redirect),
        ("HR-12", _check_misleading_brand_in_path),
        ("HR-13", _check_unencrypted_sensitive),
    ]

    total_score = 0
    for rule_id, checker_fn in rule_evaluators:
        rule_def = RULES_CATALOG.get(rule_id)
        if not rule_def:
            continue

        try:
            is_triggered = checker_fn(url)
        except Exception:
            is_triggered = False

        if is_triggered:
            total_score += rule_def.weight
            triggered.append(TriggeredRuleResult(
                rule_id=rule_def.rule_id,
                name=rule_def.name,
                category=rule_def.category,
                weight=rule_def.weight,
                description=rule_def.description,
                explanation=rule_def.explanation,
                guidance=rule_def.guidance
            ))

    # Clamp score between 0 and 100
    risk_score = min(total_score, 100)

    # Determine risk level category and color
    if risk_score >= 60:
        risk_level = "HIGH_RISK"
        color = "#e53e3e"  # Red
        summary = (
            f"HIGH RISK ({risk_score}/100): Multiple strong deception indicators or critical anomalies detected. "
            "Interaction with this address is strongly discouraged."
        )
    elif risk_score >= 25:
        risk_level = "SUSPICIOUS"
        color = "#dd6b20"  # Amber
        summary = (
            f"SUSPICIOUS ({risk_score}/100): Notable warning signs or atypical structural patterns detected. "
            "Proceed with extreme caution and manually verify domain ownership."
        )
    else:
        risk_level = "LOW_RISK"
        color = "#38a169"  # Green
        summary = (
            f"LOW RISK ({risk_score}/100): No prominent syntactic anomalies or phishing structural patterns flagged. "
            "However, always stay observant as benign structures do not guarantee safety."
        )

    return AssessmentResult(
        raw_url=url.raw_input,
        normalized_url=url.normalized_url,
        host=url.host,
        scheme=url.scheme,
        risk_score=risk_score,
        risk_level=risk_level,
        color=color,
        triggered_rules=triggered,
        total_rules_evaluated=len(rule_evaluators),
        disclaimer=DISCLAIMER_TEXT,
        breakdown_summary=summary
    )
