"""
Unit tests for the Heuristic Evaluation Engine.
Verifies correct rule activation, risk score calculation, and educational guidance generation.
"""

from app.engine.normalizer import normalize_url
from app.engine.heuristics import evaluate_url_risk, DISCLAIMER_TEXT


class TestHeuristicsEngine:

    def test_benign_url_scores_low_risk(self):
        url = normalize_url("https://www.google.com/search?q=cybersecurity")
        res = evaluate_url_risk(url)
        assert res.risk_level == "LOW_RISK"
        assert res.risk_score < 25
        assert len(res.triggered_rules) == 0
        assert DISCLAIMER_TEXT in res.disclaimer

    def test_raw_ip_triggers_rule_hr01(self):
        url = normalize_url("http://198.51.100.42/home")
        res = evaluate_url_risk(url)
        rule_ids = [r.rule_id for r in res.triggered_rules]
        assert "HR-01" in rule_ids
        assert res.risk_score >= 35

    def test_at_symbol_triggers_rule_hr02(self):
        url = normalize_url("https://paypal.com@evil-phishing-host.com/login")
        res = evaluate_url_risk(url)
        rule_ids = [r.rule_id for r in res.triggered_rules]
        assert "HR-02" in rule_ids

    def test_excessive_subdomains_and_sensitive_keyword(self):
        url = normalize_url("http://login.verify.account.portal.attacker-hub.com")
        res = evaluate_url_risk(url)
        rule_ids = [r.rule_id for r in res.triggered_rules]
        assert "HR-03" in rule_ids
        assert "HR-04" in rule_ids

    def test_high_risk_tld_rule_hr05(self):
        url = normalize_url("https://secure-update.xyz")
        res = evaluate_url_risk(url)
        rule_ids = [r.rule_id for r in res.triggered_rules]
        assert "HR-05" in rule_ids

    def test_punycode_homoglyph_rule_hr06(self):
        url = normalize_url("http://xn--gogle-pqa.com/auth")
        res = evaluate_url_risk(url)
        rule_ids = [r.rule_id for r in res.triggered_rules]
        assert "HR-06" in rule_ids

    def test_non_standard_port_rule_hr07(self):
        url = normalize_url("http://external-login.com:8443/app")
        res = evaluate_url_risk(url)
        rule_ids = [r.rule_id for r in res.triggered_rules]
        assert "HR-07" in rule_ids

    def test_excessive_hyphenation_rule_hr09(self):
        url = normalize_url("https://secure-login-account-update.com")
        res = evaluate_url_risk(url)
        rule_ids = [r.rule_id for r in res.triggered_rules]
        assert "HR-09" in rule_ids

    def test_dword_ip_obfuscation_rule_hr10(self):
        url = normalize_url("http://2130706433/path")
        res = evaluate_url_risk(url)
        rule_ids = [r.rule_id for r in res.triggered_rules]
        assert "HR-10" in rule_ids

    def test_open_redirect_rule_hr11(self):
        url = normalize_url("https://example.com/out?redirect=https://evil.com/landing")
        res = evaluate_url_risk(url)
        rule_ids = [r.rule_id for r in res.triggered_rules]
        assert "HR-11" in rule_ids

    def test_misleading_brand_in_path_rule_hr12(self):
        url = normalize_url("http://unrelated-domain.com/paypal/login")
        res = evaluate_url_risk(url)
        rule_ids = [r.rule_id for r in res.triggered_rules]
        assert "HR-12" in rule_ids

    def test_unencrypted_http_sensitive_rule_hr13(self):
        url = normalize_url("http://example.com/login")
        res = evaluate_url_risk(url)
        rule_ids = [r.rule_id for r in res.triggered_rules]
        assert "HR-13" in rule_ids

    def test_score_never_exceeds_100_cap(self):
        # A synthetic malicious URL triggering almost every single rule
        extreme_url = "http://paypal.com@verify-account-security-update.xyz:8080/paypal/login?redirect=http://evil.com"
        norm = normalize_url(extreme_url)
        res = evaluate_url_risk(norm)
        assert res.risk_score <= 100
        assert res.risk_level == "HIGH_RISK"
        assert len(res.triggered_rules) >= 4
