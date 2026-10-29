"""
Unit tests for URL Input Validation and Normalizer.
Verifies defense against invalid inputs, dangerous schemes, and ensures RFC-compliant decomposition.
"""

import pytest
from app.engine.normalizer import normalize_url, ValidationError


class TestURLNormalizer:

    def test_valid_standard_https_url(self):
        url = "https://www.google.com/search?q=cybersecurity"
        norm = normalize_url(url)
        assert norm.scheme == "https"
        assert norm.host == "www.google.com"
        assert norm.registered_domain == "google.com"
        assert norm.top_level_domain == "com"
        assert norm.subdomains == ["www"]
        assert norm.path == "/search"
        assert norm.query == "q=cybersecurity"
        assert not norm.is_ip_address
        assert not norm.scheme_was_inferred

    def test_scheme_inference_when_omitted(self):
        url = "example.com/login"
        norm = normalize_url(url)
        assert norm.scheme == "http"
        assert norm.host == "example.com"
        assert norm.scheme_was_inferred is True
        assert norm.path == "/login"

    def test_multi_part_tld_recognition(self):
        url = "https://portal.service.gov.uk/dashboard"
        norm = normalize_url(url)
        assert norm.top_level_domain == "gov.uk"
        assert norm.registered_domain == "service.gov.uk"
        assert norm.subdomains == ["portal"]

    def test_userinfo_extraction_at_symbol(self):
        url = "https://paypal.com:secret@attacker-domain.com/login"
        norm = normalize_url(url)
        assert norm.host == "attacker-domain.com"
        assert norm.userinfo == "paypal.com:secret"

    def test_ipv4_recognition(self):
        url = "http://192.168.1.100:8080/admin"
        norm = normalize_url(url)
        assert norm.is_ip_address is True
        assert norm.ip_version == 4
        assert norm.host == "192.168.1.100"
        assert norm.port == 8080

    def test_dword_ip_recognition(self):
        # 2130706433 is 127.0.0.1 in integer dword notation
        url = "http://2130706433/update"
        norm = normalize_url(url)
        assert norm.is_ip_address is True
        assert norm.ip_version == 4
        assert norm.host == "2130706433"

    def test_disallowed_javascript_scheme(self):
        with pytest.raises(ValidationError, match="Dangerous scheme 'javascript:' is blocked"):
            normalize_url("javascript:alert(document.cookie)")

    def test_disallowed_data_scheme(self):
        with pytest.raises(ValidationError, match="Dangerous scheme 'data:' is blocked"):
            normalize_url("data:text/html,<script>alert(1)</script>")

    def test_disallowed_file_scheme(self):
        with pytest.raises(ValidationError, match="Dangerous scheme 'file:' is blocked"):
            normalize_url("file:///etc/passwd")

    def test_empty_input(self):
        with pytest.raises(ValidationError, match="Please provide a URL to evaluate"):
            normalize_url("   ")

    def test_too_short_input(self):
        with pytest.raises(ValidationError, match="URL is too short"):
            normalize_url("ab")

    def test_oversized_url(self):
        oversized = "https://example.com/" + "a" * 2500
        with pytest.raises(ValidationError, match="exceeds maximum safety limit"):
            normalize_url(oversized)

    def test_illegal_control_characters(self):
        with pytest.raises(ValidationError, match="illegal control characters"):
            normalize_url("https://example.com/test\x00malicious")

    def test_invalid_port_range(self):
        with pytest.raises(ValidationError, match="out of the valid range"):
            normalize_url("http://example.com:70000/test")
