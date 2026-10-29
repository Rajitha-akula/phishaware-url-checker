"""
Automated Integration and API Security Tests for Flask Backend.
Verifies endpoints, input validation responses, database integration, and security headers.
"""

import pytest
from app import create_app
from config import Config


class TestAPISecurityAndEndpoints:

    @pytest.fixture
    def client(self):
        """Builds a test client with testing configuration."""
        app = create_app()
        app.config["TESTING"] = True
        with app.test_client() as client:
            yield client

    def test_security_headers_present_on_all_responses(self, client):
        """Verify defense-in-depth HTTP security headers."""
        response = client.get("/api/stats")
        assert response.status_code == 200
        assert response.headers.get("X-Frame-Options") == "DENY"
        assert response.headers.get("X-Content-Type-Options") == "nosniff"
        assert "Content-Security-Policy" in response.headers
        assert "strict-origin-when-cross-origin" in response.headers.get("Referrer-Policy", "")

    def test_analyze_valid_benign_url(self, client):
        payload = {"url": "https://www.wikipedia.org/wiki/Main_Page"}
        response = client.post("/api/analyze", json=payload)
        assert response.status_code == 200

        data = response.get_json()
        assert data["success"] is True
        assert data["host"] == "www.wikipedia.org"
        assert data["risk_level"] == "LOW_RISK"
        assert data["risk_score"] < 25
        assert "disclaimer" in data
        assert "static, transparent heuristic" in data["disclaimer"]

    def test_analyze_empty_payload_returns_400(self, client):
        response = client.post("/api/analyze", json={"url": "   "})
        assert response.status_code == 400
        data = response.get_json()
        assert data["success"] is False
        assert "Missing URL input" in data["error"]

    def test_analyze_dangerous_scheme_returns_400(self, client):
        payload = {"url": "javascript:alert(document.domain)"}
        response = client.post("/api/analyze", json=payload)
        assert response.status_code == 400
        data = response.get_json()
        assert data["success"] is False
        assert "Dangerous scheme" in data["message"]

    def test_analyze_phishing_triggers_rules_and_saves(self, client):
        payload = {"url": "http://paypal.com@verify-account-update.xyz/login"}
        response = client.post("/api/analyze", json=payload)
        assert response.status_code == 200

        data = response.get_json()
        assert data["success"] is True
        assert data["risk_score"] >= 40
        assert data["id"] is not None

        # Verify specific rules triggered
        rule_ids = [r["rule_id"] for r in data["triggered_rules"]]
        assert "HR-02" in rule_ids  # @ symbol
        assert "HR-05" in rule_ids  # .xyz TLD

        # Check that assessment can be retrieved by ID
        saved_id = data["id"]
        detail_resp = client.get(f"/api/assessment/{saved_id}")
        assert detail_resp.status_code == 200
        detail_data = detail_resp.get_json()
        assert detail_data["assessment"]["id"] == saved_id
        assert len(detail_data["assessment"]["triggered_rules"]) >= 2

    def test_history_endpoint_pagination_and_search(self, client):
        # 1. Fetch history
        resp = client.get("/api/history?limit=10&offset=0")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert "items" in data
        assert "total" in data

        # 2. Search query filter
        search_resp = client.get("/api/history?q=paypal")
        assert search_resp.status_code == 200
        search_data = search_resp.get_json()
        assert search_data["success"] is True

        # 3. Risk level filter
        filter_resp = client.get("/api/history?level=HIGH_RISK")
        assert filter_resp.status_code == 200

    def test_stats_endpoint(self, client):
        resp = client.get("/api/stats")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert "stats" in data
        assert "total_scans" in data["stats"]
        assert "avg_risk_score" in data["stats"]
        assert "database_engine" in data["stats"]

    def test_nonexistent_assessment_returns_404(self, client):
        resp = client.get("/api/assessment/9999999")
        assert resp.status_code == 404
        data = resp.get_json()
        assert data["success"] is False
