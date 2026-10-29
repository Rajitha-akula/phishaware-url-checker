"""
Unit tests for Database Security and Repository logic.
Verifies SQL Injection immunity and relational data mapping.
"""

import sqlite3
import pytest
from app.engine.normalizer import normalize_url
from app.engine.heuristics import evaluate_url_risk


class TestDatabaseSecurityAndIntegrity:
    """
    Verifies that parameterized queries handle malicious injection strings
    strictly as plain text, preventing SQL Injection.
    """

    @pytest.fixture
    def in_memory_db(self):
        """Creates an in-memory SQL database replicating our schema for isolated test execution."""
        conn = sqlite3.connect(":memory:")
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE assessments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                raw_url TEXT NOT NULL,
                normalized_url TEXT NOT NULL,
                host TEXT NOT NULL,
                scheme TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                color TEXT NOT NULL,
                breakdown_summary TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE triggered_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                assessment_id INTEGER NOT NULL,
                rule_id TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                category TEXT NOT NULL,
                weight INTEGER NOT NULL,
                description TEXT,
                explanation TEXT,
                guidance TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE
            )
        """)
        conn.commit()
        yield conn
        conn.close()

    def test_sql_injection_payload_is_treated_as_plain_data(self, in_memory_db):
        cursor = in_memory_db.cursor()

        # Insert a benign record
        cursor.execute(
            "INSERT INTO assessments (raw_url, normalized_url, host, scheme, risk_score, risk_level, color) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("https://google.com", "https://google.com", "google.com", "https", 0, "LOW_RISK", "#38a169")
        )
        in_memory_db.commit()

        # Malicious search attempt designed to bypass WHERE clause in vulnerable code
        malicious_search = "' OR '1'='1"

        # SECURE: Using parameterized query
        cursor.execute(
            "SELECT * FROM assessments WHERE host LIKE ?",
            (f"%{malicious_search}%",)
        )
        results = cursor.fetchall()

        # With parameterized query, ' OR '1'='1 is matched as a literal string.
        # Since 'google.com' does not contain that literal text, 0 rows must be returned.
        assert len(results) == 0

    def test_save_and_retrieve_relational_data(self, in_memory_db):
        cursor = in_memory_db.cursor()

        # Generate a test assessment
        norm = normalize_url("http://paypal.com@evil-phishing.com/login")
        assessment = evaluate_url_risk(norm)

        # Insert assessment using parameters
        cursor.execute(
            "INSERT INTO assessments (raw_url, normalized_url, host, scheme, risk_score, risk_level, color, breakdown_summary) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                assessment.raw_url,
                assessment.normalized_url,
                assessment.host,
                assessment.scheme,
                assessment.risk_score,
                assessment.risk_level,
                assessment.color,
                assessment.breakdown_summary
            )
        )
        assessment_id = cursor.lastrowid
        assert assessment_id is not None

        # Insert triggered rules using parameters
        for r in assessment.triggered_rules:
            cursor.execute(
                "INSERT INTO triggered_rules (assessment_id, rule_id, rule_name, category, weight, description, explanation, guidance) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    assessment_id,
                    r.rule_id,
                    r.name,
                    r.category,
                    r.weight,
                    r.description,
                    r.explanation,
                    r.guidance
                )
            )
        in_memory_db.commit()

        # Query back
        cursor.execute("SELECT COUNT(*) FROM assessments")
        assert cursor.fetchone()[0] == 1

        cursor.execute("SELECT COUNT(*) FROM triggered_rules WHERE assessment_id = ?", (assessment_id,))
        count_rules = cursor.fetchone()[0]
        assert count_rules == len(assessment.triggered_rules)
        assert count_rules >= 1
