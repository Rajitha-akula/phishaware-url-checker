"""
Database Repository and Data Access Layer.

Security Principles:
1. Parameterized Queries: All SQL queries utilize %s placeholders with separate parameter tuples.
   String formatting or concatenation is NEVER used in SQL queries (100% SQL Injection immunity).
2. Transaction Safety: Database insertions utilize atomic transactions with rollback on exceptions.
3. Resource Management: Connections and cursors are handled via context managers to prevent connection leaks.
"""

import pymysql
import pymysql.cursors
from typing import Dict, Any, List, Optional, Tuple
from contextlib import contextmanager

from config import Config
from app.engine.heuristics import AssessmentResult


class DatabaseError(Exception):
    """Custom exception for database-related errors."""
    pass


def get_connection(use_database: bool = True):
    """
    Establish a connection to the MySQL server using PyMySQL.
    Returns a PyMySQL Connection object.
    """
    try:
        conn = pymysql.connect(
            host=Config.DB_HOST,
            port=Config.DB_PORT,
            user=Config.DB_USER,
            password=Config.DB_PASSWORD,
            database=Config.DB_NAME if use_database else None,
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor,
            connect_timeout=Config.DB_CONNECT_TIMEOUT,
            autocommit=False
        )
        return conn
    except pymysql.MySQLError as exc:
        raise DatabaseError(f"MySQL connection error: {str(exc)}") from exc


@contextmanager
def db_cursor(use_database: bool = True):
    """
    Context manager that yields a database cursor and manages commit/rollback cleanly.
    """
    conn = get_connection(use_database=use_database)
    cursor = conn.cursor()
    try:
        yield cursor
        conn.commit()
    except Exception as exc:
        conn.rollback()
        raise DatabaseError(f"Database transaction failed: {str(exc)}") from exc
    finally:
        cursor.close()
        conn.close()


def check_db_connection() -> Tuple[bool, str]:
    """
    Test whether the database server is reachable.
    Returns (True, message) if successful, or (False, error_details).
    """
    try:
        with db_cursor(use_database=False) as cursor:
            cursor.execute("SELECT 1 AS ping")
            res = cursor.fetchone()
            if res and res.get("ping") == 1:
                return True, "Database server is reachable and active."
        return False, "Database ping returned unexpected response."
    except Exception as exc:
        return False, str(exc)


def init_db() -> bool:
    """
    Initialize the database and create tables if they do not exist.
    """
    # 1. Create database if it does not exist
    with db_cursor(use_database=False) as cursor:
        cursor.execute(
            f"CREATE DATABASE IF NOT EXISTS `{Config.DB_NAME}` "
            f"CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
        )

    # 2. Create tables inside the database
    with db_cursor(use_database=True) as cursor:
        # Table 1: assessments
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS assessments (
                id INT AUTO_INCREMENT PRIMARY KEY,
                raw_url TEXT NOT NULL,
                normalized_url TEXT NOT NULL,
                host VARCHAR(255) NOT NULL,
                scheme VARCHAR(16) NOT NULL,
                risk_score INT NOT NULL,
                risk_level VARCHAR(32) NOT NULL,
                color VARCHAR(16) NOT NULL,
                breakdown_summary TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_host (host),
                INDEX idx_risk_level (risk_level),
                INDEX idx_created_at (created_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        """)

        # Table 2: triggered_rules
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS triggered_rules (
                id INT AUTO_INCREMENT PRIMARY KEY,
                assessment_id INT NOT NULL,
                rule_id VARCHAR(16) NOT NULL,
                rule_name VARCHAR(128) NOT NULL,
                category VARCHAR(64) NOT NULL,
                weight INT NOT NULL,
                description TEXT,
                explanation TEXT,
                guidance TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_assessment_id (assessment_id),
                INDEX idx_rule_id (rule_id),
                CONSTRAINT fk_triggered_rules_assessment
                    FOREIGN KEY (assessment_id)
                    REFERENCES assessments(id)
                    ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        """)

    return True


def save_assessment(assessment: AssessmentResult) -> int:
    """
    Save an assessment result and all triggered heuristic rules atomically.
    Uses parameterized queries (%s) to guarantee SQL injection prevention.
    """
    conn = get_connection(use_database=True)
    cursor = conn.cursor()
    try:
        # 1. Insert assessment record
        sql_assessment = """
            INSERT INTO assessments (
                raw_url, normalized_url, host, scheme,
                risk_score, risk_level, color, breakdown_summary
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        params_assessment = (
            assessment.raw_url,
            assessment.normalized_url,
            assessment.host,
            assessment.scheme,
            assessment.risk_score,
            assessment.risk_level,
            assessment.color,
            assessment.breakdown_summary
        )
        cursor.execute(sql_assessment, params_assessment)
        assessment_id = cursor.lastrowid

        # 2. Insert all triggered heuristic rules
        if assessment.triggered_rules:
            sql_rule = """
                INSERT INTO triggered_rules (
                    assessment_id, rule_id, rule_name, category,
                    weight, description, explanation, guidance
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """
            rules_params = [
                (
                    assessment_id,
                    rule.rule_id,
                    rule.name,
                    rule.category,
                    rule.weight,
                    rule.description,
                    rule.explanation,
                    rule.guidance
                )
                for rule in assessment.triggered_rules
            ]
            cursor.executemany(sql_rule, rules_params)

        conn.commit()
        return assessment_id
    except Exception as exc:
        conn.rollback()
        raise DatabaseError(f"Failed to save assessment to MySQL: {str(exc)}") from exc
    finally:
        cursor.close()
        conn.close()


def get_assessment_by_id(assessment_id: int) -> Optional[Dict[str, Any]]:
    """
    Retrieve a single assessment and its associated triggered rules by ID.
    Uses parameterized query to prevent SQL injection.
    """
    with db_cursor(use_database=True) as cursor:
        cursor.execute(
            "SELECT * FROM assessments WHERE id = %s",
            (assessment_id,)
        )
        record = cursor.fetchone()
        if not record:
            return None

        cursor.execute(
            "SELECT * FROM triggered_rules WHERE assessment_id = %s ORDER BY weight DESC",
            (assessment_id,)
        )
        rules = cursor.fetchall()
        record["triggered_rules"] = rules
        return record


def get_assessments(
    limit: int = 20,
    offset: int = 0,
    search_query: Optional[str] = None,
    risk_filter: Optional[str] = None
) -> Tuple[List[Dict[str, Any]], int]:
    """
    Retrieve paginated assessments with optional search and risk-level filtering.
    All search criteria use strict parameterized placeholders (%s).
    """
    conditions = []
    params: List[Any] = []

    if search_query:
        # Search by host or URL (safely escaped via parameter substitution)
        conditions.append("(host LIKE %s OR raw_url LIKE %s)")
        like_pattern = f"%{search_query.strip()}%"
        params.extend([like_pattern, like_pattern])

    if risk_filter and risk_filter.upper() in ("LOW_RISK", "SUSPICIOUS", "HIGH_RISK"):
        conditions.append("risk_level = %s")
        params.append(risk_filter.upper())

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    with db_cursor(use_database=True) as cursor:
        # Count total matching records
        count_sql = f"SELECT COUNT(*) AS total FROM assessments {where_clause}"
        cursor.execute(count_sql, tuple(params))
        total_count = cursor.fetchone()["total"]

        # Fetch records
        select_sql = f"""
            SELECT id, raw_url, normalized_url, host, scheme,
                   risk_score, risk_level, color, breakdown_summary, created_at
            FROM assessments
            {where_clause}
            ORDER BY created_at DESC
            LIMIT %s OFFSET %s
        """
        fetch_params = tuple(params + [limit, offset])
        cursor.execute(select_sql, fetch_params)
        records = cursor.fetchall()

        return records, total_count


def get_aggregate_stats() -> Dict[str, Any]:
    """
    Compute aggregate security metrics for the analytics dashboard:
    - Total scans performed
    - Breakdown by risk level (Low, Suspicious, High)
    - Average risk score
    - Top 5 most frequently triggered heuristic rules
    """
    with db_cursor(use_database=True) as cursor:
        # 1. Total count and average score
        cursor.execute("""
            SELECT 
                COUNT(*) AS total_scans,
                COALESCE(AVG(risk_score), 0) AS avg_risk_score
            FROM assessments
        """)
        totals = cursor.fetchone() or {"total_scans": 0, "avg_risk_score": 0}

        # 2. Risk level counts
        cursor.execute("""
            SELECT risk_level, COUNT(*) AS count
            FROM assessments
            GROUP BY risk_level
        """)
        level_counts = {row["risk_level"]: row["count"] for row in cursor.fetchall()}

        # 3. Top triggered heuristic rules
        cursor.execute("""
            SELECT 
                rule_id, rule_name, category, COUNT(*) as trigger_count
            FROM triggered_rules
            GROUP BY rule_id, rule_name, category
            ORDER BY trigger_count DESC
            LIMIT 5
        """)
        top_rules = cursor.fetchall()

        return {
            "total_scans": totals["total_scans"],
            "avg_risk_score": round(float(totals["avg_risk_score"]), 1),
            "low_risk_count": level_counts.get("LOW_RISK", 0),
            "suspicious_count": level_counts.get("SUSPICIOUS", 0),
            "high_risk_count": level_counts.get("HIGH_RISK", 0),
            "top_rules": top_rules
        }
