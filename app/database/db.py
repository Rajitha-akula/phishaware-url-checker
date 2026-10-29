"""
Database Repository and Data Access Layer.

Architecture:
- Primary Engine: MySQL (PyMySQL) using 3NF relational schema.
- Resilient Auto-Fallback: SQLite engine for seamless zero-config operation if MySQL
  credentials are not configured or access is denied.
- Security: 100% Parameterized queries across both engines (SQL Injection immunity).
"""

import os
import sqlite3
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from contextlib import contextmanager

from config import Config
from app.engine.heuristics import AssessmentResult


class DatabaseError(Exception):
    """Custom exception for database-related errors."""
    pass


SQLITE_DB_PATH = Path(Config.BASE_DIR) / "phishing_checker.db"

# Track which database engine is currently active
_active_engine = "mysql"  # 'mysql' or 'sqlite'


def _test_mysql_reachability() -> bool:
    """Test if MySQL can be reached with current credentials."""
    if not Config.DB_PASSWORD and Config.DB_PASSWORD != "":
        return False
    try:
        import pymysql
        conn = pymysql.connect(
            host=Config.DB_HOST,
            port=Config.DB_PORT,
            user=Config.DB_USER,
            password=Config.DB_PASSWORD,
            connect_timeout=2
        )
        conn.close()
        return True
    except Exception:
        return False


def get_active_engine() -> str:
    """Determine the active database engine."""
    global _active_engine
    if _test_mysql_reachability():
        _active_engine = "mysql"
    else:
        _active_engine = "sqlite"
    return _active_engine


def check_db_connection() -> Tuple[bool, str, str]:
    """
    Check database connectivity.
    Returns (is_connected, engine_name, message).
    """
    engine = get_active_engine()
    if engine == "mysql":
        return True, "MySQL", f"Connected to MySQL on {Config.DB_HOST}:{Config.DB_PORT} as user '{Config.DB_USER}'."
    else:
        return True, "SQLite", (
            f"Active on SQLite ({SQLITE_DB_PATH.name}). "
            "MySQL password not yet provided or access denied; zero-config local engine is active."
        )


@contextmanager
def get_db_cursor():
    """
    Context manager returning a database cursor and active engine type.
    Handles commit, rollback, and closing cleanly.
    """
    engine = get_active_engine()

    if engine == "mysql":
        import pymysql
        import pymysql.cursors
        conn = pymysql.connect(
            host=Config.DB_HOST,
            port=Config.DB_PORT,
            user=Config.DB_USER,
            password=Config.DB_PASSWORD,
            database=Config.DB_NAME,
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor,
            connect_timeout=Config.DB_CONNECT_TIMEOUT,
            autocommit=False
        )
        cursor = conn.cursor()
        try:
            yield cursor, "mysql"
            conn.commit()
        except Exception as exc:
            conn.rollback()
            raise DatabaseError(f"MySQL transaction failed: {str(exc)}") from exc
        finally:
            cursor.close()
            conn.close()
    else:
        # SQLite Engine
        conn = sqlite3.connect(str(SQLITE_DB_PATH))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        try:
            yield cursor, "sqlite"
            conn.commit()
        except Exception as exc:
            conn.rollback()
            raise DatabaseError(f"SQLite transaction failed: {str(exc)}") from exc
        finally:
            cursor.close()
            conn.close()


def init_db() -> bool:
    """
    Initialize database schema (creates tables and indexes if missing).
    """
    engine = get_active_engine()

    if engine == "mysql":
        import pymysql
        # Create database first
        conn = pymysql.connect(
            host=Config.DB_HOST,
            port=Config.DB_PORT,
            user=Config.DB_USER,
            password=Config.DB_PASSWORD,
            connect_timeout=Config.DB_CONNECT_TIMEOUT
        )
        with conn.cursor() as cur:
            cur.execute(
                f"CREATE DATABASE IF NOT EXISTS `{Config.DB_NAME}` "
                f"CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
            )
            conn.commit()
        conn.close()

        # Create tables
        with get_db_cursor() as (cur, _):
            cur.execute("""
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
            cur.execute("""
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
                        FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
            """)
    else:
        # SQLite initialization
        with get_db_cursor() as (cur, _):
            cur.execute("""
                CREATE TABLE IF NOT EXISTS assessments (
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
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS triggered_rules (
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
                );
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_host ON assessments (host);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_risk_level ON assessments (risk_level);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_created_at ON assessments (created_at);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_assessment_id ON triggered_rules (assessment_id);")

    return True


def save_assessment(assessment: AssessmentResult) -> int:
    """
    Save an assessment and its triggered rules atomically.
    Uses parameterized queries for 100% SQL injection immunity.
    """
    with get_db_cursor() as (cur, engine):
        ph = "%s" if engine == "mysql" else "?"
        
        insert_assessment_sql = f"""
            INSERT INTO assessments (
                raw_url, normalized_url, host, scheme,
                risk_score, risk_level, color, breakdown_summary
            ) VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph})
        """
        params = (
            assessment.raw_url,
            assessment.normalized_url,
            assessment.host,
            assessment.scheme,
            assessment.risk_score,
            assessment.risk_level,
            assessment.color,
            assessment.breakdown_summary
        )
        cur.execute(insert_assessment_sql, params)
        assessment_id = cur.lastrowid

        if assessment.triggered_rules:
            insert_rule_sql = f"""
                INSERT INTO triggered_rules (
                    assessment_id, rule_id, rule_name, category,
                    weight, description, explanation, guidance
                ) VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph})
            """
            for r in assessment.triggered_rules:
                rule_params = (
                    assessment_id,
                    r.rule_id,
                    r.name,
                    r.category,
                    r.weight,
                    r.description,
                    r.explanation,
                    r.guidance
                )
                cur.execute(insert_rule_sql, rule_params)

        return assessment_id


def get_assessment_by_id(assessment_id: int) -> Optional[Dict[str, Any]]:
    """Retrieve an assessment by ID with its triggered rules."""
    with get_db_cursor() as (cur, engine):
        ph = "%s" if engine == "mysql" else "?"
        cur.execute(f"SELECT * FROM assessments WHERE id = {ph}", (assessment_id,))
        row = cur.fetchone()
        if not row:
            return None

        record = dict(row)
        cur.execute(
            f"SELECT * FROM triggered_rules WHERE assessment_id = {ph} ORDER BY weight DESC",
            (assessment_id,)
        )
        rules = [dict(r) for r in cur.fetchall()]
        record["triggered_rules"] = rules
        return record


def get_assessments(
    limit: int = 20,
    offset: int = 0,
    search_query: Optional[str] = None,
    risk_filter: Optional[str] = None
) -> Tuple[List[Dict[str, Any]], int]:
    """Retrieve paginated assessment history with parameterized search and filter."""
    with get_db_cursor() as (cur, engine):
        ph = "%s" if engine == "mysql" else "?"
        conditions = []
        params: List[Any] = []

        if search_query:
            conditions.append(f"(host LIKE {ph} OR raw_url LIKE {ph})")
            pattern = f"%{search_query.strip()}%"
            params.extend([pattern, pattern])

        if risk_filter and risk_filter.upper() in ("LOW_RISK", "SUSPICIOUS", "HIGH_RISK"):
            conditions.append(f"risk_level = {ph}")
            params.append(risk_filter.upper())

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        # Total count
        count_sql = f"SELECT COUNT(*) AS total FROM assessments {where_clause}"
        cur.execute(count_sql, tuple(params))
        total_count = cur.fetchone()["total"]

        # Page query
        select_sql = f"""
            SELECT id, raw_url, normalized_url, host, scheme,
                   risk_score, risk_level, color, breakdown_summary, created_at
            FROM assessments
            {where_clause}
            ORDER BY created_at DESC
            LIMIT {ph} OFFSET {ph}
        """
        fetch_params = tuple(params + [limit, offset])
        cur.execute(select_sql, fetch_params)
        records = [dict(row) for row in cur.fetchall()]

        return records, total_count


def get_aggregate_stats() -> Dict[str, Any]:
    """Aggregate statistics for dashboard metrics."""
    with get_db_cursor() as (cur, engine):
        cur.execute("""
            SELECT 
                COUNT(*) AS total_scans,
                COALESCE(AVG(risk_score), 0) AS avg_risk_score
            FROM assessments
        """)
        totals = cur.fetchone() or {"total_scans": 0, "avg_risk_score": 0}

        cur.execute("""
            SELECT risk_level, COUNT(*) AS count
            FROM assessments
            GROUP BY risk_level
        """)
        level_counts = {row["risk_level"]: row["count"] for row in cur.fetchall()}

        cur.execute("""
            SELECT rule_id, rule_name, category, COUNT(*) as trigger_count
            FROM triggered_rules
            GROUP BY rule_id, rule_name, category
            ORDER BY trigger_count DESC
            LIMIT 5
        """)
        top_rules = [dict(r) for r in cur.fetchall()]

        return {
            "total_scans": totals["total_scans"],
            "avg_risk_score": round(float(totals["avg_risk_score"]), 1),
            "low_risk_count": level_counts.get("LOW_RISK", 0),
            "suspicious_count": level_counts.get("SUSPICIOUS", 0),
            "high_risk_count": level_counts.get("HIGH_RISK", 0),
            "top_rules": top_rules
        }
