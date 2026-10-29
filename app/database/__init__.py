"""
Database package initialization.
"""

from app.database.db import (
    init_db,
    save_assessment,
    get_assessment_by_id,
    get_assessments,
    get_aggregate_stats,
    check_db_connection
)

__all__ = [
    "init_db",
    "save_assessment",
    "get_assessment_by_id",
    "get_assessments",
    "get_aggregate_stats",
    "check_db_connection"
]
