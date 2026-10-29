"""
REST API Endpoints for URL Risk Analysis and Telemetry.

Security Principles:
1. Strict Request Parsing: Handles both JSON and Form encodings with size limits.
2. Safe Validation: Validates before evaluation; returns clean JSON error responses.
3. Zero Outbound Requests: Ensures evaluation is 100% offline.
4. Parameterized DB Queries: Guarantees SQL injection defense on all searches.
"""

from flask import Blueprint, request, jsonify
from app.engine.normalizer import normalize_url, ValidationError
from app.engine.heuristics import evaluate_url_risk
from app.database.db import (
    save_assessment,
    get_assessment_by_id,
    get_assessments,
    get_aggregate_stats,
    check_db_connection
)

api_bp = Blueprint("api", __name__)


@api_bp.route("/analyze", methods=["POST"])
def analyze_url_endpoint():
    """
    POST /api/analyze
    Payload: {"url": "https://example.com"} or form-encoded 'url'.
    Evaluates heuristic risk, records assessment in the database, and returns results.
    """
    data = request.get_json(silent=True) or request.form

    raw_url = data.get("url") if data else None
    if not raw_url or not isinstance(raw_url, str) or not raw_url.strip():
        return jsonify({
            "success": False,
            "error": "Missing URL input",
            "message": "Please enter a URL to analyze."
        }), 400

    # 1. Normalize and Validate URL Input safely
    try:
        normalized = normalize_url(raw_url)
    except ValidationError as err:
        return jsonify({
            "success": False,
            "error": "Invalid URL",
            "message": str(err)
        }), 400
    except Exception as exc:
        return jsonify({
            "success": False,
            "error": "Parsing Exception",
            "message": f"Failed to parse URL: {str(exc)}"
        }), 400

    # 2. Evaluate Heuristic Risk offline
    try:
        assessment = evaluate_url_risk(normalized)
    except Exception as exc:
        return jsonify({
            "success": False,
            "error": "Evaluation Failed",
            "message": f"Heuristics engine error: {str(exc)}"
        }), 500

    # 3. Store Assessment in Database atomically
    saved_id = None
    try:
        saved_id = save_assessment(assessment)
    except Exception as exc:
        # Non-fatal log: if database write encounters an issue, analysis still returns
        print(f"[WARN] Failed to write assessment to database: {exc}")

    response_data = assessment.to_dict()
    response_data["id"] = saved_id
    response_data["success"] = True

    return jsonify(response_data), 200


@api_bp.route("/history", methods=["GET"])
def history_endpoint():
    """
    GET /api/history?limit=20&offset=0&q=keyword&level=HIGH_RISK
    Retrieves paginated scan history with optional search and risk-level filters.
    """
    try:
        limit = min(max(int(request.args.get("limit", 20)), 1), 100)
    except (ValueError, TypeError):
        limit = 20

    try:
        offset = max(int(request.args.get("offset", 0)), 0)
    except (ValueError, TypeError):
        offset = 0

    search_query = request.args.get("q", "").strip() or None
    risk_filter = request.args.get("level", "").strip().upper() or None

    try:
        records, total_count = get_assessments(
            limit=limit,
            offset=offset,
            search_query=search_query,
            risk_filter=risk_filter
        )
        return jsonify({
            "success": True,
            "items": records,
            "total": total_count,
            "limit": limit,
            "offset": offset
        }), 200
    except Exception as exc:
        return jsonify({
            "success": False,
            "error": "Database Query Failed",
            "message": str(exc)
        }), 500


@api_bp.route("/stats", methods=["GET"])
def stats_endpoint():
    """
    GET /api/stats
    Retrieves aggregate risk metrics and top triggered rules.
    """
    try:
        stats = get_aggregate_stats()
        is_conn, engine_name, msg = check_db_connection()
        stats["database_engine"] = engine_name
        stats["database_status"] = msg
        return jsonify({"success": True, "stats": stats}), 200
    except Exception as exc:
        return jsonify({
            "success": False,
            "error": "Failed to retrieve statistics",
            "message": str(exc)
        }), 500


@api_bp.route("/assessment/<int:assessment_id>", methods=["GET"])
def get_assessment_endpoint(assessment_id: int):
    """
    GET /api/assessment/<id>
    Fetches full assessment details including all triggered rules.
    """
    try:
        record = get_assessment_by_id(assessment_id)
        if not record:
            return jsonify({
                "success": False,
                "error": "Not Found",
                "message": f"Assessment #{assessment_id} was not found."
            }), 404
        return jsonify({"success": True, "assessment": record}), 200
    except Exception as exc:
        return jsonify({
            "success": False,
            "error": "Database error",
            "message": str(exc)
        }), 500
