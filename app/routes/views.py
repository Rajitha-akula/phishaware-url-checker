"""
Web Interface Views Blueprint.
Renders responsive HTML templates with safe contextual escaping (anti-XSS).
"""

from flask import Blueprint, render_template
from app.engine.rules import RULES_CATALOG

views_bp = Blueprint("views", __name__)


@views_bp.route("/", methods=["GET"])
def index_view():
    """Main URL Risk Checker & Phishing Awareness Dashboard."""
    return render_template("index.html")


@views_bp.route("/history", methods=["GET"])
def history_view():
    """Historical assessments table with search, filtering, and inspection."""
    return render_template("history.html")


@views_bp.route("/stats", methods=["GET"])
def stats_view():
    """Telemetry and security risk statistics dashboard."""
    return render_template("stats.html")


@views_bp.route("/education", methods=["GET"])
def education_view():
    """Educational catalog explaining all 13 heuristic rules and safe browsing habits."""
    rules_list = sorted(RULES_CATALOG.values(), key=lambda r: r.rule_id)
    return render_template("education.html", rules=rules_list)
