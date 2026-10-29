"""
Flask Application Factory.

Initializes the Flask app with security headers, route blueprints,
and centralized error handling to prevent information disclosure.
"""

from flask import Flask, jsonify, request
from config import Config
from app.database.db import init_db


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize database tables on app startup
    with app.app_context():
        try:
            init_db()
        except Exception as exc:
            app.logger.warning(f"Database initialization deferred: {exc}")

    # Register blueprints
    from app.routes.api import api_bp
    from app.routes.views import views_bp
    app.register_blueprint(api_bp, url_prefix="/api")
    app.register_blueprint(views_bp)

    # -----------------------------------------------------------------
    # Defense-in-Depth: Security Headers Middleware
    # -----------------------------------------------------------------
    @app.after_request
    def set_security_headers(response):
        """
        Inject security headers into every HTTP response.
        - X-Frame-Options: Prevents clickjacking by blocking iframe embedding.
        - X-Content-Type-Options: Prevents MIME-type sniffing.
        - Content-Security-Policy: Limits script execution and resource loading.
        - Referrer-Policy: Prevents leaking full URLs in the Referer header.
        - Permissions-Policy: Disables unused browser hardware capabilities.
        """
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self';"
        )
        return response

    # -----------------------------------------------------------------
    # Centralized Error Handlers (Prevents Stack Trace Leaks)
    # -----------------------------------------------------------------
    @app.errorhandler(400)
    def bad_request(error):
        if request.path.startswith("/api/"):
            return jsonify({"success": False, "error": "Bad Request", "details": str(error.description)}), 400
        return jsonify({"error": "Bad Request", "details": str(error.description)}), 400

    @app.errorhandler(404)
    def not_found(error):
        if request.path.startswith("/api/"):
            return jsonify({"success": False, "error": "Resource Not Found"}), 404
        return jsonify({"error": "Page Not Found"}), 404

    @app.errorhandler(405)
    def method_not_allowed(error):
        if request.path.startswith("/api/"):
            return jsonify({"success": False, "error": "HTTP Method Not Allowed"}), 405
        return jsonify({"error": "Method Not Allowed"}), 405

    @app.errorhandler(500)
    def server_error(error):
        if request.path.startswith("/api/"):
            return jsonify({"success": False, "error": "Internal Server Error"}), 500
        return jsonify({"error": "An unexpected error occurred."}), 500

    return app
