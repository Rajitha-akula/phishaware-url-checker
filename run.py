"""
Application Entry Point.
Run directly with: python run.py
"""

from app import create_app
from config import Config

app = create_app()

if __name__ == "__main__":
    print("\n" + "=" * 65)
    print("  Phishing Awareness & URL Risk Checker Web Server")
    print("=" * 65)
    print("  * Access the Application: http://127.0.0.1:5000")
    print("  * Environment           : Local Development")
    print("  * Zero Outbound Requests: ACTIVE (Zero SSRF Risk)")
    print("  * Security Headers      : ACTIVE (CSP, X-Frame-Options)")
    print("=" * 65 + "\n")
    app.run(host="127.0.0.1", port=5000, debug=Config.DEBUG)
