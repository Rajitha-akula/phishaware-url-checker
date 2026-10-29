"""
CLI utility to test database connectivity and initialize tables.
Run with: python init_db.py
"""

import sys
from config import Config
from app.database.db import check_db_connection, init_db


def main():
    print("=" * 60)
    print("  URL Risk Checker - Database Setup & Connectivity Check")
    print("=" * 60)
    print(f"Target Database Host : {Config.DB_HOST}:{Config.DB_PORT}")
    print(f"Target Database User : {Config.DB_USER}")
    print(f"Target Database Name : {Config.DB_NAME}")
    print("-" * 60)

    success, msg = check_db_connection()
    if not success:
        print("\n[!] Connection Failed:")
        print(f"    {msg}")
        print("\nTroubleshooting Guidance:")
        print("1. Check that the MySQL service is running (e.g. MySQL80).")
        print("2. Ensure your password is set in a .env file: DB_PASSWORD=your_password")
        print("3. Refer to .env.example for available configuration options.")
        sys.exit(1)

    print("\n[+] Database server is reachable!")
    try:
        init_db()
        print(f"[+] Database '{Config.DB_NAME}' and tables created successfully!")
    except Exception as exc:
        print(f"[!] Failed to initialize tables: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
