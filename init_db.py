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

    is_connected, engine_name, msg = check_db_connection()
    print(f"Active Storage Engine: {engine_name}")
    print(f"Engine Status        : {msg}")
    print("-" * 60)

    if not is_connected:
        print("\n[!] Connection Failed:")
        print(f"    {msg}")
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
