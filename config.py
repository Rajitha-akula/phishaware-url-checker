"""
Application Configuration and Environment Settings.
Loads secrets safely from .env file using python-dotenv.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Base directory of the project
BASE_DIR = Path(__file__).resolve().parent

# Load .env file if present
load_dotenv(BASE_DIR / ".env")


class Config:
    """Base application configuration with safe defaults."""
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secure-key-change-in-production-39a8f7c1")
    DEBUG = os.getenv("FLASK_DEBUG", "True").lower() in ("true", "1", "yes")

    # MySQL Database Settings
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_PORT = int(os.getenv("DB_PORT", "3306"))
    DB_USER = os.getenv("DB_USER", "root")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "")
    DB_NAME = os.getenv("DB_NAME", "phishing_checker_db")

    # Database connection timeout in seconds
    DB_CONNECT_TIMEOUT = 5
