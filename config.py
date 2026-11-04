"""
Configuration file for Security Log Analyzer (CodeNova Task 4).
Contains application settings, file upload constraints, and detection thresholds.
"""

import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'codenova-soc-log-analyzer-key-2026')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max upload limit
    ALLOWED_EXTENSIONS = {'log', 'txt'}

    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    SAMPLES_FOLDER = os.path.join(BASE_DIR, 'samples')
    REPORTS_FOLDER = os.path.join(BASE_DIR, 'reports')

    # Temporal & Localization Settings
    DEFAULT_YEAR = 2026  # Year inference for Linux syslog timestamps without year
    TIMEZONE = 'UTC'     # Explicit timezone assumption for normalized analysis

    # Business Hours definition (24-hour clock, Monday to Friday)
    BUSINESS_HOURS_START = 8   # 08:00 AM
    BUSINESS_HOURS_END = 18    # 06:00 PM

    # Detection Thresholds
    FAILED_LOGIN_LOW_MIN = 1
    FAILED_LOGIN_MED_MIN = 4
    FAILED_LOGIN_HIGH_MIN = 6

    BURST_WINDOW_SECONDS = 60
    BURST_COUNT_THRESHOLD = 4

    MULTIPLE_USERNAMES_THRESHOLD = 3
    HTTP_ERROR_BURST_THRESHOLD = 5
