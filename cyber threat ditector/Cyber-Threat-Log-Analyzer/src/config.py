"""
config.py
=========
Central place for file paths and detection thresholds.

Why a config file?
    Instead of "hardcoding" numbers like 5 or 100 inside our detection code,
    we keep them here. To make the tool more (or less) sensitive you only
    change ONE number in ONE file. Every other module imports from here.
"""

from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
# __file__ is this file (src/config.py). .parent is the "src" folder and
# .parent.parent is the project root folder. Using pathlib means the paths
# work on Windows, macOS and Linux without changes.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
REPORTS_DIR = PROJECT_ROOT / "reports"

DEFAULT_ACCESS_LOG = DATA_DIR / "access_logs.csv"
DEFAULT_AUTH_LOG = DATA_DIR / "auth_logs.csv"

# ---------------------------------------------------------------------------
# Expected log columns (the loader will validate against these in Day 2)
# ---------------------------------------------------------------------------
ACCESS_LOG_COLUMNS = [
    "timestamp",     # when the request happened
    "ip_address",    # who sent it
    "username",      # logged-in user, or "-" for anonymous visitors
    "method",        # GET, POST, ...
    "path",          # requested URL path (+ query string)
    "status_code",   # HTTP response code (200, 404, 401 ...)
    "bytes_sent",    # response size in bytes
    "user_agent",    # browser / tool that made the request
]

AUTH_LOG_COLUMNS = [
    "timestamp",
    "ip_address",
    "username",
    "event_type",    # LOGIN_SUCCESS, LOGIN_FAILED or LOGOUT
    "service",       # web, ssh or vpn
    "message",       # human-readable reason
]

TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"

# ---------------------------------------------------------------------------
# Detection thresholds (all configurable)
# ---------------------------------------------------------------------------
THRESHOLDS = {
    # Failed logins
    "failed_login_per_ip": 5,           # >= this many failures from one IP = flagged
    "failed_login_per_username": 10,    # >= this many failures against one username

    # Brute force (sliding time window)
    "brute_force_attempts": 10,         # failures needed inside the window...
    "brute_force_window_minutes": 5,     # ...of this many minutes

    # Suspicious IP behaviour
    "high_request_volume_per_ip": 100,  # total requests from one IP
    "error_responses_per_ip": 15,       # combined 401 / 403 / 404 responses
    "restricted_path_hits": 5,          # hits on sensitive paths

    # Traffic spikes (statistics)
    "traffic_spike_zscore": 3.0,        # how many standard deviations above average
}

# Paths that normal visitors rarely need. Hits here are only *indicators*.
RESTRICTED_PATHS = [
    "/admin",
    "/login",
    "/config",
    "/.env",
    "/.git",
    "/phpmyadmin",
    "/wp-admin",
    "/wp-login.php",
    "/server-status",
    "/backup",
    "/console",
]

# HTTP responses that suggest "access denied" or "probing"
SUSPICIOUS_STATUS_CODES = [401, 403, 404]

# Risk scoring (used from Day 4): score >= cutoff gives that level
RISK_LEVELS = {
    "LOW": 1,
    "MEDIUM": 3,
    "HIGH": 6,
    "CRITICAL": 10,
}
