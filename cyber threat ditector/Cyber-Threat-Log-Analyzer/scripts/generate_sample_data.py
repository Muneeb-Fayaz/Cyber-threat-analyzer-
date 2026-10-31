#!/usr/bin/env python3
"""
generate_sample_data.py
=======================
Creates SYNTHETIC (fake) server and authentication logs for testing the
Cyber Threat Log Analyzer.

*** ALL DATA PRODUCED HERE IS ARTIFICIAL. ***
No real users, companies, systems or networks are involved.

IP address ranges used (all reserved for documentation / testing, RFC 5737 and
RFC 2544, so they never belong to real servers):
    10.0.0.x, 192.168.1.x   -> "internal" normal users
    198.18.x.x              -> "external" normal users and website visitors
    203.0.113.x, 192.0.2.x, 198.51.100.x -> simulated ATTACKERS

The script uses a fixed random seed, so every run creates identical files.
That makes testing and debugging predictable.

Usage (from the project root folder):
    python scripts/generate_sample_data.py
"""

import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------
SEED = 42                                  # same seed = same data every run
BASE_DATE = datetime(2026, 10, 25)         # the simulated day (midnight)
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
TEST_DIR = DATA_DIR / "test_cases"

ACCESS_COLUMNS = ["timestamp", "ip_address", "username", "method",
                  "path", "status_code", "bytes_sent", "user_agent"]
AUTH_COLUMNS = ["timestamp", "ip_address", "username",
                "event_type", "service", "message"]

# ---------------------------------------------------------------------------
# Actors: normal users and attackers
# ---------------------------------------------------------------------------
NORMAL_USERS = {                           # username -> usual IP address
    "alice": "10.0.0.11",   "bob": "10.0.0.12",     "carol": "10.0.0.13",
    "dave": "10.0.0.14",    "eve": "10.0.0.15",     "frank": "192.168.1.21",
    "grace": "192.168.1.22", "heidi": "192.168.1.23", "ivan": "192.168.1.24",
    "judy": "192.168.1.25", "karl": "198.18.0.31",  "laura": "198.18.0.32",
    "mike": "198.18.0.33",  "nina": "198.18.0.34",
}
VISITOR_IPS = [f"198.18.1.{n}" for n in range(10, 40)]   # anonymous visitors

BRUTE_FORCE_IP = "203.0.113.45"     # hammers the web login for "admin"
SPRAY_IP = "192.0.2.88"             # tries many usernames over SSH
LOW_SLOW_IP = "198.51.100.77"       # slow attempts that hide among normal traffic
HIGH_VOLUME_IP = "203.0.113.50"     # floods the server with requests
SCANNER_IP = "198.51.100.23"        # probes for sensitive files
SQLI_IP = "192.0.2.77"              # SQL-injection-like requests
TRAVERSAL_IP = "198.51.100.99"      # directory-traversal-like requests
XSS_IP = "203.0.113.99"             # script-injection-like requests
UNAUTHORIZED_IPS = ["203.0.113.12", "192.0.2.140"]   # repeated 401/403 on /admin

BROWSER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/118.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/119.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile Safari/604.1",
]

# Normal website traffic: (method, path, weight). Higher weight = more common.
NORMAL_REQUESTS = [
    ("GET", "/", 22), ("GET", "/home", 14), ("GET", "/about", 5),
    ("GET", "/contact", 5), ("GET", "/products", 12),
    ("GET", "/products/item-101", 4), ("GET", "/products/item-205", 4),
    ("GET", "/products/item-318", 3), ("GET", "/blog", 6),
    ("GET", "/blog/security-tips", 3), ("GET", "/static/css/style.css", 8),
    ("GET", "/static/js/app.js", 8), ("GET", "/static/img/logo.png", 6),
    ("GET", "/api/items", 6), ("GET", "/search?q=laptop", 3),
    ("POST", "/api/cart", 3), ("GET", "/favicon.ico", 4),
]

# Hours 0-23: how busy the site is. Daytime gets more traffic than night.
HOUR_WEIGHTS = [1, 1, 1, 1, 1, 1, 3, 4, 8,
                10, 10, 10, 10, 10, 10, 10, 10, 10,
                6, 5, 4, 3, 2, 2]

SENSITIVE_PATHS = [
    "/admin", "/admin/login", "/config", "/config.php", "/.env",
    "/.git/config", "/phpmyadmin", "/wp-login.php", "/wp-admin",
    "/backup.zip", "/server-status", "/console", "/login", "/api/v1/users",
]

SQLI_PATHS = [
    "/products?id=1' OR '1'='1",
    "/products?id=1 UNION SELECT username,password FROM users--",
    "/login?user=admin'--",
    "/search?q=1; DROP TABLE users;--",
    "/products?id=1' AND SLEEP(5)--",
    "/api/items?id=-1 UNION ALL SELECT NULL,NULL,version()--",
    "/products?cat=1' OR 1=1#",
    "/search?q=' OR 'a'='a",
]

TRAVERSAL_PATHS = [
    "/download?file=../../etc/passwd",
    "/download?file=..%2f..%2f..%2fetc%2fshadow",
    "/static/../../../windows/win.ini",
    "/files?name=....//....//etc/passwd",
    "/view?page=%2e%2e%2f%2e%2e%2fconfig.php",
    "/download?file=..\\..\\boot.ini",
]

XSS_PATHS = [
    "/search?q=<script>alert(1)</script>",
    "/comment?text=<img src=x onerror=alert(1)>",
    "/search?q=%3Cscript%3Ealert('xss')%3C/script%3E",
    "/profile?name=<svg/onload=alert(1)>",
    "/redirect?url=javascript:alert(document.cookie)",
    "/search?q=<iframe src=javascript:alert(1)>",
]


# ---------------------------------------------------------------------------
# Small helper functions
# ---------------------------------------------------------------------------
def make_time(hour, minute=0, second=0):
    """Return a datetime on the simulated day at the given time."""
    return BASE_DATE + timedelta(hours=hour, minutes=minute, seconds=second)


def random_daytime():
    """Pick a random time, busier during the day (uses HOUR_WEIGHTS)."""
    hour = random.choices(range(24), weights=HOUR_WEIGHTS)[0]
    return make_time(hour, random.randint(0, 59), random.randint(0, 59))


def bytes_for(status):
    """Return a believable response size for an HTTP status code."""
    if status == 304:
        return 0
    if status in (301, 302):
        return 250
    if status == 200:
        return random.randint(800, 48000)
    if status == 201:
        return random.randint(200, 600)
    return random.randint(180, 1500)


def access_row(ts, ip, username, method, path, status, agent):
    """Build one access-log row as a list (same order as ACCESS_COLUMNS)."""
    return [ts.strftime(TIME_FORMAT), ip, username, method, path,
            status, bytes_for(status), agent]


def auth_row(ts, ip, username, event_type, service, message):
    """Build one authentication-log row (same order as AUTH_COLUMNS)."""
    return [ts.strftime(TIME_FORMAT), ip, username, event_type, service, message]


def write_csv(path, columns, rows):
    """Write a header line plus rows to a CSV file."""
    with open(path, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(columns)
        writer.writerows(rows)


# ---------------------------------------------------------------------------
# Access log scenarios
# ---------------------------------------------------------------------------
def build_normal_access(count=520):
    """Everyday traffic from known users and anonymous visitors."""
    rows = []
    users = list(NORMAL_USERS.items())
    weights = [item[2] for item in NORMAL_REQUESTS]
    for _ in range(count):
        if random.random() < 0.4:                      # logged-in user
            username, ip = random.choice(users)
        else:                                          # anonymous visitor
            username, ip = "-", random.choice(VISITOR_IPS)
        method, path, _w = random.choices(NORMAL_REQUESTS, weights=weights)[0]
        if method == "POST":
            status = random.choices([201, 200, 500], [85, 13, 2])[0]
        else:
            status = random.choices([200, 304, 301, 404, 500],
                                    [86, 8, 2, 3, 1])[0]
        rows.append(access_row(random_daytime(), ip, username, method, path,
                               status, random.choice(BROWSER_AGENTS)))
    return rows


def build_legit_admin_access():
    """A real administrator using /admin: a harmless 'false positive' case."""
    rows = []
    start = make_time(9, 30)
    for i, path in enumerate(["/admin", "/admin/dashboard", "/admin/users",
                              "/admin", "/admin/settings", "/admin/dashboard"]):
        rows.append(access_row(start + timedelta(minutes=7 * i), "10.0.0.11",
                               "alice", "GET", path, 200, BROWSER_AGENTS[0]))
    return rows


def build_high_volume_access(count=180):
    """One IP sends ~180 requests in about 5 minutes (flood / scraping)."""
    rows = []
    start = make_time(14, 20)
    paths = ["/api/items", "/products", "/search?q=phone", "/", "/api/items?page=2"]
    for i in range(count):
        ts = start + timedelta(seconds=int(i * 330 / count))
        if i < 110:
            status = 200
        else:                                   # server starts rate-limiting
            status = random.choices([200, 429], [30, 70])[0]
        rows.append(access_row(ts, HIGH_VOLUME_IP, "-", "GET",
                               random.choice(paths), status,
                               "python-requests/2.31.0"))
    return rows


def build_scanner_access(count=60):
    """Reconnaissance: one IP probes many sensitive paths (mostly 404/403/401)."""
    rows = []
    start = make_time(2, 10)
    for i in range(count):
        status = random.choices([404, 403, 401, 200], [55, 25, 15, 5])[0]
        rows.append(access_row(start + timedelta(seconds=15 * i + random.randint(0, 5)),
                               SCANNER_IP, "-", "GET",
                               random.choice(SENSITIVE_PATHS), status,
                               "Nikto/2.5.0"))
    return rows


def build_sqli_access():
    """SQL-injection-like request strings from one IP."""
    rows = []
    start = make_time(9, 42)
    for i in range(14):
        status = random.choices([200, 400, 500], [40, 30, 30])[0]
        rows.append(access_row(start + timedelta(seconds=35 * i), SQLI_IP, "-",
                               "GET", random.choice(SQLI_PATHS), status,
                               "sqlmap/1.7.8#stable"))
    return rows


def build_traversal_access():
    """Directory-traversal-like requests (../ sequences) from one IP."""
    rows = []
    start = make_time(21, 15)
    for i in range(10):
        status = random.choices([400, 403, 404], [30, 40, 30])[0]
        rows.append(access_row(start + timedelta(seconds=20 * i), TRAVERSAL_IP,
                               "-", "GET", random.choice(TRAVERSAL_PATHS),
                               status, "curl/8.4.0"))
    return rows


def build_xss_access():
    """Script-injection-like request strings from one IP."""
    rows = []
    start = make_time(19, 30)
    for i in range(8):
        status = random.choices([200, 400, 403], [40, 30, 30])[0]
        rows.append(access_row(start + timedelta(seconds=45 * i), XSS_IP, "-",
                               "GET", random.choice(XSS_PATHS), status,
                               BROWSER_AGENTS[2]))
    return rows


def build_unauthorized_access():
    """Repeated 401/403 responses when requesting admin / config pages."""
    rows = []
    for ip in UNAUTHORIZED_IPS:
        start = random_daytime()
        for i in range(14):
            rows.append(access_row(start + timedelta(seconds=40 * i), ip, "-",
                                   "GET",
                                   random.choice(["/admin", "/admin/users", "/config"]),
                                   random.choice([401, 403]), "curl/8.4.0"))
    return rows


def access_rows_from_auth(auth_rows):
    """Mirror the web brute-force attempts as POST /login requests, so the
    access log and the auth log tell the same story."""
    rows = []
    for ts, ip, username, event_type, _service, _msg in auth_rows:
        if ip == BRUTE_FORCE_IP:
            ok = event_type == "LOGIN_SUCCESS"
            status = 302 if ok else 401
            rows.append([ts, ip, username if ok else "-", "POST", "/login",
                         status, bytes_for(status), "python-requests/2.31.0"])
    return rows


# ---------------------------------------------------------------------------
# Authentication log scenarios
# ---------------------------------------------------------------------------
def build_normal_auth():
    """Normal logins/logouts, with the occasional mistyped password."""
    rows = []
    for username, ip in NORMAL_USERS.items():
        for _ in range(random.randint(3, 6)):
            login_time = make_time(random.randint(7, 17), random.randint(0, 59),
                                   random.randint(0, 59))
            service = random.choice(["web", "vpn", "ssh"])
            if random.random() < 0.12:         # typo first, then success
                rows.append(auth_row(login_time - timedelta(seconds=random.randint(10, 40)),
                                     ip, username, "LOGIN_FAILED", service,
                                     "Invalid password"))
            rows.append(auth_row(login_time, ip, username, "LOGIN_SUCCESS",
                                 service, "Accepted password"))
            logout_time = login_time + timedelta(minutes=random.randint(20, 240))
            rows.append(auth_row(logout_time, ip, username, "LOGOUT",
                                 service, "Session closed"))
    return rows


def build_brute_force_auth():
    """58 failures in ~5 minutes against 'admin', then a SUCCESS (suspicious!)."""
    rows = []
    ts = make_time(4, 30)
    for _ in range(58):
        rows.append(auth_row(ts, BRUTE_FORCE_IP, "admin", "LOGIN_FAILED",
                             "web", "Invalid password"))
        ts += timedelta(seconds=random.randint(3, 7))
    rows.append(auth_row(ts, BRUTE_FORCE_IP, "admin", "LOGIN_SUCCESS",
                         "web", "Accepted password"))
    return rows


def build_password_spray_auth():
    """One IP tries 10 common usernames, 3 times each (password spraying)."""
    rows = []
    ts = make_time(10, 5)
    for username in ["admin", "root", "test", "guest", "oracle",
                     "postgres", "ubuntu", "user", "support", "backup"]:
        for _ in range(3):
            message = ("Invalid password" if username in ("admin", "root")
                       else "Unknown user")
            rows.append(auth_row(ts, SPRAY_IP, username, "LOGIN_FAILED",
                                 "ssh", message))
            ts += timedelta(seconds=random.randint(15, 25))
    return rows


def build_low_and_slow_auth():
    """12 attempts spread over ~2 hours: too slow for a 5-minute window."""
    rows = []
    ts = make_time(11, 0)
    for _ in range(12):
        rows.append(auth_row(ts, LOW_SLOW_IP, "admin", "LOGIN_FAILED",
                             "ssh", "Invalid password"))
        ts += timedelta(minutes=random.randint(8, 12))
    return rows


def build_distributed_attack_auth():
    """Six different IPs each try 'root' a couple of times (distributed attack)."""
    rows = []
    for n in range(101, 107):
        ip = f"203.0.113.{n}"
        ts = make_time(16, random.randint(0, 50))
        for _ in range(random.randint(2, 3)):
            rows.append(auth_row(ts, ip, "root", "LOGIN_FAILED", "ssh",
                                 "Invalid password"))
            ts += timedelta(seconds=random.randint(30, 120))
    return rows


# ---------------------------------------------------------------------------
# Edge-case files for testing (used on Day 7)
# ---------------------------------------------------------------------------
def write_test_cases(access_rows):
    """Create small broken / unusual files to test error handling."""
    TEST_DIR.mkdir(parents=True, exist_ok=True)
    sample = access_rows[:20]

    # 1. Completely empty file (0 bytes)
    (TEST_DIR / "empty_file.csv").write_text("", encoding="utf-8")

    # 2. Header only, no data rows
    write_csv(TEST_DIR / "header_only.csv", ACCESS_COLUMNS, [])

    # 3. Missing columns: 'path' and 'status_code' removed
    keep = [i for i, col in enumerate(ACCESS_COLUMNS)
            if col not in ("path", "status_code")]
    write_csv(TEST_DIR / "missing_columns.csv",
              [ACCESS_COLUMNS[i] for i in keep],
              [[row[i] for i in keep] for row in sample])

    # 4. Invalid timestamps
    bad_time = [row[:] for row in sample]
    bad_time[2][0] = "not-a-date"
    bad_time[5][0] = "2026-13-45 99:99:99"
    bad_time[8][0] = ""
    bad_time[11][0] = "25-Oct-2026 08:00"
    write_csv(TEST_DIR / "invalid_timestamps.csv", ACCESS_COLUMNS, bad_time)

    # 5. Duplicate records (first 5 rows appear three times)
    write_csv(TEST_DIR / "duplicate_records.csv", ACCESS_COLUMNS,
              sample + sample[:5] + sample[:5])

    # 6. Corrupted rows: some lines have too few fields
    with open(TEST_DIR / "malformed_rows.csv", "w", newline="",
              encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(ACCESS_COLUMNS)
        for i, row in enumerate(sample):
            writer.writerow(row[:4] if i in (3, 7, 12) else row)


# ---------------------------------------------------------------------------
# Main program
# ---------------------------------------------------------------------------
def main():
    random.seed(SEED)
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # Authentication logs
    auth_rows = (build_normal_auth() + build_brute_force_auth()
                 + build_password_spray_auth() + build_low_and_slow_auth()
                 + build_distributed_attack_auth())
    auth_rows.sort(key=lambda row: row[0])     # ISO timestamps sort correctly

    # Access logs
    access_rows = (build_normal_access() + build_legit_admin_access()
                   + build_high_volume_access() + build_scanner_access()
                   + build_sqli_access() + build_traversal_access()
                   + build_xss_access() + build_unauthorized_access()
                   + access_rows_from_auth(auth_rows))
    access_rows.sort(key=lambda row: row[0])

    write_csv(DATA_DIR / "access_logs.csv", ACCESS_COLUMNS, access_rows)
    write_csv(DATA_DIR / "auth_logs.csv", AUTH_COLUMNS, auth_rows)
    write_test_cases(access_rows)

    print("SYNTHETIC datasets generated successfully")
    print(f"  data/access_logs.csv : {len(access_rows)} entries")
    print(f"  data/auth_logs.csv   : {len(auth_rows)} entries")
    print(f"  Total                : {len(access_rows) + len(auth_rows)} entries")
    print(f"  data/test_cases/     : 6 edge-case files")


if __name__ == "__main__":
    main()
