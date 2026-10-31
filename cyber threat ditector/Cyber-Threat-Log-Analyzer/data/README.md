# 📂 Dataset Information

> ⚠️ **ALL DATA IN THIS FOLDER IS SYNTHETIC (FAKE).**
> No real users, companies, servers or networks are represented.
> IP addresses come from ranges reserved for documentation and testing
> (RFC 5737, RFC 2544) and never belong to real machines.

## Files

| File | Entries | Purpose |
|------|--------:|---------|
| `access_logs.csv` | 885 | Web server access log (requests, paths, status codes) |
| `auth_logs.csv` | 242 | Authentication log (logins, failures, logouts) |
| `test_cases/` | 6 files | Deliberately broken files for error-handling tests |

Regenerate everything (identical output every time, seed = 42):

```bash
python scripts/generate_sample_data.py
```

## Columns

**access_logs.csv**

| Column | Example |
|--------|---------|
| `timestamp` | `2026-10-25 14:20:03` |
| `ip_address` | `203.0.113.50` |
| `username` | `alice` (or `-` for anonymous) |
| `method` | `GET` |
| `path` | `/admin` |
| `status_code` | `403` |
| `bytes_sent` | `512` |
| `user_agent` | `curl/8.4.0` |

**auth_logs.csv**

| Column | Example |
|--------|---------|
| `timestamp` | `2026-10-25 04:30:03` |
| `ip_address` | `203.0.113.45` |
| `username` | `admin` |
| `event_type` | `LOGIN_SUCCESS` / `LOGIN_FAILED` / `LOGOUT` |
| `service` | `web` / `ssh` / `vpn` |
| `message` | `Invalid password` |

## Simulated scenarios

| Scenario | Source IP | What it looks like |
|----------|-----------|--------------------|
| Normal activity | `10.0.0.x`, `192.168.1.x`, `198.18.x.x` | Everyday browsing and logins, occasional typos |
| Legitimate admin | `10.0.0.11` | User `alice` visiting `/admin` (a harmless *false-positive* test) |
| Brute force | `203.0.113.45` | 58 failed `admin` logins in about 5 minutes, then one success |
| Password spraying | `192.0.2.88` | 10 common usernames × 3 attempts over SSH |
| Low-and-slow | `198.51.100.77` | 12 attempts over ~2 hours (evades short time windows) |
| Distributed attack | `203.0.113.101`–`106` | Six IPs each trying `root` 2–3 times |
| High-volume flood | `203.0.113.50` | 180 requests in ~5.5 minutes, then HTTP 429 |
| Reconnaissance scan | `198.51.100.23` | 60 probes of `/admin`, `/.env`, `/config` … (404/403/401) |
| SQL-injection-like | `192.0.2.77` | `' OR '1'='1`, `UNION SELECT` … |
| Directory-traversal-like | `198.51.100.99` | `../../etc/passwd` and encoded variants |
| Script-injection-like | `203.0.113.99` | `<script>`, `onerror=`, `javascript:` |
| Unauthorized access | `203.0.113.12`, `192.0.2.140` | Repeated 401/403 on `/admin` and `/config` |

## Edge-case files (`test_cases/`)

| File | Problem it simulates |
|------|----------------------|
| `empty_file.csv` | 0 bytes |
| `header_only.csv` | Header row but no data |
| `missing_columns.csv` | `path` and `status_code` columns missing |
| `invalid_timestamps.csv` | `not-a-date`, impossible dates, blank, unusual format |
| `duplicate_records.csv` | First 5 rows repeated three times |
| `malformed_rows.csv` | Rows with too few fields |
