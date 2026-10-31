<div align="center">

```
 ██████╗██╗   ██╗██████╗ ███████╗██████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗
╚██████╗   ██║   ██████╔╝███████╗██║  ██║
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝
   T H R E A T   L O G   A N A L Y Z E R
```

### 🛡️ A terminal-based mini SOC that turns raw server logs into security insight

![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Pandas](https://img.shields.io/badge/Pandas-Data%20Analysis-150458?style=for-the-badge&logo=pandas&logoColor=white)
![NumPy](https://img.shields.io/badge/NumPy-Statistics-013243?style=for-the-badge&logo=numpy&logoColor=white)
![Matplotlib](https://img.shields.io/badge/Matplotlib-Charts-11557C?style=for-the-badge)
![Interface](https://img.shields.io/badge/Interface-CLI-black?style=for-the-badge&logo=gnubash&logoColor=white)
![Status](https://img.shields.io/badge/Status-In%20Development-orange?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**[Features](#-features) · [Quick Start](#-quick-start) · [Methodology](#-detection-methodology) · [Dataset](#-dataset) · [Roadmap](#-development-roadmap) · [Disclaimer](#%EF%B8%8F-cybersecurity-disclaimer)**

</div>

---

## 📖 About

**Cyber Threat Log Analyzer** simulates the daily workflow of a Security Operations Center (SOC) analyst.
It loads web-server and authentication logs, hunts for suspicious behaviour, scores risky IP addresses
and produces professional security reports, all from a clean, menu-driven terminal interface.

The project uses only **Python, Pandas, NumPy, regular expressions and the standard library**.
No machine learning and no heavy security frameworks. Every detection rule is transparent and explainable.

> 🎯 **Built to learn and to showcase:** modular Python, data analysis with Pandas,
> statistics with NumPy, and the fundamentals of log-based threat detection.

---

## ✨ Features

| | Module | What it does | Status |
|:-:|--------|--------------|:------:|
| 📥 | **Log Management** | Loads CSV/TXT logs, parses timestamps, IPs, users, paths and status codes, and survives corrupted rows | 🔜 Day 2 |
| 🔑 | **Failed Login Detection** | Counts failures per IP and per username and flags IPs over a configurable threshold | 🔜 Day 3 |
| 💥 | **Brute-Force Detection** | Sliding time-window detection with attempt counts and timestamps | 🔜 Day 3 |
| 🌐 | **Suspicious IP Detection** | Request volume, restricted-path hits and repeated 401/403/404, with **LOW → CRITICAL** risk levels | 🔜 Day 4 |
| 🕷️ | **Web Attack Indicators** | Regex rules for SQL-injection-like, traversal, script-injection and sensitive-path requests | 🔜 Day 4 |
| 📊 | **Traffic Analysis** | Top IPs and endpoints, status distribution and z-score spike detection | 🔜 Day 5 |
| 🖥️ | **Security Dashboard** | One-screen summary of the overall security risk | 🔜 Day 6 |
| 📝 | **Reporting** | CSV, JSON and TXT reports plus Matplotlib charts | 🔜 Day 6 |
| 🧪 | **Dataset Generator** | 1,100+ reproducible synthetic log entries with labelled attack scenarios | ✅ **Done** |
| ⚙️ | **Configurable Thresholds** | All detection limits live in one file, `src/config.py` | ✅ **Done** |

---

## 🧰 Technology Stack

| Technology | Used for |
|------------|----------|
| **Python 3.8+** | Core language |
| **Pandas** | Loading, filtering, grouping and aggregating logs |
| **NumPy** | Mean, standard deviation and z-scores |
| **Matplotlib** | Optional charts in reports |
| **`re`** | Pattern matching for web-attack indicators |
| **`datetime`** | Time windows and timestamp validation |
| **`collections`** | Counters for quick frequency counts |
| **`csv` / `json`** | Reading logs and exporting reports |

---

## 📁 Folder Structure

```
Cyber-Threat-Log-Analyzer/
│
├── data/
│   ├── access_logs.csv          # synthetic web-server log (885 entries)
│   ├── auth_logs.csv            # synthetic authentication log (242 entries)
│   ├── README.md                # dataset documentation
│   └── test_cases/              # empty / broken / duplicate files for testing
│
├── scripts/
│   └── generate_sample_data.py  # reproducible synthetic data generator
│
├── src/
│   ├── config.py                # paths + configurable thresholds
│   ├── log_loader.py            # Day 2
│   ├── log_parser.py            # Day 2
│   ├── login_analyzer.py        # Day 3
│   ├── ip_analyzer.py           # Day 4
│   ├── attack_detector.py       # Day 4
│   ├── traffic_analyzer.py      # Day 5
│   ├── dashboard.py             # Day 6
│   └── report_generator.py      # Day 6
│
├── reports/                     # generated reports appear here
│
├── main.py                      # entry point
├── requirements.txt
├── LICENSE
├── README.md
└── .gitignore
```

---

## 🚀 Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/<your-username>/Cyber-Threat-Log-Analyzer.git
cd Cyber-Threat-Log-Analyzer
```

### 2. Create a virtual environment *(recommended)*

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Generate the synthetic datasets *(only needed if `data/` is empty)*

```bash
python scripts/generate_sample_data.py
```

### 5. Run the application

```bash
python main.py
```

---

## 🖥️ Sample Terminal Output

### ✅ Current output (Day 1 setup check, real output)

```text
============================================================
   CYBER THREAT LOG ANALYZER  -  Day 1 Setup Check
   All datasets used here are SYNTHETIC (fake) data
============================================================
[ OK ] Python version        : 3.13.18
[ OK ] Library pandas        : 3.0.5
[ OK ] Library numpy         : 2.5.3
[ OK ] Library matplotlib    : 3.11.2

[ OK ] access_logs.csv       : 885 rows, 52 unique IPs
                              time range: 2026-10-25 00:49:43  ->  2026-10-25 23:59:20
[ OK ] auth_logs.csv         : 242 rows, 23 unique IPs
                              time range: 2026-10-25 04:30:00  ->  2026-10-25 21:07:38
============================================================
Day 1 setup complete. You are ready for Day 2 (log loading & parsing).
============================================================
```

### 🔮 Planned menu *(design preview, arrives on Day 6)*

```text
========================================
        CYBER THREAT LOG ANALYZER
========================================
 1. Load Log Dataset
 2. View Security Dashboard
 3. Analyze Failed Login Attempts
 4. Detect Suspicious IP Addresses
 5. Detect Brute Force Patterns
 6. Detect Web Attack Indicators
 7. Analyze Traffic Statistics
 8. Generate Security Report
 9. View Previous Reports
10. Exit
========================================
```

> Detection outputs (dashboard, alerts, tables) will be added here with real results as each day is completed.

---

## 🔬 Detection Methodology

Every rule is a **heuristic indicator**, not proof of an attack. Thresholds are defaults and fully configurable in
[`src/config.py`](src/config.py).

| Detection | Logic | Default threshold |
|-----------|-------|-------------------|
| **Failed logins per IP** | Count `LOGIN_FAILED` events grouped by IP | ≥ 5 |
| **Targeted username** | Count failures grouped by username | ≥ 10 |
| **Brute force** | Failures from one IP inside a sliding time window | ≥ 10 in 5 min |
| **High request volume** | Total requests per IP | ≥ 100 |
| **Probing responses** | Combined 401 / 403 / 404 per IP | ≥ 15 |
| **Restricted paths** | Hits on `/admin`, `/config`, `/.env` … | ≥ 5 |
| **SQL-injection-like** | Regex for `' OR 1=1`, `UNION SELECT`, `--`, `SLEEP(` | any match |
| **Directory traversal** | Regex for `../`, `..\`, `%2e%2e%2f` | any match |
| **Script injection** | Regex for `<script>`, `onerror=`, `javascript:` | any match |
| **Traffic spikes** | z-score of requests per minute vs. daily average | z ≥ 3.0 |

**Risk levels:** each triggered rule adds points to an IP's score, which maps to
`LOW` 🟢 → `MEDIUM` 🟡 → `HIGH` 🟠 → `CRITICAL` 🔴.

**Known limitations (honest by design):**
- A *low-and-slow* attacker can stay under a short window. The dataset includes one to show this.
- A legitimate admin visiting `/admin` can look suspicious. The dataset includes one *false-positive* case on purpose.
- Regex rules can be bypassed by encoding tricks and can also match harmless input.

---

## 🗃️ Dataset

> ⚠️ **All data is synthetic.** No real people, systems or networks are involved.

| File | Entries | Description |
|------|--------:|-------------|
| `data/access_logs.csv` | 885 | Web access log |
| `data/auth_logs.csv` | 242 | Authentication log |
| **Total** | **1,127** | Reproducible (fixed seed `42`) |

**Simulated scenarios:** normal browsing and logins · failed logins · brute force · password spraying ·
low-and-slow attack · distributed attack · high-volume flooding · reconnaissance scanning ·
SQL-injection-like requests · directory traversal · script injection · unauthorized `/admin` access.

All IPs come from documentation ranges (`10.0.0.x`, `192.168.1.x`, `198.18.x.x`, `203.0.113.x`, `192.0.2.x`,
`198.51.100.x`) and never belong to real machines. Full details are in [`data/README.md`](data/README.md).

---

## 🗺️ Development Roadmap

- [x] **Day 1:** Project setup, folder structure, config, synthetic dataset generator
- [ ] **Day 2:** Log loading, parsing and validation
- [ ] **Day 3:** Failed login and brute-force detection
- [ ] **Day 4:** Suspicious IP and web attack indicator detection
- [ ] **Day 5:** Traffic analysis with Pandas and NumPy
- [ ] **Day 6:** Terminal dashboard and report generation
- [ ] **Day 7:** Testing, debugging, documentation and GitHub publishing

---

## 🧪 Testing

Edge-case files are included in `data/test_cases/`:

| Test | Expected behaviour |
|------|--------------------|
| `empty_file.csv` | Friendly message, no crash |
| `header_only.csv` | "No log entries found" warning |
| `missing_columns.csv` | Lists exactly which columns are missing |
| `invalid_timestamps.csv` | Bad rows skipped and counted |
| `duplicate_records.csv` | Duplicates removed and counted |
| `malformed_rows.csv` | Corrupted rows skipped and counted |

---

## 📸 Screenshots

| Main Menu | Security Dashboard |
|:---------:|:------------------:|
| *screenshot coming Day 6* | *screenshot coming Day 6* |

| Brute-Force Alerts | Generated Charts |
|:------------------:|:----------------:|
| *screenshot coming Day 3* | *screenshot coming Day 6* |

> 💡 Save images in a `screenshots/` folder and link them with `![Menu](screenshots/menu.png)`.

---

## 🔭 Future Improvements

- 🌍 IP geolocation and reputation lookups
- 📡 Real-time log tailing (`tail -f` style monitoring)
- 🧾 Support for Apache / Nginx combined log format and syslog
- 🎨 Colored terminal output and richer tables
- ✅ Automated unit tests with `pytest`
- 🔔 Email or webhook alerts
- 🗺️ MITRE ATT&CK technique mapping for each detection
- 🐳 Docker image

---

## ⚖️ Cybersecurity Disclaimer

This project is for **educational and defensive purposes only**.

- All sample data is synthetic.
- Detections are **heuristic indicators**, not proof that an attack happened or succeeded.
- The tool can produce **false positives and false negatives** and must not replace professional security monitoring.
- Only analyze logs from systems **you own or have explicit permission to analyze.**
- The attack-like strings in the dataset are standard public examples included solely to test detection rules.

---

## 📄 License

Released under the [MIT License](LICENSE). Remember to replace `Your Name` in the license file.

<div align="center">

⭐ **If this project helped you learn, give it a star!** ⭐

</div>
