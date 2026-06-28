# 🛡️ EDR — Endpoint Detection & Response

> **A lightweight Windows security monitoring tool with a real-time dashboard.**
> Built as a summer internship project at Hindalco Industries.

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0-green?logo=flask)](https://flask.palletsprojects.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey?logo=windows)](https://microsoft.com/windows)

---

## 📸 Screenshots

> _Run the project and add screenshots here._

---

## ✨ Features

| Category | Feature |
|----------|---------|
| 🔍 Monitoring | Real-time process monitoring with full process tree |
| 📁 File System | Temp & Downloads folder watcher with SHA-256 hashing |
| 🌐 Network | Active connection monitoring with GeoIP world map |
| 🪟 Event Logs | Windows Security Event Log reader (4624, 4625, 4688, 4698, 1102) |
| 🧠 Intelligence | Threat scoring engine (0–100 score, 4 severity levels) |
| 🦠 VirusTotal | File hash lookup via VirusTotal v3 API |
| 🎯 Simulator | 5 safe attack simulations for live demos |
| 📊 Dashboard | Dark cyberpunk UI with Chart.js charts & Leaflet map |
| 📤 Export | One-click CSV and styled PDF report |

---

## 🚀 Quick Start (Step-by-Step)

### Step 1 — Prerequisites

Make sure **Python 3.9 or higher** is installed:

```bash
python --version
```

If not installed, download from [python.org](https://python.org).

---

### Step 2 — Clone the Project

```bash
git clone https://github.com/yourname/edr-project.git
cd edr-project
```

---

### Step 3 — Install Dependencies

```bash
pip install -r requirements.txt
```

This installs Flask, psutil, watchdog, Chart.js CDN (no npm needed), and all other libraries.

---

### Step 4 — Set Up VirusTotal API Key *(Optional)*

1. Go to [virustotal.com](https://www.virustotal.com) and create a free account
2. Navigate to your Profile → **API Key**
3. Copy your key
4. Copy the example env file:

```bash
copy .env.example .env
```

5. Open `.env` in Notepad and paste your key:

```
VIRUSTOTAL_API_KEY=your_key_here
```

> ⚠️ **If you skip this step**, the EDR still works fully — VT hash checks are silently skipped.

---

### Step 5 — Run the Project

```bash
python run.py
```

- The EDR agent starts monitoring your system in the background
- Your browser opens automatically at **http://localhost:5000**
- The dashboard shows the live alert feed

---

### Step 6 — Try the Attack Simulator

On the dashboard, find the **🎯 Attack Simulator** panel (dark red border):

| Button | What it simulates |
|--------|------------------|
| 🔴 Simulate Ransomware | 15 dummy files renamed to `.locked` in 3 seconds |
| 🟠 Simulate Suspicious Process | Fake `invoice_viewer.exe` in Temp folder |
| 🟡 Simulate Bad IP Connection | Fake connections to blacklisted IPs (map markers appear) |
| 🔵 Simulate Brute Force Login | 6 fake failed login Event ID 4625 alerts |
| 🟣 Simulate Privilege Escalation | Fake SYSTEM escalation + rogue scheduled task |
| ⚡ Run All Attacks | All 5 simulations in sequence |
| 🧹 Clear Simulation Data | Wipes simulation rows from DB and temp files |

> All simulations are **100% safe** — no real malware, no real network attacks, no system changes.

---

### Step 7 — Export a Report

Click **📄 PDF Report** in the top navigation bar.
A styled PDF with all alerts is downloaded and saved to `exports/`.

---

### Step 8 — Stop the EDR

Press `Ctrl+C` in the terminal.

---

## 🏗️ Project Structure

```
edr-project/
├── agent/                  # Monitoring threads
│   ├── main.py             # Thread orchestrator + dispatcher
│   ├── process_monitor.py  # Process & tree monitoring
│   ├── file_monitor.py     # Watchdog file monitor
│   ├── network_monitor.py  # Network connection monitor
│   ├── event_log_monitor.py# Windows Event Log reader
│   └── threat_engine.py    # Threat scoring (0–100)
│
├── backend/                # Flask API
│   ├── app.py              # Flask + SocketIO server
│   ├── database.py         # SQLite schema & queries
│   └── virustotal.py       # VT v3 API integration
│
├── dashboard/              # Frontend
│   ├── templates/index.html# Main dashboard (dark theme)
│   └── static/
│       ├── css/style.css   # Custom dark CSS
│       └── js/
│           ├── dashboard.js    # SocketIO + alert feed
│           ├── charts.js       # Chart.js graphs
│           ├── map.js          # Leaflet GeoIP map
│           └── process_tree.js # Collapsible tree
│
├── simulator/              # Safe attack simulations
│   ├── simulator.py        # Master controller
│   ├── ransomware_sim.py
│   ├── process_sim.py
│   ├── network_sim.py
│   ├── bruteforce_sim.py
│   └── privilege_sim.py
│
├── data/
│   ├── malware_hashes.txt  # SHA-256 blacklist
│   └── bad_ips.txt         # IP blacklist
│
├── config.py               # All configuration
├── run.py                  # Single launch command
└── requirements.txt
```

---

## 🔧 Tech Stack

| Layer | Technology |
|-------|-----------|
| Agent | Python, psutil, watchdog, pywin32, hashlib |
| Backend | Flask 3.0, Flask-SocketIO, SQLite |
| Frontend | HTML5, Custom CSS (dark theme), JavaScript |
| Charts | Chart.js 4 (CDN) |
| Map | Leaflet.js 1.9 + ip-api.com GeoIP (CDN) |
| Threat Intel | VirusTotal v3 API |
| Export | ReportLab (PDF), csv (stdlib) |

---

## 🧠 Detection Rules

| Rule | Trigger | Severity |
|------|---------|----------|
| Executable in Temp | `.exe/.dll` in Temp folder | HIGH |
| Ransomware behaviour | 10+ file changes in 5 seconds | CRITICAL |
| VirusTotal hit | Hash detected as malicious | CRITICAL |
| Hash blacklist match | SHA-256 in `malware_hashes.txt` | CRITICAL |
| Suspicious process spawn | `word.exe → cmd.exe` | HIGH |
| Privilege escalation | Process gains SYSTEM rights | HIGH |
| Audit log cleared | Event ID 1102 | CRITICAL |
| Scheduled task created | Event ID 4698 | MEDIUM |
| Brute force login | 5+ failed logons in 60 seconds | HIGH |
| Bad IP connection | IP in `bad_ips.txt` | HIGH |
| Unusual port | Port not in NORMAL_PORTS list | MEDIUM |

---

## ⚙️ Configuration

All settings live in [`config.py`](config.py):

```python
WATCHED_FOLDERS        = ["~\\AppData\\Local\\Temp", "~\\Downloads"]
RANSOMWARE_THRESHOLD   = 10     # files
RANSOMWARE_TIME_WINDOW = 5      # seconds
POLL_INTERVAL          = 3      # process poll seconds
NORMAL_PORTS           = [80, 443, 53, 22, 3389, 8080]
```

---

## ⚠️ Important Notes

- **Educational purpose only** — do not use on systems you don't own
- **Requires Windows** for Event Log monitoring (`pywin32`); all other features work cross-platform
- **Simulator is 100% safe** — creates harmless dummy files only in `%TEMP%\edr_simulation`
- **Simulation data** is clearly tagged with a purple **SIM** badge and can be cleared anytime
- **VirusTotal free tier** allows 4 requests/minute — the code rate-limits automatically

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

*Built with ❤️ as a cybersecurity internship project.*
