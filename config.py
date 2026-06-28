"""
config.py — Central configuration for the EDR system.
All tunable parameters live here so operators can tweak behaviour
without touching any other source file.
"""
import os

# ─── VirusTotal ───────────────────────────────────────────────────────────────
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

# ─── Folders to watch ────────────────────────────────────────────────────────
WATCHED_FOLDERS = [
    os.path.expanduser("~\\AppData\\Local\\Temp"),
    os.path.expanduser("~\\Downloads"),
]

# ─── Timing ──────────────────────────────────────────────────────────────────
POLL_INTERVAL        = 3    # seconds between process polls
NETWORK_INTERVAL     = 5    # seconds between network polls

# ─── Ransomware detection ─────────────────────────────────────────────────────
RANSOMWARE_THRESHOLD   = 10   # file events in …
RANSOMWARE_TIME_WINDOW = 5    # … seconds → CRITICAL alert

# ─── Threat classification ────────────────────────────────────────────────────
SUSPICIOUS_EXTENSIONS = ['.exe', '.dll', '.bat', '.ps1', '.vbs', '.js']
NORMAL_PORTS          = [80, 443, 53, 22, 3389, 8080]

# ─── Paths ───────────────────────────────────────────────────────────────────
DB_PATH     = "data/edr.db"
LOG_PATH    = "logs/edr.log"
EXPORT_PATH = "exports/"

# ─── Server ──────────────────────────────────────────────────────────────────
FLASK_PORT = 5000

# ─── Simulator ───────────────────────────────────────────────────────────────
# All simulation file activity is confined to this folder.
SIMULATOR_FOLDER = os.path.expanduser(
    "~\\AppData\\Local\\Temp\\edr_simulation"
)
