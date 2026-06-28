"""
agent/threat_engine.py — Threat scoring & severity classification.

Each raw event dictionary is passed through score() which returns
the same dict enriched with  'score' and 'severity' keys.

Score range:  0 – 100
Severity:     LOW (0-30) | MEDIUM (31-60) | HIGH (61-85) | CRITICAL (86-100)
"""
import os
import logging

logger = logging.getLogger(__name__)

# ── Severity thresholds ───────────────────────────────────────────────────────
SEVERITY_MAP = [
    (86, "CRITICAL"),
    (61, "HIGH"),
    (31, "MEDIUM"),
    (0,  "LOW"),
]

# ── Known-suspicious process names ──────────────────────────────────────────
SUSPICIOUS_NAMES = {
    "mimikatz", "netcat", "nc", "nmap", "meterpreter",
    "psexec", "cobalt", "beacon", "empire",
}

# ── High-risk parent → child spawn patterns ──────────────────────────────────
SUSPICIOUS_SPAWN = {
    ("winword.exe",  "cmd.exe"),
    ("winword.exe",  "powershell.exe"),
    ("excel.exe",    "cmd.exe"),
    ("excel.exe",    "powershell.exe"),
    ("outlook.exe",  "cmd.exe"),
    ("mshta.exe",    "cmd.exe"),
    ("word.exe",     "cmd.exe"),
}

# ── High-risk file extensions ────────────────────────────────────────────────
HIGH_RISK_EXT   = {'.exe', '.dll', '.bat', '.ps1'}
MEDIUM_RISK_EXT = {'.vbs', '.js', '.hta', '.cmd'}

# ── High-risk launch directories ────────────────────────────────────────────
TEMP_PATHS = ("temp", "tmp", "appdata\\local\\temp", "downloads")


def _path_is_suspicious(path: str) -> bool:
    if not path:
        return False
    lower = path.lower()
    return any(t in lower for t in TEMP_PATHS)


def score(event: dict) -> dict:
    """
    Compute a threat score for *event* and attach 'score' / 'severity'.
    Returns the enriched event dict.
    """
    points = 0
    reasons = []

    etype = event.get("type", "")
    sev_override = event.get("severity")   # allow callers to hard-set severity

    # ── File events ──────────────────────────────────────────────────────────
    if etype == "file":
        file_path = event.get("file_path", "")
        ext = os.path.splitext(file_path)[1].lower()
        vt_result = event.get("virustotal_result", "")

        if ext in HIGH_RISK_EXT:
            points += 40
            reasons.append(f"High-risk extension: {ext}")
        elif ext in MEDIUM_RISK_EXT:
            points += 25
            reasons.append(f"Medium-risk extension: {ext}")

        if _path_is_suspicious(file_path):
            points += 30
            reasons.append("File in suspicious directory")

        if "positives" in str(vt_result).lower() or "malicious" in str(vt_result).lower():
            points += 40
            reasons.append("VirusTotal hit")

        if event.get("hash_blacklisted"):
            points += 50
            reasons.append("Hash on blacklist")

        if event.get("ransomware"):
            points += 60
            reasons.append("Ransomware-like behaviour")

    # ── Process events ────────────────────────────────────────────────────────
    elif etype == "process":
        proc_name   = event.get("process", "").lower()
        proc_path   = event.get("file_path", "")
        parent_name = event.get("parent_name", "").lower()

        if any(s in proc_name for s in SUSPICIOUS_NAMES):
            points += 55
            reasons.append(f"Suspicious process name: {proc_name}")

        if _path_is_suspicious(proc_path):
            points += 35
            reasons.append("Process running from suspicious path")

        if (parent_name, proc_name) in SUSPICIOUS_SPAWN:
            points += 50
            reasons.append(f"Suspicious spawn: {parent_name} → {proc_name}")

        if event.get("privilege_escalation"):
            points += 45
            reasons.append("Privilege escalation detected")

    # ── Network events ────────────────────────────────────────────────────────
    elif etype == "network":
        port = event.get("remote_port", 0)
        from config import NORMAL_PORTS
        if event.get("bad_ip"):
            points += 55
            reasons.append("Connection to known bad IP")
        if port and port not in NORMAL_PORTS:
            points += 20
            reasons.append(f"Unusual port: {port}")

    # ── Event Log events ──────────────────────────────────────────────────────
    elif etype == "eventlog":
        event_id = event.get("event_id")
        if event_id == 4625:     # Failed logon
            points += 20
            reasons.append("Failed logon event")
        elif event_id == 1102:   # Audit log cleared
            points += 70
            reasons.append("Audit log cleared")
        elif event_id == 4698:   # Scheduled task created
            points += 35
            reasons.append("Scheduled task created")
        elif event_id == 4688:   # Process created
            points += 10
            reasons.append("Process creation logged")

    # ── Cap at 100 ────────────────────────────────────────────────────────────
    points = min(points, 100)

    # ── Severity ─────────────────────────────────────────────────────────────
    if sev_override and sev_override in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        severity = sev_override
    else:
        severity = "LOW"
        for threshold, label in SEVERITY_MAP:
            if points >= threshold:
                severity = label
                break

    event["score"]    = points
    event["severity"] = severity
    if reasons:
        event.setdefault("description",
                         event.get("description", "") or "; ".join(reasons))

    logger.debug("Scored event '%s': %d → %s", etype, points, severity)
    return event
