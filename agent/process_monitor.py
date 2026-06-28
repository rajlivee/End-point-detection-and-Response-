"""
agent/process_monitor.py — Polls running processes every POLL_INTERVAL seconds.

Detects:
  • Processes running from Temp / AppData / Downloads
  • Known-suspicious process names
  • Suspicious parent → child spawn patterns
  • Privilege escalation (process user = SYSTEM unexpectedly)

All findings are pushed onto the shared event_queue as alert dicts.
Process snapshot is also written to the DB for the process-tree view.
"""
import logging
import time
import queue

import psutil

from config import POLL_INTERVAL, SUSPICIOUS_EXTENSIONS
from agent.threat_engine import score

logger = logging.getLogger(__name__)

SUSPICIOUS_NAMES = {
    "mimikatz", "netcat", "nc.exe", "nmap", "psexec",
    "meterpreter", "cobalt", "beacon",
}

TEMP_PATHS = ("temp", "tmp", "appdata\\local\\temp", "downloads")

SUSPICIOUS_SPAWN_PAIRS = {
    ("winword.exe",  "cmd.exe"),
    ("winword.exe",  "powershell.exe"),
    ("excel.exe",    "cmd.exe"),
    ("excel.exe",    "powershell.exe"),
    ("word.exe",     "cmd.exe"),
    ("outlook.exe",  "cmd.exe"),
    ("mshta.exe",    "powershell.exe"),
}


def _is_suspicious_path(path: str) -> bool:
    if not path:
        return False
    lower = path.lower()
    return any(t in lower for t in TEMP_PATHS)


class ProcessMonitor:
    def __init__(self, event_queue: queue.Queue):
        self.q = event_queue
        self._seen_pids: set = set()       # pids we have already alerted on
        self._process_tree: dict = {}      # pid → info dict

    # ── helpers ───────────────────────────────────────────────────────────────

    def _get_proc_info(self, proc: psutil.Process) -> dict | None:
        try:
            with proc.oneshot():
                pid        = proc.pid
                name       = proc.name()
                exe        = proc.exe() if proc.is_running() else ""
                username   = proc.username() if proc.is_running() else ""
                status     = proc.status()
                ppid       = proc.ppid()
                try:
                    parent_name = psutil.Process(ppid).name() if ppid else ""
                except Exception:
                    parent_name = ""
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

        return {
            "pid":         pid,
            "name":        name,
            "exe":         exe,
            "username":    username,
            "status":      status,
            "ppid":        ppid,
            "parent_name": parent_name,
        }

    def _persist_process(self, info: dict):
        """Save process snapshot to DB (non-blocking best-effort)."""
        try:
            from backend.database import insert_process
            insert_process(info)
        except Exception as exc:
            logger.debug("insert_process: %s", exc)

    def _check_process(self, info: dict):
        """Apply detection rules; push alert if suspicious."""
        pid  = info["pid"]
        name = info["name"].lower()
        exe  = info["exe"]
        parent_name = info["parent_name"].lower()
        username    = info["username"].lower() if info["username"] else ""

        alerts = []

        # Rule: suspicious name
        if any(s in name for s in SUSPICIOUS_NAMES):
            alerts.append({
                "title": f"Suspicious Process Detected: {info['name']}",
                "description": f"Known-suspicious process '{name}' is running (PID {pid}).",
                "type": "process",
            })

        # Rule: launched from temp / downloads
        if _is_suspicious_path(exe):
            alerts.append({
                "title": f"Process in Suspicious Location: {info['name']}",
                "description": (
                    f"'{name}' (PID {pid}) is executing from a high-risk path: {exe}"
                ),
                "type": "process",
                "file_path": exe,
            })

        # Rule: parent → child spawn pattern
        if (parent_name, name) in SUSPICIOUS_SPAWN_PAIRS:
            alerts.append({
                "title": "Suspicious Process Spawn Detected",
                "description": (
                    f"'{parent_name}' spawned '{name}' (PID {pid}) — potential living-off-the-land attack."
                ),
                "type": "process",
                "parent_name": parent_name,
            })

        # Rule: SYSTEM process (privilege escalation heuristic)
        if "system" in username and name not in {
            "system", "idle", "registry", "smss.exe", "csrss.exe",
            "wininit.exe", "services.exe", "lsass.exe",
        }:
            alerts.append({
                "title": "Privilege Escalation Detected",
                "description": (
                    f"Process '{name}' (PID {pid}) is running as SYSTEM unexpectedly."
                ),
                "type": "process",
                "privilege_escalation": True,
            })

        for alert in alerts:
            if pid not in self._seen_pids:
                alert.update({
                    "process":      info["name"],
                    "event_type":   "alert",
                    "is_simulation": False,
                })
                scored = score(alert)
                self.q.put(scored)

        if alerts:
            self._seen_pids.add(pid)

    # ── main loop ─────────────────────────────────────────────────────────────

    def run(self):
        logger.info("Process monitor running (interval=%ds).", POLL_INTERVAL)
        while True:
            try:
                current_pids = set()
                tree = {}

                for proc in psutil.process_iter():
                    info = self._get_proc_info(proc)
                    if info is None:
                        continue

                    current_pids.add(info["pid"])
                    tree[info["pid"]] = info
                    self._persist_process(info)
                    self._check_process(info)

                self._process_tree = tree

                # Flush PIDs that no longer exist so we can re-alert if they restart
                self._seen_pids &= current_pids

            except Exception as exc:
                logger.error("Process monitor error: %s", exc)

            time.sleep(POLL_INTERVAL)
