"""
agent/file_monitor.py — Real-time file system watcher using watchdog.

Monitors every folder listed in WATCHED_FOLDERS.
On each create/modify/delete event:
  1. Compute SHA-256 of the file.
  2. Check against malware_hashes.txt blacklist.
  3. Flag suspicious extensions.
  4. Query VirusTotal (if API key is configured).

Ransomware detection:
  If 10+ file-change events occur within 5 seconds → CRITICAL alert.
"""
import hashlib
import logging
import os
import queue
import time
from collections import deque
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from config import (
    WATCHED_FOLDERS,
    SUSPICIOUS_EXTENSIONS,
    RANSOMWARE_THRESHOLD,
    RANSOMWARE_TIME_WINDOW,
)
from agent.threat_engine import score

logger = logging.getLogger(__name__)

# Path to the hash blacklist (relative to project root)
HASH_BLACKLIST_PATH = "data/malware_hashes.txt"


def _sha256(path: str) -> str | None:
    """Return the SHA-256 hex-digest of *path*, or None on error."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _load_blacklist() -> set:
    bl = set()
    try:
        with open(HASH_BLACKLIST_PATH, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    bl.add(line.lower())
    except FileNotFoundError:
        pass
    return bl


class _Handler(FileSystemEventHandler):
    def __init__(self, event_queue: queue.Queue, blacklist: set):
        super().__init__()
        self.q          = event_queue
        self.blacklist  = blacklist
        self._event_times: deque = deque()   # timestamps of recent events
        self._ransomware_alerted = False

    # ── helpers ───────────────────────────────────────────────────────────────

    def _ransomware_check(self):
        """Push CRITICAL alert if file change rate exceeds threshold."""
        now = time.time()
        self._event_times.append(now)
        # Prune events older than the time window
        while self._event_times and self._event_times[0] < now - RANSOMWARE_TIME_WINDOW:
            self._event_times.popleft()

        if len(self._event_times) >= RANSOMWARE_THRESHOLD and not self._ransomware_alerted:
            self._ransomware_alerted = True
            alert = {
                "event_type":    "alert",
                "type":          "file",
                "title":         "Ransomware Behavior Detected",
                "description":   (
                    f"{len(self._event_times)} file changes detected within "
                    f"{RANSOMWARE_TIME_WINDOW} seconds — possible ransomware activity."
                ),
                "severity":      "CRITICAL",
                "score":         95,
                "ransomware":    True,
                "is_simulation": False,
            }
            self.q.put(alert)
            logger.warning("Ransomware threshold breached!")
            # Reset after 30 seconds so we can alert again
            threading.Timer(30, self._reset_ransomware).start()

    def _reset_ransomware(self):
        self._ransomware_alerted = False
        self._event_times.clear()

    def _process_file(self, path: str, action: str):
        if not os.path.isfile(path):
            return

        ext = Path(path).suffix.lower()
        file_hash = _sha256(path)

        alert = {
            "event_type":        "alert",
            "type":              "file",
            "file_path":         path,
            "title":             f"File {action}: {Path(path).name}",
            "description":       f"File '{Path(path).name}' was {action} (ext: {ext}).",
            "hash_blacklisted":  False,
            "virustotal_result": "",
            "is_simulation":     False,
        }

        # Hash blacklist check
        if file_hash and file_hash.lower() in self.blacklist:
            alert["hash_blacklisted"] = True
            alert["title"]            = f"Blacklisted File Detected: {Path(path).name}"
            alert["description"]      = f"SHA-256 {file_hash} matches known malware hash."

        # VirusTotal check (lazy import to avoid circular deps)
        if file_hash:
            try:
                from backend.virustotal import check_hash
                vt = check_hash(file_hash)
                if vt:
                    alert["virustotal_result"] = vt
            except Exception as exc:
                logger.debug("VT check skipped: %s", exc)

        scored = score(alert)
        # Only push if there is something interesting OR the extension is suspicious
        if scored["score"] > 0 or ext in SUSPICIOUS_EXTENSIONS:
            self.q.put(scored)

    # ── watchdog callbacks ────────────────────────────────────────────────────

    def on_created(self, event):
        if not event.is_directory:
            self._ransomware_check()
            self._process_file(event.src_path, "created")

    def on_modified(self, event):
        if not event.is_directory:
            self._ransomware_check()
            self._process_file(event.src_path, "modified")

    def on_deleted(self, event):
        if not event.is_directory:
            self._ransomware_check()

    def on_moved(self, event):
        if not event.is_directory:
            self._ransomware_check()
            self._process_file(event.dest_path, "renamed")


# Need threading for the reset timer
import threading


class FileMonitor:
    def __init__(self, event_queue: queue.Queue):
        self.q = event_queue

    def run(self):
        blacklist = _load_blacklist()
        logger.info("File monitor watching: %s", WATCHED_FOLDERS)

        handler  = _Handler(self.q, blacklist)
        observer = Observer()

        for folder in WATCHED_FOLDERS:
            os.makedirs(folder, exist_ok=True)
            observer.schedule(handler, folder, recursive=True)

        observer.start()
        try:
            while True:
                time.sleep(1)
        except Exception:
            pass
        finally:
            observer.stop()
            observer.join()
