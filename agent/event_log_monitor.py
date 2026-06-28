"""
agent/event_log_monitor.py — Reads Windows Security/System Event Logs live.

Uses pywin32 (win32evtlog) to tail the Security log.
Monitored Event IDs:
  4624 — Successful logon
  4625 — Failed logon          → score each; 5+ in 60 s → brute-force alert
  4688 — Process created
  4698 — Scheduled task created
  1102 — Audit log cleared     → CRITICAL

Falls back to a silent no-op on non-Windows platforms so the rest of
the project still runs on Linux/macOS for development.
"""
import logging
import queue
import time
from collections import deque

from agent.threat_engine import score

logger = logging.getLogger(__name__)

MONITORED_IDS = {4624, 4625, 4688, 4698, 1102}
POLL_INTERVAL_S       = 5      # seconds between log polls
BRUTE_FORCE_THRESHOLD = 5      # failed logons in …
BRUTE_FORCE_WINDOW    = 60     # … seconds → HIGH alert


class EventLogMonitor:
    def __init__(self, event_queue: queue.Queue):
        self.q = event_queue
        self._failed_logons: deque = deque()
        self._bf_alerted = False

    def _brute_force_check(self, ts: float):
        self._failed_logons.append(ts)
        cutoff = ts - BRUTE_FORCE_WINDOW
        while self._failed_logons and self._failed_logons[0] < cutoff:
            self._failed_logons.popleft()

        if len(self._failed_logons) >= BRUTE_FORCE_THRESHOLD and not self._bf_alerted:
            self._bf_alerted = True
            alert = {
                "event_type":    "alert",
                "type":          "eventlog",
                "event_id":      4625,
                "title":         "Brute Force Attack Detected",
                "description":   (
                    f"{len(self._failed_logons)} failed login attempts within "
                    f"{BRUTE_FORCE_WINDOW} seconds."
                ),
                "severity":      "HIGH",
                "score":         75,
                "is_simulation": False,
            }
            self.q.put(alert)
            logger.warning("Brute-force threshold hit.")

    def _handle_event(self, event_id: int, message: str):
        now = time.time()
        alert = {
            "event_type": "alert",
            "type":       "eventlog",
            "event_id":   event_id,
            "description": message[:500] if message else f"Event ID {event_id}",
            "is_simulation": False,
        }

        if event_id == 4625:
            alert["title"]   = "Failed Logon Attempt"
            self._brute_force_check(now)
        elif event_id == 4624:
            alert["title"]   = "Successful Logon"
        elif event_id == 4688:
            alert["title"]   = "New Process Created"
        elif event_id == 4698:
            alert["title"]   = "Scheduled Task Created"
        elif event_id == 1102:
            alert["title"]   = "Audit Log Cleared"
            alert["severity"] = "CRITICAL"
            alert["score"]    = 90
        else:
            return

        self.q.put(score(alert))

    def _run_windows(self):
        """Windows-specific event log polling using pywin32."""
        import win32evtlog  # type: ignore
        import win32con     # type: ignore
        import pywintypes   # type: ignore

        log_type = "Security"
        server   = None   # local machine

        # Remember the current record number so we only process *new* events
        try:
            hand = win32evtlog.OpenEventLog(server, log_type)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            # Read one event just to get the latest record number
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            last_record = events[0].RecordNumber if events else 0
            win32evtlog.CloseEventLog(hand)
        except Exception:
            last_record = 0

        logger.info("Event log monitor: starting from record %d.", last_record)
        _err_logged = False  # suppress repeated privilege error messages

        while True:
            try:
                hand = win32evtlog.OpenEventLog(server, log_type)
                flags = (
                    win32evtlog.EVENTLOG_FORWARDS_READ
                    | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                )
                while True:
                    events = win32evtlog.ReadEventLog(hand, flags, 0)
                    if not events:
                        break
                    for ev in events:
                        if ev.RecordNumber <= last_record:
                            continue
                        last_record = ev.RecordNumber
                        eid = ev.EventID & 0xFFFF
                        if eid in MONITORED_IDS:
                            try:
                                msg = str(ev.StringInserts) if ev.StringInserts else ""
                            except Exception:
                                msg = ""
                            self._handle_event(eid, msg)
                win32evtlog.CloseEventLog(hand)
            except Exception as exc:
                if not _err_logged:
                    logger.warning(
                        "Event Log monitor: %s  — Tip: Run as Administrator for full access.",
                        exc
                    )
                    _err_logged = True

            time.sleep(POLL_INTERVAL_S)

    def run(self):
        try:
            self._run_windows()
        except ImportError:
            logger.warning(
                "pywin32 not available — Event Log monitor disabled. "
                "(Normal on non-Windows systems.)"
            )
