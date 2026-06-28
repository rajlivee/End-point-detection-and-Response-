"""
simulator/privilege_sim.py — Privilege escalation simulation.

Injects two fake alerts:
  1. A process escalating to SYSTEM.
  2. A suspicious scheduled task registration.
"""
import logging
import time

logger = logging.getLogger(__name__)


def _emit(alert: dict):
    try:
        from backend.app import emit_alert
        from backend.database import insert_alert
        alert_id = insert_alert(alert)
        alert["id"] = alert_id
        emit_alert(alert)
    except Exception as exc:
        logger.error("privilege_sim emit: %s", exc)


def run_privilege_sim():
    logger.info("▶ Privilege escalation simulation starting …")

    # Alert 1 — user → SYSTEM escalation
    _emit({
        "timestamp":     time.time(),
        "type":          "process",
        "severity":      "HIGH",
        "score":         85,
        "title":         "Privilege Escalation Detected",
        "description":   (
            "Process svchost_helper.exe (PID 8823) escalated from User to SYSTEM. "
            "Possible token impersonation or exploit-based escalation."
        ),
        "process":       "svchost_helper.exe",
        "is_simulation": True,
    })

    time.sleep(1)

    # Alert 2 — suspicious scheduled task creation (Event ID 4698)
    _emit({
        "timestamp":     time.time(),
        "type":          "eventlog",
        "severity":      "MEDIUM",
        "score":         50,
        "title":         "Suspicious Scheduled Task Created",
        "description":   (
            "New scheduled task 'WindowsUpdateHelper' registered by an unknown process. "
            "Event ID 4698. This is a common persistence mechanism used by malware."
        ),
        "process":       "taskschd.exe",
        "is_simulation": True,
    })

    logger.info("Privilege escalation simulation alerts injected.")
