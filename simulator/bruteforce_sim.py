"""
simulator/bruteforce_sim.py — Brute-force login simulation.

Injects 6 fake failed-login alerts (Event ID 4625) into the DB,
then fires a summary "Brute Force Attack Detected" HIGH alert.
"""
import logging
import time

logger = logging.getLogger(__name__)

FAKE_USERS = ["admin", "administrator", "user", "root", "guest", "test"]


def _emit(alert: dict):
    try:
        from backend.app import emit_alert
        from backend.database import insert_alert
        alert_id = insert_alert(alert)
        alert["id"] = alert_id
        emit_alert(alert)
    except Exception as exc:
        logger.error("bruteforce_sim emit: %s", exc)


def run_bruteforce_sim():
    logger.info("▶ Brute-force simulation starting …")

    for username in FAKE_USERS:
        _emit({
            "timestamp":     time.time(),
            "type":          "eventlog",
            "severity":      "MEDIUM",
            "score":         40,
            "title":         "Failed Logon Attempt",
            "description":   (
                f"Event ID 4625 — Account '{username}' failed to logon. "
                "Logon type: Network. Source: 127.0.0.1."
            ),
            "process":       "winlogon.exe",
            "is_simulation": True,
        })
        time.sleep(0.5)

    # Summary brute-force alert
    _emit({
        "timestamp":     time.time(),
        "type":          "eventlog",
        "severity":      "HIGH",
        "score":         80,
        "title":         "Brute Force Attack Detected",
        "description":   (
            "6 failed login attempts in under 60 seconds from the local machine. "
            "Attempted accounts: admin, administrator, user, root, guest, test."
        ),
        "process":       "winlogon.exe",
        "is_simulation": True,
    })

    logger.info("Brute-force simulation alerts injected.")
