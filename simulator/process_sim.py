"""
simulator/process_sim.py — Suspicious process injection simulation.

Injects two fake process-spawn alerts directly into the database
without launching any real process.
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
        logger.error("process_sim emit: %s", exc)


def run_suspicious_process_sim():
    logger.info("▶ Suspicious process simulation starting …")

    # Alert 1 — fake executable running from Temp
    _emit({
        "timestamp":     time.time(),
        "type":          "process",
        "severity":      "HIGH",
        "score":         72,
        "title":         "Suspicious Process Detected",
        "description":   (
            "Process invoice_viewer.exe (PID 9999) spawned from Temp folder "
            "with active network connection. Parent: explorer.exe."
        ),
        "process":       "invoice_viewer.exe",
        "file_path":     r"C:\Users\user\AppData\Local\Temp\invoice_viewer.exe",
        "is_simulation": True,
    })

    time.sleep(1)

    # Alert 2 — Office spawning a shell
    _emit({
        "timestamp":     time.time(),
        "type":          "process",
        "severity":      "HIGH",
        "score":         80,
        "title":         "Malicious Office Macro Detected",
        "description":   (
            "word.exe (PID 4420) spawned cmd.exe — possible malicious macro execution. "
            "This is a common initial access technique."
        ),
        "process":       "cmd.exe",
        "file_path":     r"C:\Windows\System32\cmd.exe",
        "is_simulation": True,
    })

    logger.info("Process simulation alerts injected.")
