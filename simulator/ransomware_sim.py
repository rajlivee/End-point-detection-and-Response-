"""
simulator/ransomware_sim.py — Safe ransomware behaviour simulation.

What happens:
  1. Creates SIMULATOR_FOLDER if it doesn't exist.
  2. Writes 15 harmless .txt dummy files inside it.
  3. Renames them all to .locked within 3 seconds.
  4. Injects a CRITICAL alert into the DB and emits it via SocketIO.
  5. Deletes all created files after 10 seconds.

No real malware.  No encryption.  100 % safe.
"""
import logging
import os
import time
import threading

from config import SIMULATOR_FOLDER

logger = logging.getLogger(__name__)


def _emit(alert: dict):
    """Push an alert to connected dashboard clients."""
    try:
        from backend.app import emit_alert
        from backend.database import insert_alert
        alert_id = insert_alert(alert)
        alert["id"] = alert_id
        emit_alert(alert)
    except Exception as exc:
        logger.error("ransomware_sim emit: %s", exc)


def run_ransomware_sim():
    """Entry point called by the Flask endpoint."""
    logger.info("▶ Ransomware simulation starting …")
    os.makedirs(SIMULATOR_FOLDER, exist_ok=True)

    created_files  = []
    renamed_files  = []

    # Step 1 — create dummy text files
    for i in range(15):
        path = os.path.join(SIMULATOR_FOLDER, f"document_{i:02d}.txt")
        try:
            with open(path, "w") as f:
                f.write(f"Harmless dummy file #{i} created by EDR ransomware simulation.\n")
            created_files.append(path)
        except Exception as exc:
            logger.warning("Could not create sim file: %s", exc)

    time.sleep(0.5)

    # Step 2 — rename to .locked (triggers the ransomware rule in file_monitor)
    for path in created_files:
        locked = path.replace(".txt", ".locked")
        try:
            os.rename(path, locked)
            renamed_files.append(locked)
        except Exception as exc:
            logger.warning("Could not rename sim file: %s", exc)

    # Step 3 — inject CRITICAL alert
    alert = {
        "timestamp":     time.time(),
        "type":          "file",
        "severity":      "CRITICAL",
        "score":         95,
        "title":         "Ransomware Behavior Detected",
        "description":   (
            "15 files were renamed to .locked extension within 3 seconds "
            "in the EDR simulation folder. Ransomware-like bulk encryption detected."
        ),
        "file_path":     SIMULATOR_FOLDER,
        "is_simulation": True,
    }
    _emit(alert)
    logger.info("Ransomware simulation alert injected.")

    # Step 4 — cleanup after 10 seconds
    def _cleanup():
        time.sleep(10)
        for path in renamed_files:
            try:
                os.remove(path)
            except Exception:
                pass
        logger.info("Ransomware simulation files cleaned up.")

    threading.Thread(target=_cleanup, daemon=True).start()
