"""
simulator/simulator.py — Master simulation controller.

Orchestrates all individual simulations and provides a cleanup helper
that wipes simulation rows from the DB and deletes temp files.
"""
import logging
import os
import shutil
import time

from config import SIMULATOR_FOLDER

logger = logging.getLogger(__name__)


def run_ransomware_sim():
    from simulator.ransomware_sim import run_ransomware_sim as _run
    _run()


def run_suspicious_process_sim():
    from simulator.process_sim import run_suspicious_process_sim as _run
    _run()


def run_network_sim():
    from simulator.network_sim import run_network_sim as _run
    _run()


def run_bruteforce_sim():
    from simulator.bruteforce_sim import run_bruteforce_sim as _run
    _run()


def run_privilege_sim():
    from simulator.privilege_sim import run_privilege_sim as _run
    _run()


def run_all_attacks():
    """Run all simulations sequentially with short pauses between them."""
    logger.info("▶ Running ALL attack simulations …")
    run_ransomware_sim();           time.sleep(2)
    run_suspicious_process_sim();   time.sleep(1)
    run_network_sim();              time.sleep(1)
    run_bruteforce_sim();           time.sleep(1)
    run_privilege_sim()
    logger.info("All attack simulations complete.")


def cleanup_simulation():
    """
    Remove:
      • All is_simulation=1 rows from the alerts table.
      • All flagged rows from network_connections.
      • The SIMULATOR_FOLDER directory and its contents.
    """
    logger.info("▶ Cleaning up simulation data …")

    # DB cleanup
    try:
        from backend.database import delete_simulation_alerts
        delete_simulation_alerts()
        logger.info("Simulation DB rows deleted.")
    except Exception as exc:
        logger.error("DB cleanup failed: %s", exc)

    # Filesystem cleanup
    try:
        if os.path.isdir(SIMULATOR_FOLDER):
            shutil.rmtree(SIMULATOR_FOLDER, ignore_errors=True)
            logger.info("Simulator folder deleted: %s", SIMULATOR_FOLDER)
    except Exception as exc:
        logger.error("Filesystem cleanup failed: %s", exc)

    # Emit a refresh event so the dashboard reloads
    try:
        from backend.app import socketio
        socketio.emit("simulation_cleared", {"message": "Simulation data cleared"})
    except Exception as exc:
        logger.debug("Could not emit simulation_cleared: %s", exc)

    logger.info("Cleanup complete.")
