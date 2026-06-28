"""
run.py — Single entry point.
Starts the EDR agent threads and the Flask/SocketIO server,
then auto-opens the browser at the dashboard.
"""
import os
import sys
import time
import logging
import threading
import webbrowser

# ── Bootstrap: make sure data / logs / exports directories exist ──────────────
for folder in ("data", "logs", "exports"):
    os.makedirs(folder, exist_ok=True)

# ── Import application pieces ──────────────────────────────────────────────────
from backend.database import init_db
from backend.app import app, socketio, start_background_emitter
from agent.main import start_agent

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("logs/edr.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger("run")


def open_browser():
    """Wait a moment for the server to start, then open the dashboard."""
    time.sleep(2)
    webbrowser.open("http://localhost:5000")


if __name__ == "__main__":
    logger.info("═══════════════════════════════════════════")
    logger.info("  EDR System — Starting up …")
    logger.info("═══════════════════════════════════════════")

    # 1. Initialise the database
    init_db()
    logger.info("Database initialised.")

    # 2. Start agent monitoring threads
    start_agent()
    logger.info("Agent threads started.")

    # 3. Start the background SocketIO emitter (stats_update every 10 s)
    start_background_emitter()

    # 4. Open browser after a brief delay
    threading.Thread(target=open_browser, daemon=True).start()

    logger.info("Dashboard → http://localhost:5000")
    logger.info("Press Ctrl+C to stop.")

    # 5. Run Flask-SocketIO (blocking)
    socketio.run(app, host="0.0.0.0", port=5000, debug=False, use_reloader=False, allow_unsafe_werkzeug=True)
