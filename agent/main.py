"""
agent/main.py — Orchestrates all monitoring threads.

Each monitor runs in its own daemon thread.  Events are pushed into a
shared queue; a dispatcher thread reads that queue and persists them
to the database and emits them via SocketIO.
"""
import logging
import queue
import threading

logger = logging.getLogger(__name__)

# Shared event queue ─ all monitors write here; dispatcher reads here
event_queue: queue.Queue = queue.Queue()


def _dispatcher():
    """
    Read events from the queue and persist / emit them.
    Runs forever as a daemon thread.
    """
    from backend.database import insert_alert
    from backend.app import emit_alert

    while True:
        try:
            event = event_queue.get(timeout=1)
            if event is None:
                break

            event_type = event.get("event_type", "alert")

            if event_type == "alert":
                try:
                    alert_id = insert_alert(event)
                    event["id"] = alert_id
                    emit_alert(event)
                except Exception as exc:
                    logger.error("Dispatcher: insert_alert failed — %s", exc)

            event_queue.task_done()

        except queue.Empty:
            continue
        except Exception as exc:
            logger.error("Dispatcher error: %s", exc)


def start_agent():
    """Start all monitor threads and the dispatcher."""

    # ── Dispatcher ──────────────────────────────────────────────────────────
    t_dispatch = threading.Thread(
        target=_dispatcher, name="dispatcher", daemon=True
    )
    t_dispatch.start()

    # ── Process monitor ─────────────────────────────────────────────────────
    try:
        from agent.process_monitor import ProcessMonitor
        pm = ProcessMonitor(event_queue)
        threading.Thread(
            target=pm.run, name="process_monitor", daemon=True
        ).start()
        logger.info("Process monitor started.")
    except Exception as exc:
        logger.warning("Process monitor failed to start: %s", exc)

    # ── File monitor ────────────────────────────────────────────────────────
    try:
        from agent.file_monitor import FileMonitor
        fm = FileMonitor(event_queue)
        threading.Thread(
            target=fm.run, name="file_monitor", daemon=True
        ).start()
        logger.info("File monitor started.")
    except Exception as exc:
        logger.warning("File monitor failed to start: %s", exc)

    # ── Network monitor ─────────────────────────────────────────────────────
    try:
        from agent.network_monitor import NetworkMonitor
        nm = NetworkMonitor(event_queue)
        threading.Thread(
            target=nm.run, name="network_monitor", daemon=True
        ).start()
        logger.info("Network monitor started.")
    except Exception as exc:
        logger.warning("Network monitor failed to start: %s", exc)

    # ── Event log monitor ───────────────────────────────────────────────────
    try:
        from agent.event_log_monitor import EventLogMonitor
        elm = EventLogMonitor(event_queue)
        threading.Thread(
            target=elm.run, name="event_log_monitor", daemon=True
        ).start()
        logger.info("Event log monitor started.")
    except Exception as exc:
        logger.warning("Event log monitor failed to start: %s", exc)
