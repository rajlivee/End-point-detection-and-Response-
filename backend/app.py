"""
backend/app.py — Flask + Flask-SocketIO server.

Provides:
  REST API   — alerts, processes, network, stats, export, whitelist
  Simulation — POST /api/simulate/<type>
  WebSocket  — real-time alert & stats push
"""
import csv
import io
import json
import logging
import os
import threading
import time

from flask import Flask, jsonify, render_template, request, send_file
from flask_cors import CORS
from flask_socketio import SocketIO

from config import FLASK_PORT, EXPORT_PATH

logger = logging.getLogger(__name__)

# ── App setup ─────────────────────────────────────────────────────────────────
app = Flask(
    __name__,
    template_folder="../dashboard/templates",
    static_folder="../dashboard/static",
)
app.secret_key = "edr-project-secret-key-2024"
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")


# ── SocketIO helpers ──────────────────────────────────────────────────────────

def emit_alert(alert: dict):
    """Emit a single alert to all connected dashboard clients."""
    try:
        socketio.emit("new_alert", alert)
    except Exception as exc:
        logger.debug("emit_alert: %s", exc)


def _stats_emitter():
    """Emit 'stats_update' every 10 seconds."""
    while True:
        try:
            from backend.database import get_alert_stats
            stats = get_alert_stats()
            socketio.emit("stats_update", stats)
        except Exception as exc:
            logger.debug("stats_emitter: %s", exc)
        time.sleep(10)


def start_background_emitter():
    t = threading.Thread(target=_stats_emitter, name="stats_emitter", daemon=True)
    t.start()


# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# ── REST API — Alerts ─────────────────────────────────────────────────────────

@app.route("/api/alerts")
def api_alerts():
    from backend.database import get_alerts
    severity = request.args.get("severity")
    limit    = int(request.args.get("limit", 200))
    alerts   = get_alerts(limit=limit, severity=severity)
    return jsonify(alerts)


@app.route("/api/alerts/live")
def api_alerts_live():
    """Return the 20 most recent alerts (for initial page load)."""
    from backend.database import get_alerts
    return jsonify(get_alerts(limit=20))


# ── REST API — Processes ──────────────────────────────────────────────────────

@app.route("/api/processes")
def api_processes():
    from backend.database import get_processes
    return jsonify(get_processes())


# ── REST API — Network ────────────────────────────────────────────────────────

@app.route("/api/network")
def api_network():
    from backend.database import get_connections
    return jsonify(get_connections())


# ── REST API — Stats ──────────────────────────────────────────────────────────

@app.route("/api/stats")
def api_stats():
    from backend.database import (
        get_alert_stats, get_alerts_over_time,
        get_alerts_by_type, get_top_processes,
    )
    return jsonify({
        "counts":      get_alert_stats(),
        "over_time":   get_alerts_over_time(),
        "by_type":     get_alerts_by_type(),
        "top_procs":   get_top_processes(),
    })


# ── REST API — Whitelist ──────────────────────────────────────────────────────

@app.route("/api/whitelist", methods=["POST"])
def api_whitelist():
    from backend.database import add_whitelist
    data  = request.get_json(silent=True) or {}
    wtype = data.get("type", "process")
    value = data.get("value", "")
    if not value:
        return jsonify({"error": "value required"}), 400
    add_whitelist(wtype, value)
    return jsonify({"status": "ok"})


# ── REST API — Exports ────────────────────────────────────────────────────────

@app.route("/api/export/csv")
def api_export_csv():
    from backend.database import get_alerts
    alerts = get_alerts(limit=5000)
    os.makedirs(EXPORT_PATH, exist_ok=True)
    filepath = os.path.join(EXPORT_PATH, "edr_alerts.csv")

    fields = [
        "id", "timestamp", "type", "severity", "score",
        "title", "description", "process", "file_path",
        "ip", "country", "virustotal_result", "is_simulation",
    ]
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(alerts)

    return send_file(
        os.path.abspath(filepath),
        mimetype="text/csv",
        as_attachment=True,
        download_name="edr_alerts.csv",
    )


@app.route("/api/export/pdf")
def api_export_pdf():
    from backend.database import get_alerts
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer,
    )
    from reportlab.lib.styles import getSampleStyleSheet

    alerts   = get_alerts(limit=200)
    os.makedirs(EXPORT_PATH, exist_ok=True)
    filepath = os.path.join(EXPORT_PATH, "edr_report.pdf")

    doc    = SimpleDocTemplate(filepath, pagesize=letter)
    styles = getSampleStyleSheet()
    story  = []

    story.append(Paragraph("EDR Threat Report", styles["Title"]))
    story.append(Paragraph(
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}  |  Total alerts: {len(alerts)}",
        styles["Normal"],
    ))
    story.append(Spacer(1, 12))

    # Table header
    header = ["ID", "Time", "Severity", "Score", "Title", "Type"]
    rows   = [header]

    SEV_COLOR = {
        "CRITICAL": colors.HexColor("#ef4444"),
        "HIGH":     colors.HexColor("#f97316"),
        "MEDIUM":   colors.HexColor("#eab308"),
        "LOW":      colors.HexColor("#22c55e"),
    }

    for a in alerts:
        rows.append([
            str(a.get("id", "")),
            time.strftime("%H:%M:%S", time.localtime(a.get("timestamp", 0))),
            a.get("severity", ""),
            str(a.get("score", "")),
            (a.get("title") or "")[:60],
            a.get("type", ""),
        ])

    t = Table(rows, colWidths=[35, 65, 60, 40, 220, 70])
    ts = TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.HexColor("#0f172a"), colors.HexColor("#1e293b")]),
        ("TEXTCOLOR",   (0, 1), (-1, -1), colors.HexColor("#e2e8f0")),
        ("GRID",        (0, 0), (-1, -1), 0.25, colors.HexColor("#334155")),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
        ("PADDING",     (0, 0), (-1, -1), 4),
    ])
    # Colour severity cells
    for i, alert in enumerate(alerts, start=1):
        sev = alert.get("severity", "LOW")
        col = SEV_COLOR.get(sev, colors.grey)
        ts.add("BACKGROUND", (2, i), (2, i), col)
        ts.add("TEXTCOLOR",  (2, i), (2, i), colors.white)
    t.setStyle(ts)
    story.append(t)

    doc.build(story)
    return send_file(
        os.path.abspath(filepath),
        mimetype="application/pdf",
        as_attachment=True,
        download_name="edr_report.pdf",
    )


# ── Simulation endpoints ──────────────────────────────────────────────────────

def _run_sim_thread(func):
    """Run *func* in a daemon thread so the HTTP response returns immediately."""
    t = threading.Thread(target=func, daemon=True)
    t.start()


@app.route("/api/simulate/ransomware", methods=["POST"])
def sim_ransomware():
    from simulator.ransomware_sim import run_ransomware_sim
    _run_sim_thread(run_ransomware_sim)
    return jsonify({"status": "ok", "message": "Ransomware simulation started"})


@app.route("/api/simulate/process", methods=["POST"])
def sim_process():
    from simulator.process_sim import run_suspicious_process_sim
    _run_sim_thread(run_suspicious_process_sim)
    return jsonify({"status": "ok", "message": "Process simulation started"})


@app.route("/api/simulate/network", methods=["POST"])
def sim_network():
    from simulator.network_sim import run_network_sim
    _run_sim_thread(run_network_sim)
    return jsonify({"status": "ok", "message": "Network simulation started"})


@app.route("/api/simulate/bruteforce", methods=["POST"])
def sim_bruteforce():
    from simulator.bruteforce_sim import run_bruteforce_sim
    _run_sim_thread(run_bruteforce_sim)
    return jsonify({"status": "ok", "message": "Brute-force simulation started"})


@app.route("/api/simulate/privilege", methods=["POST"])
def sim_privilege():
    from simulator.privilege_sim import run_privilege_sim
    _run_sim_thread(run_privilege_sim)
    return jsonify({"status": "ok", "message": "Privilege escalation simulation started"})


@app.route("/api/simulate/all", methods=["POST"])
def sim_all():
    from simulator.simulator import run_all_attacks
    _run_sim_thread(run_all_attacks)
    return jsonify({"status": "ok", "message": "All attack simulations started"})


@app.route("/api/simulate/cleanup", methods=["POST"])
def sim_cleanup():
    from simulator.simulator import cleanup_simulation
    _run_sim_thread(cleanup_simulation)
    return jsonify({"status": "ok", "message": "Cleanup started"})


# ── SocketIO events ───────────────────────────────────────────────────────────

@socketio.on("connect")
def on_connect():
    logger.info("Dashboard client connected: %s", request.sid)


@socketio.on("disconnect")
def on_disconnect():
    logger.info("Dashboard client disconnected: %s", request.sid)
