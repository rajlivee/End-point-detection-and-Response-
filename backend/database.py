"""
backend/database.py — SQLite schema definition and query helpers.

Tables
──────
  alerts              — Every detected threat event.
  processes           — Process snapshots for the tree view.
  network_connections — Active flagged connections.
  whitelist           — User-managed exclusion list.
"""
import logging
import sqlite3
import time
from contextlib import contextmanager

from config import DB_PATH

logger = logging.getLogger(__name__)


# ── Connection factory ────────────────────────────────────────────────────────

@contextmanager
def _conn():
    """Yields a thread-safe SQLite connection with WAL mode enabled."""
    con = sqlite3.connect(DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=NORMAL")
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


# ── Schema ────────────────────────────────────────────────────────────────────

def init_db():
    """Create all tables if they do not exist yet."""
    with _conn() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS alerts (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp           REAL    NOT NULL,
            type                TEXT,
            severity            TEXT,
            score               INTEGER DEFAULT 0,
            title               TEXT,
            description         TEXT,
            process             TEXT,
            file_path           TEXT,
            ip                  TEXT,
            country             TEXT,
            lat                 REAL,
            lng                 REAL,
            virustotal_result   TEXT,
            is_simulation       INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS processes (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   REAL    NOT NULL,
            pid         INTEGER,
            name        TEXT,
            parent_pid  INTEGER,
            parent_name TEXT,
            path        TEXT,
            username    TEXT,
            status      TEXT
        );

        CREATE TABLE IF NOT EXISTS network_connections (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp    REAL    NOT NULL,
            pid          INTEGER,
            process_name TEXT,
            remote_ip    TEXT,
            remote_port  INTEGER,
            country      TEXT,
            city         TEXT,
            lat          REAL,
            lng          REAL,
            flagged      INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS whitelist (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            type     TEXT,
            value    TEXT UNIQUE,
            added_at REAL
        );
        """)
    logger.info("Database schema ready at '%s'.", DB_PATH)


# ── Alerts ────────────────────────────────────────────────────────────────────

def insert_alert(alert: dict) -> int:
    """Insert one alert row; returns the new row ID."""
    with _conn() as con:
        cur = con.execute(
            """
            INSERT INTO alerts
                (timestamp, type, severity, score, title, description,
                 process, file_path, ip, country, lat, lng,
                 virustotal_result, is_simulation)
            VALUES
                (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert.get("timestamp", time.time()),
                alert.get("type"),
                alert.get("severity", "LOW"),
                alert.get("score", 0),
                alert.get("title"),
                alert.get("description"),
                alert.get("process"),
                alert.get("file_path"),
                alert.get("ip"),
                alert.get("country"),
                alert.get("lat"),
                alert.get("lng"),
                alert.get("virustotal_result"),
                1 if alert.get("is_simulation") else 0,
            ),
        )
        return cur.lastrowid


def get_alerts(limit: int = 200, severity: str = None,
               sim_only: bool = False) -> list[dict]:
    """Return recent alerts as a list of dicts."""
    where_clauses = []
    params        = []

    if severity:
        where_clauses.append("severity = ?")
        params.append(severity.upper())
    if sim_only:
        where_clauses.append("is_simulation = 1")

    where = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
    sql   = f"SELECT * FROM alerts {where} ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    with _conn() as con:
        rows = con.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def delete_simulation_alerts():
    """Remove all is_simulation=1 rows."""
    with _conn() as con:
        con.execute("DELETE FROM alerts WHERE is_simulation = 1")
        con.execute("DELETE FROM network_connections WHERE flagged = 1")


def get_alert_stats() -> dict:
    """Aggregate counts by severity."""
    with _conn() as con:
        rows = con.execute(
            "SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity"
        ).fetchall()
        total = con.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

    stats = {"total": total, "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for row in rows:
        stats[row["severity"]] = row["cnt"]
    return stats


def get_alerts_over_time(minutes: int = 60) -> list[dict]:
    """Return alert counts grouped into 5-minute buckets for the past *minutes* minutes."""
    cutoff = time.time() - (minutes * 60)
    with _conn() as con:
        rows = con.execute(
            """
            SELECT
                CAST((timestamp - ?) / 300 AS INTEGER) AS bucket,
                COUNT(*) AS cnt
            FROM alerts
            WHERE timestamp >= ?
            GROUP BY bucket
            ORDER BY bucket
            """,
            (cutoff, cutoff),
        ).fetchall()
    return [dict(r) for r in rows]


def get_alerts_by_type() -> list[dict]:
    with _conn() as con:
        rows = con.execute(
            "SELECT type, COUNT(*) as cnt FROM alerts GROUP BY type"
        ).fetchall()
    return [dict(r) for r in rows]


def get_top_processes(limit: int = 5) -> list[dict]:
    with _conn() as con:
        rows = con.execute(
            """
            SELECT process, COUNT(*) as cnt
            FROM alerts
            WHERE process IS NOT NULL AND process != ''
            GROUP BY process
            ORDER BY cnt DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


# ── Processes ─────────────────────────────────────────────────────────────────

def insert_process(info: dict):
    with _conn() as con:
        con.execute(
            """
            INSERT OR IGNORE INTO processes
                (timestamp, pid, name, parent_pid, parent_name, path, username, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                time.time(),
                info.get("pid"),
                info.get("name"),
                info.get("ppid"),
                info.get("parent_name"),
                info.get("exe"),
                info.get("username"),
                info.get("status"),
            ),
        )


def get_processes(limit: int = 100) -> list[dict]:
    with _conn() as con:
        rows = con.execute(
            """
            SELECT DISTINCT pid, name, parent_pid, parent_name, path, username, status
            FROM processes
            ORDER BY rowid DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


# ── Network connections ───────────────────────────────────────────────────────

def insert_connection(row: dict):
    with _conn() as con:
        con.execute(
            """
            INSERT INTO network_connections
                (timestamp, pid, process_name, remote_ip, remote_port,
                 country, city, lat, lng, flagged)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                time.time(),
                row.get("pid"),
                row.get("process_name"),
                row.get("remote_ip"),
                row.get("remote_port"),
                row.get("country"),
                row.get("city"),
                row.get("lat"),
                row.get("lng"),
                1 if row.get("flagged") else 0,
            ),
        )


def get_connections(limit: int = 100) -> list[dict]:
    with _conn() as con:
        rows = con.execute(
            "SELECT * FROM network_connections ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


# ── Whitelist ─────────────────────────────────────────────────────────────────

def add_whitelist(wtype: str, value: str):
    with _conn() as con:
        con.execute(
            "INSERT OR IGNORE INTO whitelist (type, value, added_at) VALUES (?, ?, ?)",
            (wtype, value, time.time()),
        )


def get_whitelist() -> list[dict]:
    with _conn() as con:
        rows = con.execute("SELECT * FROM whitelist").fetchall()
    return [dict(r) for r in rows]
