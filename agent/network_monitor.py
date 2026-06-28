"""
agent/network_monitor.py — Polls active network connections every NETWORK_INTERVAL seconds.

For each connection:
  • Checks the remote IP against bad_ips.txt
  • Flags unusual ports (not in NORMAL_PORTS)
  • Calls ip-api.com for GeoIP data (country, city, lat, lng)
  • Persists connection row to DB
  • Pushes alerts for flagged connections
"""
import logging
import os
import queue
import time

import psutil
import requests

from config import NETWORK_INTERVAL, NORMAL_PORTS
from agent.threat_engine import score

logger = logging.getLogger(__name__)

BAD_IPS_PATH = "data/bad_ips.txt"
GEO_API      = "http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon"


def _load_bad_ips() -> set:
    bad = set()
    try:
        with open(BAD_IPS_PATH, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    bad.add(line)
    except FileNotFoundError:
        pass
    return bad


def _geoip(ip: str) -> dict:
    """Return geo dict for *ip* using ip-api.com (free, no key needed)."""
    try:
        resp = requests.get(GEO_API.format(ip=ip), timeout=4)
        data = resp.json()
        if data.get("status") == "success":
            return {
                "country": data.get("country", ""),
                "city":    data.get("city", ""),
                "lat":     data.get("lat", 0.0),
                "lng":     data.get("lon", 0.0),
            }
    except Exception as exc:
        logger.debug("GeoIP failed for %s: %s", ip, exc)
    return {"country": "", "city": "", "lat": 0.0, "lng": 0.0}


def _get_process_name(pid: int) -> str:
    try:
        return psutil.Process(pid).name()
    except Exception:
        return "unknown"


class NetworkMonitor:
    def __init__(self, event_queue: queue.Queue):
        self.q           = event_queue
        self._seen        = set()   # (pid, remote_ip, remote_port) already alerted

    def _persist(self, row: dict):
        try:
            from backend.database import insert_connection
            insert_connection(row)
        except Exception as exc:
            logger.debug("insert_connection: %s", exc)

    def run(self):
        logger.info("Network monitor running (interval=%ds).", NETWORK_INTERVAL)
        bad_ips = _load_bad_ips()

        while True:
            try:
                bad_ips = _load_bad_ips()   # reload so operators can update list at runtime
                conns   = psutil.net_connections(kind="inet")

                for conn in conns:
                    if not conn.raddr:
                        continue

                    remote_ip   = conn.raddr.ip
                    remote_port = conn.raddr.port
                    pid         = conn.pid or 0
                    proc_name   = _get_process_name(pid) if pid else "unknown"

                    key = (pid, remote_ip, remote_port)
                    if key in self._seen:
                        continue
                    self._seen.add(key)

                    is_bad_ip    = remote_ip in bad_ips
                    unusual_port = remote_port not in NORMAL_PORTS

                    if not (is_bad_ip or unusual_port):
                        continue   # not interesting

                    # GeoIP lookup
                    geo = _geoip(remote_ip)

                    row = {
                        "pid":          pid,
                        "process_name": proc_name,
                        "remote_ip":    remote_ip,
                        "remote_port":  remote_port,
                        "flagged":      True,
                        **geo,
                    }
                    self._persist(row)

                    alert = {
                        "event_type":    "alert",
                        "type":          "network",
                        "process":       proc_name,
                        "ip":            remote_ip,
                        "remote_port":   remote_port,
                        "country":       geo["country"],
                        "lat":           geo["lat"],
                        "lng":           geo["lng"],
                        "bad_ip":        is_bad_ip,
                        "is_simulation": False,
                    }

                    if is_bad_ip:
                        alert["title"]       = "Connection to Known Malicious IP"
                        alert["description"] = (
                            f"'{proc_name}' (PID {pid}) connected to blacklisted IP "
                            f"{remote_ip} ({geo.get('country','?')})."
                        )
                    else:
                        alert["title"]       = f"Unusual Port Connection Detected"
                        alert["description"] = (
                            f"'{proc_name}' (PID {pid}) connected to {remote_ip}:{remote_port} "
                            f"({geo.get('country','?')}) on an unusual port."
                        )

                    self.q.put(score(alert))

            except Exception as exc:
                logger.error("Network monitor error: %s", exc)

            time.sleep(NETWORK_INTERVAL)
