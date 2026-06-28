"""
simulator/network_sim.py — Malicious IP connection simulation.

Picks up to 3 IPs from data/bad_ips.txt (or uses hardcoded fallbacks),
calls ip-api.com for real geo data so map markers appear correctly,
then injects HIGH alerts into the database.

No real network connections are made to the bad IPs.
"""
import logging
import time

import requests

logger = logging.getLogger(__name__)

FALLBACK_IPS = ["185.220.101.1", "194.165.16.11", "45.142.212.100"]
GEO_URL      = "http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon"


def _load_bad_ips() -> list:
    ips = []
    try:
        with open("data/bad_ips.txt") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    ips.append(line)
    except FileNotFoundError:
        pass
    return ips[:3] if ips else FALLBACK_IPS


def _geoip(ip: str) -> dict:
    try:
        r = requests.get(GEO_URL.format(ip=ip), timeout=5)
        d = r.json()
        if d.get("status") == "success":
            return {
                "country": d.get("country", "Unknown"),
                "city":    d.get("city", ""),
                "lat":     d.get("lat", 0.0),
                "lng":     d.get("lon", 0.0),
            }
    except Exception as exc:
        logger.debug("GeoIP failed for %s: %s", ip, exc)
    return {"country": "Unknown", "city": "", "lat": 0.0, "lng": 0.0}


def _emit(alert: dict):
    try:
        from backend.app import emit_alert
        from backend.database import insert_alert, insert_connection
        # Also add a network_connection row so the map gets a dot
        insert_connection({
            "pid":          0,
            "process_name": alert.get("process", "chrome_update.exe"),
            "remote_ip":    alert.get("ip", ""),
            "remote_port":  alert.get("remote_port", 443),
            "country":      alert.get("country", ""),
            "city":         "",
            "lat":          alert.get("lat", 0.0),
            "lng":          alert.get("lng", 0.0),
            "flagged":      True,
        })
        alert_id = insert_alert(alert)
        alert["id"] = alert_id
        emit_alert(alert)
    except Exception as exc:
        logger.error("network_sim emit: %s", exc)


def run_network_sim():
    logger.info("▶ Network simulation starting …")
    bad_ips = _load_bad_ips()

    fake_processes = ["chrome_update.exe", "svchost32.exe", "updater.exe"]

    for i, ip in enumerate(bad_ips[:3]):
        geo  = _geoip(ip)
        proc = fake_processes[i % len(fake_processes)]

        _emit({
            "timestamp":     time.time(),
            "type":          "network",
            "severity":      "HIGH",
            "score":         78,
            "title":         "Connection to Known Malicious IP",
            "description":   (
                f"Process {proc} attempted connection to {ip} "
                f"({geo['country']}) — IP is on the threat intelligence blacklist."
            ),
            "process":       proc,
            "ip":            ip,
            "remote_port":   443,
            "country":       geo["country"],
            "lat":           geo["lat"],
            "lng":           geo["lng"],
            "is_simulation": True,
        })
        time.sleep(0.8)

    logger.info("Network simulation alerts injected.")
