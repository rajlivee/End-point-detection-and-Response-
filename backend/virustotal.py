"""
backend/virustotal.py — VirusTotal v3 API integration.

Only the hash-lookup endpoint is used (free tier: 4 req/min).
Returns a short human-readable summary string, or None if:
  • No API key is configured.
  • The request fails.
  • The file is unknown to VT.
"""
import logging
import time

import requests

from config import VIRUSTOTAL_API_KEY

logger  = logging.getLogger(__name__)
VT_URL  = "https://www.virustotal.com/api/v3/files/{hash}"
_LAST   = 0.0          # timestamp of the last VT request (rate-limit guard)
_MIN_GAP = 15.0        # seconds (free tier: 4 req/min)


def check_hash(file_hash: str) -> str | None:
    """
    Look up *file_hash* on VirusTotal.

    Returns a short summary string like "3/72 engines flagged as malware"
    or None when the hash is unknown / the key is missing.
    """
    global _LAST

    if not VIRUSTOTAL_API_KEY:
        return None   # Key not configured — skip silently

    # Rate-limit: free tier allows 4 requests / minute
    elapsed = time.time() - _LAST
    if elapsed < _MIN_GAP:
        time.sleep(_MIN_GAP - elapsed)

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        resp = requests.get(
            VT_URL.format(hash=file_hash),
            headers=headers,
            timeout=10,
        )
        _LAST = time.time()

        if resp.status_code == 404:
            return None   # Unknown to VT
        if resp.status_code == 429:
            logger.warning("VirusTotal rate limit hit — skipping.")
            return None
        resp.raise_for_status()

        data        = resp.json()
        stats       = data["data"]["attributes"]["last_analysis_stats"]
        malicious   = stats.get("malicious", 0)
        total       = sum(stats.values())
        name_guess  = (
            data["data"]["attributes"].get("meaningful_name")
            or data["data"]["attributes"].get("name", "unknown")
        )

        if malicious > 0:
            return f"{malicious}/{total} engines flagged '{name_guess}' as malicious"
        return f"0/{total} detections (clean)"

    except requests.RequestException as exc:
        logger.error("VirusTotal request failed: %s", exc)
        return None
    except (KeyError, ValueError) as exc:
        logger.error("VirusTotal response parse error: %s", exc)
        return None
