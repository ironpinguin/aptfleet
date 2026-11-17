"""Load the CISA KEV catalog (Known Exploited Vulnerabilities) and cache it locally."""
from __future__ import annotations

import datetime
import http.client
import json
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from cve_info import _default_ssl_context

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEFAULT_CACHE_PATH = Path.home() / ".cache" / "aptfleet" / "kev.json"
CACHE_TTL_SECONDS = 24 * 3600
FETCH_TIMEOUT = 30


@dataclass
class KevEntry:
    cve_id: str
    vendor: str
    product: str
    name: str
    date_added: str  # ISO YYYY-MM-DD


@dataclass
class KevData:
    entries: dict[str, KevEntry]
    fetched_at: float
    stale: bool  # True: fetch failed, expired cache used


def parse_kev_json(data: dict) -> dict[str, KevEntry]:
    """Converts the KEV feed into entries; entries without a valid cveID are skipped.

    A feed without valid entries is an error (ValueError)."""
    vulnerabilities = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(vulnerabilities, list):
        raise ValueError("KEV feed has no 'vulnerabilities' list")
    entries: dict[str, KevEntry] = {}
    for item in vulnerabilities:
        if not isinstance(item, dict):
            continue
        cve_id = item.get("cveID")
        if not isinstance(cve_id, str) or not cve_id.strip():
            continue
        cve_id = cve_id.strip()
        entries[cve_id] = KevEntry(
            cve_id=cve_id,
            vendor=str(item.get("vendorProject") or ""),
            product=str(item.get("product") or ""),
            name=str(item.get("vulnerabilityName") or ""),
            date_added=str(item.get("dateAdded") or ""),
        )
    if not entries:
        raise ValueError("KEV feed has no valid entries")
    return entries


def fetch_kev() -> dict:
    with urllib.request.urlopen(KEV_URL, timeout=FETCH_TIMEOUT, context=_default_ssl_context()) as resp:
        return json.load(resp)


def _load_cache(path: Path) -> KevData | None:
    """Reads the cache; missing or broken files count as no cache."""
    try:
        raw = json.loads(path.read_text())
        fetched_at = float(raw["fetched_at"])
        entries = {
            cve_id: KevEntry(cve_id, *(str(part) for part in values))
            for cve_id, values in raw["entries"].items()
        }
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return None
    return KevData(entries, fetched_at, False)


def _save_cache(path: Path, kev: KevData) -> None:
    payload = {
        "fetched_at": kev.fetched_at,
        "entries": {
            e.cve_id: [e.vendor, e.product, e.name, e.date_added] for e in kev.entries.values()
        },
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=1, sort_keys=True))
        tmp.replace(path)
    except OSError:
        pass  # The cache is only an optimisation; without it the next run fetches again.


def load_kev(
    cache_path: Path = DEFAULT_CACHE_PATH,
    fetch=fetch_kev,
    now: float | None = None,
) -> KevData | None:
    """Returns the KEV catalog (cache, 24 h TTL); None if neither fetch nor cache is available."""
    now = time.time() if now is None else now
    cached = _load_cache(cache_path)
    if cached is not None and now - cached.fetched_at < CACHE_TTL_SECONDS:
        return cached
    try:
        entries = parse_kev_json(fetch())
    except (OSError, ValueError, http.client.HTTPException):
        if cached is None:
            return None
        cached.stale = True
        return cached
    kev = KevData(entries, now, False)
    _save_cache(cache_path, kev)
    return kev


def recent_entries(kev: KevData, days: int, today: datetime.date) -> list[KevEntry]:
    """Entries from the last `days` calendar days including today, newest first, then by CVE ID."""
    cutoff = (today - datetime.timedelta(days=days)).isoformat()
    recent = [e for e in kev.entries.values() if e.date_added > cutoff]
    recent.sort(key=lambda e: e.cve_id)
    recent.sort(key=lambda e: e.date_added, reverse=True)  # stable: CVE ID stays the tiebreaker
    return recent
