"""CVE-Priorität und -Beschreibung über die Ubuntu-Security-API, mit lokalem Cache."""
from __future__ import annotations

import functools
import http.client
import json
import ssl
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

API_URL = "https://ubuntu.com/security/cves/{cve_id}.json"
DEFAULT_CACHE_PATH = Path.home() / ".cache" / "aptfleet" / "cves.json"
CACHE_TTL_SECONDS = 7 * 24 * 3600
FETCH_TIMEOUT = 10
MAX_WORKERS = 8
DESCRIPTION_MAX = 200
SYSTEM_CA_FILE = Path("/etc/ssl/cert.pem")
PRIORITY_ORDER = ["critical", "high", "medium", "low", "negligible"]


@dataclass
class CveInfo:
    cve_id: str
    priority: str | None
    description: str | None


def priority_rank(priority: str | None) -> int:
    if priority in PRIORITY_ORDER:
        return PRIORITY_ORDER.index(priority)
    return len(PRIORITY_ORDER)


def _one_line(text: str | None) -> str | None:
    if not text:
        return None
    collapsed = " ".join(text.split())
    if len(collapsed) <= DESCRIPTION_MAX:
        return collapsed
    return collapsed[: DESCRIPTION_MAX - 1] + "…"


def parse_cve_json(cve_id: str, data: dict) -> CveInfo:
    return CveInfo(
        cve_id=cve_id,
        priority=data.get("priority") or None,
        description=_one_line(data.get("description") or data.get("ubuntu_description")),
    )


def build_ssl_context(fallback_cafile: Path = SYSTEM_CA_FILE, factory=ssl.create_default_context):
    """Python von python.org bringt unter macOS keine CA-Zertifikate mit; dann System-CAs laden."""
    context = factory()
    if context.cert_store_stats()["x509_ca"] == 0 and fallback_cafile.exists():
        context.load_verify_locations(cafile=str(fallback_cafile))
    return context


@functools.lru_cache(maxsize=1)
def _default_ssl_context() -> ssl.SSLContext:
    return build_ssl_context()


def fetch_cve(cve_id: str) -> CveInfo:
    url = API_URL.format(cve_id=cve_id)
    with urllib.request.urlopen(url, timeout=FETCH_TIMEOUT, context=_default_ssl_context()) as resp:
        return parse_cve_json(cve_id, json.load(resp))


def _load_cache(path: Path) -> dict:
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _save_cache(path: Path, cache: dict) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(cache, indent=1, sort_keys=True))
        tmp.replace(path)
    except OSError:
        pass  # Cache ist nur eine Optimierung; ohne ihn wird beim nächsten Lauf neu abgefragt.


def lookup_cves(
    cve_ids,
    cache_path: Path = DEFAULT_CACHE_PATH,
    fetch=fetch_cve,
    now: float | None = None,
) -> tuple[dict[str, CveInfo], list[str]]:
    """Liefert Infos zu allen IDs und die Liste der IDs, deren Abfrage fehlschlug."""
    ids = sorted(set(cve_ids))
    if not ids:
        return {}, []
    now = time.time() if now is None else now
    cache = _load_cache(cache_path)

    infos: dict[str, CveInfo] = {}
    missing: list[str] = []
    for cve_id in ids:
        entry = cache.get(cve_id)
        if isinstance(entry, dict) and now - entry.get("fetched_at", 0) < CACHE_TTL_SECONDS:
            infos[cve_id] = CveInfo(cve_id, entry.get("priority"), entry.get("description"))
        else:
            missing.append(cve_id)

    def safe_fetch(cve_id: str) -> CveInfo | None:
        try:
            return fetch(cve_id)
        except (OSError, ValueError, http.client.HTTPException):
            return None

    failed: list[str] = []
    if missing:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            for cve_id, info in zip(missing, pool.map(safe_fetch, missing)):
                if info is None:
                    failed.append(cve_id)
                    infos[cve_id] = CveInfo(cve_id, None, None)
                else:
                    infos[cve_id] = info
                    cache[cve_id] = {
                        "priority": info.priority,
                        "description": info.description,
                        "fetched_at": now,
                    }
        _save_cache(cache_path, cache)
    return infos, failed
