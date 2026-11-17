"""Load the Ubuntu OVAL feed (CVE definitions per codename), parse it and cache it locally."""
from __future__ import annotations

import bz2
import http.client
import io
import json
import re
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from cve_info import _default_ssl_context

OVAL_URL = "https://security-metadata.canonical.com/oval/com.ubuntu.{codename}.cve.oval.xml.bz2"
DEFAULT_CACHE_DIR = Path.home() / ".cache" / "aptfleet"
CACHE_TTL_SECONDS = 24 * 3600
FETCH_TIMEOUT = 120

CODENAME_RE = re.compile(r"[a-z]+")
CVE_RE = re.compile(r'<cve href="[^"]*" priority="([a-z]+)"[^>]*>(CVE-\d{4}-\d+)</cve>')
# The archive can be "noble", "esm-apps/noble" or similar, hence the broad character class.
PKG_RE = re.compile(
    r"comment=\"([a-z0-9.+-]+) source package in [a-z0-9/.+-]+, "
    r"(?:is affected and has been fixed \(note: '([^']*)'\)|might be affected and may need fixing)"
)
KERNEL_FIXED_RE = re.compile(
    r"comment=\"'([a-z0-9.+-]+)' kernel in [a-z]+ was vulnerable but has been fixed \(note: '([^']*)'\)"
)
KERNEL_RUNNING_RE = re.compile(r"comment=\"Is kernel '([a-z0-9.+-]+)' running\?\"")


@dataclass
class OvalCve:
    cve_id: str
    priority: str | None
    packages: dict[str, str | None]  # source package -> fix version, None = not fixed
    kernels: dict[str, str | None]  # kernel source package -> fix version, None = not fixed


@dataclass
class OvalData:
    cves: dict[str, OvalCve]
    fetched_at: float
    stale: bool  # True: fetch failed, expired cache used


def _merge_package(packages: dict[str, str | None], name: str, fixed: str | None) -> None:
    """Several archives (e.g. noble and esm-apps/noble) can list the same package."""
    if name not in packages:
        packages[name] = fixed
        return
    old = packages[name]
    if old is None:
        packages[name] = fixed
    elif fixed is not None and "esm" in old and "esm" not in fixed:
        packages[name] = fixed  # regular archive wins over ESM


def parse_oval(lines: Iterable[str]) -> dict[str, OvalCve]:
    """Line-based parser: <definition> opens, </definition> closes.

    Definitions without a CVE ID are dropped.
    """
    cves: dict[str, OvalCve] = {}
    current: OvalCve | None = None
    in_definition = False
    for line in lines:
        if not in_definition:
            if "<definition " in line:
                in_definition = True
                current = OvalCve("", None, {}, {})
            continue
        if "</definition>" in line:
            if current is not None and current.cve_id:
                cves[current.cve_id] = current
            in_definition = False
            current = None
            continue
        if current is None:
            continue
        if not current.cve_id:
            m = CVE_RE.search(line)
            if m:
                current.priority, current.cve_id = m.group(1), m.group(2)
                continue
        m = PKG_RE.search(line)
        if m:
            _merge_package(current.packages, m.group(1), m.group(2))
            continue
        m = KERNEL_FIXED_RE.search(line)
        if m:
            current.kernels[m.group(1)] = m.group(2)  # always overrides None
            continue
        m = KERNEL_RUNNING_RE.search(line)
        if m:
            current.kernels.setdefault(m.group(1), None)
    return cves


def fetch_oval(codename: str) -> bytes:
    url = OVAL_URL.format(codename=codename)
    with urllib.request.urlopen(url, timeout=FETCH_TIMEOUT, context=_default_ssl_context()) as resp:
        return resp.read()


def _parse_blob(blob: bytes) -> dict[str, OvalCve]:
    """Decompresses as a stream and parses; broken data or 0 CVEs is an error."""
    try:
        with io.TextIOWrapper(bz2.BZ2File(io.BytesIO(blob)), encoding="utf-8") as text:
            cves = parse_oval(text)
    except (OSError, EOFError, ValueError) as exc:
        raise ValueError(f"OVAL feed unreadable: {exc}") from exc
    if not cves:
        raise ValueError("OVAL feed has no CVE definitions")
    return cves


def _load_cache(path: Path) -> OvalData | None:
    """Reads the cache; missing or broken files count as no cache."""
    try:
        raw = json.loads(path.read_text())
        fetched_at = float(raw["fetched_at"])
        cves = {
            cve_id: OvalCve(cve_id, priority, dict(packages), dict(kernels))
            for cve_id, (priority, packages, kernels) in raw["cves"].items()
        }
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return None
    return OvalData(cves, fetched_at, False)


def _save_cache(path: Path, data: OvalData) -> None:
    payload = {
        "fetched_at": data.fetched_at,
        "cves": {c.cve_id: [c.priority, c.packages, c.kernels] for c in data.cves.values()},
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, separators=(",", ":"), sort_keys=True))
        tmp.replace(path)
    except OSError:
        pass  # The cache is only an optimisation; without it the next run fetches again.


def load_oval(
    codename: str,
    cache_dir: Path = DEFAULT_CACHE_DIR,
    fetch=fetch_oval,
    now: float | None = None,
) -> OvalData | None:
    """Returns the OVAL data (cache, 24 h TTL); None for an invalid codename
    or if neither fetch nor cache is available."""
    if not CODENAME_RE.fullmatch(codename):
        return None
    now = time.time() if now is None else now
    path = cache_dir / f"oval-{codename}.json"
    cached = _load_cache(path)
    if cached is not None and now - cached.fetched_at < CACHE_TTL_SECONDS:
        return cached
    try:
        cves = _parse_blob(fetch(codename))
    except (OSError, ValueError, http.client.HTTPException):
        if cached is None:
            return None
        cached.stale = True
        return cached
    data = OvalData(cves, now, False)
    _save_cache(path, data)
    return data
