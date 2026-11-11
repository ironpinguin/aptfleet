"""Ubuntu-OVAL-Feed (CVE-Definitionen je Codename) laden, parsen und lokal cachen."""
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
DEFAULT_CACHE_DIR = Path.home() / ".cache" / "updates_report"
CACHE_TTL_SECONDS = 24 * 3600
FETCH_TIMEOUT = 120

CODENAME_RE = re.compile(r"[a-z]+")
CVE_RE = re.compile(r'<cve href="[^"]*" priority="([a-z]+)"[^>]*>(CVE-\d{4}-\d+)</cve>')
# Archiv kann "noble", "esm-apps/noble" o. ä. sein, daher großzügige Zeichenklasse.
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
    packages: dict[str, str | None]  # Quellpaket -> Fix-Version, None = ungefixt
    kernels: dict[str, str | None]  # Kernel-Quellpaket -> Fix-Version, None = ungefixt


@dataclass
class OvalData:
    cves: dict[str, OvalCve]
    fetched_at: float
    stale: bool  # True: Abruf fehlgeschlagen, abgelaufener Cache verwendet


def _merge_package(packages: dict[str, str | None], name: str, fixed: str | None) -> None:
    """Mehrere Archive (z. B. noble und esm-apps/noble) können dasselbe Paket nennen."""
    if name not in packages:
        packages[name] = fixed
        return
    old = packages[name]
    if old is None:
        packages[name] = fixed
    elif fixed is not None and "esm" in old and "esm" not in fixed:
        packages[name] = fixed  # reguläres Archiv schlägt ESM


def parse_oval(lines: Iterable[str]) -> dict[str, OvalCve]:
    """Zeilenweiser Parser: <definition> startet, </definition> schließt.

    Definitionen ohne CVE-ID werden verworfen.
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
            current.kernels[m.group(1)] = m.group(2)  # überschreibt immer None
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
    """Dekomprimiert streamend und parst; kaputte Daten oder 0 CVEs sind ein Fehler."""
    try:
        with io.TextIOWrapper(bz2.BZ2File(io.BytesIO(blob)), encoding="utf-8") as text:
            cves = parse_oval(text)
    except (OSError, EOFError, ValueError) as exc:
        raise ValueError(f"OVAL-Feed nicht lesbar: {exc}") from exc
    if not cves:
        raise ValueError("OVAL-Feed ohne CVE-Definitionen")
    return cves


def _load_cache(path: Path) -> OvalData | None:
    """Liest den Cache; fehlende oder kaputte Dateien zählen als kein Cache."""
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
        pass  # Cache ist nur eine Optimierung; ohne ihn wird beim nächsten Lauf neu abgefragt.


def load_oval(
    codename: str,
    cache_dir: Path = DEFAULT_CACHE_DIR,
    fetch=fetch_oval,
    now: float | None = None,
) -> OvalData | None:
    """Liefert die OVAL-Daten (Cache, 24 h TTL); None bei ungültigem Codename
    oder wenn weder Abruf noch Cache möglich sind."""
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
