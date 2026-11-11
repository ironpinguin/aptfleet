"""Debian-Versionsvergleich nach Debian Policy 5.6.12 (wie `dpkg --compare-versions`)."""
from __future__ import annotations


def _order(ch: str) -> int:
    """Sortiergewicht eines Zeichens im nicht-numerischen Teil."""
    if ch == "~":
        return -1
    if ch.isascii() and ch.isalpha():
        return ord(ch)
    return ord(ch) + 256


def _compare_part(a: str, b: str) -> int:
    """Vergleicht upstream- bzw. revision-Teil abwechselnd nicht-numerisch/numerisch."""
    i = j = 0
    while i < len(a) or j < len(b):
        # Nicht-numerischer Präfix
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            oa = _order(a[i]) if i < len(a) and not a[i].isdigit() else 0
            ob = _order(b[j]) if j < len(b) and not b[j].isdigit() else 0
            if oa != ob:
                return -1 if oa < ob else 1
            if i < len(a) and not a[i].isdigit():
                i += 1
            if j < len(b) and not b[j].isdigit():
                j += 1
        # Numerischer Präfix (leer = 0)
        si = i
        while i < len(a) and a[i].isdigit():
            i += 1
        sj = j
        while j < len(b) and b[j].isdigit():
            j += 1
        na = int(a[si:i] or 0)
        nb = int(b[sj:j] or 0)
        if na != nb:
            return -1 if na < nb else 1
    return 0


def _split(version: str) -> tuple[int, str, str]:
    """Zerlegt in (epoch, upstream, revision); Revision default "0"."""
    epoch = 0
    if ":" in version:
        e, version = version.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    upstream, sep, revision = version.rpartition("-")
    if not sep:
        upstream, revision = version, "0"
    return epoch, upstream, revision


def compare_versions(a: str, b: str) -> int:
    """Gibt -1, 0 oder 1 zurück, wenn a kleiner, gleich oder größer als b ist."""
    ea, ua, ra = _split(a)
    eb, ub, rb = _split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _compare_part(ua, ub) or _compare_part(ra, rb)
