"""Debian version comparison per Debian Policy 5.6.12 (like `dpkg --compare-versions`)."""
from __future__ import annotations


def _order(ch: str) -> int:
    """Sort weight of a character in the non-numeric part."""
    if ch == "~":
        return -1
    if ch.isascii() and ch.isalpha():
        return ord(ch)
    return ord(ch) + 256


def _compare_part(a: str, b: str) -> int:
    """Compares the upstream or revision part, alternating non-numeric/numeric."""
    i = j = 0
    while i < len(a) or j < len(b):
        # non-numeric prefix
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            oa = _order(a[i]) if i < len(a) and not a[i].isdigit() else 0
            ob = _order(b[j]) if j < len(b) and not b[j].isdigit() else 0
            if oa != ob:
                return -1 if oa < ob else 1
            if i < len(a) and not a[i].isdigit():
                i += 1
            if j < len(b) and not b[j].isdigit():
                j += 1
        # numeric prefix (empty = 0)
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
    """Splits into (epoch, upstream, revision); revision defaults to "0"."""
    epoch = 0
    if ":" in version:
        e, version = version.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    upstream, sep, revision = version.rpartition("-")
    if not sep:
        upstream, revision = version, "0"
    return epoch, upstream, revision


def compare_versions(a: str, b: str) -> int:
    """Returns -1, 0 or 1 if a is less than, equal to or greater than b."""
    ea, ua, ra = _split(a)
    eb, ub, rb = _split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _compare_part(ua, ub) or _compare_part(ra, rb)
