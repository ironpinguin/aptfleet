"""Parsing der Remote-Ausgabe (reine Funktionen, kein I/O)."""
from __future__ import annotations

import re
from dataclasses import dataclass

SECTION_RE = re.compile(r"^===SECTION (?P<name>.+)===$")
END_MARKER = "===END==="
# Die Klammer ist locale-unabhängig gehalten ("upgradable from:" / "aktualisierbar von:").
UPGRADABLE_RE = re.compile(
    r"^(?P<package>[^/\s]+)/(?P<pockets>\S+)\s+(?P<new>\S+)\s+(?P<arch>\S+)"
    r"\s+\[[^:\]]*:\s*(?P<old>[^\]\s]+)\]"
)


@dataclass
class Upgrade:
    package: str
    pockets: list[str]
    new_version: str
    old_version: str
    arch: str

    @property
    def is_security(self) -> bool:
        return any(pocket.endswith("-security") for pocket in self.pockets)


def split_sections(raw: str) -> dict[str, str]:
    """Teilt die Remote-Ausgabe an den ===SECTION <name>=== Markern auf."""
    sections: dict[str, str] = {}
    current: str | None = None
    lines: list[str] = []
    for line in raw.splitlines():
        if line == END_MARKER:
            break
        match = SECTION_RE.match(line)
        if match:
            if current is not None:
                sections[current] = "\n".join(lines)
            current = match.group("name")
            lines = []
        elif current is not None:
            lines.append(line)
    if current is not None:
        sections[current] = "\n".join(lines)
    return sections


def parse_upgradable(text: str) -> tuple[list[Upgrade], list[str]]:
    upgrades: list[Upgrade] = []
    unparsed: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("Listing"):
            continue
        match = UPGRADABLE_RE.match(line)
        if not match:
            unparsed.append(line)
            continue
        upgrades.append(
            Upgrade(
                package=match["package"],
                pockets=match["pockets"].split(","),
                new_version=match["new"],
                old_version=match["old"],
                arch=match["arch"],
            )
        )
    return upgrades, unparsed


def parse_sources(text: str) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        mapping[parts[0]] = parts[1] if len(parts) > 1 else parts[0]
    return mapping
