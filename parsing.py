"""Parsing der Remote-Ausgabe (reine Funktionen, kein I/O)."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

SECTION_RE = re.compile(r"^===SECTION (?P<name>.+)===$")
END_MARKER = "===END==="
# Die Klammer ist locale-unabhängig gehalten ("upgradable from:" / "aktualisierbar von:").
UPGRADABLE_RE = re.compile(
    r"^(?P<package>[^/\s]+)/(?P<pockets>\S+)\s+(?P<new>\S+)\s+(?P<arch>\S+)"
    r"\s+\[[^:\]]*:\s*(?P<old>[^\]\s]+)\]"
)
CHANGELOG_HEADER_RE = re.compile(
    r"^(?P<source>[a-z0-9][a-z0-9.+-]*) \((?P<version>[^)\s]+)\) [^;]*;"
)
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
MAX_UNCERTAIN_ENTRIES = 10


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


@dataclass
class ChangelogEntry:
    version: str
    text: str


@dataclass
class PackageReport:
    upgrade: Upgrade
    source: str
    entries: list[ChangelogEntry]
    cves: list[str]
    changelog_available: bool
    changelog_uncertain: bool


@dataclass
class HostReport:
    host: str
    os_version: str | None = None
    packages: list[PackageReport] = field(default_factory=list)
    error: str | None = None
    warnings: list[str] = field(default_factory=list)
    unparsed: list[str] = field(default_factory=list)


def parse_changelog(text: str) -> list[ChangelogEntry]:
    entries: list[ChangelogEntry] = []
    version: str | None = None
    body: list[str] = []
    for line in text.splitlines():
        match = CHANGELOG_HEADER_RE.match(line)
        if match:
            if version is not None:
                entries.append(ChangelogEntry(version, "\n".join(body).strip("\n")))
            version = match["version"]
            body = []
        elif version is not None:
            body.append(line)
    if version is not None:
        entries.append(ChangelogEntry(version, "\n".join(body).strip("\n")))
    return entries


def new_changelog_entries(
    changelog: str, installed_version: str
) -> tuple[list[ChangelogEntry], bool]:
    """Einträge neuer als die installierte Version; zweiter Wert: Abgleich unsicher."""
    entries = parse_changelog(changelog)
    for index, entry in enumerate(entries):
        if entry.version == installed_version:
            return entries[:index], False
    return entries[:MAX_UNCERTAIN_ENTRIES], True


def extract_cves(entries: list[ChangelogEntry]) -> list[str]:
    found = {cve for entry in entries for cve in CVE_RE.findall(entry.text)}
    return sorted(found, key=lambda cve: tuple(int(part) for part in cve.split("-")[1:]))


def build_host_report(host: str, raw_output: str, error: str | None = None) -> HostReport:
    if error is not None:
        return HostReport(host=host, error=error)

    sections = split_sections(raw_output)
    report = HostReport(host=host, os_version=sections.get("os", "").strip() or None)

    apt_update = sections.get("apt_update")
    if apt_update is not None:
        lines = apt_update.splitlines()
        rc_line = lines[0] if lines else ""
        if rc_line != "rc=0":
            detail = next((line for line in lines[1:] if line.strip()), "keine Details")
            report.warnings.append(
                f"apt-get update fehlgeschlagen ({rc_line or 'rc=?'}): {detail}"
                " – nutze vorhandenen Paket-Cache"
            )

    upgrades, report.unparsed = parse_upgradable(sections.get("upgradable", ""))
    sources = parse_sources(sections.get("sources", ""))
    for upgrade in upgrades:
        source = sources.get(upgrade.package, upgrade.package)
        changelog = sections.get(f"changelog {source}", "")
        if changelog.strip():
            entries, uncertain = new_changelog_entries(changelog, upgrade.old_version)
            available = True
        else:
            entries, uncertain, available = [], False, False
        report.packages.append(
            PackageReport(
                upgrade=upgrade,
                source=source,
                entries=entries,
                cves=extract_cves(entries),
                changelog_available=available,
                changelog_uncertain=uncertain,
            )
        )
    return report
