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


def parse_source_versions(text: str) -> dict[str, str]:
    """Binärpaket → installierte Quellversion (dritte Spalte, falls vorhanden)."""
    return {parts[0]: parts[2] for parts in map(str.split, text.splitlines()) if len(parts) > 2}


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
class InstalledPackage:
    binary: str
    version: str
    source: str
    source_version: str


@dataclass
class OpenVuln:
    source: str
    binaries: list[str]  # Anzeige-Binärpaket = binaries[0]
    installed_version: str
    cve_id: str
    priority: str | None
    status: str
    kev: bool
    is_kernel: bool = False


@dataclass
class HostReport:
    host: str
    os_version: str | None = None
    packages: list[PackageReport] = field(default_factory=list)
    error: str | None = None
    warnings: list[str] = field(default_factory=list)
    unparsed: list[str] = field(default_factory=list)
    codename: str | None = None
    installed: list[InstalledPackage] = field(default_factory=list)
    ubuntu_origin: set[tuple[str, str]] = field(default_factory=set)
    kernel_release: str | None = None
    open_vulns: list[OpenVuln] = field(default_factory=list)
    vuln_check_problem: str | None = None


def parse_installed(text: str) -> list[InstalledPackage]:
    """Zeilen `<status> <binary> <version> [<source> <source_version>]`; nur Status `ii`."""
    result: list[InstalledPackage] = []
    seen: set[tuple[str, str]] = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3 or parts[0] != "ii":
            continue
        binary, version = parts[1], parts[2]
        source = parts[3] if len(parts) > 3 else binary
        source_version = parts[4] if len(parts) > 4 else version
        if (binary, version) in seen:
            continue
        seen.add((binary, version))
        result.append(InstalledPackage(binary, version, source, source_version))
    return result


def parse_origins(text: str) -> set[tuple[str, str]]:
    origins: set[tuple[str, str]] = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            origins.add((parts[0], parts[1]))
    return origins


def parse_os(text: str) -> tuple[str | None, str | None]:
    lines = [line.strip() for line in text.splitlines()]
    version = lines[0] if lines and lines[0] else None
    codename = lines[1] if len(lines) > 1 and lines[1] else None
    return version, codename


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
    os_version, codename = parse_os(sections.get("os", ""))
    report = HostReport(host=host, os_version=os_version, codename=codename)
    report.installed = parse_installed(sections.get("installed", ""))
    report.ubuntu_origin = parse_origins(sections.get("origins", ""))
    report.kernel_release = sections.get("kernel", "").strip() or None
    if not codename:
        report.vuln_check_problem = "kein Ubuntu-Codename"
    elif not report.installed:
        report.vuln_check_problem = "keine Paketliste"
    elif not report.ubuntu_origin:
        report.vuln_check_problem = "Paketherkunft nicht ermittelbar"

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

    if "timeout" in sections:
        report.warnings.append(sections["timeout"].strip())

    upgrades, report.unparsed = parse_upgradable(sections.get("upgradable", ""))
    sources = parse_sources(sections.get("sources", ""))
    source_versions = parse_source_versions(sections.get("sources", ""))
    for upgrade in upgrades:
        source = sources.get(upgrade.package, upgrade.package)
        changelog = sections.get(f"changelog {source}", "")
        if changelog.strip():
            # Changelog-Header tragen die Quellversion (z. B. grub2-signed 1.202 statt 1.202+2.12-…).
            installed = source_versions.get(upgrade.package, upgrade.old_version)
            entries, uncertain = new_changelog_entries(changelog, installed)
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
