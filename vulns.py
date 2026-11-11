from __future__ import annotations

from cve_info import priority_rank
from debversion import compare_versions
from oval import OvalCve
from parsing import HostReport, InstalledPackage, OpenVuln, running_kernel_image

RELEVANT_PRIORITIES = {"high", "critical"}


def kernel_source_name(source: str) -> str:
    """`linux-signed` -> `linux`, `linux-signed-<rest>` -> `linux-<rest>`."""
    if source == "linux-signed":
        return "linux"
    if source.startswith("linux-signed-"):
        return "linux-" + source[len("linux-signed-"):]
    return source


def _status_for_fix(fixed: str | None) -> str:
    if fixed is None:
        return "kein Fix"
    if "esm" in fixed:
        return f"Fix nur via ESM/Pro ({fixed})"
    return f"Fix {fixed} nicht angeboten"


def _is_relevant(cve: OvalCve, kev_ids: set[str]) -> bool:
    return cve.cve_id in kev_ids or cve.priority in RELEVANT_PRIORITIES


def _lowest_version(versions: list[str]) -> str:
    lowest = versions[0]
    for version in versions[1:]:
        if compare_versions(version, lowest) < 0:
            lowest = version
    return lowest


def _package_vulns(
    report: HostReport, relevant: list[OvalCve], kev_ids: set[str]
) -> list[OpenVuln]:
    groups: dict[str, list[InstalledPackage]] = {}
    for pkg in report.installed:
        if report.is_ubuntu_package(pkg):
            groups.setdefault(pkg.source, []).append(pkg)

    result: list[OpenVuln] = []
    for source, members in groups.items():
        binaries = sorted({m.binary for m in members})
        installed_version = _lowest_version([m.source_version for m in members])
        updates = [p for p in report.packages if p.source == source]
        for cve in relevant:
            if source not in cve.packages:
                continue
            fixed = cve.packages[source]
            if fixed is not None:
                if compare_versions(installed_version, fixed) >= 0:
                    continue
                if any(
                    compare_versions(p.upgrade.new_version, fixed) >= 0
                    or cve.cve_id in p.cves
                    for p in updates
                ):
                    continue
            result.append(
                OpenVuln(
                    source=source,
                    binaries=binaries,
                    installed_version=installed_version,
                    cve_id=cve.cve_id,
                    priority=cve.priority,
                    status=_status_for_fix(fixed),
                    kev=cve.cve_id in kev_ids,
                )
            )
    return result


def _kernel_vulns(
    report: HostReport, relevant: list[OvalCve], kev_ids: set[str]
) -> list[OpenVuln]:
    image = running_kernel_image(report.installed, report.kernel_release)
    if image is None:
        return []
    name = kernel_source_name(image.source)
    result: list[OpenVuln] = []
    for cve in relevant:
        if name not in cve.kernels:
            continue
        fixed = cve.kernels[name]
        if fixed is not None and compare_versions(image.source_version, fixed) >= 0:
            continue
        result.append(
            OpenVuln(
                source=name,
                binaries=[image.binary],
                installed_version=image.source_version,
                cve_id=cve.cve_id,
                priority=cve.priority,
                status=_status_for_fix(fixed),
                kev=cve.cve_id in kev_ids,
                is_kernel=True,
            )
        )
    return result


def find_open_vulns(
    report: HostReport, oval: dict[str, OvalCve], kev_ids: set[str]
) -> list[OpenVuln]:
    if report.vuln_check_problem:
        return []
    relevant = [c for c in oval.values() if _is_relevant(c, kev_ids)]
    vulns = _package_vulns(report, relevant, kev_ids) + _kernel_vulns(
        report, relevant, kev_ids
    )
    vulns.sort(
        key=lambda v: (
            not v.kev,
            priority_rank(v.priority),
            v.source if v.is_kernel else v.binaries[0],
            v.cve_id,
        )
    )
    return vulns


def kev_fix_count(report: HostReport, kev_ids: set[str]) -> int:
    return sum(1 for p in report.packages if any(c in kev_ids for c in p.cves))
