from __future__ import annotations

import unittest

from oval import OvalCve
from parsing import HostReport, InstalledPackage, PackageReport, Upgrade
from vulns import find_open_vulns, kernel_source_name, kev_fix_count


def pkg(binary, version, source, source_version=None):
    return InstalledPackage(binary, version, source, source_version or version)


def upgrade(binary, source, new, cves=()):
    return PackageReport(
        upgrade=Upgrade(binary, ["noble-security"], new, "0", "amd64"),
        source=source,
        entries=[],
        cves=list(cves),
        changelog_available=True,
        changelog_uncertain=False,
    )


def host(installed, upgrades=(), kernel=None):
    return HostReport(
        host="h",
        codename="noble",
        packages=list(upgrades),
        installed=list(installed),
        ubuntu_origin={(p.binary, p.version) for p in installed},
        kernel_release=kernel,
    )


def cve(cve_id, prio, packages=None, kernels=None):
    return OvalCve(cve_id, prio, packages or {}, kernels or {})


class FindOpenVulnsTest(unittest.TestCase):
    def test_unfixed_high_is_reported(self):
        r = host([pkg("imagemagick", "8:6.9-1", "imagemagick")])
        v = find_open_vulns(r, {"CVE-1": cve("CVE-1", "high", {"imagemagick": None})}, set())
        self.assertEqual([(x.cve_id, x.status, x.kev) for x in v], [("CVE-1", "kein Fix", False)])

    def test_medium_only_with_kev(self):
        oval = {"CVE-1": cve("CVE-1", "medium", {"openssh": None})}
        r = host([pkg("openssh-server", "1:9.6p1-1", "openssh")])
        self.assertEqual(find_open_vulns(r, oval, set()), [])
        self.assertTrue(find_open_vulns(r, oval, {"CVE-1"})[0].kev)

    def test_fixed_and_installed_is_not_reported(self):
        r = host([pkg("openssh-server", "1:9.6p1-3ubuntu13.5", "openssh")])
        oval = {"CVE-1": cve("CVE-1", "high", {"openssh": "1:9.6p1-3ubuntu13.3"})}
        self.assertEqual(find_open_vulns(r, oval, set()), [])

    def test_installed_equal_to_fix_is_not_reported(self):
        r = host([pkg("openssh-server", "1:9.6p1-3ubuntu13.3", "openssh")])
        oval = {"CVE-1": cve("CVE-1", "high", {"openssh": "1:9.6p1-3ubuntu13.3"})}
        self.assertEqual(find_open_vulns(r, oval, set()), [])

    def test_fixed_by_pending_update_is_not_reported(self):
        r = host(
            [pkg("openssh-server", "1:9.6p1-3ubuntu13.2", "openssh")],
            upgrades=[upgrade("openssh-server", "openssh", new="1:9.6p1-3ubuntu13.3")],
        )
        oval = {"CVE-1": cve("CVE-1", "high", {"openssh": "1:9.6p1-3ubuntu13.3"})}
        self.assertEqual(find_open_vulns(r, oval, set()), [])

    def test_update_too_old_but_cve_in_changelog_is_not_reported(self):
        r = host(
            [pkg("openssh-server", "1:9.6p1-1", "openssh")],
            upgrades=[upgrade("openssh-server", "openssh", new="1:9.6p1-2", cves=["CVE-1"])],
        )
        oval = {"CVE-1": cve("CVE-1", "high", {"openssh": "1:9.6p1-3"})}
        self.assertEqual(find_open_vulns(r, oval, set()), [])

    def test_update_too_old_without_cve_is_reported(self):
        r = host(
            [pkg("openssh-server", "1:9.6p1-1", "openssh")],
            upgrades=[upgrade("openssh-server", "openssh", new="1:9.6p1-2")],
        )
        oval = {"CVE-1": cve("CVE-1", "high", {"openssh": "1:9.6p1-3"})}
        v = find_open_vulns(r, oval, set())
        self.assertEqual(v[0].status, "Fix 1:9.6p1-3 nicht angeboten")

    def test_update_of_other_source_does_not_cover(self):
        r = host(
            [pkg("openssh-server", "1:9.6p1-1", "openssh")],
            upgrades=[upgrade("curl", "curl", new="9", cves=["CVE-1"])],
        )
        oval = {"CVE-1": cve("CVE-1", "high", {"openssh": "1:9.6p1-3"})}
        self.assertEqual(len(find_open_vulns(r, oval, set())), 1)

    def test_unfixed_not_covered_by_update(self):
        r = host(
            [pkg("openssh-server", "1:9.6p1-1", "openssh")],
            upgrades=[upgrade("openssh-server", "openssh", new="99")],
        )
        oval = {"CVE-1": cve("CVE-1", "high", {"openssh": None})}
        self.assertEqual(find_open_vulns(r, oval, set())[0].status, "kein Fix")

    def test_esm_only_fix(self):
        r = host([pkg("libxml2", "2.9.14+dfsg-1.3ubuntu3.1", "libxml2")])
        oval = {"CVE-1": cve("CVE-1", "critical", {"libxml2": "2.9.14+dfsg-1.3ubuntu3.1+esm1"})}
        v = find_open_vulns(r, oval, set())
        self.assertEqual(v[0].status, "Fix nur via ESM/Pro (2.9.14+dfsg-1.3ubuntu3.1+esm1)")

    def test_fixed_but_not_offered(self):
        r = host([pkg("curl", "8.5.0-2ubuntu10.1", "curl")])
        oval = {"CVE-1": cve("CVE-1", "high", {"curl": "8.5.0-2ubuntu10.4"})}
        v = find_open_vulns(r, oval, set())
        self.assertEqual(v[0].status, "Fix 8.5.0-2ubuntu10.4 nicht angeboten")

    def test_third_party_package_is_ignored(self):
        r = host([pkg("containerd", "1.7-1", "containerd")])
        r.ubuntu_origin = set()
        oval = {"CVE-1": cve("CVE-1", "critical", {"containerd": None})}
        self.assertEqual(find_open_vulns(r, oval, {"CVE-1"}), [])

    def test_one_line_per_source_and_cve(self):
        r = host([pkg("openssh-server", "1:9.6p1-1", "openssh"), pkg("openssh-client", "1:9.6p1-1", "openssh")])
        v = find_open_vulns(r, {"CVE-1": cve("CVE-1", "high", {"openssh": None})}, set())
        self.assertEqual(len(v), 1)
        self.assertEqual(v[0].binaries, ["openssh-client", "openssh-server"])

    def test_installed_version_is_lowest_source_version(self):
        r = host([
            pkg("a-1", "2", "a", "2"),
            pkg("a-2", "1", "a", "1"),
        ])
        v = find_open_vulns(r, {"CVE-1": cve("CVE-1", "high", {"a": "3"})}, set())
        self.assertEqual(v[0].installed_version, "1")

    def test_mixed_versions_in_group_reported_when_lowest_is_vulnerable(self):
        r = host([pkg("a-1", "5", "a", "5"), pkg("a-2", "1", "a", "1")])
        v = find_open_vulns(r, {"CVE-1": cve("CVE-1", "high", {"a": "3"})}, set())
        self.assertEqual(len(v), 1)

    def test_non_ubuntu_binary_excluded_from_group(self):
        r = host([pkg("a-1", "1", "a"), pkg("a-2", "9", "a")])
        r.ubuntu_origin = {("a-2", "9")}
        v = find_open_vulns(r, {"CVE-1": cve("CVE-1", "high", {"a": "3"})}, set())
        self.assertEqual(v, [])

    def test_running_kernel_only(self):
        r = host(
            [
                pkg("linux-image-6.8.0-45-generic", "6.8.0-45.45", "linux-signed", "6.8.0-45.45"),
                pkg("linux-image-6.8.0-50-generic", "6.8.0-50.51", "linux-signed", "6.8.0-50.51"),
            ],
            kernel="6.8.0-45-generic",
        )
        oval = {"CVE-K": cve("CVE-K", "high", kernels={"linux": "6.8.0-50.51"})}
        v = find_open_vulns(r, oval, set())
        self.assertEqual(
            [(x.source, x.is_kernel, x.status) for x in v],
            [("linux", True, "Fix 6.8.0-50.51 nicht angeboten")],
        )
        self.assertEqual(v[0].binaries, ["linux-image-6.8.0-45-generic"])
        self.assertEqual(v[0].installed_version, "6.8.0-45.45")

    def test_kernel_fixed_in_running_is_not_reported(self):
        r = host([pkg("linux-image-6.8.0-50-generic", "6.8.0-50.51", "linux-signed")], kernel="6.8.0-50-generic")
        oval = {"CVE-K": cve("CVE-K", "high", kernels={"linux": "6.8.0-50.51"})}
        self.assertEqual(find_open_vulns(r, oval, set()), [])

    def test_kernel_unfixed_and_esm(self):
        r = host([pkg("linux-image-6.8.0-45-generic", "6.8.0-45.45", "linux-signed")], kernel="6.8.0-45-generic")
        oval = {
            "CVE-U": cve("CVE-U", "high", kernels={"linux": None}),
            "CVE-E": cve("CVE-E", "high", kernels={"linux": "6.8.0-99+esm1"}),
        }
        st = {x.cve_id: x.status for x in find_open_vulns(r, oval, set())}
        self.assertEqual(st, {"CVE-U": "kein Fix", "CVE-E": "Fix nur via ESM/Pro (6.8.0-99+esm1)"})

    def test_kernel_not_covered_by_pending_update(self):
        r = host(
            [pkg("linux-image-6.8.0-45-generic", "6.8.0-45.45", "linux-signed")],
            upgrades=[upgrade("linux-image-generic", "linux-signed", new="6.8.0-99.1", cves=["CVE-K"])],
            kernel="6.8.0-45-generic",
        )
        oval = {"CVE-K": cve("CVE-K", "high", kernels={"linux": "6.8.0-50.51"})}
        self.assertEqual(len(find_open_vulns(r, oval, set())), 1)

    def test_kernel_unsigned_fallback_and_hwe_mapping(self):
        r = host(
            [pkg("linux-image-unsigned-6.8.0-45-generic", "6.8.0-45.45", "linux-hwe-6.8")],
            kernel="6.8.0-45-generic",
        )
        oval = {"CVE-K": cve("CVE-K", "high", kernels={"linux-hwe-6.8": None})}
        v = find_open_vulns(r, oval, set())
        self.assertEqual((v[0].source, v[0].binaries), ("linux-hwe-6.8", ["linux-image-unsigned-6.8.0-45-generic"]))

    def test_kernel_image_without_ubuntu_origin_is_checked(self):
        # Ubuntu entfernt alte Kernel-ABI-Pakete aus den Indizes; der laufende Kernel zählt trotzdem.
        r = host([pkg("linux-image-6.8.0-45-generic", "6.8.0-45.45", "linux-signed")], kernel="6.8.0-45-generic")
        r.ubuntu_origin = set()
        oval = {"CVE-K": cve("CVE-K", "high", kernels={"linux": None})}
        v = find_open_vulns(r, oval, set())
        self.assertEqual([(x.cve_id, x.is_kernel) for x in v], [("CVE-K", True)])

    def test_superseded_ubuntu_version_is_checked(self):
        # Index kennt nur 0.7; installiert ist 0.6 ohne angebotenes Update.
        r = host([pkg("libperl5.38t64", "5.38.2-3.2ubuntu0.6", "perl")])
        r.ubuntu_origin = set()
        r.ubuntu_names = {"libperl5.38t64"}
        oval = {"CVE-P": cve("CVE-P", "high", {"perl": "5.38.2-3.2ubuntu0.7"})}
        v = find_open_vulns(r, oval, set())
        self.assertEqual([x.status for x in v], ["Fix 5.38.2-3.2ubuntu0.7 nicht angeboten"])

    def test_package_without_any_ubuntu_origin_is_skipped(self):
        r = host([pkg("docker-ce", "5:28.0.4-1", "docker-ce")])
        r.ubuntu_origin = set()
        r.ubuntu_names = {"other"}
        oval = {"CVE-D": cve("CVE-D", "high", {"docker-ce": None})}
        self.assertEqual(find_open_vulns(r, oval, set()), [])

    def test_no_kernel_release_skips_kernel(self):
        r = host([pkg("linux-image-6.8.0-45-generic", "6.8.0-45.45", "linux-signed")])
        oval = {"CVE-K": cve("CVE-K", "high", kernels={"linux": None})}
        self.assertEqual(find_open_vulns(r, oval, set()), [])

    def test_kernel_name_mapping(self):
        self.assertEqual(kernel_source_name("linux-signed"), "linux")
        self.assertEqual(kernel_source_name("linux-signed-hwe-6.8"), "linux-hwe-6.8")
        self.assertEqual(kernel_source_name("linux-aws"), "linux-aws")

    def test_sorting_kev_first(self):
        r = host([pkg("a", "1", "a")])
        oval = {
            "CVE-A": cve("CVE-A", "critical", {"a": None}),
            "CVE-B": cve("CVE-B", "high", {"a": None}),
        }
        v = find_open_vulns(r, oval, {"CVE-B"})
        self.assertEqual([x.cve_id for x in v], ["CVE-B", "CVE-A"])

    def test_sorting_priority_name_then_cve(self):
        r = host([pkg("zeta", "1", "zeta"), pkg("alpha", "1", "alpha")])
        oval = {
            "CVE-2": cve("CVE-2", "high", {"zeta": None, "alpha": None}),
            "CVE-1": cve("CVE-1", "high", {"alpha": None}),
            "CVE-3": cve("CVE-3", "critical", {"zeta": None}),
        }
        v = find_open_vulns(r, oval, set())
        self.assertEqual(
            [(x.cve_id, x.binaries[0]) for x in v],
            [("CVE-3", "zeta"), ("CVE-1", "alpha"), ("CVE-2", "alpha"), ("CVE-2", "zeta")],
        )

    def test_problem_skips_check(self):
        r = host([pkg("a", "1", "a")])
        r.vuln_check_problem = "keine Paketliste"
        self.assertEqual(find_open_vulns(r, {"CVE-1": cve("CVE-1", "high", {"a": None})}, set()), [])


class KevFixCountTest(unittest.TestCase):
    def test_kev_fix_count(self):
        r = host(
            [],
            upgrades=[
                upgrade("a", "a", "2", cves=["CVE-1", "CVE-2"]),
                upgrade("b", "b", "2", cves=["CVE-3"]),
            ],
        )
        self.assertEqual(kev_fix_count(r, {"CVE-2"}), 1)
        self.assertEqual(kev_fix_count(r, set()), 0)
        self.assertEqual(kev_fix_count(r, {"CVE-1", "CVE-2", "CVE-3"}), 2)


if __name__ == "__main__":
    unittest.main()
