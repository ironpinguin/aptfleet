# Security Policy

## Supported versions

Fixes go into the latest release only. There are no maintained release
branches: a security fix ships as the next version.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report it through GitHub's private vulnerability reporting: go to the
[Security tab](https://github.com/ironpinguin/aptfleet/security) and choose
*Report a vulnerability*. That channel is private between you and the
maintainer.

Useful in a report:

- what an attacker can do, not just what looks wrong
- the affected version or commit
- steps to reproduce
- whether it needs local access, control of a checked host, or a position in
  the network path (for example between aptfleet and a data feed)

What to expect: an acknowledgement, and a decision on whether it is a
vulnerability or a plain bug. This is a hobby project maintained by one person,
so please allow for real-world response times rather than a fixed SLA. You will
be credited in the release notes unless you prefer otherwise.

**In scope:** command or shell injection through host names, package names or
data coming back from a checked host; handling of the SSH connection and
options; parsing of the downloaded feeds (Ubuntu CVE JSON, OVAL, CISA KEV) and
the local cache; HTML injection in the HTML report or the mail; leaking SMTP
credentials from `aptfleet-mail` (command line, process list, temp files);
file permissions set by the `.deb` package.

**Out of scope:** the accuracy of the upstream vulnerability data itself, a
host or SSH configuration you control being misconfigured, and reports
produced purely by an automated scanner without a working exploit path.
