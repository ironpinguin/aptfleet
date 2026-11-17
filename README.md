# aptfleet

[![CI](https://github.com/ironpinguin/aptfleet/actions/workflows/ci.yml/badge.svg)](https://github.com/ironpinguin/aptfleet/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Shows the pending apt updates on one or many Ubuntu hosts, together with the
security information that matters for deciding what to patch first:

- **Updates per host**, marked as security updates, with the CVEs each update fixes
  (taken from the package changelog) and their Ubuntu priority (`critical`, `high`, …)
- **KEV markers:** CVEs that are actively exploited according to the
  [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  catalog are highlighted as `KEV`
- **Open vulnerabilities without a fix:** installed packages with CVEs that have no
  update yet. Only CVEs on KEV or with priority `high`/`critical` are shown
  (source: Ubuntu OVAL data)
- **Kernel:** outdated running kernels (reboot required) and superseded package versions
- optionally **new on KEV:** the CVEs most recently added to the KEV catalog

It is agentless: hosts are only read, over one SSH session per host. The remote
script is sent on stdin, nothing is stored on the host. With `--local` it checks the
machine it runs on instead, for example from a cron job that mails the report
(see [Local cron job with mail](#local-cron-job-with-mail)).

aptfleet is plain Python 3 and Bash, with no dependencies beyond the standard library.

## Requirements

**Where aptfleet runs:**

- Python ≥ 3.9, standard library only, no `pip install` needed
- an `ssh` client with key-based login to the hosts. aptfleet uses `BatchMode=yes`, so it
  never asks for a password
- internet access to `ubuntu.com`, `security-metadata.canonical.com` and `cisa.gov`.
  Without these sources the report still runs, with less information (see exit code 3)

**On the hosts:**

- Ubuntu with `bash`, `apt`, `dpkg-query`, `timeout` (all part of a standard install)
- for the `apt-get update` before the check: passwordless `sudo` for the SSH user.
  Without sudo rights, use `--no-refresh` (see [Running without sudo](#running-without-sudo))

## Installation

### .deb package

Download `aptfleet_<version>_all.deb` from the
[releases page](https://github.com/ironpinguin/aptfleet/releases) and install it:

```bash
sudo apt install ./aptfleet_1.0.0_all.deb
```

| Path | Content |
|---|---|
| `/usr/bin/aptfleet` | runs `aptfleet.py`, same options |
| `/usr/bin/aptfleet-mail` | cron wrapper that mails the report (see [Local cron job with mail](#local-cron-job-with-mail)) |
| `/usr/lib/aptfleet/` | modules and `cron/aptfleet-mail.sh` |
| `/etc/aptfleet/mail.env` | configuration of the mail wrapper (conffile, mode 0600) |
| `/etc/cron.d/aptfleet` | cron job, **commented out** until `/etc/aptfleet/mail.env` is configured |
| `/etc/aptfleet/` | optional `hosts.ini` and `ssh.conf` for checking hosts over SSH (see [Defaults](#3-defaults)) |

Both files under `/etc` are conffiles: your changes survive package updates, and
`apt purge aptfleet` removes them. The only dependencies are `python3` and `bash`.
`ca-certificates` and `openssh-client` are recommended, and `curl` or an MTA for
sending mail.

To build the package yourself, run `make package`. It uses
[nfpm](https://nfpm.goreleaser.com), or the `goreleaser/nfpm` Docker image if nfpm is
not installed, and runs the tests first:

```bash
make package                  # → dist/aptfleet_1.0.0_all.deb
make package VERSION=1.1.0    # different version
```

### From a checkout

No installation needed:

```bash
git clone https://github.com/ironpinguin/aptfleet.git
./aptfleet/aptfleet.py --help
```

## Choosing hosts

There are three ways to check hosts over SSH. To check the local machine without SSH,
use `--local` (see [Local cron job with mail](#local-cron-job-with-mail)).

### 1. Ad hoc: `--host` + `--user`

Name the hosts directly. Your normal `~/.ssh/config` applies (aliases, keys,
`ProxyJump`) unless you pass `--ssh-config`:

```bash
aptfleet --user admin --host web1.example.com --host 10.0.0.12
aptfleet --user admin --host my-alias-from-ssh-config
```

### 2. Your own inventory: `--inventory` / `--ssh-config`

The inventory and the SSH config can live anywhere:

```bash
aptfleet --inventory ~/fleet/hosts.ini --ssh-config ~/fleet/ssh.conf
aptfleet --inventory ~/fleet/hosts.ini     # SSH via ~/.ssh/config
```

Without `--ssh-config`, the default file (see 3.) is used if it exists, otherwise
your normal `~/.ssh/config`. Both formats are described under
[Inventory format](#inventory-format) and [SSH config](#ssh-config).

### 3. Defaults

Without `--user` and `--inventory`, aptfleet reads two files, the first one found:

| File | Looked up in |
|---|---|
| inventory | `~/.config/aptfleet/hosts.ini`, then `/etc/aptfleet/hosts.ini` |
| SSH config | `~/.config/aptfleet/ssh.conf`, then `/etc/aptfleet/ssh.conf` |

`~/.config` follows `$XDG_CONFIG_HOME` if set. A single call then checks all hosts:

```bash
aptfleet
aptfleet --host db1       # only this one (must be in the inventory)
```

If there is no inventory, aptfleet exits with code 2 and points to `--inventory` or
`--host`/`--user`.

### Inventory format

A text file in the style of an Ansible INI inventory. An existing Ansible inventory can
usually be used as is:

```ini
# comment
[ubuntu]
web1
web2                # a comment after the host is allowed
#web3              commented out, skipped

[databases]
db1 ansible_host=10.0.0.20

[all:vars]
ansible_user=admin   # ignored

[servers:children]
ubuntu               # group names, not hosts – ignored
```

Rules:

- One host per line. Only the **first word** of the line counts.
- Empty lines and lines starting with `#` are skipped.
- Group headers like `[group]` are skipped. **Groups have no meaning:** all hosts from all
  groups are checked. Use `--host` to pick single hosts.
- The content of `[group:vars]` (variables) and `[group:children]` (group names) is
  skipped completely, as is every line whose first word contains `=`.
- Ansible variables after the name (`ansible_host=`, `ansible_user=` …) are **ignored**.
  The name is passed to `ssh` as is, so it must be an alias from the SSH config, a
  resolvable host name or an IP address. In the example above aptfleet connects to
  `db1`, not to `10.0.0.20`.
- A host listed in several groups is checked once, at the position where it first
  appears.
- YAML inventories are not supported.

### SSH config

A normal OpenSSH config, passed with `ssh -F`. It has a matching `Host` block for every
name in the inventory:

```
Host web1
  HostName 192.0.2.10
  User admin
  IdentityFile ~/.ssh/fleet_ed25519

Host db1
  HostName 10.0.0.20
  User admin
  IdentityFile ~/.ssh/fleet_ed25519
  ProxyJump web1
```

With `-F`, `ssh` reads **only** this file; `~/.ssh/config` is not used then. Login must
work without a password prompt (key, ssh-agent if needed), because aptfleet uses
`BatchMode=yes`. Test it with `ssh -F <config> web1 true`.

## Usage and options

```bash
aptfleet [options]
```

| Option | Effect |
|---|---|
| `--local` | check only the local machine, without SSH. Cannot be combined with `--host`, `--user`, `--inventory`, `--ssh-config` |
| `--host NAME` | check only this host, repeatable. Without `--user` the name must be in the inventory |
| `--user NAME` | SSH user. Uses the `--host` names directly, without an inventory |
| `--inventory PATH` | inventory file (see [Defaults](#3-defaults)) |
| `--ssh-config PATH` | SSH config for `ssh -F` (see [Defaults](#3-defaults); otherwise `~/.ssh/config`) |
| `--security-only` | show security updates only |
| `--details` | show the new changelog entries of each update. Also fetches CVE details for open vulnerabilities |
| `--package NAME` | only this binary package, repeatable |
| `--no-refresh` | no `apt-get update` first, so no sudo needed. Shows per host how old the package lists are |
| `--timeout SECONDS` | timeout per host (default 120) |
| `--verbose` | show unparsable lines and packages not from Ubuntu (PPAs, third-party repositories) |
| `--kev-recent [DAYS]` | list CVEs added to KEV in the last DAYS days (default 7) |
| `--html PATH` | also write the report as an HTML file (see [HTML report](#html-report)) |
| `--no-progress` | no progress output on stderr (see below) |

Examples:

```bash
aptfleet --security-only
aptfleet --host web1 --details
aptfleet --package openssh-server --package sudo
aptfleet --kev-recent 14
aptfleet --details --html ~/reports/updates-$(date +%F).html
```

Up to 6 hosts are checked in parallel. Output is coloured when it goes to a terminal and
plain when redirected to a file or pipe.

**Progress:** in a terminal, aptfleet shows on stderr what it is doing. A status line
names the current step of every running host (`SSH connection`, `apt-get update`,
`Changelog 3/12: openssl`, …). Finished hosts and the steps after them (KEV list, Ubuntu
vulnerability data, CVE info) appear as lines of their own:

```text
» Checking 3 host(s) …
  ✓ [1/3] web1 done (14s)
  ✗ [2/3] db1: ssh timeout after 120s (120s)
  [2/3] app1: Changelog 4/9: linux-meta
```

When stderr is not a terminal (cron, `2>file`) there is no progress output. Use
`--no-progress` to turn it off in a terminal too. The report on stdout is the same
either way.

### Terminal output

With several hosts an overview comes first, followed by one block per host with its
updates and open vulnerabilities:

```
Host  Ubuntu  Updates  Security  KEV fix  Open vulnerabilities
web1  24.04         5         3        2  1 (1 KEV)
db1   ERROR: ssh timeout after 120s

━━ web1 (Ubuntu 24.04) — 5 updates, 3 security, 1 open vulnerability ━━
   Updates:
      Package     Version                                                        CVEs
 SEC  libssl3t64  3.0.13-0ubuntu3.4 → 3.0.13-0ubuntu3.5                          CVE-2025-9231 (high), CVE-2025-9232 (high, KEV)
 SEC  openssl     3.0.13-0ubuntu3.4 → 3.0.13-0ubuntu3.5                          CVE-2025-9231 (high), CVE-2025-9232 (high, KEV)
 SEC  libxml2     2.9.14+dfsg-1.3ubuntu3.1 → 2.9.14+dfsg-1.3ubuntu3.1+esm1       (changelog unavailable)
      docker-ce   5:28.0.4-1~ubuntu.24.04~noble → 5:28.1.1-1~ubuntu.24.04~noble
      tzdata      2025a-0ubuntu0.24.04 → 2025b-0ubuntu0.24.04.1
   Open vulnerabilities (no fix available yet):
      Package  Installed                 CVE                   Status
 KEV  libxml2  2.9.14+dfsg-1.3ubuntu3.1  CVE-2025-7000 (high)  no fix

━━ db1 — ERROR: ssh timeout after 120s ━━

Summary: 2 hosts, 5 updates, 3 security, 2 KEV fixes available, 1 open vulnerability (1 KEV), 1 host unreachable
```

`SEC` = security update, `KEV` = vulnerability on the CISA KEV list. In the overview,
`KEV fix` is the number of updates that fix a KEV vulnerability. `not checked` means the
vulnerability check was not possible for that host (the reason is in the host block).

### HTML report

`--html PATH` also writes the report as an HTML file. The terminal output stays the same.
`--security-only`, `--details` and `--kev-recent` apply to the file as well.

- a single file: CSS is embedded, no JavaScript, no external resources, so it can be
  mailed or archived
- an overview table linking to the host sections; hosts that need attention (security,
  KEV, errors) are marked red
- with `--details`, changelogs and CVE descriptions are in collapsible blocks. When
  printing (or "Save as PDF" in the browser) they are expanded automatically
- light/dark follows the system setting

If the file cannot be written, aptfleet prints an error and exits with code 2. The
terminal output still appears.

## Running without sudo

aptfleet needs sudo only for the `apt-get update` before the check. With `--no-refresh`
it runs as a normal user without sudo rights. It then uses the package lists already on
the host, which Ubuntu normally refreshes once a day via `apt-daily.timer`.

Because the information may be outdated, every host gets a warning with the age of its
lists:

```
━━ web1 (Ubuntu 24.04) — 3 updates, 1 security ━━
  ⚠ Package lists not refreshed (--no-refresh), last updated 2026-11-12 06:12 (2 days ago) – updates and security info may be outdated
```

If the update fails without `--no-refresh` (for example because sudo asks for a
password), the report continues as well, with the error message and the same age.

aptfleet takes the age from the newest of these timestamps on the host:

1. `/var/lib/apt/periodic/update-success-stamp` or `update-stamp`
   (from update-notifier or `apt-daily`)
2. modification time of `/var/lib/apt/lists/partial` (apt touches it on every update)
3. the newest `*Release` file in `/var/lib/apt/lists` (only the publication date of the
   repository, so a rough fallback)

If none exists, it says "last updated unknown". The age is computed with the host's
clock, so a skewed local clock does not matter.

Note on the exit code: with old package lists it can be `0` although security updates
have long been available.

## Exit codes

For cron jobs and monitoring:

| Code | Meaning |
|---|---|
| `0` | nothing urgent: no security updates, no open KEV vulnerability |
| `1` | security updates are pending **or** an open KEV vulnerability without a fix exists |
| `2` | at least one host unreachable, or a usage/inventory error |
| `3` | check incomplete: KEV list or Ubuntu vulnerability data unavailable, or host data missing |

If several apply, 2 wins over 3, and 3 over 1.

## Local cron job with mail

With `--local`, aptfleet checks the machine it runs on. The remote script runs through
`bash` instead of `ssh`; no inventory or SSH config is needed. The host is named after
`hostname` in the report. The server then also needs Python ≥ 3.9 (preinstalled on
Ubuntu).

```bash
sudo aptfleet --local                 # as root: apt-get update without sudo
aptfleet --local --no-refresh         # as a normal user
```

Running as root, aptfleet calls `apt-get update` directly, otherwise through `sudo -n`.

### Mail wrapper: `aptfleet-mail`

`aptfleet-mail` (`cron/aptfleet-mail.sh` in a checkout) runs aptfleet and mails the
result: the text report as the mail body, the HTML report as the HTML view of the mail
and as an attachment. The subject names the host and the result, for example
`[aptfleet] web1: security updates or open KEV vulnerability`.

It is configured in an env file (template: `cron/mail.env.sample`):

| Variable | Effect | Default |
|---|---|---|
| `APTFLEET_ARGS` | options for aptfleet (the wrapper adds `--no-progress` and `--html`) | `--local --details` |
| `MAIL_TO` | recipients, comma-separated | – (required) |
| `MAIL_FROM` | sender | `aptfleet@<hostname -f>` |
| `MAIL_WHEN` | `problems`: only if the exit code is not 0, `always`: on every run | `problems` |
| `MAIL_TRANSPORT` | `sendmail` (local MTA), `smtp` (directly via `curl`), `print` (output only) | `sendmail` |
| `MAIL_HTML_INLINE` | `1`: HTML as mail body, `0`: attachment only | `1` |
| `MAIL_SUBJECT_PREFIX` | subject prefix | `[aptfleet]` |
| `SENDMAIL` | sendmail binary | `/usr/sbin/sendmail` |
| `SMTP_URL` | e.g. `smtps://mail.example.com:465` or `smtp://mail.example.com:587` | – |
| `SMTP_STARTTLS` | `1`: require STARTTLS (for port 587) | `0` |
| `SMTP_USER`, `SMTP_PASSWORD` | SMTP login (never passed on the command line) | – |
| `REPORT_NAME` | host name in subject and file name | `hostname` |
| `REPORT_DIR` | also archive the HTML reports here | – |
| `REPORT_KEEP_DAYS` | delete older reports in `REPORT_DIR` | `30` |
| `APTFLEET`, `PYTHON` | path to `aptfleet.py` and the interpreter | `../aptfleet.py`, `python3` |

`MAIL_TRANSPORT=smtp` needs `curl` but no MTA on the server. The wrapper also works
without `--local`, for a central check over SSH (`APTFLEET_ARGS` with `--inventory` …).

Exit code of the wrapper: the one from aptfleet, `4` if sending the mail fails, `5` for
configuration errors. Error messages go to stderr, so cron mails them to `MAILTO`.

### Setup

With the [.deb package](#deb-package), the wrapper, env file and cron job are already in
place:

```bash
sudoedit /etc/aptfleet/mail.env           # MAIL_TO, transport …
sudo aptfleet-mail --dry-run | less       # test run, sends nothing
sudoedit /etc/cron.d/aptfleet             # uncomment the cron line
```

From a checkout:

```bash
sudo git clone https://github.com/ironpinguin/aptfleet.git /opt/aptfleet
sudo install -d /etc/aptfleet
sudo install -m 600 /opt/aptfleet/cron/mail.env.sample /etc/aptfleet/mail.env
sudoedit /etc/aptfleet/mail.env           # MAIL_TO, transport …

# test run: always build the mail and print it instead of sending it
sudo /opt/aptfleet/cron/aptfleet-mail.sh --dry-run /etc/aptfleet/mail.env | less

sudo cp /opt/aptfleet/cron/aptfleet.cron /etc/cron.d/aptfleet
```

`cron/aptfleet.cron` runs the wrapper daily at 06:30 as root. Usage:
`aptfleet-mail.sh [--dry-run] [ENV_FILE]`, default `/etc/aptfleet/mail.env`.

## Data sources and cache

| Source | Used for | Cache | Valid for |
|---|---|---|---|
| `ubuntu.com/security/cves/<id>.json` | priority/description of single CVEs | `~/.cache/aptfleet/cves.json` | 7 days |
| CISA KEV feed (JSON) | actively exploited CVEs | `~/.cache/aptfleet/kev.json` | 24 h |
| Ubuntu OVAL (`security-metadata.canonical.com`) | open vulnerabilities per release | `~/.cache/aptfleet/oval-<codename>.json` | 24 h |

If a source is unreachable, an older cache is used and the report notes how old the data
is. Without any cache, that part is missing and the exit code is 3. To clear the cache:
`rm -rf ~/.cache/aptfleet`.

## Similar projects

- [kevward](https://github.com/ForexRobotics/kevward): per-host HTML report of patch
  posture, KEV exposure and attacker IPs (AGPL). Runs on each host.
- [apt-watch](https://github.com/StuMP90/apt-watch): watches a Debian/Ubuntu host for CVEs
  and pending updates, raises severity for KEV.

aptfleet focuses on checking a whole fleet from one place over SSH, without installing
anything on the hosts.

## Development

The tests need no real hosts and no network:

```bash
make test        # python3 -m unittest discover -s tests -t .
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the quality bar and the release process.

| Module | Purpose |
|---|---|
| `aptfleet.py` | CLI, inventory, control flow, exit code |
| `remote.py` | SSH or local call and the remote script (sections `===SECTION …===`) |
| `progress.py` | progress output on stderr (terminal only) |
| `parsing.py` | parse the remote output into `HostReport`s |
| `debversion.py` | Debian version comparison |
| `cve_info.py` | Ubuntu CVE API with cache |
| `kev.py` | CISA KEV catalog with cache |
| `oval.py` | load and parse the Ubuntu OVAL feed |
| `vulns.py` | find open vulnerabilities from installed packages and OVAL |
| `render.py` | text output and shared preparation (sorting, overview, summary) |
| `render_html.py` | HTML report (`--html`) |
| `cron/aptfleet-mail.sh` | cron wrapper: build the report and mail it |
| `packaging/`, `Makefile` | .deb package (nfpm config, shims, cron job, maintainer scripts) |

## License

[Apache License 2.0](LICENSE). Copyright 2026 Michele Catalano.
