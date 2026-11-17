# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-11-17

First public release as a standalone project.

### Added
- Report of pending apt updates for many Ubuntu hosts over SSH (Ansible-style
  INI inventory, SSH config) or for the local machine (`--local`).
- Fixed CVEs per update from the package changelogs, with Ubuntu priorities.
- CISA KEV (Known Exploited Vulnerabilities) markers and a list of recently
  added KEV entries.
- Open vulnerabilities without a fix yet, from Ubuntu OVAL data, including
  checks for superseded package versions and an outdated running kernel.
- Terminal output and a self-contained HTML report (`--html`).
- `aptfleet-mail`: cron wrapper that mails the report via sendmail or SMTP.
- `.deb` package built with `make package`.

[Unreleased]: https://github.com/ironpinguin/aptfleet/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/ironpinguin/aptfleet/releases/tag/v1.0.0
