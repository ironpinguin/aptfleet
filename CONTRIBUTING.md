# Contributing

Thanks for your interest in improving aptfleet! This document describes how to
set up the project, the quality bar, and how releases are made.

## Development setup

aptfleet is plain Python 3 (3.9 or newer) and Bash with no third-party
dependencies. A checkout runs as is:

```bash
git clone https://github.com/ironpinguin/aptfleet.git
cd aptfleet
./aptfleet.py --help
./aptfleet.py --local --no-refresh      # check this machine, no sudo needed
```

## Quality bar

Every change must pass the same gates CI runs:

```bash
make test                                   # unit tests (python3 -m unittest)
shellcheck cron/aptfleet-mail.sh packaging/aptfleet packaging/aptfleet-mail \
           packaging/postinst packaging/prerm
make package                                # builds the .deb with nfpm (or Docker)
```

Please add or update tests for the behaviour you change. Tests never touch the
network or SSH: remote output, feeds and HTTP fetches are faked
(see `tests/fixtures/`).

Keep the tool dependency-free. A new runtime dependency needs a very good reason,
because aptfleet is meant to be copied onto any Ubuntu server and just work.

## Making changes

- Open an issue before a larger change so the design can be agreed there
  rather than in a finished pull request. Small fixes can go straight to a PR.
- Work on a feature branch and open a pull request against `main`.
- CI (tests on Python 3.9 to 3.14, shellcheck, package build) must
  be green before merging.
- Keep commits focused with a clear, descriptive message in the imperative mood.
- Add a line to the `[Unreleased]` section of [CHANGELOG.md](CHANGELOG.md) for
  anything a user would notice.

## Releases

1. Move the `[Unreleased]` entries in `CHANGELOG.md` under a new version heading
   with today's date.
2. Commit, then tag with a SemVer tag: `git tag v1.2.0 && git push --tags`.
3. CI builds `aptfleet_<version>_all.deb` from the tag and attaches it to a
   GitHub Release.
