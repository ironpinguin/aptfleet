"""SSH-Ausführung des Remote-Skripts auf den Hosts."""
from __future__ import annotations

import shlex
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from parsing import END_MARKER

MAX_WORKERS = 6
CONNECT_TIMEOUT = 15

# Wird per stdin an `bash -s -- <refresh 0|1> [paket ...]` übergeben; legt nichts auf dem Host ab.
# Alle Befehle bekommen </dev/null, damit sie nicht den Rest des Skripts von stdin lesen.
REMOTE_SCRIPT = r"""
export LC_ALL=C
REFRESH="${1:-1}"
shift || true
FILTER=" $* "

echo "===SECTION os==="
( . /etc/os-release 2>/dev/null && echo "${VERSION_ID:-}" )

if [ "$REFRESH" = "1" ]; then
  echo "===SECTION apt_update==="
  out=$(sudo -n apt-get update -qq </dev/null 2>&1)
  rc=$?
  echo "rc=$rc"
  [ -n "$out" ] && printf '%s\n' "$out"
fi

echo "===SECTION upgradable==="
pkgs=""
while IFS= read -r line; do
  case "$line" in
    */*\[*) ;;
    *) continue ;;
  esac
  name="${line%%/*}"
  if [ "$FILTER" != "  " ]; then
    case "$FILTER" in
      *" $name "*) ;;
      *) continue ;;
    esac
  fi
  printf '%s\n' "$line"
  pkgs="$pkgs $name"
done < <(apt list --upgradable </dev/null 2>/dev/null)

srcmap=""
if [ -n "$pkgs" ]; then
  srcmap=$(dpkg-query -W -f='${Package} ${source:Package}\n' $pkgs </dev/null 2>/dev/null)
fi
echo "===SECTION sources==="
[ -n "$srcmap" ] && printf '%s\n' "$srcmap"

seen=" "
while read -r bin src; do
  [ -n "$bin" ] || continue
  src="${src:-$bin}"
  case "$seen" in
    *" $src "*) continue ;;
  esac
  seen="$seen$src "
  echo "===SECTION changelog $src==="
  timeout 60 apt-get changelog -qq "$bin" </dev/null 2>/dev/null | head -n 500
done <<< "$srcmap"

echo "===END==="
"""


@dataclass
class HostResult:
    host: str
    ok: bool
    error: str | None
    raw_output: str


def build_ssh_command(
    host: str, ssh_config: Path | str, refresh: bool, packages: list[str]
) -> list[str]:
    args = ["1" if refresh else "0", *packages]
    remote_cmd = "bash -s -- " + " ".join(shlex.quote(arg) for arg in args)
    return [
        "ssh", "-F", str(ssh_config),
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={CONNECT_TIMEOUT}",
        host, remote_cmd,
    ]


def run_host(
    host: str,
    ssh_config: Path | str,
    refresh: bool,
    packages: list[str],
    timeout: int,
    runner=subprocess.run,
) -> HostResult:
    cmd = build_ssh_command(host, ssh_config, refresh, packages)
    try:
        proc = runner(cmd, input=REMOTE_SCRIPT, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return HostResult(host, False, f"ssh timeout nach {timeout}s", "")
    except OSError as exc:
        return HostResult(host, False, f"ssh nicht ausführbar: {exc}", "")

    if proc.returncode == 0 and END_MARKER in proc.stdout:
        return HostResult(host, True, None, proc.stdout)
    if proc.returncode == 0:
        return HostResult(host, False, f"unvollständige Ausgabe (kein {END_MARKER})", proc.stdout)
    stderr_lines = [line for line in proc.stderr.splitlines() if line.strip()]
    reason = stderr_lines[-1] if stderr_lines else f"exit code {proc.returncode}"
    return HostResult(host, False, reason, proc.stdout)


def run_all(
    hosts: list[str],
    ssh_config: Path | str,
    refresh: bool,
    packages: list[str],
    timeout: int,
    max_workers: int = MAX_WORKERS,
    runner=subprocess.run,
) -> list[HostResult]:
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [
            pool.submit(run_host, host, ssh_config, refresh, packages, timeout, runner)
            for host in hosts
        ]
        return [future.result() for future in futures]
