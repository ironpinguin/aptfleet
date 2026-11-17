"""Runs the remote script on the hosts via SSH."""
from __future__ import annotations

import shlex
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from parsing import END_MARKER

MAX_WORKERS = 6
SOURCES_MARKER = "===SECTION sources==="
CONNECT_TIMEOUT = 15

# Bash fragment: reads "<package> <version>" lines from stdin and prints
#   "<package> <version>" if the pair is in an Ubuntu package list (apt lists with
#   "Origin: Ubuntu"), otherwise
#   "<package> *" if the name appears in an Ubuntu package list and in no third-party one
#   (Ubuntu indexes only carry the release and the newest update version; superseded versions).
# The groups are separated by awk assignment operands (g=u / g=f). POSIX awk, mawk-compatible.
ORIGINS_SNIPPET = r"""lists="${APT_LISTS:-/var/lib/apt/lists}"
ubuntu=""
foreign=""
for rel in "$lists"/*_InRelease "$lists"/*_Release; do
  [ -f "$rel" ] || continue
  group=foreign
  grep -q '^Origin: Ubuntu' "$rel" && group=ubuntu
  prefix="${rel%InRelease}"; prefix="${prefix%Release}"
  for f in "$prefix"*_Packages; do
    [ -f "$f" ] || continue
    if [ "$group" = ubuntu ]; then ubuntu="$ubuntu $f"; else foreign="$foreign $f"; fi
  done
done
awk 'g == "" { want[$1" "$2]=1; name[$1]=1; next }
     /^Package: / { p=$2; if (p in name) { if (g == "u") inu[p]=1; else inf[p]=1 } }
     g == "u" && /^Version: / {
       k=p" "$2; if ((k in want) && !(k in seen)) { print k; seen[k]=1; hit[p]=1 } }
     END { for (p in inu) if (!(p in inf) && !(p in hit)) print p" *" }' - g=u $ubuntu g=f $foreign"""

# Passed via stdin to `bash -s -- <refresh 0|1> [package ...]`; stores nothing on the host.
# Without refresh the script needs no sudo.
# Every command gets </dev/null so it does not read the rest of the script from stdin.
REMOTE_SCRIPT = r"""
export LC_ALL=C
REFRESH="${1:-1}"
shift || true
FILTER=" $* "

echo "===SECTION os==="
( . /etc/os-release 2>/dev/null && echo "${VERSION_ID:-}" && echo "${VERSION_CODENAME:-}" )

echo "===SECTION apt_update==="
if [ "$REFRESH" = "1" ]; then
  # As root (e.g. local cron job) without sudo, otherwise passwordless sudo.
  sudo=""
  [ "$(id -u)" = "0" ] || sudo="sudo -n"
  out=$(timeout 90 $sudo apt-get update -qq </dev/null 2>&1)
  rc=$?
  echo "rc=$rc"
  [ -n "$out" ] && printf '%s\n' "$out"
else
  echo "rc=skipped"
fi

# Package lists last updated: "now <epoch>", then epochs of the update stamps
# (update-notifier/apt.systemd.daily), of lists/partial (apt touches it on every update)
# and of the newest Release file (only carries the server's publication date).
echo "===SECTION lists_age==="
mtime() { stat -c %Y "$1" 2>/dev/null || stat -f %m "$1" 2>/dev/null; }
echo "now $(date +%s)"
periodic="${APT_PERIODIC:-/var/lib/apt/periodic}"
for stamp in "$periodic/update-success-stamp" "$periodic/update-stamp"; do
  [ -f "$stamp" ] && echo "stamp $(mtime "$stamp")"
done
lists_dir="${APT_LISTS:-/var/lib/apt/lists}"
[ -d "$lists_dir/partial" ] && echo "partial $(mtime "$lists_dir/partial")"
newest=$(ls -t "$lists_dir"/*Release 2>/dev/null </dev/null | head -n 1)
[ -n "$newest" ] && echo "lists $(mtime "$newest")"

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
  srcmap=$(dpkg-query -W -f='${Package} ${source:Package} ${source:Version}\n' $pkgs </dev/null 2>/dev/null)
fi
echo "===SECTION installed==="
installed=$(dpkg-query -W -f='${db:Status-Abbrev} ${Package} ${Version} ${source:Package} ${source:Version}\n' </dev/null 2>/dev/null)
[ -n "$installed" ] && printf '%s\n' "$installed"

echo "===SECTION kernel==="
uname -r </dev/null 2>/dev/null

echo "===SECTION origins==="
# stdin here explicitly comes from the pipe, not from the script stdin.
printf '%s\n' "$installed" | awk '$1=="ii"{print $2" "$3}' | {
@@ORIGINS_SNIPPET@@
}

echo "===SECTION sources==="
[ -n "$srcmap" ] && printf '%s\n' "$srcmap"

seen=" "
while read -r bin src _srcver; do
  [ -n "$bin" ] || continue
  src="${src:-$bin}"
  case "$seen" in
    *" $src "*) continue ;;
  esac
  seen="$seen$src "
  echo "===SECTION changelog $src==="
  timeout 20 apt-get changelog -qq "$bin" </dev/null 2>/dev/null | head -n 500
done <<< "$srcmap"

echo "===END==="
""".replace("@@ORIGINS_SNIPPET@@", ORIGINS_SNIPPET)


SECTION_PREFIX = "===SECTION "
# What the host is doing once the respective section starts (progress output).
SECTION_PHASES = {
    "os": "connected",
    "apt_update": "apt-get update",
    "upgradable": "listing pending updates",
    "installed": "reading installed packages",
    "origins": "checking package origin",
    "sources": "mapping source packages",
}


def phase_tracker(on_phase):
    """Returns a line callback that turns the section markers of the remote output into
    phases for on_phase(text); changelogs are counted as "Changelog n/m: <source>"."""
    state = {"section": None, "sources": set(), "changelogs": 0}

    def on_line(line: str) -> None:
        line = line.rstrip("\n")
        if line.startswith(SECTION_PREFIX) and line.endswith("==="):
            name = line[len(SECTION_PREFIX):-3]
            state["section"] = name
            if name.startswith("changelog "):
                state["changelogs"] += 1
                total = max(len(state["sources"]), state["changelogs"])
                on_phase(f"Changelog {state['changelogs']}/{total}: {name[len('changelog '):]}")
            elif name in SECTION_PHASES:
                on_phase(SECTION_PHASES[name])
        elif state["section"] == "sources":
            fields = line.split()
            if fields:
                state["sources"].add(fields[1] if len(fields) > 1 else fields[0])

    return on_line


def stream_run(cmd, *, input, timeout, on_line=None, encoding="utf-8", errors="replace", **kwargs):
    """Like subprocess.run(..., capture_output=True); with on_line, stdout is also
    reported line by line while the process is still running. On timeout,
    TimeoutExpired.output contains the output read so far."""
    if on_line is None:
        return subprocess.run(cmd, input=input, timeout=timeout, encoding=encoding,
                              errors=errors, capture_output=True)
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, encoding=encoding, errors=errors)
    stderr_chunks: list[str] = []
    timed_out = threading.Event()

    def feed():
        try:
            proc.stdin.write(input)
            proc.stdin.close()
        except OSError:
            pass

    def kill():
        timed_out.set()
        proc.kill()

    helpers = [threading.Thread(target=feed, daemon=True),
               threading.Thread(target=lambda: stderr_chunks.append(proc.stderr.read()), daemon=True)]
    for thread in helpers:
        thread.start()
    timer = threading.Timer(timeout, kill)
    timer.start()
    lines: list[str] = []
    try:
        for line in proc.stdout:
            lines.append(line)
            on_line(line)
        proc.wait()
    finally:
        timer.cancel()
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    for thread in helpers:
        thread.join(timeout=5)
    stdout, stderr = "".join(lines), "".join(stderr_chunks)
    if timed_out.is_set():
        raise subprocess.TimeoutExpired(cmd, timeout, output=stdout, stderr=stderr)
    return subprocess.CompletedProcess(cmd, proc.returncode, stdout, stderr)


@dataclass
class HostResult:
    host: str
    ok: bool
    error: str | None
    raw_output: str


def build_ssh_command(
    host: str,
    ssh_config: Path | str | None,
    refresh: bool,
    packages: list[str],
    user: str | None = None,
) -> list[str]:
    """Without ssh_config the normal ~/.ssh/config applies; user sets the login name."""
    args = ["1" if refresh else "0", *packages]
    remote_cmd = "bash -s -- " + " ".join(shlex.quote(arg) for arg in args)
    cmd = ["ssh"]
    if ssh_config is not None:
        cmd += ["-F", str(ssh_config)]
    cmd += ["-o", "BatchMode=yes", "-o", f"ConnectTimeout={CONNECT_TIMEOUT}"]
    if user:
        cmd += ["-l", user]
    return [*cmd, host, remote_cmd]


def build_local_command(refresh: bool, packages: list[str]) -> list[str]:
    """Runs the remote script on the local machine (--local, without SSH)."""
    return ["bash", "-s", "--", "1" if refresh else "0", *packages]


def run_host(
    host: str,
    ssh_config: Path | str | None,
    refresh: bool,
    packages: list[str],
    timeout: int,
    runner=stream_run,
    user: str | None = None,
    on_phase=None,
    local: bool = False,
) -> HostResult:
    """on_phase(text) reports what is currently running on the host (progress output only).
    local: run the script locally with bash instead of via SSH; host is then only the display name."""
    if local:
        cmd = build_local_command(refresh, packages)
    else:
        cmd = build_ssh_command(host, ssh_config, refresh, packages, user)
    tool = "bash" if local else "ssh"
    extra = {"on_line": phase_tracker(on_phase)} if on_phase else {}
    if on_phase:
        on_phase("starting locally" if local else "SSH connection")
    try:
        proc = runner(
            cmd,
            input=REMOTE_SCRIPT,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            **extra,
        )
    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout or ""
        if isinstance(partial, bytes):
            partial = partial.decode("utf-8", errors="replace")
        # Package list is complete, only changelogs are missing: partial result instead of error.
        if SOURCES_MARKER in partial:
            note = f"\n===SECTION timeout===\nTimeout after {timeout}s – changelogs incomplete\n"
            return HostResult(host, True, None, partial + note)
        return HostResult(host, False, f"{tool} timeout after {timeout}s", "")
    except OSError as exc:
        return HostResult(host, False, f"{tool} not executable: {exc}", "")

    if proc.returncode == 0 and END_MARKER in proc.stdout:
        return HostResult(host, True, None, proc.stdout)
    if proc.returncode == 0:
        return HostResult(host, False, f"incomplete output (no {END_MARKER})", proc.stdout)
    stderr_lines = [line for line in proc.stderr.splitlines() if line.strip()]
    reason = stderr_lines[-1] if stderr_lines else f"exit code {proc.returncode}"
    return HostResult(host, False, reason, proc.stdout)


def run_all(
    hosts: list[str],
    ssh_config: Path | str | None,
    refresh: bool,
    packages: list[str],
    timeout: int,
    max_workers: int = MAX_WORKERS,
    runner=stream_run,
    user: str | None = None,
    progress=None,
    local: bool = False,
) -> list[HostResult]:
    """progress: object with host_phase(host, text) and host_done(host, error), e.g. progress.Progress.
    local: see run_host."""

    def check(host: str) -> HostResult:
        if progress is None:
            return run_host(host, ssh_config, refresh, packages, timeout, runner, user,
                            local=local)
        result = run_host(host, ssh_config, refresh, packages, timeout, runner, user,
                          on_phase=lambda phase: progress.host_phase(host, phase), local=local)
        progress.host_done(host, result.error)
        return result

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        return list(pool.map(check, hosts))
