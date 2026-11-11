"""SSH-Ausführung des Remote-Skripts auf den Hosts."""
from __future__ import annotations

import shlex
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from parsing import END_MARKER

MAX_WORKERS = 6
SOURCES_MARKER = "===SECTION sources==="
CONNECT_TIMEOUT = 15

# Bash-Fragment: liest "<paket> <version>"-Zeilen von stdin und gibt die davon aus Ubuntu-Origins
# (apt-Listen mit "Origin: Ubuntu") stammenden Paare aus. POSIX-awk, mawk-kompatibel.
ORIGINS_SNIPPET = r"""lists="${APT_LISTS:-/var/lib/apt/lists}"
files=""
for rel in "$lists"/*_InRelease "$lists"/*_Release; do
  [ -f "$rel" ] || continue
  grep -q '^Origin: Ubuntu' "$rel" || continue
  prefix="${rel%InRelease}"; prefix="${prefix%Release}"
  for f in "$prefix"*_Packages; do [ -f "$f" ] && files="$files $f"; done
done
awk 'FNR==NR { want[$1" "$2]=1; next }
     /^Package: / { p=$2 }
     /^Version: / { k=p" "$2; if ((k in want) && !(k in seen)) { print k; seen[k]=1 } }' - $files"""

# Wird per stdin an `bash -s -- <refresh 0|1> [paket ...]` übergeben; legt nichts auf dem Host ab.
# Alle Befehle bekommen </dev/null, damit sie nicht den Rest des Skripts von stdin lesen.
REMOTE_SCRIPT = r"""
export LC_ALL=C
REFRESH="${1:-1}"
shift || true
FILTER=" $* "

echo "===SECTION os==="
( . /etc/os-release 2>/dev/null && echo "${VERSION_ID:-}" && echo "${VERSION_CODENAME:-}" )

if [ "$REFRESH" = "1" ]; then
  echo "===SECTION apt_update==="
  out=$(timeout 90 sudo -n apt-get update -qq </dev/null 2>&1)
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
  srcmap=$(dpkg-query -W -f='${Package} ${source:Package} ${source:Version}\n' $pkgs </dev/null 2>/dev/null)
fi
echo "===SECTION installed==="
installed=$(dpkg-query -W -f='${db:Status-Abbrev} ${Package} ${Version} ${source:Package} ${source:Version}\n' </dev/null 2>/dev/null)
[ -n "$installed" ] && printf '%s\n' "$installed"

echo "===SECTION kernel==="
uname -r </dev/null 2>/dev/null

echo "===SECTION origins==="
# stdin kommt hier ausdrücklich aus der Pipe, nicht aus dem Skript-stdin.
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
    """Ohne ssh_config greift die normale ~/.ssh/config; user setzt den Login-Namen."""
    args = ["1" if refresh else "0", *packages]
    remote_cmd = "bash -s -- " + " ".join(shlex.quote(arg) for arg in args)
    cmd = ["ssh"]
    if ssh_config is not None:
        cmd += ["-F", str(ssh_config)]
    cmd += ["-o", "BatchMode=yes", "-o", f"ConnectTimeout={CONNECT_TIMEOUT}"]
    if user:
        cmd += ["-l", user]
    return [*cmd, host, remote_cmd]


def run_host(
    host: str,
    ssh_config: Path | str | None,
    refresh: bool,
    packages: list[str],
    timeout: int,
    runner=subprocess.run,
    user: str | None = None,
) -> HostResult:
    cmd = build_ssh_command(host, ssh_config, refresh, packages, user)
    try:
        proc = runner(
            cmd,
            input=REMOTE_SCRIPT,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout or ""
        if isinstance(partial, bytes):
            partial = partial.decode("utf-8", errors="replace")
        # Paketliste ist vollständig, nur Changelogs fehlen: Teilergebnis statt Fehler.
        if SOURCES_MARKER in partial:
            note = f"\n===SECTION timeout===\nTimeout nach {timeout}s – Changelogs unvollständig\n"
            return HostResult(host, True, None, partial + note)
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
    ssh_config: Path | str | None,
    refresh: bool,
    packages: list[str],
    timeout: int,
    max_workers: int = MAX_WORKERS,
    runner=subprocess.run,
    user: str | None = None,
) -> list[HostResult]:
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [
            pool.submit(run_host, host, ssh_config, refresh, packages, timeout, runner, user)
            for host in hosts
        ]
        return [future.result() for future in futures]
