"""SSH-Ausführung des Remote-Skripts auf den Hosts."""
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

# Bash-Fragment: liest "<paket> <version>"-Zeilen von stdin und gibt aus
#   "<paket> <version>", wenn das Paar in einer Ubuntu-Paketliste steht (apt-Listen mit
#   "Origin: Ubuntu"), sonst
#   "<paket> *", wenn der Name in einer Ubuntu- und in keiner Fremd-Paketliste vorkommt
#   (Ubuntu-Indizes führen nur Release- und neueste Update-Version; überholte Versionen).
# Die Gruppen werden per awk-Zuweisungsoperand (g=u / g=f) getrennt. POSIX-awk, mawk-kompatibel.
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

# Wird per stdin an `bash -s -- <refresh 0|1> [paket ...]` übergeben; legt nichts auf dem Host ab.
# Ohne Refresh braucht das Skript kein sudo.
# Alle Befehle bekommen </dev/null, damit sie nicht den Rest des Skripts von stdin lesen.
REMOTE_SCRIPT = r"""
export LC_ALL=C
REFRESH="${1:-1}"
shift || true
FILTER=" $* "

echo "===SECTION os==="
( . /etc/os-release 2>/dev/null && echo "${VERSION_ID:-}" && echo "${VERSION_CODENAME:-}" )

echo "===SECTION apt_update==="
if [ "$REFRESH" = "1" ]; then
  out=$(timeout 90 sudo -n apt-get update -qq </dev/null 2>&1)
  rc=$?
  echo "rc=$rc"
  [ -n "$out" ] && printf '%s\n' "$out"
else
  echo "rc=skipped"
fi

# Stand der Paketlisten: "now <epoch>", danach Epochen der Update-Stempel
# (update-notifier/apt.systemd.daily), von lists/partial (ändert apt bei jedem Update)
# und der neuesten Release-Datei (trägt nur das Veröffentlichungsdatum des Servers).
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


SECTION_PREFIX = "===SECTION "
# Was der Host gerade tut, sobald die jeweilige Sektion beginnt (Fortschrittsanzeige).
SECTION_PHASES = {
    "os": "verbunden",
    "apt_update": "apt-get update",
    "upgradable": "anstehende Updates ermitteln",
    "installed": "installierte Pakete lesen",
    "origins": "Paketherkunft prüfen",
    "sources": "Quellpakete zuordnen",
}


def phase_tracker(on_phase):
    """Liefert einen Zeilen-Callback, der aus den Sektionsmarkern der Remote-Ausgabe
    Phasen für on_phase(text) macht; Changelogs werden als "Changelog n/m: <quelle>" gezählt."""
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
    """Wie subprocess.run(..., capture_output=True); mit on_line wird stdout zusätzlich
    zeilenweise gemeldet, während der Prozess noch läuft. Bei Timeout enthält
    TimeoutExpired.output die bis dahin gelesene Ausgabe."""
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
    runner=stream_run,
    user: str | None = None,
    on_phase=None,
) -> HostResult:
    """on_phase(text) meldet, was auf dem Host gerade läuft (nur für die Fortschrittsanzeige)."""
    cmd = build_ssh_command(host, ssh_config, refresh, packages, user)
    extra = {"on_line": phase_tracker(on_phase)} if on_phase else {}
    if on_phase:
        on_phase("SSH-Verbindung")
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
    runner=stream_run,
    user: str | None = None,
    progress=None,
) -> list[HostResult]:
    """progress: Objekt mit host_phase(host, text) und host_done(host, error), z. B. progress.Progress."""

    def check(host: str) -> HostResult:
        if progress is None:
            return run_host(host, ssh_config, refresh, packages, timeout, runner, user)
        result = run_host(host, ssh_config, refresh, packages, timeout, runner, user,
                          on_phase=lambda phase: progress.host_phase(host, phase))
        progress.host_done(host, result.error)
        return result

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        return list(pool.map(check, hosts))
