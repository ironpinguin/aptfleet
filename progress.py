"""Fortschrittsanzeige auf stderr für interaktive Läufe (ohne TTY, z. B. cron, stumm)."""
from __future__ import annotations

import shutil
import sys
import threading
import time


class Progress:
    """Feste Zeilen für Schritte und Host-Ergebnisse, dazu eine Statuszeile, die laufend
    überschrieben wird und zeigt, was auf den gerade laufenden Hosts passiert.

    Thread-sicher: Host-Ereignisse kommen aus den SSH-Worker-Threads."""

    def __init__(self, stream=None, enabled: bool | None = None, clock=time.monotonic):
        self.stream = stream or sys.stderr
        if enabled is None:
            isatty = getattr(self.stream, "isatty", None)
            enabled = bool(isatty and isatty())
        self.enabled = enabled
        self._clock = clock
        self._lock = threading.Lock()
        self._running: dict[str, str] = {}
        self._started: dict[str, float] = {}
        self._total = 0
        self._done = 0
        self._status_shown = False

    def step(self, message: str) -> None:
        with self._lock:
            self._line(f"» {message}")

    def hosts_start(self, total: int) -> None:
        with self._lock:
            self._total, self._done = total, 0
            self._line(f"» {total} Host(s) prüfen …")

    def host_phase(self, host: str, phase: str) -> None:
        with self._lock:
            if host not in self._started:
                self._started[host] = self._clock()
            self._running[host] = phase
            self._draw_status()

    def host_done(self, host: str, error: str | None = None) -> None:
        with self._lock:
            self._running.pop(host, None)
            started = self._started.pop(host, None)
            self._done += 1
            took = f" ({self._clock() - started:.0f}s)" if started is not None else ""
            count = f"[{self._done}/{self._total}]"
            if error:
                self._line(f"  ✗ {count} {host}: {error}{took}")
            else:
                self._line(f"  ✓ {count} {host} fertig{took}")

    def close(self) -> None:
        with self._lock:
            self._clear_status()
            self._running.clear()

    def _line(self, text: str) -> None:
        if not self.enabled:
            return
        self._clear_status()
        print(text, file=self.stream, flush=True)
        self._draw_status()

    def _clear_status(self) -> None:
        if self._status_shown:
            self.stream.write("\r\033[K")
            self.stream.flush()
            self._status_shown = False

    def _draw_status(self) -> None:
        if not self.enabled or not self._running:
            self._clear_status()
            return
        parts = " · ".join(f"{host}: {phase}" for host, phase in self._running.items())
        text = f"  [{self._done}/{self._total}] {parts}"
        width = shutil.get_terminal_size((100, 20)).columns - 1
        if len(text) > width:
            text = text[: max(width - 1, 0)] + "…"
        self.stream.write("\r\033[K" + text)
        self.stream.flush()
        self._status_shown = True
