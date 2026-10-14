"""Styled console output helpers (stdlib only)."""

from __future__ import annotations

import os
import shutil
import sys

_CODES = {
    "info": "\033[36m",    # cyan
    "ok": "\033[32m",      # green
    "warn": "\033[33m",    # yellow
    "fail": "\033[31m",    # red
    "bold": "\033[1m",
    "dim": "\033[2m",
    "reset": "\033[0m",
}

_PREFIX = {
    "info": "[*]",
    "ok": "[+]",
    "warn": "[!]",
    "fail": "[x]",
    "note": " |",
}


class Console:
    """Small print helper with optional ANSI color and column alignment."""

    def __init__(self, color: bool = True, width: int | None = None) -> None:
        self.color = (
            color
            and sys.stdout.isatty()
            and os.environ.get("NO_COLOR") is None
            and os.environ.get("TERM") != "dumb"
        )
        self.width = width or (shutil.get_terminal_size().columns or 100)

    def _c(self, text: str, style: str) -> str:
        return f"{_CODES[style]}{text}{_CODES['reset']}" if self.color else text

    def section(self, title: str) -> None:
        print()
        print(self._c(f"== {title.upper()} ==", "bold"))

    def line(self, kind: str, msg: str) -> None:
        prefix = self._c(_PREFIX.get(kind, "[*]"), kind if kind in _CODES else "info")
        print(f"{prefix} {msg}")

    def info(self, msg: str) -> None:
        self.line("info", msg)

    def ok(self, msg: str) -> None:
        self.line("ok", msg)

    def warn(self, msg: str) -> None:
        self.line("warn", msg)

    def fail(self, msg: str) -> None:
        self.line("fail", msg)

    def kv(self, key: str, value, style: str = "info") -> None:
        key_txt = self._c(f"{key:<18}", "dim")
        print(f"{key_txt} {self._c(str(value), style)}")

    def table(self, rows: list[list[str]], headers: list[str]) -> None:
        cols = len(headers)
        widths = [len(h) for h in headers]
        for row in rows:
            for i in range(cols):
                widths[i] = max(widths[i], len(str(row[i])) if i < len(row) else 0)
        header = "  ".join(self._c(f"{h:<{widths[i]}}", "bold") for i, h in enumerate(headers))
        print(header)
        print("  ".join("-" * w for w in widths))
        for row in rows:
            cells = [f"{str(row[i]) if i < len(row) else '':<{widths[i]}}" for i in range(cols)]
            print("  ".join(cells))
