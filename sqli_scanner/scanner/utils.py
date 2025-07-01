"""
scanner.utils  (v1.1)
~~~~~~~~~~~~~~~~~~~~~

Utility helpers **updated** to integrate the new built-in–payload workflow
and configurable UNION marker.

Key additions
-------------
* Support for ``builtin_payloads`` list in YAML/CLI (e.g. ["classic","time"]).
* Automatic inclusion of built-in payloads via
  :pyfunc:`scanner.payloads.get_builtin_payloads`.
* Honour custom ``union_marker`` (falls back to the constant
  :pydata:`scanner.payloads.DEFAULT_MARKER`).

Everything else (rate-limiter, logger, etc.) is unchanged.
"""
from __future__ import annotations

import json
import logging
import pathlib
import random
import sys
import time
from typing import Dict, Iterable, List, Sequence

from rich.console import Console
from rich.logging import RichHandler
from rich.progress import Progress, SpinnerColumn, TextColumn

# New import – for built-ins
from scanner.payloads import (
    DEFAULT_MARKER,
    get_builtin_payloads,
    list_categories as builtin_categories,
)

__all__ = [
    "merge_configs",
    "load_targets",
    "load_payloads",
    "RateLimiter",
    "get_random_user_agent",
    "get_random_proxy",
    "init_logger",
    "builtin_categories",        # expose for CLI auto-completion later
]

# ────────────────────────────────────────────────────────────────────────────
# Constants
# ────────────────────────────────────────────────────────────────────────────

COMMON_UAS: Sequence[str] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_7) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
)

# ────────────────────────────────────────────────────────────────────────────
# Configuration helpers
# ────────────────────────────────────────────────────────────────────────────


def merge_configs(base: Dict, override: Dict) -> Dict:
    """
    Shallow-merge *override* into *base* (non-destructive).

    Lists are concatenated (override wins first), scalars are overwritten.
    """
    merged: Dict = {**base}  # copy
    for key, val in override.items():
        if val in (None, "", [], {}):
            continue
        if isinstance(val, list) and isinstance(base.get(key), list):
            merged[key] = val + base[key]  # type: ignore[index]
        elif isinstance(val, dict) and isinstance(base.get(key), dict):
            merged[key] = {**base[key], **val}  # type: ignore[index]
        else:
            merged[key] = val
    return merged


def _strip_comments(line: str) -> str:
    return line.split("#", 1)[0].strip()


def load_targets(cfg: Dict) -> List[str]:
    """
    Load target URLs from ``cfg["targets"]`` and/or ``cfg["url_file"]``.
    """
    targets: List[str] = []
    for url in cfg.get("targets", []):
        if url and isinstance(url, str):
            targets.append(url.strip())

    file_path = cfg.get("url_file")
    if file_path:
        path = pathlib.Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Target file not found: {path}")
        targets.extend(
            _strip_comments(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if _strip_comments(line)
        )

    # De-duplicate
    seen: set[str] = set()
    uniq_targets = [t for t in targets if not (t in seen or seen.add(t))]
    return uniq_targets


def load_payloads(cfg: Dict) -> List[str]:
    """
    Aggregate payloads from three sources **in priority order**:

    1. **Built-ins** specified via ``cfg["builtin_payloads"]`` –
       falls back to *all* default categories.
    2. Files listed in ``cfg["payload_files"]`` (each: one payload per line).
    3. Inline strings in ``cfg["payloads_inline"]``.

    Returns a de-duplicated list preserving insertion order.
    """
    marker = cfg.get("union_marker", DEFAULT_MARKER)
    builtin_cats = cfg.get("builtin_payloads", [])  # [] → default set

    payloads: List[str] = []

    # 1️⃣ Built-ins
    payloads.extend(get_builtin_payloads(builtin_cats, marker=marker))

    # 2️⃣ Files
    for file_path in cfg.get("payload_files", []):
        path = pathlib.Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Payload file not found: {path}")
        payloads.extend(
            _strip_comments(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if _strip_comments(line)
        )

    # 3️⃣ Inline
    payloads.extend(cfg.get("payloads_inline", []))

    # De-duplicate while preserving earlier precedence
    seen: set[str] = set()
    uniq = [p for p in payloads if not (p in seen or seen.add(p))]
    return uniq


# ────────────────────────────────────────────────────────────────────────────
# Request helpers
# ────────────────────────────────────────────────────────────────────────────
class RateLimiter:
    """Token-bucket style rate-limiter (see previous docstring)."""

    def __init__(self, rate_per_sec: int = 5) -> None:
        self._rate = max(rate_per_sec, 1)
        self._interval = 1.0 / float(self._rate)
        self._next_allowed = time.perf_counter()

    def __enter__(self):
        now = time.perf_counter()
        wait_for = self._next_allowed - now
        if wait_for > 0:
            time.sleep(wait_for)
        self._next_allowed = max(self._next_allowed + self._interval, now)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False


def get_random_user_agent(extra_uas: Iterable[str] | None = None) -> str:
    pop = list(COMMON_UAS)
    if extra_uas:
        pop.extend(extra_uas)
    return random.choice(pop)


def get_random_proxy(proxies: Sequence[str] | None) -> str | None:
    if not proxies:
        return None
    return random.choice(proxies)


# ────────────────────────────────────────────────────────────────────────────
# Logging helper
# ────────────────────────────────────────────────────────────────────────────
def init_logger(level_name: str = "INFO", console: Console | None = None) -> logging.Logger:
    level = getattr(logging, level_name.upper(), logging.INFO)

    handler = RichHandler(
        console=console or Console(),
        show_time=False,
        rich_tracebacks=True,
        markup=True,
    )
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[handler],
        force=True,  # override previous root handlers
    )
    return logging.getLogger()
