"""
scanner.parser
~~~~~~~~~~~~~~

**Light-weight helpers to enumerate parameters in URLs and HTML forms** so the
scanner can fuzz **GET *and* POST** targets.

This is intentionally independent of any particular crawler or request engine
so it can be unit-tested in isolation.

Key objects
-----------
* :class:`HTMLForm` – dataclass representing a single <form> element.
* :func:`extract_get_params(url)` – return list of query-string keys.
* :func:`parse_forms(html, base_url)` – yield :class:`HTMLForm` objects.
* :func:`build_form_variants(form, payloads)` – helper to generate payload
  permutations ready for :pyclass:`scanner.requester.Requester`.

The core scanner can:

1. Fetch baseline HTML.
2. Call :func:`parse_forms` to discover forms.
3. For each form, call :func:`build_form_variants` to obtain request specs
   (`{"method": "POST", "url": …, "data": …}`) and feed them into the
   Requester.
"""
from __future__ import annotations

import urllib.parse as urlparse
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Sequence
from bs4 import BeautifulSoup


# ────────────────────────────────────────────────────────────────────────────
# Helpers for GET parameters
# ────────────────────────────────────────────────────────────────────────────
def extract_get_params(url: str) -> List[str]:
    """
    Return a list of query-string parameter names in *url*.

    Example
    -------
    >>> extract_get_params("https://foo/?id=1&name=bob")
    ['id', 'name']
    """
    qs = urlparse.urlparse(url).query
    return list(urlparse.parse_qs(qs, keep_blank_values=True).keys())


# ────────────────────────────────────────────────────────────────────────────
# Form model
# ────────────────────────────────────────────────────────────────────────────
@dataclass(slots=True)
class HTMLForm:
    """
    Minimal representation of an HTML <form> for fuzzing.

    Attributes
    ----------
    action_url : str            -- absolute URL the form submits to.
    method     : str            -- "GET" or "POST".
    inputs     : Dict[str,str]  -- {name: default_value}.  Empty values allowed.
    """

    action_url: str
    method: str
    inputs: Dict[str, str] = field(default_factory=dict)


# ────────────────────────────────────────────────────────────────────────────
# HTML form parser
# ────────────────────────────────────────────────────────────────────────────
def _make_absolute(base_url: str, link: str) -> str:
    return urlparse.urljoin(base_url, link)


def parse_forms(html: str, base_url: str) -> List[HTMLForm]:
    """
    Parse *html* and return a list of :class:`HTMLForm`.

    Only <input type=text|hidden|search|password|email|number|url> and
    <textarea> fields are captured; buttons / submit inputs are ignored.
    """
    soup = BeautifulSoup(html, "lxml")
    forms: List[HTMLForm] = []

    for f in soup.find_all("form"):
        method = (f.get("method") or "GET").strip().upper()
        action = f.get("action") or base_url
        action_url = _make_absolute(base_url, action)

        inputs: Dict[str, str] = {}
        # Input elements
        for inp in f.find_all("input"):
            itype = (inp.get("type") or "text").lower()
            if itype in {"submit", "button", "reset", "image", "file"}:
                continue
            name = inp.get("name")
            if not name:
                continue
            inputs[name] = inp.get("value", "")
        # Textareas
        for ta in f.find_all("textarea"):
            name = ta.get("name")
            if name:
                inputs[name] = ta.text or ""

        if inputs:  # ignore forms with no fuzzable inputs
            forms.append(HTMLForm(action_url=action_url, method=method, inputs=inputs))
    return forms


# ────────────────────────────────────────────────────────────────────────────
# Variant generator
# ────────────────────────────────────────────────────────────────────────────
def build_form_variants(
    form: HTMLForm,
    payloads: Sequence[str],
    *,
    max_variants: int = 100,
) -> Iterable[Dict]:
    """
    Yield request-spec dictionaries suitable for ``Requester.request_many``.

    Currently: *one parameter changes at a time* (others keep default values).

    Example spec
    ------------
    {
        "method": "POST",
        "url": "https://target/submit.php",
        "data": {"username": "admin' OR 1=1 --", "pass": ""}
    }
    """
    count = 0
    for param in form.inputs.keys():
        default_data = dict(form.inputs)
        for p in payloads:
            if count >= max_variants:  # safety valve
                return
            mutated = dict(default_data)
            mutated[param] = p
            yield {
                "method": form.method,
                "url": form.action_url,
                "data": mutated if form.method == "POST" else None,
                "params": mutated if form.method == "GET" else None,
            }
            count += 1
