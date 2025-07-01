"""
scanner.crawler
~~~~~~~~~~~~~~~

**Purpose** – A compact, breadth-first crawler that discovers additional pages
and HTML forms to feed into the scanner.

Highlights
----------
* Same-domain restriction by default (configurable).
* Honours maximum depth & page limits.
* Re-uses the project’s :class:`scanner.requester.Requester` for HTTP fetching
  (shares rate-limiter, proxy rotation, etc.).
* Parses links (`<a href>`), frames, and forms via **BeautifulSoup**.
* Emits two collections:
    1. ``pages``  – unique URLs discovered (incl. start URLs)
    2. ``forms``  – :class:`scanner.parser.HTMLForm` objects ready for fuzzing
"""
from __future__ import annotations

import logging
import urllib.parse as urlparse
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

from bs4 import BeautifulSoup
from rich.console import Console

from parser import HTMLForm, parse_forms
from scanner.requester import HTTPResponse, Requester

logger = logging.getLogger(__name__)

__all__ = ["CrawlResult", "Crawler"]


@dataclass(slots=True)
class CrawlResult:
    pages: Set[str] = field(default_factory=set)
    forms: List[HTMLForm] = field(default_factory=list)


class Crawler:
    """
    Breadth-first web spider with form discovery.

    Parameters
    ----------
    requester : Requester
        An *open* Requester instance (sync or async).
    console : rich.console.Console
        For status output (optional; can pass ``None`` for silent mode).
    same_domain : bool
        Restrict crawl to the domain(s) of the seed URLs.
    max_depth : int
        Link-following depth (seed URLs = depth 0).
    max_pages : int
        Hard cap on number of pages fetched.
    """

    def __init__(
        self,
        requester: Requester,
        console: Console | None = None,
        *,
        same_domain: bool = True,
        max_depth: int = 2,
        max_pages: int = 50,
    ):
        self.requester = requester
        self.console = console or Console(stderr=True, quiet=True)
        self.same_domain = same_domain
        self.max_depth = max_depth
        self.max_pages = max_pages

    # ------------------------------------------------------------------ #
    # Private helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _get_domain(url: str) -> str:
        return urlparse.urlparse(url).netloc.lower()

    @staticmethod
    def _extract_links(base_url: str, html: str) -> Set[str]:
        """
        Return absolute URLs found in <a href>, <frame src>, <iframe src>.
        """
        soup = BeautifulSoup(html, "lxml")
        links: Set[str] = set()

        def _abs(link: str) -> str:
            return urlparse.urljoin(base_url, link)

        # Anchor tags
        for a in soup.find_all("a", href=True):
            links.add(_abs(a["href"]))
        # Frames / iframes
        for fr in soup.find_all(["frame", "iframe"], src=True):
            links.add(_abs(fr["src"]))

        return links

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def crawl(self, seeds: List[str]) -> CrawlResult:
        """
        Crawl starting from *seeds*.  Returns :class:`CrawlResult`.
        """
        queue: deque[Tuple[str, int]] = deque((s, 0) for s in seeds)
        visited: Set[str] = set()
        allowed_domains = {self._get_domain(s) for s in seeds}

        pages: Set[str] = set()
        forms: List[HTMLForm] = []

        while queue and len(pages) < self.max_pages:
            url, depth = queue.popleft()
            if url in visited or depth > self.max_depth:
                continue
            visited.add(url)

            resp: HTTPResponse = self.requester.request("GET", url)
            if resp.status_code == 0 or not resp.text:
                continue

            pages.add(resp.url)

            # Parse forms
            try:
                f_list = parse_forms(resp.text, resp.url)
                forms.extend(f_list)
                logger.debug("Found %d forms on %s", len(f_list), resp.url)
            except Exception as exc:  # noqa: BLE001
                logger.debug("Form parse error on %s: %s", resp.url, exc)

            # Extract & enqueue links
            for link in self._extract_links(resp.url, resp.text):
                if self.same_domain and self._get_domain(link) not in allowed_domains:
                    continue
                if link not in visited:
                    queue.append((link, depth + 1))

            if len(pages) >= self.max_pages:
                break

            # Progress hint
            self.console.print(f"[grey58]Crawled:[/] {resp.url}", highlight=False)

        return CrawlResult(pages=pages, forms=forms)
