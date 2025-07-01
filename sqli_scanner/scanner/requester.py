"""
scanner.requester
~~~~~~~~~~~~~~~~~

HTTP request engine that powers the scanner.

Features
--------
* **Async** (httpx.AsyncClient) *or* **thread-pooled sync** (requests.Session).
* Automatic User-Agent rotation & optional proxy rotation.
* Built-in rate-limiting, retry/back-off, and timeout handling.
* Supports GET & POST with custom headers / cookies / data / JSON body.
* Returns a thin dataclass wrapper ― ``HTTPResponse`` ― so detectors only
  depend on a stable, library-agnostic interface.

The engine is intentionally minimal; all higher-level logic (payload fuzzing,
parameter handling, etc.) lives in ``scanner.core`` and friends.
"""
from __future__ import annotations

import asyncio
import logging
import random
import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional

import httpx
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from scanner.utils import (
    RateLimiter,
    get_random_proxy,
    get_random_user_agent,
)

logger = logging.getLogger(__name__)

__all__ = ["HTTPResponse", "Requester"]


# ────────────────────────────────────────────────────────────────────────────
# Thin wrapper around responses
# ────────────────────────────────────────────────────────────────────────────
@dataclass(slots=True)
class HTTPResponse:
    """
    Library-agnostic HTTP response.

    Only a subset of attributes is exposed to simplify detectors and ease
    future refactors (e.g. swapping httpx for aiohttp).
    """

    url: str
    method: str
    status_code: int
    elapsed: float
    headers: Dict[str, str]
    text: str
    raw: object  # underlying response object (requests.Response | httpx.Response)


# ────────────────────────────────────────────────────────────────────────────
# Main engine
# ────────────────────────────────────────────────────────────────────────────
class Requester:
    """
    Facade wrapping async **or** threaded-sync HTTP logic behind a common API.

    Parameters
    ----------
    config : dict
        Merged configuration dict.
    console : rich.console.Console
        For pretty progress bars (not used directly here, but kept for future UI).
    """

    def __init__(self, config: dict, console) -> None:  # noqa: D401
        self.cfg = config
        self.console = console
        self.rate_limiter = RateLimiter(rate_per_sec=config.get("rate_limit", 5))
        self.retries = config.get("retries", 3)
        self.timeout = config.get("timeout", 10)
        self.async_mode = bool(config.get("async_mode", False))
        self.proxies = config.get("proxies", [])
        self.user_agents = config.get("user_agents", [])
        self._thread_pool: Optional[ThreadPoolExecutor] = None
        self._async_client: Optional[httpx.AsyncClient] = None
        logger.debug("Requester initialised (async=%s)", self.async_mode)

    # ------------------------------------------------------------------ #
    # Public high-level helpers used by the scanner
    # ------------------------------------------------------------------ #
    def open(self):
        """Open sockets / thread-pools as needed (idempotent)."""
        if self.async_mode and self._async_client is None:
            self._async_client = httpx.AsyncClient(
                timeout=self.timeout, verify=False, follow_redirects=True
            )
        elif not self.async_mode and self._thread_pool is None:
            workers = max(2, self.cfg.get("threads", 10))
            self._thread_pool = ThreadPoolExecutor(max_workers=workers)

    def close(self):
        """Gracefully close any open resources."""
        if self._async_client:
            asyncio.run(self._async_client.aclose())  # pragma: no cover
            self._async_client = None
        if self._thread_pool:
            self._thread_pool.shutdown(wait=True)
            self._thread_pool = None

    # ------------------------------------------------------------------ #
    # Core request methods
    # ------------------------------------------------------------------ #
    async def _async_request(
        self,
        method: str,
        url: str,
        *,
        params=None,
        data=None,
        json=None,
        headers=None,
        cookies=None,
    ) -> HTTPResponse:  # noqa: A002
        """
        Single async request with retry & rate-limit.
        """
        assert self._async_client is not None  # open() was called
        attempt = 0
        proxy_url = get_random_proxy(self.proxies)
        while attempt < self.retries:
            attempt += 1
            ua = get_random_user_agent(self.user_agents)
            h = {"User-Agent": ua, **(headers or {})}

            async with self.rate_limiter:
                start = time.perf_counter()
                try:
                    resp = await self._async_client.request(
                        method.upper(),
                        url,
                        params=params,
                        data=data,
                        json=json,
                        headers=h,
                        cookies=cookies,
                        proxies=proxy_url,
                        timeout=self.timeout,
                    )
                    elapsed = time.perf_counter() - start
                    return HTTPResponse(
                        url=str(resp.url),
                        method=method.upper(),
                        status_code=resp.status_code,
                        elapsed=elapsed,
                        headers=dict(resp.headers),
                        text=resp.text,
                        raw=resp,
                    )
                except (httpx.RequestError, httpx.TimeoutException) as exc:
                    logger.debug("Async error (%s) %s → retry %d/%d", url, exc, attempt, self.retries)
                    await asyncio.sleep(0.5 * attempt)  # linear back-off
        # Exhausted retries
        return HTTPResponse(
            url=url,
            method=method.upper(),
            status_code=0,
            elapsed=0.0,
            headers={},
            text="",
            raw=None,
        )

    def _sync_request(
        self,
        method: str,
        url: str,
        *,
        params=None,
        data=None,
        json=None,
        headers=None,
        cookies=None,
    ) -> HTTPResponse:
        """
        Single synchronous request with retry & rate-limit.
        """
        session = requests.Session()
        session.verify = False
        proxy_url = get_random_proxy(self.proxies)
        attempt = 0
        while attempt < self.retries:
            attempt += 1
            ua = get_random_user_agent(self.user_agents)
            h = {"User-Agent": ua, **(headers or {})}
            with self.rate_limiter:
                start = time.perf_counter()
                try:
                    resp = session.request(
                        method.upper(),
                        url,
                        params=params,
                        data=data,
                        json=json,
                        headers=h,
                        cookies=cookies,
                        proxies={"http": proxy_url, "https": proxy_url} if proxy_url else None,
                        timeout=self.timeout,
                        allow_redirects=True,
                    )
                    elapsed = time.perf_counter() - start
                    return HTTPResponse(
                        url=resp.url,
                        method=method.upper(),
                        status_code=resp.status_code,
                        elapsed=elapsed,
                        headers=dict(resp.headers),
                        text=resp.text,
                        raw=resp,
                    )
                except (requests.RequestException,) as exc:
                    logger.debug("Sync error (%s) %s → retry %d/%d", url, exc, attempt, self.retries)
                    time.sleep(0.5 * attempt)
        return HTTPResponse(
            url=url,
            method=method.upper(),
            status_code=0,
            elapsed=0.0,
            headers={},
            text="",
            raw=None,
        )

    # ------------------------------------------------------------------ #
    # Batch helpers (public)
    # ------------------------------------------------------------------ #
    async def _async_batch(self, requests_iter):
        tasks = [self._async_request(**kw) for kw in requests_iter]
        for coro in asyncio.as_completed(tasks):
            yield await coro

    def _sync_batch(self, requests_iter):
        # Submit to ThreadPool, yield as completed
        futures = [self._thread_pool.submit(self._sync_request, **kw) for kw in requests_iter]  # type: ignore[arg-type]
        for fut in as_completed(futures):
            yield fut.result()

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def request(self, method: str, url: str, **kwargs) -> HTTPResponse:
        """
        One-off helper for simple use-cases (blocking).

        Returns
        -------
        HTTPResponse
        """
        self.open()
        if self.async_mode:
            return asyncio.run(self._async_request(method, url, **kwargs))
        return self._sync_request(method, url, **kwargs)

    def request_many(self, requests_iter):
        """
        Generator yielding ``HTTPResponse`` objects for each request spec in
        *requests_iter* (dicts with keys matching ``_sync_request`` signature).

        Example
        -------
        >>> specs = [{"method": "GET", "url": "https://example.com"}]
        >>> for resp in requester.request_many(specs):
        ...     print(resp.status_code)
        """
        self.open()
        if self.async_mode:
            # Run the async batch inside an event-loop, return sync iterator
            return asyncio.run(self._async_batch(requests_iter))
        return self._sync_batch(requests_iter)

    # ------------------------------------------------------------------ #
    # Context-manager helpers
    # ------------------------------------------------------------------ #
    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False  # propagate exceptions
