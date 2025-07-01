# File: sqli_scanner/scanner/core.py

"""
scanner.core  – orchestration of crawling, parameter fuzzing, detection, and reporting.

Features
--------
* Optional crawling of seed URLs to discover additional pages and forms.
* GET and POST parameter fuzzing against both URLs and HTML forms.
* Detection of SQLi via error-based, time-based, boolean-based, and UNION-based techniques.
* Reporting to JSON, CSV, or HTML depending on output file extension.

Public API
----------
* class Scanner
"""
from __future__ import annotations

import logging
import pathlib
import urllib.parse as urlparse
from datetime import datetime
from typing import Dict, List, Sequence

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from scanner import __version__
from .crawler import Crawler
from .detector import DetectionResult, Detector
from parser import HTMLForm, build_form_variants, extract_get_params, parse_forms
from .requester import HTTPResponse, Requester
from .utils import init_logger

from reports.json_report import write_json_report
from reports.csv_report import write_csv_report
from reports.html_report import write_html_report

logger = logging.getLogger(__name__)

__all__ = ["Scanner"]


class Scanner:
    """
    Main orchestrator for SQLi scanning.

    Parameters
    ----------
    config : dict
        Scanner configuration (merged CLI + config file).
    console : rich.console.Console
        Rich console for output and progress bars.
    """

    def __init__(self, config: Dict, console: Console):
        self.cfg = config
        self.console = console
        self.logger = init_logger(config.get("logging_level", "INFO"), console)
        self.requester = Requester(config, console)
        self.detector = Detector(config)
        self.findings: List[DetectionResult] = []

    # ────────────────────────────────────────────────────────────────────
    # Private helpers
    # ────────────────────────────────────────────────────────────────────
    @staticmethod
    def _inject_payload(url: str, param: str, payload: str) -> str:
        parsed = urlparse.urlparse(url)
        qs = urlparse.parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [payload]
        new_query = urlparse.urlencode(qs, doseq=True)
        return urlparse.urlunparse(parsed._replace(query=new_query))

    def _render_finding(self, finding: DetectionResult):
        # Use ASCII arrow to avoid Windows code-page issues
        self.console.print(
            f"[bold green]SQLi ->[/] {finding.url} "
            f"[cyan]{finding.parameter}[/] "
            f"({finding.detection_type}|{finding.confidence}%)"
        )

    def _crawl_if_enabled(self, seeds: Sequence[str]) -> tuple[set[str], List[HTMLForm]]:
        """
        If `crawl` is enabled in config, run the spider and return
        (pages, forms). Otherwise, return (set(seeds), []).
        """
        if not self.cfg.get("crawl"):
            return set(seeds), []

        depth = int(self.cfg.get("crawl_depth", 2))
        limit = int(self.cfg.get("crawl_pages", 50))

        with self.requester:
            crawler = Crawler(
                requester=self.requester,
                console=self.console,
                same_domain=True,
                max_depth=depth,
                max_pages=limit,
            )
            result = crawler.crawl(list(seeds))
            self.console.print(
                f"[blue]Crawler:[/] {len(result.pages)} pages, "
                f"{len(result.forms)} forms discovered."
            )
            return result.pages, result.forms

    def _fuzz_get_parameters(
        self,
        page_url: str,
        baseline_resp: HTTPResponse,
        payloads: Sequence[str],
    ):
        params = extract_get_params(page_url)
        for param in params:
            for payload in payloads:
                test_url = self._inject_payload(page_url, param, payload)
                variant = self.requester.request("GET", test_url)
                res = self.detector.analyse(baseline_resp, variant, payload, param)
                if res:
                    self.findings.append(res)
                    self._render_finding(res)

    def _fuzz_forms(self, form: HTMLForm, payloads: Sequence[str]):
        # Send baseline with default form values
        default_data = dict(form.inputs)
        baseline = self.requester.request(
            form.method,
            form.action_url,
            data=default_data if form.method == "POST" else None,
            params=default_data if form.method == "GET" else None,
        )

        for spec in build_form_variants(form, payloads):
            variant = self.requester.request(**spec)
            data = spec.get("data") or spec.get("params") or {}
            changed = next(
                (k for k, v in data.items() if v != default_data.get(k)), "unknown"
            )
            res = self.detector.analyse(baseline, variant, data.get(changed, ""), changed)
            if res:
                self.findings.append(res)
                self._render_finding(res)

    # ────────────────────────────────────────────────────────────────────
    # Public API
    # ────────────────────────────────────────────────────────────────────
    def scan_targets(self, targets: Sequence[str], payloads: Sequence[str]):
        """
        Execute the full scan:

        1. Optional crawl → pages + forms
        2. Fetch baseline for each page
        3. Fuzz GET parameters
        4. Parse & fuzz forms (GET/POST)
        5. Emit report
        """
        if not targets:
            self.console.print("[red]No targets supplied, aborting.[/]")
            return

        pages, forms_from_crawl = self._crawl_if_enabled(targets)
        pages.update(targets)

        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TextColumn("{task.completed}/{task.total} pages"),
            console=self.console,
            transient=True,
        )
        task_id = progress.add_task("Scanning", total=len(pages))

        with self.requester, progress:
            all_forms: List[HTMLForm] = list(forms_from_crawl)

            for page in pages:
                progress.update(task_id, advance=1)
                baseline = self.requester.request("GET", page)
                if baseline.status_code == 0 or not baseline.text:
                    continue

                self._fuzz_get_parameters(page, baseline, payloads)

                try:
                    page_forms = parse_forms(baseline.text, baseline.url)
                    all_forms.extend(page_forms)
                except Exception as exc:
                    logger.debug("Form parse error on %s: %s", baseline.url, exc)

            for form in all_forms:
                self._fuzz_forms(form, payloads)

        self._emit_report(self.findings)

    def _emit_report(self, findings: List[DetectionResult]):
        """
        Write findings to a report file based on its extension:
        .json → JSON, .csv → CSV, .html/.htm → HTML.
        """
        if not findings:
            self.console.print("[bold yellow]No SQLi found.[/]")
            return

        # ASCII-based rules to avoid Unicode issues on Windows
        self.console.rule("[bold red] Findings [/]", characters="-")
        for f in findings:
            self.console.print(
                f"[green]{f.detection_type.upper():8}[/] "
                f"{f.confidence:3}%  "
                f"[cyan]{f.parameter}[/]  "
                f"{f.url}"
            )
        self.console.rule(characters="-")

        report_file = self.cfg.get("report_file")
        if not report_file:
            return

        path = pathlib.Path(report_file)
        suffix = path.suffix.lower()

        try:
            if suffix == ".json":
                write_json_report(findings, path, config=self.cfg)
            elif suffix == ".csv":
                write_csv_report(findings, path)
            elif suffix in {".html", ".htm"}:
                write_html_report(findings, path, scanner=__version__)
            else:
                alt = path.with_suffix(".json")
                write_json_report(findings, alt, config=self.cfg)
                self.console.print(
                    f"[yellow]Unknown extension '{suffix}', wrote JSON to {alt} instead.[/]"
                )
                return

            self.console.print(f"[green]Report saved:[/] {path}")
        except Exception as e:
            logger.error("Failed to write report %s: %s", path, e)
