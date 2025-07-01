# File: cli.py

"""
Typer-powered CLI for SQLi-Scanner with fixed option definitions.
"""
from __future__ import annotations

import json
import pathlib
import sys
from typing import List, Optional

import typer
import yaml
from rich.console import Console
from rich.table import Table

from scanner.utils import (
    builtin_categories,
    load_payloads,
    load_targets,
    merge_configs,
)
from scanner.core import Scanner

APP_NAME = "sqli-scanner"
console = Console()
app = typer.Typer(
    name=APP_NAME,
    help="Advanced SQL Injection scanner.",
    no_args_is_help=True,
)


def _read_config_file(config_path: pathlib.Path) -> dict:
    if not config_path.exists():
        console.print(f"[bold red]Config file not found →[/] {config_path}")
        raise typer.Exit(1)
    try:
        text = config_path.read_text(encoding="utf-8")
        if config_path.suffix.lower() in {".yaml", ".yml"}:
            return yaml.safe_load(text) or {}
        if config_path.suffix.lower() == ".json":
            return json.loads(text)
    except Exception as exc:  # pragma: no cover
        console.print(f"[bold red]Invalid config:[/] {exc}")
        raise typer.Exit(1)
    console.print("[bold red]Unsupported config format – use YAML or JSON.[/]")
    raise typer.Exit(1)


def _csv_to_list(value: str | None) -> List[str]:
    return [v.strip() for v in value.split(",") if v.strip()] if value else []


@app.callback()
def _common_options(
    ctx: typer.Context,
    config: Optional[pathlib.Path] = typer.Option(
        None, "--config", "-c", exists=True, readable=True, help="YAML/JSON config file."
    ),
    verbose: int = typer.Option(
        0, "--verbose", "-v", count=True, help="Increase verbosity (-v, -vv, -vvv)."
    ),
):
    cfg: dict = _read_config_file(config) if config else {}
    cfg["logging_level"] = ["WARNING", "INFO", "DEBUG"][min(verbose, 2)]
    ctx.obj = cfg


@app.command("list-builtins", help="Show built-in payload categories and exit.")
def _list_builtins():
    table = Table(title="Built-in Payload Categories")
    table.add_column("Category", style="cyan")
    for cat in builtin_categories():
        table.add_row(cat)
    console.print(table)
    raise typer.Exit()


@app.command("scan", help="Scan a single URL or list of URLs.")
def scan_cmd(
    ctx: typer.Context,
    url: Optional[str] = typer.Option(
        None, "--url", "-u", help="Single target URL (must include at least one query parameter)."
    ),
    url_file: Optional[pathlib.Path] = typer.Option(
        None, "--url-file", "-U", exists=True, readable=True, help="File with one URL per line."
    ),
    headers: Optional[str] = typer.Option(
        None, "--headers", "-H", help='JSON string of extra headers, e.g. \'{"X-Api-Key":"123"}\'.'
    ),
    cookies: Optional[str] = typer.Option(
        None, "--cookies", "-C", help='Cookie string, e.g. "session=abc; csrf=def".'
    ),
    payload_file: Optional[pathlib.Path] = typer.Option(
        None, "--payload-file", "-P", exists=True, readable=True, help="Custom payload file."
    ),
    builtins: Optional[str] = typer.Option(
        None,
        "--builtins",
        help="Comma-separated built-in payload categories (default: all), e.g. classic,time",
    ),
    marker: str = typer.Option(
        "SQLISCANNERUNIONTEST",
        "--marker",
        help="Marker to embed in UNION payloads (and detected).",
    ),
    output: Optional[pathlib.Path] = typer.Option(
        None, "--output", "-o", help="Write report to this file (.json, .csv, or .html)."
    ),
    threads: int = typer.Option(
        10, "--threads", "-t", help="Number of worker threads (sync mode)."
    ),
    async_mode: bool = typer.Option(
        False, "--async", help="Use async HTTP engine (httpx)."
    ),
    crawl: bool = typer.Option(
        False, "--crawl", help="Enable crawler to discover additional pages/forms."
    ),
    crawl_depth: int = typer.Option(
        2, "--crawl-depth", help="Link-following depth when crawling."
    ),
    crawl_pages: int = typer.Option(
        50, "--crawl-pages", help="Maximum number of pages to fetch when crawling."
    ),
):
    """
    Perform a SQLi scan with the given options.
    """
    cfg_file = ctx.obj or {}
    cfg_cli = {
        "targets": [url] if url else [],
        "url_file": str(url_file) if url_file else None,
        "headers": json.loads(headers) if headers else {},
        "cookies": cookies or "",
        "payload_files": [str(payload_file)] if payload_file else [],
        "builtin_payloads": _csv_to_list(builtins),
        "union_marker": marker,
        "crawl": crawl,
        "crawl_depth": crawl_depth,
        "crawl_pages": crawl_pages,
        "threads": threads,
        "async_mode": async_mode,
        "report_file": str(output) if output else None,
    }

    final_cfg = merge_configs(cfg_file, cfg_cli)

    # Show configuration summary
    table = Table(title="Configuration Summary", show_lines=True)
    for key, val in final_cfg.items():
        table.add_row(
            str(key),
            json.dumps(val, indent=2, ensure_ascii=False)
            if isinstance(val, (dict, list))
            else str(val),
        )
    console.print(table)

    targets = load_targets(final_cfg)
    payloads = load_payloads(final_cfg)

    if not targets:
        console.print("[bold red]No targets specified.[/]")
        raise typer.Exit(1)
    if not payloads:
        console.print("[bold red]No payloads loaded.[/]")
        raise typer.Exit(1)

    try:
        scanner = Scanner(config=final_cfg, console=console)
        scanner.scan_targets(targets, payloads)
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Scan aborted by user.[/]")
        raise typer.Exit(130)

    if final_cfg.get("report_file"):
        console.print(f"[green]Report saved:[/] {final_cfg['report_file']}")
