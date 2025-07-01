# File: reports/html_report.py

"""
reports.html_report
~~~~~~~~~~~~~~~~~~~

Generate an HTML report of SQLi-Scanner findings using Jinja2.

Example
-------
>>> from pathlib import Path
>>> from sqli_scanner.reports.html_report import write_html_report
>>> write_html_report(findings, Path("reports/scan.html"), scanner="sqli-scanner", version="1.0.0")
"""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from jinja2 import Environment, select_autoescape, Template

from scanner.detector import DetectionResult

__all__ = ["write_html_report"]

# ────────────────────────────────────────────────────────────────────────────
# Inline Jinja2 template
# ────────────────────────────────────────────────────────────────────────────
_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SQLi Scanner Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    h1, h2 { color: #333; }
    table { border-collapse: collapse; width: 100%; margin-top: 1em; }
    th, td { border: 1px solid #ccc; padding: 0.5em; text-align: left; }
    th { background-color: #f5f5f5; }
    tbody tr:nth-child(even) { background-color: #fafafa; }
  </style>
</head>
<body>
  <h1>SQLi Scanner Report</h1>
  <p><strong>Generated at:</strong> {{ generated_at }}</p>
  <p><strong>Total findings:</strong> {{ total_findings }}</p>
  {% if meta %}
  <h2>Metadata</h2>
  <ul>
    {% for key, value in meta.items() %}
    <li><strong>{{ key }}:</strong> {{ value }}</li>
    {% endfor %}
  </ul>
  {% endif %}
  <h2>Findings</h2>
  <table>
    <thead>
      <tr>
        <th>#</th>
        <th>URL</th>
        <th>Param</th>
        <th>Method</th>
        <th>Payload</th>
        <th>Type</th>
        <th>Confidence</th>
        <th>Evidence</th>
        <th>Δ Time (s)</th>
      </tr>
    </thead>
    <tbody>
      {% for f in findings %}
      <tr>
        <td>{{ loop.index }}</td>
        <td>{{ f.url }}</td>
        <td>{{ f.parameter }}</td>
        <td>{{ f.method }}</td>
        <td>{{ f.payload }}</td>
        <td>{{ f.detection_type }}</td>
        <td>{{ f.confidence }}%</td>
        <td>{{ f.evidence }}</td>
        <td>{{ "%.2f"|format(f.timing_delta) }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</body>
</html>
"""

def write_html_report(
    findings: List[DetectionResult],
    outfile: Path,
    **meta: Any,
) -> Path:
    """
    Render an HTML report to *outfile*.

    Parameters
    ----------
    findings
        List of DetectionResult objects.
    outfile
        Destination .html file path.
    **meta
        Arbitrary metadata to display (e.g., scanner name, config, duration).

    Returns
    -------
    Path
        The written HTML file path.
    """
    # Convert dataclasses (including slots) into dicts
    findings_dicts = [asdict(f) for f in findings]

    context: Dict[str, Any] = {
        "generated_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "total_findings": len(findings_dicts),
        "findings": findings_dicts,
        "meta": meta or {},
    }

    env = Environment(autoescape=select_autoescape(["html", "xml"]))
    template: Template = env.from_string(_HTML_TEMPLATE)
    html = template.render(**context)

    outfile.parent.mkdir(parents=True, exist_ok=True)
    outfile.write_text(html, encoding="utf-8")
    return outfile
