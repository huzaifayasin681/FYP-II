"""
reports.csv_report
~~~~~~~~~~~~~~~~~~

CSV writer for SQLi-Scanner findings (RFC 4180 compliant).

Example
-------
>>> from pathlib import Path
>>> from sqli_scanner.reports.csv_report import write_csv_report
>>> write_csv_report(findings, Path("reports/scan.csv"))

The resulting file will have a header row followed by one row per
``DetectionResult``.
"""
from __future__ import annotations

import csv
from pathlib import Path
from typing import List

from scanner.detector import DetectionResult

__all__ = ["write_csv_report"]


def write_csv_report(findings: List[DetectionResult], outfile: Path) -> Path:
    """
    Serialize *findings* to **outfile** in UTF-8 CSV.

    Parameters
    ----------
    findings : list[DetectionResult]
        Results returned by the detector.
    outfile : pathlib.Path
        Destination file path (parent dirs created automatically).

    Returns
    -------
    pathlib.Path
        The same *outfile* path for convenience.
    """
    outfile.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "url",
        "parameter",
        "method",
        "payload",
        "detection_type",
        "confidence",
        "evidence",
        "timing_delta",
    ]

    with outfile.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for f in findings:
            writer.writerow(
                {
                    "url": f.url,
                    "parameter": f.parameter,
                    "method": f.method,
                    "payload": f.payload,
                    "detection_type": f.detection_type,
                    "confidence": f.confidence,
                    "evidence": f.evidence,
                    "timing_delta": f.timing_delta,
                }
            )

    return outfile
