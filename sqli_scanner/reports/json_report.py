"""
reports.json_report
~~~~~~~~~~~~~~~~~~~

Tiny helper around :pyfunc:`json.dump` that adds a consistent
metadata envelope and ISO-8601 timestamps.

The scanner’s core module can simply do::

    from sqli_scanner.reports.json_report import write_json_report

    write_json_report(findings, Path("reports/scan-2025-07-01.json"),
                      scanner_config=cfg,
                      target_count=len(pages_scanned))
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from scanner.detector import DetectionResult


# --------------------------------------------------------------------------- #
# Serialisation helpers
# --------------------------------------------------------------------------- #
def _finding_to_dict(f: DetectionResult) -> Dict[str, Any]:
    """Convert dataclass → plain dict (avoids dataclasses.asdict recursion)."""
    return {
        "url": f.url,
        "parameter": f.parameter,
        "method": f.method,
        "payload": f.payload,
        "detection_type": f.detection_type,
        "confidence": f.confidence,
        "evidence": f.evidence,
        "timing_delta": f.timing_delta,
    }


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def write_json_report(
    findings: List[DetectionResult],
    outfile: Path,
    **meta: Any,
) -> Path:
    """
    Serialize *findings* to **outfile** in UTF-8 JSON.  Extra keyword
    arguments are stored under ``"meta"`` for provenance.

    Returns the :class:`Path` of the written report.
    """
    data: Dict[str, Any] = {
        "generated_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "total_findings": len(findings),
        "findings": [_finding_to_dict(f) for f in findings],
        "meta": meta or {},
    }

    outfile.parent.mkdir(parents=True, exist_ok=True)
    outfile.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return outfile
