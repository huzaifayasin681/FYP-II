"""
scanner.detector
~~~~~~~~~~~~~~~~

Light-weight yet *production-ready* SQL-Injection detection engine.

Detection techniques implemented
--------------------------------
1. **Error-based**   ― regex signatures for MySQL, MSSQL, Oracle, Postgres, SQLite.
2. **Time-based blind**   ― compare RTT vs baseline (configurable threshold).
3. **Boolean-based blind**   ― diff response bodies for significant change.
4. **UNION-based**   ― look for successful UNION clause echo (configurable marker).
5. **Heuristic scoring**   ― combines evidence to assign confidence (0-100).

The engine is *stateless* between requests; the caller (``scanner.core``) provides
the baseline/variant responses and the payload used.  This keeps the API simple
and unit-test friendly.

Public API
~~~~~~~~~~
* :class:`Detector`
* :data:`DetectionResult`

Other modules only need to call::

    detector = Detector(config)
    result = detector.analyse(baseline_response, test_response, payload, param)

If *result* is ``None`` no significant SQLi evidence was found.
"""
from __future__ import annotations

import difflib
import re
import statistics
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from scanner.requester import HTTPResponse

__all__ = ["DetectionResult", "Detector"]


# ────────────────────────────────────────────────────────────────────────────
# Dataclass Holding a Finding
# ────────────────────────────────────────────────────────────────────────────
@dataclass(slots=True)
class DetectionResult:
    url: str
    parameter: str
    method: str
    payload: str
    detection_type: str  # "error", "time", "boolean", "union"
    confidence: int  # 0-100
    evidence: str  # Short human-readable snippet (error string, diff size, etc.)
    timing_delta: float  # seconds (0 for non-time-based)


# ────────────────────────────────────────────────────────────────────────────
# Engine
# ────────────────────────────────────────────────────────────────────────────
class Detector:
    """
    SQLi detection heuristics.

    Parameters
    ----------
    config : dict
        Global scanner configuration (thresholds, enabled techniques…).
    """

    # ------------------------------------------------------------------ #
    # Pre-compiled error signatures by backend
    # ------------------------------------------------------------------ #
    _ERROR_PATTERNS: Dict[str, List[re.Pattern]] = {
        "MySQL": [
            re.compile(r"you have an error in your sql syntax", re.I),
            re.compile(r"warning: mysql", re.I),
            re.compile(r"unknown column '[^']+' in 'field list'", re.I),
        ],
        "PostgreSQL": [
            re.compile(r"pg_query\(\): query failed:", re.I),
            re.compile(r"pg_exec\(\): query failed:", re.I),
            re.compile(r"syntax error at or near", re.I),
        ],
        "MSSQL": [
            re.compile(r"unclosed quotation mark after the character string", re.I),
            re.compile(r"microsoft sql server odbc", re.I),
            re.compile(r"\[sql server\]", re.I),
        ],
        "Oracle": [
            re.compile(r"ora-\d{5}", re.I),
            re.compile(r"oracle error", re.I),
            re.compile(r"quoted string not properly terminated", re.I),
        ],
        "SQLite": [
            re.compile(r"sqlite.*syntax error", re.I),
            re.compile(r"unrecognized token:", re.I),
            re.compile(r"sqlite error", re.I),
        ],
    }

    def __init__(self, config: Dict) -> None:  # noqa: D401
        self.cfg = config
        self.enable_error = config.get("detection", {}).get("error_based", True)
        self.enable_time = config.get("detection", {}).get("time_based", True)
        self.enable_boolean = config.get("detection", {}).get("boolean_based", True)
        self.enable_union = config.get("detection", {}).get("union_based", True)

        self.time_threshold = float(config.get("time_threshold", 5.0))
        self.boolean_diff_threshold = float(config.get("boolean_threshold", 0.3))
        # Marker injected in UNION payloads to detect echoed UNION results.
        self.union_marker = config.get("union_marker", "SQLISCANNERUNIONTEST")

    # ------------------------------------------------------------------ #
    # Public ­API
    # ------------------------------------------------------------------ #
    def analyse(
        self,
        baseline: HTTPResponse,
        variant: HTTPResponse,
        payload: str,
        parameter: str,
    ) -> Optional[DetectionResult]:
        """
        Compare *variant* response against *baseline* for SQLi evidence.

        Returns ``DetectionResult`` or ``None``.
        """
        detectors = (
            self._detect_error_based,
            self._detect_time_based,
            self._detect_boolean_based,
            self._detect_union_based,
        )

        for fn in detectors:
            result = fn(baseline, variant, payload, parameter)
            if result:
                return result  # first positive is enough

        return None

    # ------------------------------------------------------------------ #
    # Individual detection techniques
    # ------------------------------------------------------------------ #
    # 1) Error-based
    def _detect_error_based(
        self,
        baseline: HTTPResponse,
        variant: HTTPResponse,
        payload: str,
        param: str,
    ) -> Optional[DetectionResult]:
        if not self.enable_error or not variant.text:
            return None

        for backend, patterns in self._ERROR_PATTERNS.items():
            for pat in patterns:
                if pat.search(variant.text) and not pat.search(baseline.text):
                    confidence = 90
                    evidence = f"{backend} error: {pat.pattern[:40]}..."
                    return DetectionResult(
                        url=variant.url,
                        parameter=param,
                        method=variant.method,
                        payload=payload,
                        detection_type="error",
                        confidence=confidence,
                        evidence=evidence,
                        timing_delta=0.0,
                    )
        return None

    # 2) Time-based blind
    def _detect_time_based(
        self,
        baseline: HTTPResponse,
        variant: HTTPResponse,
        payload: str,
        param: str,
    ) -> Optional[DetectionResult]:
        if not self.enable_time:
            return None

        delta = variant.elapsed - baseline.elapsed
        if delta > self.time_threshold and variant.status_code:
            confidence = min(100, int(70 + (delta - self.time_threshold) * 10))
            evidence = f"RTT Δ = {delta:.1f}s (> {self.time_threshold}s)"
            return DetectionResult(
                url=variant.url,
                parameter=param,
                method=variant.method,
                payload=payload,
                detection_type="time",
                confidence=confidence,
                evidence=evidence,
                timing_delta=delta,
            )
        return None

    # 3) Boolean-based blind
    def _detect_boolean_based(
        self,
        baseline: HTTPResponse,
        variant: HTTPResponse,
        payload: str,
        param: str,
    ) -> Optional[DetectionResult]:
        if not self.enable_boolean or not baseline.text or not variant.text:
            return None

        ratio = difflib.SequenceMatcher(None, baseline.text, variant.text).quick_ratio()
        diff_score = 1.0 - ratio  # larger = more difference
        if diff_score >= self.boolean_diff_threshold:
            confidence = int(60 + diff_score * 40)  # 60-100
            evidence = f"Diff score {diff_score:.2f} (thr {self.boolean_diff_threshold})"
            return DetectionResult(
                url=variant.url,
                parameter=param,
                method=variant.method,
                payload=payload,
                detection_type="boolean",
                confidence=confidence,
                evidence=evidence,
                timing_delta=0.0,
            )
        return None

    # 4) UNION-based
    def _detect_union_based(
        self,
        baseline: HTTPResponse,
        variant: HTTPResponse,
        payload: str,
        param: str,
    ) -> Optional[DetectionResult]:
        if not self.enable_union or self.union_marker not in payload:
            return None

        if self.union_marker in variant.text and self.union_marker not in baseline.text:
            evidence = f"Marker '{self.union_marker}' echoed in response."
            return DetectionResult(
                url=variant.url,
                parameter=param,
                method=variant.method,
                payload=payload,
                detection_type="union",
                confidence=95,
                evidence=evidence,
                timing_delta=0.0,
            )
        return None
