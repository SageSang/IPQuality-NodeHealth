from __future__ import annotations

import json
import re
import subprocess
import urllib.error
import uuid
from dataclasses import dataclass, field
from typing import Any

import yaml


ERROR_CODES = frozenset({
    "internal_error", "inventory_invalid_yaml", "invalid_json", "invalid_input",
    "download_failed", "download_timeout", "worker_start_failed",
    "storage_failed", "storage_access_denied", "legacy_error_detail_hidden",
    "provider_http_error", "provider_rate_limited", "provider_denied",
    "provider_invalid_response", "provider_backoff", "provider_budget_exhausted",
    "probe_timeout", "probe_failed", "full_audit_failed", "full_audit_incomplete",
    "egress_mismatch", "mapping_unavailable", "report_unavailable",
    "scan_failed", "audit_failed", "audit_interrupted", "unsafe_first_run",
    "evidence_version_unsupported",
})
PHASES = frozenset({
    "queued", "downloading", "quick-scan", "waiting-retry", "rechecking",
    "full-scan", "publishing", "writing-report", "report", "startup",
    "completed", "failed", "interrupted", "unknown",
})
_SAFE_TEXT = re.compile(r"^([a-z_]+) \[diagnostic:([0-9a-f]{24})\]$")


@dataclass(frozen=True)
class SafeFailure:
    code: str
    phase: str
    diagnostic_id: str = field(default_factory=lambda: uuid.uuid4().hex[:24])
    line: int | None = None
    column: int | None = None
    retryable: bool = False

    def __post_init__(self) -> None:
        if self.code not in ERROR_CODES:
            object.__setattr__(self, "code", "internal_error")
        if self.phase not in PHASES:
            object.__setattr__(self, "phase", "unknown")
        if not re.fullmatch(r"[0-9a-f]{24}", self.diagnostic_id):
            object.__setattr__(self, "diagnostic_id", uuid.uuid4().hex[:24])

    def __str__(self) -> str:
        return f"{self.code} [diagnostic:{self.diagnostic_id}]"

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "safe_error_schema": 1,
            "code": self.code,
            "phase": self.phase,
            "diagnostic_id": self.diagnostic_id,
            "retryable": self.retryable,
        }
        for name in ("line", "column"):
            value = getattr(self, name)
            if isinstance(value, int) and not isinstance(value, bool) and 0 < value <= 2**31:
                result[name] = value
        return result


def safe_failure(
    error: BaseException | None,
    phase: str,
    *,
    code: str | None = None,
) -> SafeFailure:
    """Classify failures without formatting source-bearing exception objects."""
    line = column = None
    retryable = False
    inferred = "internal_error"
    if isinstance(error, yaml.MarkedYAMLError):
        inferred = "inventory_invalid_yaml"
        mark = error.problem_mark or error.context_mark
        if mark is not None:
            line, column = mark.line + 1, mark.column + 1
    elif isinstance(error, json.JSONDecodeError):
        inferred = "invalid_json"
        line, column = error.lineno, error.colno
    elif isinstance(error, (TimeoutError, subprocess.TimeoutExpired)):
        inferred = "download_timeout" if phase == "downloading" else "probe_timeout"
        retryable = True
    elif isinstance(error, urllib.error.HTTPError):
        inferred = "provider_rate_limited" if error.code == 429 else "download_failed"
        retryable = error.code == 429 or 500 <= error.code <= 599
    elif isinstance(error, urllib.error.URLError):
        inferred, retryable = "download_failed", True
    elif isinstance(error, PermissionError):
        inferred = "storage_access_denied"
    elif isinstance(error, OSError):
        inferred, retryable = "storage_failed", True
    elif isinstance(error, (TypeError, ValueError)):
        inferred = "invalid_input"
    return SafeFailure(code or inferred, phase, line=line, column=column, retryable=retryable)


def safe_error_text(
    error: BaseException | None,
    phase: str,
    *,
    code: str | None = None,
) -> str:
    return str(safe_failure(error, phase, code=code))


def safe_error_value(value: Any, phase: str = "report") -> Any:
    if value is None or value == "":
        return value
    if isinstance(value, SafeFailure):
        return value.to_dict()
    if isinstance(value, list):
        return [safe_error_value(item, phase) for item in value]
    if isinstance(value, str):
        match = _SAFE_TEXT.fullmatch(value)
        if match and match.group(1) in ERROR_CODES:
            return value
    if isinstance(value, dict) and value.get("safe_error_schema") == 1:
        return SafeFailure(
            code=str(value.get("code", "internal_error")),
            phase=str(value.get("phase", phase)),
            diagnostic_id=str(value.get("diagnostic_id", "")),
            line=value.get("line"),
            column=value.get("column"),
            retryable=value.get("retryable") is True,
        ).to_dict()
    return "legacy_error_detail_hidden"


def sanitize_error_fields(value: Any, phase: str = "report") -> Any:
    """Project legacy records safely without rewriting immutable source files."""
    if isinstance(value, list):
        return [sanitize_error_fields(item, phase) for item in value]
    if not isinstance(value, dict):
        return value
    output: dict[Any, Any] = {}
    for key, item in value.items():
        name = str(key).lower()
        is_error = name in {"error", "errors", "error_detail", "last_error_detail"} or name.endswith(("_error", "_errors"))
        output[key] = safe_error_value(item, phase) if is_error else sanitize_error_fields(item, phase)
    return output
