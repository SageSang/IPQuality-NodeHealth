from __future__ import annotations

import hashlib
import re
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from .config import AppConfig


AUDIT_ID_PATTERN = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]{8}$")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


def _origin(value: str) -> str:
    parsed = urlsplit(value)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("subscription_url must be an absolute http or https URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("subscription_url must not contain user information")
    if parsed.fragment:
        raise ValueError("subscription_url must not contain a fragment")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError("subscription_url contains a control character")
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("subscription_url contains an invalid port") from error
    default_port = 80 if scheme == "http" else 443
    host = parsed.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    return f"{scheme}://{host}:{port or default_port}"


def validate_subscription_url(url: str, config: AppConfig) -> tuple[str, str]:
    value = str(url or "").strip()
    if not value or len(value) > 8192:
        raise ValueError("subscription_url is required and must be at most 8192 characters")
    origin = _origin(value)
    configured = config.audit.allowed_origins or [_origin(config.inventory.url)]
    allowed = {_origin(item) for item in configured}
    if origin not in allowed:
        raise ValueError("subscription_url origin is not allowed by audit.allowed_origins")
    return value, origin


def normalize_audit_name(value: str) -> str:
    name = " ".join(str(value or "subscription audit").split())
    if not name:
        name = "subscription audit"
    if len(name) > 120:
        raise ValueError("name must be at most 120 characters")
    return name


def new_audit_id(now: datetime | None = None) -> str:
    timestamp = now or datetime.now(timezone.utc)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]


def validate_audit_id(value: str) -> str:
    audit_id = str(value or "")
    if not AUDIT_ID_PATTERN.fullmatch(audit_id):
        raise ValueError("invalid audit id")
    return audit_id


def audit_day_parts(audit_id: str) -> tuple[str, str, str]:
    value = validate_audit_id(audit_id)
    return value[0:4], value[4:6], value[6:8]


def source_fingerprint(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


def download_subscription(url: str, timeout: float, max_bytes: int) -> bytes:
    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/yaml,text/yaml,text/plain,application/octet-stream",
            "Cache-Control": "no-cache",
            "User-Agent": "IPQuality-node-health/0.2",
        },
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            declared = response.headers.get("Content-Length")
            if declared:
                try:
                    if int(declared) > max_bytes:
                        raise ValueError("subscription exceeds audit.max_subscription_bytes")
                except ValueError as error:
                    if "exceeds" in str(error):
                        raise
            payload = response.read(max_bytes + 1)
    except urllib.error.HTTPError as error:
        if 300 <= error.code < 400:
            raise RuntimeError("subscription download redirect was refused") from error
        raise RuntimeError(f"subscription download failed with HTTP {error.code}") from error
    except urllib.error.URLError as error:
        raise RuntimeError("subscription download failed") from error
    if len(payload) > max_bytes:
        raise ValueError("subscription exceeds audit.max_subscription_bytes")
    if not payload:
        raise ValueError("subscription is empty")
    return payload

