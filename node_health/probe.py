from __future__ import annotations

import contextlib
import hashlib
import ipaddress
import json
import math
import os
import re
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import Counter
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Protocol

import yaml

from .config import AppConfig
from .errors import safe_error_text
from .models import ClaudeResult, FullResult, Node, QuickResult, SiteProbeResult
from .policy import PROBE_CONTRACT_VERSION, RISK_EVIDENCE_VERSION

BUNDLED_DNSBL_FILE = "/app/ref/dnsbl.list"


@dataclass(frozen=True)
class HTTPResult:
    transport_code: int
    http_status: int
    elapsed_ms: float
    body: str = ""
    host: str = ""
    retry_after: float | None = None
    error_code: str = ""


class ProbeFailure(RuntimeError):
    def __init__(self, code: str, response: HTTPResult | None = None):
        self.code = code
        self.response = response
        super().__init__(safe_error_text(None, "quick-scan", code=code))


def _retry_after_seconds(value: str, now: datetime | None = None) -> float | None:
    try:
        seconds = float(value)
        return seconds if math.isfinite(seconds) and seconds >= 0 else None
    except (ValueError, TypeError):
        try:
            deadline = parsedate_to_datetime(value)
            if deadline.tzinfo is None:
                deadline = deadline.replace(tzinfo=timezone.utc)
            return max(0.0, (deadline - (now or datetime.now(timezone.utc))).total_seconds())
        except (ValueError, TypeError, OverflowError):
            return None


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def generate_mihomo_probe_config(
    nodes: list[Node], start_port: int = 20000, listener_host: str = "127.0.0.1"
) -> tuple[dict[str, Any], dict[str, int]]:
    if start_port < 1024 or start_port > 65535 or (nodes and start_port + len(nodes) - 1 > 65535):
        raise ValueError("probe port range is outside 1024..65535")
    proxies: list[dict[str, Any]] = []
    listeners: list[dict[str, Any]] = []
    ports: dict[str, int] = {}
    names = [node.name for node in nodes]
    duplicates = {name for name, count in Counter(names).items() if count > 1}
    if any(node.proxy.get("dialer-proxy") in duplicates for node in nodes):
        raise ValueError("ambiguous proxy dependency")
    assigned_names = set(names) - duplicates
    probe_names = {}
    for node in sorted(nodes, key=lambda item: item.key):
        candidate = node.name
        if candidate in duplicates:
            candidate = f"nh-probe-{node.key}"
            while candidate in assigned_names:
                candidate += "-alias"
        assigned_names.add(candidate)
        probe_names[node.key] = candidate
    for index, node in enumerate(nodes):
        probe_name = probe_names[node.key]
        proxy = {key: value for key, value in node.proxy.items() if not str(key).startswith("_")}
        proxy["name"] = probe_name
        port = start_port + index
        proxies.append(proxy)
        listeners.append(
            {
                "name": f"listener-{index:05d}",
                "type": "mixed",
                "listen": listener_host,
                "port": port,
                "proxy": probe_name,
            }
        )
        ports[node.key] = port
    config = {
        "mode": "rule",
        "log-level": "warning",
        "ipv6": False,
        "proxies": proxies,
        "listeners": listeners,
        "rules": ["MATCH,DIRECT"],
    }
    return config, ports


def preserve_sidecar_controller(
    probe_config: dict[str, Any], controller_listen: str, controller_secret: str
) -> dict[str, Any]:
    probe_config.update(
        {
            "allow-lan": True,
            "bind-address": "*",
            "external-controller": controller_listen,
            "secret": controller_secret,
        }
    )
    return probe_config


class ProbeEnvironment(Protocol):
    @contextlib.contextmanager
    def open(self, nodes: list[Node]) -> Iterator[dict[str, int]]: ...


class MihomoProbeEnvironment:
    def __init__(self, config: AppConfig):
        self.config = config

    @contextlib.contextmanager
    def open(self, nodes: list[Node]) -> Iterator[dict[str, int]]:
        probe_config, ports = generate_mihomo_probe_config(
            nodes,
            self.config.probe.start_port,
            self.config.probe.listener_host,
        )
        if self.config.probe.controller_url:
            preserve_sidecar_controller(
                probe_config,
                self.config.probe.controller_listen,
                self.config.probe.controller_secret,
            )
            yield from self._open_sidecar(probe_config, ports)
            return
        with tempfile.TemporaryDirectory(prefix="node-health-") as temp_dir:
            temp_path = Path(temp_dir)
            config_path = temp_path / "probe.yaml"
            config_path.write_text(
                yaml.safe_dump(probe_config, allow_unicode=True, sort_keys=False),
                encoding="utf-8",
            )
            process = subprocess.Popen(
                [self.config.probe.mihomo_binary, "-d", str(temp_path), "-f", str(config_path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT,
                text=True,
            )
            try:
                self._wait_ready(process, next(iter(ports.values())))
                yield ports
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)

    def _open_sidecar(
        self, probe_config: dict[str, Any], ports: dict[str, int]
    ) -> Iterator[dict[str, int]]:
        payload = yaml.safe_dump(probe_config, allow_unicode=True, sort_keys=False)
        body = json.dumps({"payload": payload}).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.config.probe.controller_secret:
            headers["Authorization"] = f"Bearer {self.config.probe.controller_secret}"
        request = urllib.request.Request(
            self.config.probe.controller_url.rstrip("/") + "/configs?force=true",
            data=body,
            headers=headers,
            method="PUT",
        )
        try:
            with urllib.request.urlopen(
                request, timeout=self.config.probe.startup_timeout_seconds
            ):
                pass
        except urllib.error.HTTPError as error:
            raise RuntimeError(
                f"mihomo controller rejected config: HTTP {error.code}"
            ) from error
        self._wait_port(next(iter(ports.values())))
        yield ports

    def _wait_port(self, port: int) -> None:
        deadline = time.monotonic() + self.config.probe.startup_timeout_seconds
        while time.monotonic() < deadline:
            with socket.socket() as client:
                client.settimeout(0.2)
                if client.connect_ex((self.config.probe.proxy_host, port)) == 0:
                    return
            time.sleep(0.1)
        raise TimeoutError("mihomo sidecar did not expose the first probe listener in time")

    def _wait_ready(self, process: subprocess.Popen[str], port: int) -> None:
        deadline = time.monotonic() + self.config.probe.startup_timeout_seconds
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(safe_error_text(None, "quick-scan", code="probe_failed"))
            with socket.socket() as client:
                client.settimeout(0.2)
                if client.connect_ex(("127.0.0.1", port)) == 0:
                    return
            time.sleep(0.1)
        raise TimeoutError("mihomo did not expose the first probe listener in time")


class QuickProbe(Protocol):
    def check(self, node: Node, port: int) -> QuickResult: ...


class FullAuditor(Protocol):
    def check(self, node: Node, port: int) -> FullResult: ...


class CurlQuickProbe:
    def __init__(self, config: AppConfig):
        self.config = config
        self._provider_lock = threading.Lock()
        self._provider_locks: dict[str, threading.Lock] = {}
        self._provider_cache: dict[str, tuple[float, str, float]] = {}
        self._provider_backoff: dict[tuple[str, ...], tuple[float, str]] = {}
        self._provider_counts: dict[str, Counter] = {}
        self._provider_budget: dict[str, int] = {}
        self._provider_failures: dict[str, list[tuple[float, int, str]]] = {}
        self._diagnostic_retries: Counter[str] = Counter()
        self._planned_routes: set[int] | None = None

    def begin_scan(self, request_routes: list[int] | None = None) -> None:
        # Evidence may be shared for one IP within a scan, but never promoted
        # into another day's fresh evidence just because it was cached.
        with self._provider_lock:
            self._provider_cache.clear()
            self._provider_counts.clear()
            self._provider_failures.clear()
            self._diagnostic_retries.clear()
            self._planned_routes = set(request_routes) if request_routes is not None else None
            self._provider_budget.clear()
            # Listener ports are reassigned between scans; only account and
            # provider cooldowns have a meaning beyond this route allocation.
            self._provider_backoff = {
                key: value for key, value in self._provider_backoff.items()
                if key[0] != "route"
            }
            if request_routes is not None:
                for template in (
                    self.config.probe.geo_url_template,
                    self.config.probe.claude_ipinfo_url_template,
                    self.config.probe.claude_ipapi_url_template,
                ):
                    source = urllib.parse.urlsplit(template).hostname or "unknown"
                    self._provider_budget[source] = min(
                        self.config.probe.provider_max_requests_per_scan,
                        self._provider_budget.get(source, 0) + len(self._planned_routes),
                    )

    def diagnostics(self) -> dict[str, Any]:
        with self._provider_lock:
            return {source: dict(counts) for source, counts in self._provider_counts.items()}

    def _provider_get(
        self, port: int, url: str, timeout_seconds: float | None = None,
        *, resource_kind: str = "geo", target_ip: str = "",
    ) -> tuple[str, float]:
        source = urllib.parse.urlsplit(url).hostname or "unknown"
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        credentials = {name: query[name] for name in ("key", "token", "api_key") if name in query}
        auth = hashlib.sha256(json.dumps(credentials, sort_keys=True).encode()).hexdigest()
        authenticated = any(any(value for value in values) for values in credentials.values())
        cache_key = json.dumps((source, auth, resource_kind, target_ip or url, RISK_EVIDENCE_VERSION))
        scopes = [("provider", source), ("account", source, auth), ("route", source, auth, str(port))]
        with self._provider_lock:
            lock = self._provider_locks.setdefault(source, threading.Lock())
        # Serialize each provider to avoid a quota burst, and coalesce lookups
        # for the same explicit target IP. Reachability probes are never cached.
        with lock:
            now = time.monotonic()
            with self._provider_lock:
                counts = self._provider_counts.setdefault(source, Counter())
                cached = self._provider_cache.get(cache_key)
                if cached and cached[0] > now:
                    counts["cache_hits"] += 1
                    return cached[1], cached[2]
                active = [self._provider_backoff[key] for key in scopes if key in self._provider_backoff]
                if any(until > now for until, _ in active):
                    counts["backoff_skips"] += 1
                    raise ProbeFailure("provider_backoff")
                budget = self._provider_budget.get(source, 0 if self._planned_routes is not None else self.config.probe.provider_max_requests_per_scan)
                if (self._planned_routes is not None and port not in self._planned_routes) or counts["requests"] >= budget:
                    counts["budget_skips"] += 1
                    raise ProbeFailure("provider_budget_exhausted")
                half_open = bool(active)
                if half_open:
                    if self._diagnostic_retries[source] >= 2:
                        counts["diagnostic_budget_skips"] += 1
                        raise ProbeFailure("provider_budget_exhausted")
                    self._diagnostic_retries[source] += 1
                    counts["half_open_requests"] += 1
                counts["requests"] += 1
            try:
                response = self._http_get(port, url, timeout_seconds)
                body, elapsed = response.body, response.elapsed_ms
                if response.transport_code or response.error_code or not 200 <= response.http_status < 300:
                    code = (
                        "provider_rate_limited" if response.http_status == 429
                        else "provider_denied" if response.http_status in {401, 403}
                        else "probe_timeout" if response.transport_code == 28
                        else "provider_http_error" if response.http_status
                        else "probe_failed"
                    )
                    raise ProbeFailure(code, response)
                payload = json.loads(body)
                if not isinstance(payload, dict) or payload.get("error"):
                    raise ProbeFailure("provider_invalid_response", response)
            except Exception as error:
                failure = error if isinstance(error, ProbeFailure) else ProbeFailure("provider_invalid_response")
                response = failure.response
                code = failure.code
                with self._provider_lock:
                    counts[code] += 1
                    now = time.monotonic()
                    status = response.http_status if response else 0
                    retry_after = response.retry_after if response else None
                    account_error = False
                    if authenticated and response:
                        try:
                            error_payload = json.loads(response.body)
                            marker = error_payload.get("error", {}) if isinstance(error_payload, dict) else {}
                            marker = marker.get("code", "") if isinstance(marker, dict) else marker
                            account_error = str(marker).lower() in {
                                "invalid_api_key", "invalid_token", "invalid_authentication",
                                "quota_exceeded", "insufficient_quota", "account_limit_exceeded",
                            }
                        except (ValueError, TypeError):
                            pass
                    if account_error:
                        self._provider_backoff[scopes[1]] = (now + (retry_after if retry_after is not None else 300), code)
                    else:
                        delay = 300 if status == 403 else 60
                        self._provider_backoff[scopes[2]] = (now + (retry_after if retry_after is not None else delay), code)
                        failures = [(stamp, route, kind) for stamp, route, kind in self._provider_failures.get(source, []) if now - stamp <= 60]
                        failures.append((now, port, code))
                        self._provider_failures[source] = failures
                        if len({route for _, route, kind in failures if kind == code}) >= 2 or half_open:
                            self._provider_backoff[scopes[0]] = (now + max(60, retry_after or 0), code)
                raise failure from None
            with self._provider_lock:
                # Bound memory even for repeated independent audit jobs.
                if len(self._provider_cache) >= 4096:
                    self._provider_cache.pop(next(iter(self._provider_cache)))
                if _provider_payload_cacheable(payload, resource_kind):
                    self._provider_cache[cache_key] = (time.monotonic() + 3600, body, elapsed)
                else:
                    counts["partial_responses"] += 1
                for scope in scopes:
                    self._provider_backoff.pop(scope, None)
                self._provider_failures.pop(source, None)
                counts["successes"] += 1
            return body, elapsed

    def _get(
        self, port: int, url: str, timeout_seconds: float | None = None
    ) -> tuple[str, float]:
        response = self._http_get(port, url, timeout_seconds)
        if response.transport_code or response.error_code or not 200 <= response.http_status < 300:
            raise ProbeFailure("probe_timeout" if response.transport_code == 28 else "probe_failed", response)
        return response.body, response.elapsed_ms

    def _http_get(self, port: int | None, url: str, timeout_seconds: float | None = None) -> HTTPResult:
        timeout = timeout_seconds or self.config.probe.request_timeout_seconds
        started = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="node-health-http-") as directory:
            body_path = Path(directory) / "body"
            headers_path = Path(directory) / "headers"
            command = ["curl", "--silent", "--show-error", "--location", "--max-redirs", "3",
                       "--connect-timeout", str(timeout), "--max-time", str(timeout),
                       "--max-filesize", str(self.config.probe.max_response_bytes),
                       "--output", str(body_path), "--dump-header", str(headers_path),
                       "--write-out", "%{http_code}\n%{url_effective}"]
            if port is not None:
                command.extend(["--proxy", f"http://{self.config.probe.proxy_host}:{port}"])
            command.append(url)
            try:
                result = subprocess.run(command, capture_output=True, text=True, timeout=timeout + 3, check=False)
                metadata = result.stdout.splitlines()
                status = int(metadata[0]) if metadata and metadata[0].isdigit() else 0
                host = urllib.parse.urlsplit(metadata[1]).hostname or "" if len(metadata) > 1 else ""
                body = ""
                error_code = ""
                if body_path.exists():
                    with body_path.open("rb") as stream:
                        raw = stream.read(self.config.probe.max_response_bytes + 1)
                    if len(raw) > self.config.probe.max_response_bytes:
                        error_code = "provider_invalid_response"
                    else:
                        body = raw.decode("utf-8", errors="replace")
                retry_after = None
                if headers_path.exists():
                    with headers_path.open("r", encoding="utf-8", errors="replace") as stream:
                        headers = stream.read(65536)
                    final_headers = re.split(r"\r?\n\r?\n", headers.strip())[-1]
                    for line in final_headers.splitlines():
                        key, _, value = line.partition(":")
                        if key.lower() == "retry-after":
                            retry_after = _retry_after_seconds(value.strip())
                return HTTPResult(result.returncode, status, (time.monotonic() - started) * 1000, body, host, retry_after, error_code)
            except subprocess.TimeoutExpired:
                return HTTPResult(28, 0, (time.monotonic() - started) * 1000, error_code="probe_timeout")
            except (OSError, ValueError):
                return HTTPResult(1, 0, (time.monotonic() - started) * 1000, error_code="probe_failed")

    def _reachable(self, port: int, url: str) -> bool:
        try:
            self._get(port, url)
            return True
        except (OSError, RuntimeError, subprocess.TimeoutExpired):
            return False

    def _direct_get(self, url: str, timeout_seconds: float) -> str:
        response = self._http_get(None, url, timeout_seconds)
        if response.transport_code or response.error_code or response.http_status != 200:
            raise ProbeFailure("probe_failed", response)
        return response.body

    def diagnose_ai_service(self, service: str) -> dict[str, Any]:
        """Collect non-ranking diagnostics after a fleet-wide AI failure."""
        timeout = min(8.0, self.config.probe.claude_timeout_seconds)
        if service == "chatgpt":
            direct_urls = [self.config.probe.chatgpt_url]
            status_url = "https://status.openai.com/api/v2/status.json"
        elif service == "claude":
            direct_urls = [
                self.config.probe.claude_trace_url,
                self.config.probe.anthropic_trace_url,
            ]
            status_url = "https://status.anthropic.com/api/v2/status.json"
        else:
            raise ValueError(f"unsupported AI service: {service}")

        direct: dict[str, bool] = {}
        errors: list[str] = []
        for index, url in enumerate(direct_urls):
            try:
                self._direct_get(url, timeout)
                direct[f"endpoint-{index + 1}"] = True
            except Exception:
                direct[f"endpoint-{index + 1}"] = False
                errors.append(safe_error_text(None, "quick-scan", code="probe_failed"))

        official_status: dict[str, str] = {}
        try:
            response = json.loads(self._direct_get(status_url, timeout))
            status = response.get("status") if isinstance(response, dict) else None
            if isinstance(status, dict):
                official_status = {
                    "indicator": str(status.get("indicator")) if status.get("indicator") in {"none", "minor", "major", "critical"} else "unknown",
                }
            else:
                raise ValueError("official status response has no status object")
        except Exception:
            errors.append(safe_error_text(None, "quick-scan", code="probe_failed"))
        return {
            "direct": direct,
            "official_status": official_status,
            "diagnostic_only": True,
            "errors": errors,
        }

    def _claude_risk_intelligence(self, port: int, exit_ip: str) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "asn": "",
            "organization": "",
            "risk_sources": {},
            "factors": {},
            "residential": "unknown",
            "complete": False,
            "errors": [],
        }
        risk_providers: set[str] = set()

        try:
            body, _ = self._provider_get(
                port,
                _provider_url(
                    self.config.probe.claude_ipinfo_url_template,
                    exit_ip,
                    "token",
                    self.config.probe.claude_ipinfo_token,
                ),
                self.config.probe.claude_timeout_seconds,
                resource_kind="ipinfo-risk", target_ip=exit_ip,
            )
            response = json.loads(body)
            data = response.get("data") if isinstance(response, dict) else None
            if not isinstance(data, dict) and isinstance(response, dict):
                data = response
            if not isinstance(data, dict):
                raise ValueError("IPinfo response is not an object")
            asn_value = data.get("as") or data.get("asn")
            asn = asn_value if isinstance(asn_value, dict) else {}
            company = data.get("company") if isinstance(data.get("company"), dict) else {}
            privacy_value = data.get("privacy") or data.get("anonymous")
            privacy = privacy_value if isinstance(privacy_value, dict) else {}
            payload["asn"] = str(
                asn.get("asn")
                or (asn_value if isinstance(asn_value, str) else "")
                or ""
            )
            payload["organization"] = str(asn.get("name") or company.get("name") or "")
            ipinfo_factors: dict[str, bool] = {}
            for factor, keys in {
                "proxy": ("proxy", "is_proxy", "relay", "is_relay"),
                "vpn": ("vpn", "is_vpn"),
                "tor": ("tor", "is_tor"),
            }.items():
                present, value = _first_present(privacy, keys)
                values = [_risk_bool(privacy[key]) for key in keys if key in privacy]
                if any(value is True for value in values):
                    ipinfo_factors[factor] = True
                elif values and all(value is False for value in values):
                    ipinfo_factors[factor] = False
            anonymous_present, anonymous = _first_present(data, ("is_anonymous",))
            if anonymous_present and _risk_bool(anonymous) is True and not any(
                ipinfo_factors.get(name) for name in ("proxy", "vpn", "tor")
            ):
                ipinfo_factors["proxy"] = True
            hosting_present, hosting = _first_present(data, ("is_hosting",))
            privacy_hosting_present, privacy_hosting = _first_present(
                privacy, ("hosting", "is_hosting")
            )
            hosting_values = [_risk_bool(value) for present, value in ((hosting_present, hosting), (privacy_hosting_present, privacy_hosting)) if present]
            usage_type = str(asn.get("type") or "").strip().lower()
            if any(value is True for value in hosting_values) or usage_type == "hosting":
                ipinfo_factors["server"] = True
            elif hosting_values and all(value is False for value in hosting_values):
                ipinfo_factors["server"] = False
            elif not hosting_values and usage_type in {"isp", "business", "education", "government", "banking"}:
                ipinfo_factors["server"] = False
            for factor, active in ipinfo_factors.items():
                payload["factors"].setdefault(factor, {})["IPinfo"] = active
            ipinfo_core = {"proxy", "vpn", "tor", "server"}
            if any(ipinfo_factors.values()) or ipinfo_core <= ipinfo_factors.keys():
                payload["risk_sources"]["IPinfo-privacy"] = (
                    "high" if any(ipinfo_factors.values()) else "low"
                )
                risk_providers.add("IPinfo")
            usage = str(asn.get("type") or "").strip().lower()
            company_type = str(company.get("type") or "").strip().lower()
            if usage == "isp" and company_type != "hosting" and not ipinfo_factors.get("server", False):
                payload["residential"] = "probable"
            geo = data.get("geo") if isinstance(data.get("geo"), dict) else {}
            payload["country"] = str(
                geo.get("country_code") or data.get("country_code") or ""
            ).upper()
        except Exception as error:
            payload["errors"].append(safe_error_text(None, "quick-scan", code=error.code if isinstance(error, ProbeFailure) else "provider_invalid_response"))

        try:
            body, _ = self._provider_get(
                port,
                _provider_url(
                    self.config.probe.claude_ipapi_url_template,
                    exit_ip,
                    "key",
                    self.config.probe.claude_ipapi_key,
                ),
                self.config.probe.claude_timeout_seconds,
                resource_kind="ipapi-risk", target_ip=exit_ip,
            )
            response = json.loads(body)
            if not isinstance(response, dict):
                raise ValueError("ipapi response is not an object")
            if response.get("error"):
                raise ValueError(str(response["error"]))
            asn = response.get("asn") if isinstance(response.get("asn"), dict) else {}
            company = response.get("company") if isinstance(response.get("company"), dict) else {}
            location = response.get("location") if isinstance(response.get("location"), dict) else {}
            flat_asn = str(response.get("asn_num") or "").strip()
            if flat_asn and not flat_asn.upper().startswith("AS"):
                flat_asn = "AS" + flat_asn
            payload["asn"] = payload["asn"] or str(asn.get("asn") or flat_asn)
            payload["organization"] = payload["organization"] or str(
                company.get("name")
                or response.get("company_name")
                or response.get("asn_org")
                or ""
            )
            ipapi_factors: dict[str, bool] = {}
            for factor, field_name in {
                "proxy": "is_proxy",
                "vpn": "is_vpn",
                "tor": "is_tor",
                "server": "is_datacenter",
                "abuser": "is_abuser",
                "robot": "is_crawler",
            }.items():
                value = _risk_bool(response.get(field_name))
                if value is not None:
                    ipapi_factors[factor] = value
            for factor, active in ipapi_factors.items():
                payload["factors"].setdefault(factor, {})["ipapi"] = active
            score = _ipapi_score(company.get("abuser_score"))
            if score is not None:
                payload["risk_sources"]["ipapi"] = score
            if "ipapi" not in payload["risk_sources"]:
                if any(ipapi_factors.values()) or {"proxy", "vpn", "tor", "server", "abuser"} <= ipapi_factors.keys():
                    payload["risk_sources"]["ipapi-flags"] = (
                        "high" if any(ipapi_factors.values()) else "low"
                    )
            if "ipapi" in payload["risk_sources"] or "ipapi-flags" in payload["risk_sources"]:
                risk_providers.add("ipapi")
            usage = str(asn.get("type") or "").strip().lower()
            company_type = str(company.get("type") or "").strip().lower()
            if (
                usage == "isp"
                and company_type != "hosting"
                and not ipapi_factors.get("server", False)
                and payload["residential"] == "probable"
            ):
                payload["residential"] = "confirmed"
            payload["country"] = str(
                location.get("country_code")
                or response.get("cc")
                or payload.get("country")
                or ""
            ).upper()
        except Exception as error:
            payload["errors"].append(safe_error_text(None, "quick-scan", code=error.code if isinstance(error, ProbeFailure) else "provider_invalid_response"))

        payload["complete"] = risk_providers == {"IPinfo", "ipapi"}
        return payload

    def _check_claude(self, port: int, generic_exit_ip: str) -> ClaudeResult:
        checked_at = utc_now()
        errors: list[str] = []
        site = self._check_site(port, self.config.probe.claude_trace_url, set(self.config.probe.claude_supported_countries))
        secondary = self._check_site(port, self.config.probe.anthropic_trace_url, None)
        trace_ok = site.result_class in {"available", "restricted"}
        anthropic_ok = secondary.result_class == "available"
        exit_ip, country = site.exit_ip, site.country
        supported = site.result_class == "available" if trace_ok else None
        errors.extend(safe_error_text(None, "quick-scan", code=value.error_code) for value in (site, secondary) if value.error_code)
        intelligence: dict[str, Any] = {}
        if trace_ok and exit_ip != generic_exit_ip:
            intelligence = self._claude_risk_intelligence(port, exit_ip)
            errors.extend(str(value) for value in intelligence.get("errors", []))

        if trace_ok and supported is False:
            status = "restricted"
        elif trace_ok and anthropic_ok and supported is True:
            status = "available"
        elif trace_ok or anthropic_ok:
            status = "degraded"
        else:
            status = "unknown"
        return ClaudeResult(
            status=status,
            trace_ok=trace_ok,
            anthropic_ok=anthropic_ok,
            exit_ip=exit_ip,
            country=country,
            intelligence_country=str(intelligence.get("country") or "").upper(),
            supported=supported,
            asn=str(intelligence.get("asn") or ""),
            organization=str(intelligence.get("organization") or ""),
            risk_sources=dict(intelligence.get("risk_sources") or {}),
            factors=dict(intelligence.get("factors") or {}),
            residential=str(intelligence.get("residential") or "unknown"),
            intelligence_complete=bool(intelligence.get("complete")),
            checked_at=checked_at,
            error="; ".join(errors)[:1000],
            site_probe=site,
            anthropic_probe=secondary,
            risk_evidence_version=RISK_EVIDENCE_VERSION,
        )

    def _check_site(self, port: int, url: str, supported_countries: set[str] | None) -> SiteProbeResult:
        response = self._http_get(port, url, self.config.probe.claude_timeout_seconds)
        result = SiteProbeResult(
            attempted=True, probe_contract_version=PROBE_CONTRACT_VERSION,
            observation_id=uuid.uuid4().hex, checked_at=utc_now(),
            http_status=response.http_status, transport_code=response.transport_code,
        )
        expected_host = urllib.parse.urlsplit(url).hostname or ""
        if response.transport_code or response.error_code or response.http_status != 200:
            result.error_code = "probe_timeout" if response.transport_code == 28 else "probe_failed"
            return result
        try:
            trace = _parse_cloudflare_trace(response.body)
            address = ipaddress.ip_address(trace.get("ip", ""))
            country = trace.get("loc", "")
            if not address.is_global or not re.fullmatch(r"[A-Z]{2}", country):
                raise ValueError
            if trace.get("h", "").lower() != expected_host.lower() or response.host.lower() != expected_host.lower():
                raise ValueError
            result.exit_ip, result.country, result.host = str(address), country, expected_host.lower()
            result.result_class = "available" if supported_countries is None or country in supported_countries else "restricted"
        except (ValueError, TypeError):
            result.error_code = "provider_invalid_response"
        return result

    def check(self, node: Node, port: int) -> QuickResult:
        checked_at = utc_now()
        ips: list[str] = []
        latencies: list[float] = []
        failures: list[str] = []
        for _ in range(max(1, self.config.probe.samples)):
            try:
                body, latency = self._get(port, self.config.probe.ip_url)
                parsed = json.loads(body)
                ip = str(parsed.get("ip", "")).strip()
                address = ipaddress.ip_address(ip)
                if not address.is_global:
                    raise ValueError("egress IP is not public")
                ips.append(ip)
                latencies.append(latency)
            except Exception:
                failures.append(safe_error_text(None, "quick-scan", code="probe_failed"))
        if not ips:
            return QuickResult(available=False, checked_at=checked_at, sample_count=max(1, self.config.probe.samples), error="; ".join(failures)[:1000])

        exit_ip = ips[0]
        country = ""
        asn = ""
        try:
            body, _ = self._provider_get(port, self.config.probe.geo_url_template.format(ip=exit_ip), resource_kind="geo", target_ip=exit_ip)
            geo = json.loads(body)
            country = str(geo.get("country_code") or geo.get("country") or "").upper()
            if not re.fullmatch(r"[A-Z]{2}", country):
                country = ""
            asn = str(geo.get("asn") or geo.get("org") or "")
        except Exception as error:
            failures.append(safe_error_text(None, "quick-scan", code=error.code if isinstance(error, ProbeFailure) else "provider_invalid_response"))

        claude = self._check_claude(port, exit_ip)
        chatgpt = self._check_site(port, self.config.probe.chatgpt_url, set(self.config.probe.chatgpt_supported_countries))
        return QuickResult(
            available=True,
            exit_ip=exit_ip,
            country=country,
            asn=asn,
            latency_ms=round(sum(latencies) / len(latencies), 2),
            success_rate=round(len(ips) / max(1, self.config.probe.samples), 4),
            exit_ip_stable=len(set(ips)) == 1,
            google_ok=self._reachable(port, self.config.probe.google_url),
            chatgpt_ok=True if chatgpt.result_class == "available" else False if chatgpt.result_class == "restricted" else None,
            claude=claude,
            checked_at=checked_at,
            error="; ".join(failures)[:1000],
            chatgpt=chatgpt,
            success_count=len(ips),
            sample_count=max(1, self.config.probe.samples),
        )


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _risk_bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _ipapi_score(value: Any) -> str | None:
    if isinstance(value, bool) or value is None:
        return None
    match = re.fullmatch(r"\s*([0-9]+(?:\.[0-9]+)?)\s*(?:\((Very Low|Low|Elevated|Medium|High|Very High)\))?\s*", str(value), re.IGNORECASE)
    if match is None:
        return None
    number = float(match.group(1))
    if not math.isfinite(number) or not 0 <= number <= 1:
        return None
    return match.group(2).lower() if match.group(2) else f"{number * 100:.2f}"


def _provider_payload_cacheable(payload: dict[str, Any], resource_kind: str) -> bool:
    if resource_kind == "geo":
        return bool(re.fullmatch(r"[A-Z]{2}", str(payload.get("country_code") or payload.get("country") or "").upper()))
    if resource_kind == "ipapi-risk":
        company = payload.get("company") if isinstance(payload.get("company"), dict) else {}
        fields = ("is_proxy", "is_vpn", "is_tor", "is_datacenter", "is_abuser")
        values = [_risk_bool(payload.get(key)) for key in fields]
        return _ipapi_score(company.get("abuser_score")) is not None or any(value is True for value in values) or all(value is False for value in values)
    if resource_kind == "ipinfo-risk":
        data = payload.get("data") if isinstance(payload.get("data"), dict) else payload
        privacy = data.get("privacy") or data.get("anonymous")
        privacy = privacy if isinstance(privacy, dict) else {}
        values = [_risk_bool(privacy.get(key)) for key in ("proxy", "vpn", "tor", "hosting")]
        return any(value is True for value in values) or all(value is False for value in values)
    return False


def _first_present(mapping: dict[str, Any], keys: tuple[str, ...]) -> tuple[bool, Any]:
    for key in keys:
        if key in mapping:
            return True, mapping.get(key)
    return False, None


def _provider_url(
    template: str,
    exit_ip: str,
    credential_name: str,
    credential: str,
) -> str:
    url = template.format(
        ip=exit_ip,
        token=credential if credential_name == "token" else "",
        key=credential if credential_name == "key" else "",
    )
    if not credential:
        return url
    parsed = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    if not any(key == credential_name for key, _ in query):
        query.append((credential_name, credential))
    return urllib.parse.urlunsplit(
        parsed._replace(query=urllib.parse.urlencode(query))
    )


def _parse_cloudflare_trace(body: str) -> dict[str, str]:
    if "<" in body or len(body) > 16384:
        raise ValueError("invalid trace")
    values: dict[str, str] = {}
    for line in body.splitlines():
        key, separator, value = line.partition("=")
        if separator and key.strip():
            if key.strip() in values:
                raise ValueError("duplicate trace field")
            values[key.strip()] = value.strip()
    if not all(values.get(key) for key in ("ip", "loc", "h")):
        raise ValueError("response is not a Cloudflare trace")
    return values


class IPQualityAuditor:
    def __init__(self, config: AppConfig):
        self.config = config

    def check(self, node: Node, port: int) -> FullResult:
        checked_at = utc_now()
        command = [
            "bash",
            self.config.probe.ipquality_script,
            "-4",
            "-E",
            "-x",
            f"socks5h://{self.config.probe.proxy_host}:{port}",
            "-j",
            "-p",
            "-n",
            "-f",
        ]
        with tempfile.TemporaryDirectory(prefix="ipquality-audit-") as directory:
            checkpoint = Path(directory) / "partial.json"
            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=max(120, self.config.probe.request_timeout_seconds * 20),
                    check=False,
                    env={
                        **os.environ,
                        "IPQUALITY_AUTOMATION": "1",
                        "IPQUALITY_CHECKPOINT_FILE": str(checkpoint),
                        "IPQUALITY_REQUEST_TIMEOUT": str(self.config.probe.request_timeout_seconds),
                        "IPQUALITY_SKIP_MAIL": "1",
                        "IPQUALITY_SKIP_AI": "1",
                        "IPQUALITY_DNSBL_FILE": BUNDLED_DNSBL_FILE,
                    },
                )
            except (OSError, subprocess.TimeoutExpired):
                return _partial_full_result(checkpoint, checked_at)
            details = _extract_json(result.stdout)
            automation = details.get("Automation") if isinstance(details, dict) else None
            if result.returncode or details is None or (isinstance(automation, dict) and automation.get("complete") is not True):
                return _partial_full_result(checkpoint, checked_at, details)
            return normalize_ipquality(details, checked_at)


def _partial_full_result(checkpoint: Path, checked_at: str, fallback: dict[str, Any] | None = None) -> FullResult:
    partial = None
    try:
        partial = _extract_json(checkpoint.read_text(encoding="utf-8"))
    except (OSError, UnicodeError):
        pass
    partial = partial or fallback
    saved = normalize_ipquality(partial, checked_at) if partial else FullResult(completed=False, checked_at=checked_at)
    saved.completed = False
    saved.error = safe_error_text(None, "full-scan", code="full_audit_incomplete")
    return saved


def _extract_json(output: str) -> dict[str, Any] | None:
    decoder = json.JSONDecoder()
    for offset, char in enumerate(output):
        if char != "{":
            continue
        try:
            value, _ = decoder.raw_decode(output[offset:])
        except json.JSONDecodeError:
            continue
        if (
            isinstance(value, dict)
            and isinstance(value.get("Head"), dict)
            and value["Head"].get("IP")
            and isinstance(value.get("Score"), dict)
        ):
            return value
    return None


def normalize_ipquality(details: dict[str, Any], checked_at: str = "") -> FullResult:
    risk_sources: dict[str, str] = {}
    source = details["Score"] if isinstance(details.get("Score"), dict) else details.get("risk_sources") or details.get("risk") or {}
    if isinstance(source, dict):
        for key, value in source.items():
            if isinstance(value, dict):
                value = value.get("level") or value.get("risk") or value.get("score")
            risk_sources[str(key)] = str(value).lower()
    labels = list(details.get("labels")) if isinstance(details.get("labels"), list) else []
    factor = details.get("Factor") if isinstance(details.get("Factor"), dict) else {}
    tor_value = factor.get("Tor", details.get("tor") or details.get("is_tor"))
    if isinstance(tor_value, dict):
        tor = any(value is True for value in tor_value.values())
    elif isinstance(tor_value, list):
        tor = any(value is True for value in tor_value)
    else:
        tor = tor_value is True
    for label in ("Proxy", "VPN", "Server", "Abuser", "Robot"):
        value = factor.get(label)
        active = any(item is True for item in value.values()) if isinstance(value, dict) else value is True
        if active and label.lower() not in {item.lower() for item in labels}:
            labels.append(label.lower())
    mail = details.get("Mail") if isinstance(details.get("Mail"), dict) else {}
    dns = mail.get("DNSBlacklist") if isinstance(mail.get("DNSBlacklist"), dict) else {}
    blacklisted = dns.get("Blacklisted", details.get("dnsbl_blacklisted") or details.get("dnsbl") or 0)
    try:
        dnsbl_listed_count = max(0, int(float(blacklisted)))
    except (TypeError, ValueError):
        dnsbl_listed_count = (
            1
            if str(blacklisted).strip().lower()
            in {"true", "yes", "listed", "blacklisted"}
            else 0
        )
    dnsbl = dnsbl_listed_count > 0
    head = details.get("Head") if isinstance(details.get("Head"), dict) else {}
    audited_exit_ip = str(head.get("IP") or details.get("ip") or "").strip()
    public_egress = False
    try:
        address = ipaddress.ip_address(audited_exit_ip)
        audited_exit_ip = str(address)
        public_egress = address.is_global
    except ValueError:
        audited_exit_ip = ""
    media = details.get("Media") if isinstance(details.get("Media"), dict) else {}
    chatgpt_data = media.get("ChatGPT") if isinstance(media.get("ChatGPT"), dict) else {}
    observation = SiteProbeResult.from_dict(chatgpt_data.get("Probe"))
    return FullResult(
        completed=True,
        audited_exit_ip=audited_exit_ip,
        tor=tor,
        dnsbl_blacklisted=dnsbl,
        dnsbl_listed_count=dnsbl_listed_count,
        risk_sources=risk_sources,
        labels=[str(item) for item in labels],
        details=details,
        checked_at=checked_at or utc_now(),
        risk_evidence_version=RISK_EVIDENCE_VERSION if public_egress and isinstance(details.get("Score"), dict) and isinstance(details.get("Factor"), dict) else 0,
        chatgpt=observation,
        chatgpt_evidence_version=observation.probe_contract_version,
    )


def run_parallel(
    nodes: list[Node],
    ports: dict[str, int],
    checker: QuickProbe | FullAuditor,
    concurrency: int,
    result_kind: str,
    progress_callback: Callable[[int, int], None] | None = None,
) -> dict[str, QuickResult | FullResult]:
    if result_kind not in {"quick", "full"}:
        raise ValueError("result_kind must be quick or full")
    results: dict[str, QuickResult | FullResult] = {}
    completed = 0
    total = len(nodes)
    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as executor:
        futures = {executor.submit(checker.check, node, ports[node.key]): node for node in nodes}
        for future in as_completed(futures):
            node = futures[future]
            try:
                results[node.key] = future.result()
            except Exception:
                if result_kind == "full":
                    results[node.key] = FullResult(completed=False, checked_at=utc_now(), error=safe_error_text(None, "full-scan", code="full_audit_failed"))
                else:
                    results[node.key] = QuickResult(available=False, checked_at=utc_now(), error=safe_error_text(None, "quick-scan", code="probe_failed"))
            completed += 1
            if progress_callback is not None:
                progress_callback(completed, total)
    return results
