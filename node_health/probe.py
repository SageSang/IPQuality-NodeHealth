from __future__ import annotations

import contextlib
import ipaddress
import json
import os
import re
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

import yaml

from .config import AppConfig
from .models import ClaudeResult, FullResult, Node, QuickResult

BUNDLED_DNSBL_FILE = "/app/ref/dnsbl.list"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def generate_mihomo_probe_config(
    nodes: list[Node], start_port: int = 20000, listener_host: str = "127.0.0.1"
) -> tuple[dict[str, Any], dict[str, int]]:
    if start_port < 1024 or start_port + len(nodes) > 65535:
        raise ValueError("probe port range is outside 1024..65535")
    proxies: list[dict[str, Any]] = []
    listeners: list[dict[str, Any]] = []
    ports: dict[str, int] = {}
    names = [node.name for node in nodes]
    duplicates = sorted(name for name, count in Counter(names).items() if count > 1)
    if duplicates:
        raise ValueError(
            "inventory contains duplicate proxy names; normalize them in Sub-Store before probing: "
            + ", ".join(duplicates[:10])
        )
    for index, node in enumerate(nodes):
        probe_name = node.name
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
                stdout=subprocess.PIPE,
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
                output = process.stdout.read() if process.stdout else ""
                raise RuntimeError(f"mihomo exited before readiness: {output[-1000:]}")
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

    def _get(
        self, port: int, url: str, timeout_seconds: float | None = None
    ) -> tuple[str, float]:
        timeout = timeout_seconds or self.config.probe.request_timeout_seconds
        started = time.monotonic()
        result = subprocess.run(
            [
                "curl",
                "--silent",
                "--show-error",
                "--location",
                "--fail-with-body",
                "--proxy",
                f"http://{self.config.probe.proxy_host}:{port}",
                "--connect-timeout",
                str(timeout),
                "--max-time",
                str(timeout),
                url,
            ],
            capture_output=True,
            text=True,
            timeout=timeout + 3,
            check=False,
        )
        elapsed_ms = (time.monotonic() - started) * 1000
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or f"curl exited {result.returncode}")
        return result.stdout, elapsed_ms

    def _reachable(self, port: int, url: str) -> bool:
        try:
            self._get(port, url)
            return True
        except (OSError, RuntimeError, subprocess.TimeoutExpired):
            return False

    def _direct_get(self, url: str, timeout_seconds: float) -> str:
        result = subprocess.run(
            [
                "curl",
                "--silent",
                "--show-error",
                "--location",
                "--fail-with-body",
                "--connect-timeout",
                str(timeout_seconds),
                "--max-time",
                str(timeout_seconds),
                url,
            ],
            capture_output=True,
            text=True,
            timeout=timeout_seconds + 3,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or f"curl exited {result.returncode}")
        return result.stdout

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
        for url in direct_urls:
            try:
                self._direct_get(url, timeout)
                direct[url] = True
            except Exception as error:
                direct[url] = False
                errors.append(f"direct {url}: {error}")

        official_status: dict[str, str] = {}
        try:
            response = json.loads(self._direct_get(status_url, timeout))
            status = response.get("status") if isinstance(response, dict) else None
            if isinstance(status, dict):
                official_status = {
                    "indicator": str(status.get("indicator") or ""),
                    "description": str(status.get("description") or ""),
                }
            else:
                raise ValueError("official status response has no status object")
        except Exception as error:
            errors.append(f"official status: {error}")
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
            body, _ = self._get(
                port,
                _provider_url(
                    self.config.probe.claude_ipinfo_url_template,
                    exit_ip,
                    "token",
                    self.config.probe.claude_ipinfo_token,
                ),
                self.config.probe.claude_timeout_seconds,
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
                if present:
                    ipinfo_factors[factor] = _as_bool(value)
            anonymous_present, anonymous = _first_present(data, ("is_anonymous",))
            if anonymous_present and _as_bool(anonymous) and not any(
                ipinfo_factors.get(name) for name in ("proxy", "vpn", "tor")
            ):
                ipinfo_factors["proxy"] = True
            hosting_present, hosting = _first_present(data, ("is_hosting",))
            privacy_hosting_present, privacy_hosting = _first_present(
                privacy, ("hosting", "is_hosting")
            )
            if hosting_present or privacy_hosting_present or asn.get("type") is not None:
                ipinfo_factors["server"] = bool(
                    _as_bool(hosting)
                    or _as_bool(privacy_hosting)
                    or str(asn.get("type") or "").strip().lower() == "hosting"
                )
            for factor, active in ipinfo_factors.items():
                payload["factors"].setdefault(factor, {})["IPinfo"] = active
            if ipinfo_factors or anonymous_present:
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
            payload["errors"].append(f"ipinfo: {error}")

        try:
            body, _ = self._get(
                port,
                _provider_url(
                    self.config.probe.claude_ipapi_url_template,
                    exit_ip,
                    "key",
                    self.config.probe.claude_ipapi_key,
                ),
                self.config.probe.claude_timeout_seconds,
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
                if field_name in response:
                    ipapi_factors[factor] = _as_bool(response.get(field_name))
            for factor, active in ipapi_factors.items():
                payload["factors"].setdefault(factor, {})["ipapi"] = active
            score = company.get("abuser_score")
            label_match = re.search(r"\(([^)]+)\)", str(score or ""))
            if label_match:
                label = " ".join(label_match.group(1).strip().lower().split())
                if label in {"very low", "low", "medium", "moderate", "elevated", "high", "very high", "critical"}:
                    payload["risk_sources"]["ipapi"] = label
            if "ipapi" not in payload["risk_sources"]:
                number_match = re.match(r"\s*([0-9]+(?:\.[0-9]+)?)", str(score or ""))
                if number_match:
                    numeric = float(number_match.group(1))
                    if 0 <= numeric <= 1:
                        numeric *= 100
                    if 0 <= numeric <= 100:
                        payload["risk_sources"]["ipapi"] = f"{numeric:.2f}"
            if "ipapi" not in payload["risk_sources"]:
                if ipapi_factors:
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
            payload["errors"].append(f"ipapi: {error}")

        payload["complete"] = risk_providers == {"IPinfo", "ipapi"}
        return payload

    def _check_claude(self, port: int, generic_exit_ip: str) -> ClaudeResult:
        checked_at = utc_now()
        errors: list[str] = []
        trace_ok = False
        anthropic_ok = False
        exit_ip = ""
        country = ""
        uncertain_failure = False
        try:
            body, _ = self._get(
                port,
                self.config.probe.claude_trace_url,
                self.config.probe.claude_timeout_seconds,
            )
            trace = _parse_cloudflare_trace(body)
            candidate_ip = str(trace.get("ip") or "").strip()
            address = ipaddress.ip_address(candidate_ip)
            if not address.is_global:
                raise ValueError("Claude trace egress IP is not public")
            exit_ip = str(address)
            country = str(trace.get("loc") or "").upper()
            trace_ok = True
        except Exception as error:
            uncertain_failure = uncertain_failure or _is_uncertain_probe_error(error)
            errors.append(f"claude.ai: {error}")
        try:
            self._get(
                port,
                self.config.probe.anthropic_trace_url,
                self.config.probe.claude_timeout_seconds,
            )
            anthropic_ok = True
        except Exception as error:
            uncertain_failure = uncertain_failure or _is_uncertain_probe_error(error)
            errors.append(f"anthropic.com: {error}")

        supported = (
            country in set(self.config.probe.claude_supported_countries)
            if country
            else None
        )
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
        elif uncertain_failure:
            status = "unknown"
        elif errors:
            status = "unreachable"
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
        )

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
            except Exception as error:  # result records the bounded external failure
                failures.append(str(error))
        if not ips:
            return QuickResult(available=False, checked_at=checked_at, error="; ".join(failures)[:1000])

        exit_ip = ips[0]
        country = ""
        asn = ""
        try:
            body, _ = self._get(port, self.config.probe.geo_url_template.format(ip=exit_ip))
            geo = json.loads(body)
            country = str(geo.get("country_code") or geo.get("country") or "").upper()
            asn = str(geo.get("asn") or geo.get("org") or "")
        except Exception as error:
            failures.append(f"geo: {error}")

        claude = self._check_claude(port, exit_ip)
        return QuickResult(
            available=True,
            exit_ip=exit_ip,
            country=country,
            asn=asn,
            latency_ms=round(sum(latencies) / len(latencies), 2),
            success_rate=round(len(ips) / max(1, self.config.probe.samples), 4),
            exit_ip_stable=len(set(ips)) == 1,
            google_ok=self._reachable(port, self.config.probe.google_url),
            chatgpt_ok=self._reachable(port, self.config.probe.chatgpt_url),
            claude=claude,
            checked_at=checked_at,
            error="; ".join(failures)[:1000],
        )


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value or "").strip().lower() in {"1", "true", "yes", "y", "on"}


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
    values: dict[str, str] = {}
    for line in body.splitlines():
        key, separator, value = line.partition("=")
        if separator and key.strip():
            values[key.strip()] = value.strip()
    if not values:
        raise ValueError("response is not a Cloudflare trace")
    return values


def _is_uncertain_probe_error(error: Exception) -> bool:
    if isinstance(error, subprocess.TimeoutExpired):
        return True
    message = str(error).strip().lower()
    if any(token in message for token in ("timeout", "timed out", "curl exited 28")):
        return True
    return bool(
        re.search(r"(?:http(?: status| error)?\s*)?429\b", message)
        or re.search(r"(?:http(?: status| error)?\s*)?5\d\d\b", message)
    )


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
                    "IPQUALITY_SKIP_MAIL": "1",
                    "IPQUALITY_DNSBL_FILE": BUNDLED_DNSBL_FILE,
                },
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            return FullResult(completed=False, checked_at=checked_at, error=str(error))
        details = _extract_json(result.stdout)
        if details is None:
            suffix = (result.stderr or result.stdout)[-1800:]
            exit_note = f" (exit {result.returncode})" if result.returncode else ""
            return FullResult(
                completed=False,
                checked_at=checked_at,
                error=(f"IPQuality returned no JSON{exit_note}: {suffix}").strip(),
            )
        normalized = normalize_ipquality(details, checked_at)
        # ip.sh can emit valid IPv4 JSON and still exit 1 because its final
        # disabled-IPv6 condition is false. The JSON is the authoritative
        # completion signal. The bundled script also ends with an explicit
        # success exit, but accepting valid JSON keeps older images compatible.
        return normalized


def _extract_json(output: str) -> dict[str, Any] | None:
    decoder = json.JSONDecoder()
    for offset, char in enumerate(output):
        if char != "{":
            continue
        try:
            value, _ = decoder.raw_decode(output[offset:])
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    return None


def normalize_ipquality(details: dict[str, Any], checked_at: str = "") -> FullResult:
    risk_sources: dict[str, str] = {}
    source = details.get("Score") or details.get("risk_sources") or details.get("risk") or {}
    if isinstance(source, dict):
        for key, value in source.items():
            if isinstance(value, dict):
                value = value.get("level") or value.get("risk") or value.get("score")
            risk_sources[str(key)] = str(value).lower()
    labels = list(details.get("labels")) if isinstance(details.get("labels"), list) else []
    factor = details.get("Factor") if isinstance(details.get("Factor"), dict) else {}
    tor_value = factor.get("Tor", details.get("tor") or details.get("is_tor"))
    if isinstance(tor_value, dict):
        tor = any(bool(value) for value in tor_value.values())
    elif isinstance(tor_value, list):
        tor = any(bool(value) for value in tor_value)
    else:
        tor = bool(tor_value)
    for label in ("Proxy", "VPN", "Server", "Abuser", "Robot"):
        value = factor.get(label)
        active = any(bool(item) for item in value.values()) if isinstance(value, dict) else bool(value)
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
    try:
        audited_exit_ip = str(ipaddress.ip_address(audited_exit_ip))
    except ValueError:
        audited_exit_ip = ""
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
            except Exception as error:
                if result_kind == "full":
                    results[node.key] = FullResult(completed=False, checked_at=utc_now(), error=str(error))
                else:
                    results[node.key] = QuickResult(available=False, checked_at=utc_now(), error=str(error))
            completed += 1
            if progress_callback is not None:
                progress_callback(completed, total)
    return results
