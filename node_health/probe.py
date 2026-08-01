from __future__ import annotations

import contextlib
import ipaddress
import json
import os
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from collections import Counter
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

import yaml

from .config import AppConfig
from .models import FullResult, Node, QuickResult

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

    def _get(self, port: int, url: str) -> tuple[str, float]:
        started = time.monotonic()
        result = subprocess.run(
            [
                "curl",
                "--silent",
                "--show-error",
                "--location",
                "--proxy",
                f"http://{self.config.probe.proxy_host}:{port}",
                "--connect-timeout",
                str(self.config.probe.request_timeout_seconds),
                "--max-time",
                str(self.config.probe.request_timeout_seconds),
                url,
            ],
            capture_output=True,
            text=True,
            timeout=self.config.probe.request_timeout_seconds + 3,
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
            checked_at=checked_at,
            error="; ".join(failures)[:1000],
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
) -> dict[str, QuickResult | FullResult]:
    if result_kind not in {"quick", "full"}:
        raise ValueError("result_kind must be quick or full")
    results: dict[str, QuickResult | FullResult] = {}
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
    return results
