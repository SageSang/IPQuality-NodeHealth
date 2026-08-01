from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml


DEFAULT_REGION_PATTERNS = {
    "hong-kong": [r"香港|港(?:[^A-Za-z]|$)|\bHK\b|Hong\s*Kong"],
    "taiwan": [r"台湾|臺灣|台北|臺北|台中|臺中|台南|臺南|高雄|\bTW\b|Taiwan|Taipei"],
    "japan": [r"日本|\bJP\b|Japan|Tokyo|Osaka"],
    "singapore": [r"新加坡|狮城|獅城|\bSG\b|Singapore"],
    "united-states": [r"美国|美國|\bUS\b|\bUSA\b|United\s*States|洛杉矶|洛杉磯|西雅图|纽约"],
    "south-korea": [r"韩国|韓國|\bKR\b|Korea|首尔|首爾"],
    "united-kingdom": [r"英国|英國|\bUK\b|Britain|United\s*Kingdom|London"],
    "germany": [r"德国|德國|\bDE\b|Germany|Frankfurt"],
    "france": [r"法国|法國|\bFR\b|France|Paris"],
    "canada": [r"加拿大|\bCA\b|Canada|Toronto"],
    "australia": [r"澳大利亚|澳大利亞|澳洲|\bAU\b|Australia|Sydney"],
}

DEFAULT_REGION_PORT_BASES = {
    "hong-kong": 62000,
    "taiwan": 62200,
    "japan": 62400,
    "singapore": 62600,
    "united-states": 62800,
    "south-korea": 63000,
    "united-kingdom": 63200,
    "germany": 63400,
    "france": 63600,
    "canada": 63800,
    "australia": 64000,
    "other": 64200,
}
DEFAULT_REGION_ORDER = list(DEFAULT_REGION_PORT_BASES)


@dataclass
class InventoryConfig:
    url: str
    timeout_seconds: float = 60.0
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class ProbeConfig:
    mihomo_binary: str = "/usr/local/bin/mihomo"
    controller_url: str = ""
    controller_listen: str = "0.0.0.0:9090"
    controller_secret: str = ""
    listener_host: str = "127.0.0.1"
    proxy_host: str = "127.0.0.1"
    ipquality_script: str = "/app/ip.sh"
    start_port: int = 20000
    startup_timeout_seconds: float = 20.0
    request_timeout_seconds: float = 12.0
    concurrency: int = 12
    full_concurrency: int = 2
    samples: int = 3
    ip_url: str = "https://api.ipify.org?format=json"
    geo_url_template: str = "https://ipapi.co/{ip}/json/"
    google_url: str = "https://www.gstatic.com/generate_204"
    chatgpt_url: str = "https://chatgpt.com/cdn-cgi/trace"


@dataclass
class PolicyConfig:
    stable_slots: int = 3
    full_audit_top_candidates: int = 10
    full_audit_max_age_hours: int = 48
    min_full_passes_high_confidence: int = 2
    minimum_publish_available_ratio: float = 0.2
    minimum_rebuild_full_completion_ratio: float = 0.8
    min_valid_risk_sources: int = 2
    dnsbl_redline_threshold: int = 3
    minimum_candidate_success_rate: float = 0.6666
    promotion_enabled: bool = True
    promotion_min_full_passes: int = 2
    promotion_score_margin: float = 12.0
    promotion_max_per_region_per_run: int = 1
    promotion_cooldown_days: int = 7
    expected_country: dict[str, str] = field(default_factory=dict)


@dataclass
class ScheduleConfig:
    enabled: bool = True
    time: str = "05:30"
    timezone: str = "Asia/Shanghai"
    default_mode: str = "maintenance"


@dataclass
class HttpConfig:
    host: str = "0.0.0.0"
    port: int = 8080
    api_token: str = ""


@dataclass
class ReportConfig:
    markdown: bool = True
    json: bool = True
    include_exit_ip: bool = True
    include_raw_details: bool = True
    retention_days: int = 180


@dataclass
class AuditConfig:
    enabled: bool = True
    allowed_origins: list[str] = field(default_factory=list)
    max_subscription_bytes: int = 10 * 1024 * 1024
    max_nodes: int = 500


@dataclass
class AppConfig:
    inventory: InventoryConfig
    data_dir: Path = Path("/app/data")
    reports_dir: Path = Path("/app/data/reports")
    region_patterns: dict[str, list[str]] = field(
        default_factory=lambda: {key: list(value) for key, value in DEFAULT_REGION_PATTERNS.items()}
    )
    region_port_bases: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_REGION_PORT_BASES))
    region_order: list[str] = field(default_factory=lambda: list(DEFAULT_REGION_ORDER))
    probe: ProbeConfig = field(default_factory=ProbeConfig)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    schedule: ScheduleConfig = field(default_factory=ScheduleConfig)
    http: HttpConfig = field(default_factory=HttpConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)


_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def _expand_env(value: Any) -> Any:
    if isinstance(value, str):
        def replace(match: re.Match[str]) -> str:
            name, default = match.group(1), match.group(2)
            if name in os.environ:
                return os.environ[name]
            if default is not None:
                return default
            raise ValueError(f"missing environment variable: {name}")

        return _ENV_PATTERN.sub(replace, value)
    if isinstance(value, list):
        return [_expand_env(item) for item in value]
    if isinstance(value, dict):
        return {key: _expand_env(item) for key, item in value.items()}
    return value


def load_config(path: str | os.PathLike[str]) -> AppConfig:
    config_path = Path(path)
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    raw = _expand_env(raw)
    if not isinstance(raw, dict) or not raw.get("inventory", {}).get("url"):
        raise ValueError("config.inventory.url is required")

    base = config_path.resolve().parent
    data_dir = Path(raw.get("data_dir", "/app/data"))
    reports_dir = Path(raw.get("reports_dir", str(data_dir / "reports")))
    if not data_dir.is_absolute():
        data_dir = base / data_dir
    if not reports_dir.is_absolute():
        reports_dir = base / reports_dir

    inventory_raw = raw["inventory"]
    patterns = raw.get("regions", DEFAULT_REGION_PATTERNS)
    if not isinstance(patterns, dict) or not all(isinstance(v, list) for v in patterns.values()):
        raise ValueError("config.regions must map region keys to regex lists")

    local_socks_raw = raw.get("local_socks", {})
    port_bases = local_socks_raw.get("port_bases", raw.get("region_port_bases", DEFAULT_REGION_PORT_BASES))
    region_order = local_socks_raw.get("region_order", raw.get("region_order", list(port_bases)))

    config = AppConfig(
        inventory=InventoryConfig(
            url=str(inventory_raw["url"]),
            timeout_seconds=float(inventory_raw.get("timeout_seconds", 60)),
            headers={str(k): str(v) for k, v in inventory_raw.get("headers", {}).items()},
        ),
        data_dir=data_dir,
        reports_dir=reports_dir,
        region_patterns={str(k): [str(p) for p in v] for k, v in patterns.items()},
        region_port_bases={str(k): int(v) for k, v in port_bases.items()},
        region_order=[str(value) for value in region_order],
        probe=ProbeConfig(**raw.get("probe", {})),
        policy=PolicyConfig(**raw.get("policy", {})),
        schedule=ScheduleConfig(**raw.get("schedule", {})),
        http=HttpConfig(**raw.get("http", {})),
        report=ReportConfig(**raw.get("report", {})),
        audit=AuditConfig(**raw.get("audit", {})),
    )
    _validate_config(config, local_socks_raw)
    return config


def _validate_config(config: AppConfig, local_socks_raw: dict[str, Any]) -> None:
    if config.policy.stable_slots != 3:
        raise ValueError("policy.stable_slots must be 3 for the Sub-Store/OpenWrt contract")
    if int(local_socks_raw.get("stable_slots", 3)) != 3:
        raise ValueError("local_socks.stable_slots must be 3")
    if int(local_socks_raw.get("dynamic_offset", 3)) != 3:
        raise ValueError("local_socks.dynamic_offset must be 3")
    if config.region_order != DEFAULT_REGION_ORDER:
        raise ValueError("local_socks.region_order must use the documented fixed region order")
    if config.region_port_bases != DEFAULT_REGION_PORT_BASES:
        raise ValueError("local_socks.port_bases must use the documented 62000-64200 plan")
    unsupported_regions = sorted(set(config.region_patterns) - set(config.region_port_bases))
    if unsupported_regions:
        raise ValueError(
            "regions contains keys outside the fixed local-socks port plan: "
            + ", ".join(unsupported_regions)
        )
    if not 0 < config.policy.minimum_publish_available_ratio <= 1:
        raise ValueError("policy.minimum_publish_available_ratio must be in (0, 1]")
    if not 0 < config.policy.minimum_rebuild_full_completion_ratio <= 1:
        raise ValueError("policy.minimum_rebuild_full_completion_ratio must be in (0, 1]")
    if config.policy.min_valid_risk_sources < 1:
        raise ValueError("policy.min_valid_risk_sources must be positive")
    if config.policy.dnsbl_redline_threshold < 2:
        raise ValueError("policy.dnsbl_redline_threshold must be at least 2")
    if not 0 < config.policy.minimum_candidate_success_rate <= 1:
        raise ValueError("policy.minimum_candidate_success_rate must be in (0, 1]")
    if config.policy.full_audit_max_age_hours <= 0:
        raise ValueError("policy.full_audit_max_age_hours must be positive")
    if config.probe.start_port < 1024 or config.probe.start_port > 65535:
        raise ValueError("probe.start_port must be in 1024..65535")
    if config.http.port < 1 or config.http.port > 65535:
        raise ValueError("http.port must be in 1..65535")
    if config.report.retention_days < 1:
        raise ValueError("report.retention_days must be positive")
    if config.audit.max_subscription_bytes < 1024:
        raise ValueError("audit.max_subscription_bytes must be at least 1024")
    if config.audit.max_nodes < 1:
        raise ValueError("audit.max_nodes must be positive")
    if not isinstance(config.audit.allowed_origins, list) or not all(
        isinstance(value, str) and value.strip() for value in config.audit.allowed_origins
    ):
        raise ValueError("audit.allowed_origins must be a list of non-empty URL origins")
    try:
        hour_text, minute_text = config.schedule.time.split(":", 1)
        hour, minute = int(hour_text), int(minute_text)
    except (AttributeError, TypeError, ValueError) as error:
        raise ValueError("schedule.time must be HH:MM") from error
    if (
        len(hour_text) != 2
        or len(minute_text) != 2
        or not 0 <= hour <= 23
        or not 0 <= minute <= 59
    ):
        raise ValueError("schedule.time must be HH:MM")
    if config.schedule.default_mode not in {"maintenance", "rebuild"}:
        raise ValueError("schedule.default_mode must be maintenance or rebuild")
    try:
        ZoneInfo(config.schedule.timezone)
    except (ZoneInfoNotFoundError, ValueError) as error:
        raise ValueError("schedule.timezone is invalid") from error
    loopback_hosts = {"127.0.0.1", "::1", "localhost"}
    if not config.http.api_token and config.http.host not in loopback_hosts:
        raise ValueError("http.api_token is required when the API listens beyond loopback")
    for region, expressions in config.region_patterns.items():
        for expression in expressions:
            try:
                re.compile(expression)
            except re.error as error:
                raise ValueError(f"invalid region regex for {region}: {expression}") from error
