from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class NodeAlias:
    entry_id: str
    name: str
    source_id: str = ""
    original_name: str = ""
    normalized_name: str = ""
    logical_id: str = ""
    declared_region: str = "other"
    duplicate_ordinal: int = 1

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Node:
    key: str
    name: str
    region: str
    proxy: dict[str, Any] = field(repr=False, compare=False)
    source_id: str = ""
    original_name: str = ""
    normalized_name: str = ""
    logical_id: str = ""
    aliases: tuple[NodeAlias, ...] = ()
    representative_alias_id: str = ""
    region_conflict: bool = False

    @property
    def effective_region(self) -> str:
        return self.region


@dataclass
class SiteProbeResult:
    attempted: bool = False
    result_class: str = "unknown"
    probe_scope: str = "site-region"
    probe_contract_version: int = 0
    observation_id: str = ""
    exit_ip: str = ""
    country: str = ""
    host: str = ""
    checked_at: str = ""
    http_status: int = 0
    transport_code: int = 0
    error_code: str = ""

    @classmethod
    def from_dict(cls, value: Any) -> SiteProbeResult:
        if isinstance(value, cls):
            return value
        if not isinstance(value, dict):
            return cls()
        fields = cls.__dataclass_fields__
        clean = {key: item for key, item in value.items() if key in fields}
        for name in ("probe_contract_version", "http_status", "transport_code"):
            try:
                clean[name] = int(clean.get(name, 0))
            except (TypeError, ValueError, OverflowError):
                clean[name] = 0
        clean["attempted"] = clean.get("attempted") is True
        for name in fields:
            if name not in {"attempted", "probe_contract_version", "http_status", "transport_code"} and name in clean:
                clean[name] = clean[name] if isinstance(clean[name], str) else ""
        if clean.get("result_class") not in {"available", "restricted", "unknown"}:
            clean["result_class"] = "unknown"
        return cls(**clean)


@dataclass
class ClaudeResult:
    status: str = "unknown"
    trace_ok: bool = False
    anthropic_ok: bool = False
    exit_ip: str = ""
    country: str = ""
    intelligence_country: str = ""
    supported: bool | None = None
    asn: str = ""
    organization: str = ""
    risk_sources: dict[str, str] = field(default_factory=dict)
    factors: dict[str, dict[str, bool]] = field(default_factory=dict)
    residential: str = "unknown"
    route_stable: bool = True
    intelligence_complete: bool = False
    intelligence_cached: bool = False
    service_outage: bool = False
    checked_at: str = ""
    error: str = ""
    site_probe: SiteProbeResult = field(default_factory=SiteProbeResult)
    anthropic_probe: SiteProbeResult = field(default_factory=SiteProbeResult)
    risk_evidence_version: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class QuickResult:
    available: bool
    exit_ip: str = ""
    country: str = ""
    asn: str = ""
    latency_ms: float | None = None
    success_rate: float = 0.0
    exit_ip_stable: bool = True
    google_ok: bool | None = None
    chatgpt_ok: bool | None = None
    claude: ClaudeResult = field(default_factory=ClaudeResult)
    transient_recovery: bool = False
    retry_count: int = 0
    chatgpt_service_outage: bool = False
    checked_at: str = ""
    error: str = ""
    chatgpt: SiteProbeResult = field(default_factory=SiteProbeResult)
    success_count: int = 0
    sample_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FullResult:
    completed: bool
    audited_exit_ip: str = ""
    tor: bool = False
    dnsbl_blacklisted: bool = False
    dnsbl_listed_count: int = 0
    risk_sources: dict[str, str] = field(default_factory=dict)
    labels: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    checked_at: str = ""
    error: str = ""
    chatgpt: SiteProbeResult = field(default_factory=SiteProbeResult)
    risk_evidence_version: int = 0
    chatgpt_evidence_version: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Evaluation:
    decision: str
    score: float
    confidence: str
    reasons: list[str] = field(default_factory=list)
    components: dict[str, float] = field(default_factory=dict)
    ai_grade: str = "B"
    risk_grade: str = "B"
    overall_grade: str = "B"
    residential_grade: str = "unknown"
    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def eligible(self) -> bool:
        return self.decision == "eligible"

    @property
    def redline(self) -> bool:
        return self.decision == "rejected"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class NodeAssessment:
    node: Node
    quick: QuickResult
    full: FullResult | None
    evaluation: Evaluation
    consecutive_full_passes: int = 0
    consecutive_unavailable_runs: int = 0
    fresh_full_completed: bool = False
    fresh_full_usable: bool = False
    fresh_full_attempt: FullResult | None = None
    healthy_streak_days: int = 0
    last_healthy_day: str = ""
    consecutive_unavailable_valid_days: int = 0
    last_unavailable_day: str = ""
    unavailable_grace_active: bool = False
    daily_quality_history: list[dict[str, Any]] = field(default_factory=list)
    evidence_valid: bool = False
    qualification_version: int = 1
