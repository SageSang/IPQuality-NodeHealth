from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


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
