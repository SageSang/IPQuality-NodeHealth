from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class Node:
    key: str
    name: str
    region: str
    proxy: dict[str, Any] = field(repr=False, compare=False)


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
    fresh_full_completed: bool = False
    fresh_full_usable: bool = False
    fresh_full_attempt: FullResult | None = None
