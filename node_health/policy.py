from __future__ import annotations

import math
from datetime import datetime, timezone
from statistics import median
from typing import Any

from .config import PolicyConfig
from .models import Evaluation, FullResult, Node, QuickResult


GRADE_ORDER = {"A": 0, "B": 1, "C": 2}


_RISK_LABELS = {
    "very low",
    "low",
    "medium",
    "moderate",
    "elevated",
    "high",
    "very high",
    "veryhigh",
    "high risk",
    "highrisk",
    "very high risk",
    "critical",
    "极低",
    "低",
    "中等",
    "高",
    "极高",
    "高风险",
    "极高风险",
}
_UNKNOWN_RISK_VALUES = {"", "none", "null", "unknown", "n/a", "na", "nan", "-", "timeout"}
_RISK_SEVERITY = {
    "very low": 0.05,
    "low": 0.15,
    "medium": 0.5,
    "moderate": 0.5,
    "elevated": 0.65,
    "high": 0.8,
    "high risk": 0.8,
    "highrisk": 0.8,
    "very high": 0.95,
    "veryhigh": 0.95,
    "very high risk": 0.95,
    "critical": 1.0,
}
_DEFAULT_DNSBL_REDLINE_THRESHOLD = 3


def _dnsbl_severe_threshold(policy: PolicyConfig) -> int:
    # Direct PolicyConfig construction was part of the old test/public API.
    # Honour a non-default legacy value unless the new field was also changed.
    if (
        policy.dnsbl_severe_threshold == _DEFAULT_DNSBL_REDLINE_THRESHOLD
        and policy.dnsbl_redline_threshold != _DEFAULT_DNSBL_REDLINE_THRESHOLD
    ):
        return policy.dnsbl_redline_threshold
    return policy.dnsbl_severe_threshold


def normalize_risk_value(value: Any) -> str:
    """Return a comparable risk value, or an empty string when the source failed."""
    if value is None or isinstance(value, bool):
        return ""
    if isinstance(value, (int, float)):
        number = float(value)
        return str(value) if math.isfinite(number) and 0 <= number <= 100 else ""
    normalized = str(value).strip().lower().replace("_", " ").replace("-", " ")
    normalized = " ".join(normalized.split())
    if normalized in _UNKNOWN_RISK_VALUES:
        return ""
    numeric = normalized[:-1].strip() if normalized.endswith("%") else normalized
    try:
        number = float(numeric)
    except ValueError:
        return normalized if normalized in _RISK_LABELS else ""
    return normalized if math.isfinite(number) and 0 <= number <= 100 else ""


def valid_risk_sources(full: FullResult | None) -> dict[str, str]:
    if full is None or not full.completed:
        return {}
    return {
        str(name): normalized
        for name, value in full.risk_sources.items()
        if (normalized := normalize_risk_value(value))
    }


def risk_sources_conflict(full: FullResult | None) -> bool:
    values = [_risk_severity(value) for value in valid_risk_sources(full).values()]
    if len(values) >= 2 and max(values) - min(values) >= 0.5:
        return True
    if full is None or not full.completed or not isinstance(full.details, dict):
        return False
    factor = full.details.get("Factor")
    if not isinstance(factor, dict):
        return False
    for name in ("proxy", "vpn", "server", "abuser"):
        evidence = next(
            (value for key, value in factor.items() if str(key).lower() == name),
            None,
        )
        if isinstance(evidence, dict):
            observed = {_as_bool(value) for value in evidence.values()}
            if observed == {False, True}:
                return True
    return False


def full_has_sufficient_risk_coverage(full: FullResult | None, policy: PolicyConfig) -> bool:
    return len(valid_risk_sources(full)) >= policy.min_valid_risk_sources


def _risk_severity(value: str) -> float:
    normalized = value.strip().lower().replace("_", " ").replace("-", " ")
    normalized = " ".join(normalized.split())
    numeric = normalized[:-1].strip() if normalized.endswith("%") else normalized
    try:
        return max(0.0, min(1.0, float(numeric) / 100.0))
    except ValueError:
        return _RISK_SEVERITY.get(normalized, 0.5)


def _is_high_risk(value: str) -> bool:
    normalized = value.strip().lower().replace("_", " ").replace("-", " ")
    if normalized in {
        "high",
        "very high",
        "veryhigh",
        "high risk",
        "highrisk",
        "critical",
        "danger",
        "dangerous",
        "高风险",
        "极高风险",
    }:
        return True
    try:
        return float(normalized.rstrip("%")) >= 75
    except ValueError:
        return False


def dnsbl_listed_count(full: FullResult | None) -> int:
    if full is None or not full.completed:
        return 0
    try:
        count = max(0, int(full.dnsbl_listed_count))
    except (TypeError, ValueError):
        count = 0
    if count:
        return count

    mail = full.details.get("Mail") if isinstance(full.details, dict) else None
    dns = mail.get("DNSBlacklist") if isinstance(mail, dict) else None
    raw_count = dns.get("Blacklisted") if isinstance(dns, dict) else None
    try:
        return max(0, int(float(raw_count)))
    except (TypeError, ValueError):
        if str(raw_count).strip().lower() in {"true", "yes", "listed", "blacklisted"}:
            return 1
        # Old state files only retained a boolean. Treat that as one listing,
        # which is intentionally below the default confirmed-redline threshold.
        return 1 if full.dnsbl_blacklisted else 0


def chatgpt_status(details: dict[str, Any]) -> str:
    media = details.get("Media")
    if not isinstance(media, dict):
        media = details.get("media")
    if not isinstance(media, dict):
        return ""
    chatgpt = next(
        (value for key, value in media.items() if str(key).lower() == "chatgpt"),
        None,
    )
    if isinstance(chatgpt, dict):
        status = next(
            (value for key, value in chatgpt.items() if str(key).lower() == "status"),
            "",
        )
    else:
        status = chatgpt
    return str(status or "").strip()


def chatgpt_is_redline(status: str) -> bool:
    normalized = status.strip().lower().replace("_", " ").replace("-", " ")
    normalized = " ".join(normalized.split())
    if not normalized or normalized in {
        "unknown",
        "n/a",
        "null",
        "timeout",
        "failed",
        "failure",
        "失败",
    }:
        return False
    if normalized in {"webonly", "web only", "apponly", "app only", "仅网页", "仅app"}:
        return True
    if any(word in normalized for word in {"屏蔽", "封禁", "不支持", "不可用", "受限", "拒绝"}):
        return True
    redline_words = {
        "block",
        "blocked",
        "no",
        "failed",
        "failure",
        "unsupported",
        "unavailable",
        "denied",
        "deny",
        "banned",
        "not",
        "restricted",
        "restriction",
    }
    words = set(normalized.replace("(", " ").replace(")", " ").split())
    return normalized in redline_words or bool(words & redline_words)


def chatgpt_explicitly_allowed(full: FullResult | None) -> bool:
    if full is None or not full.completed:
        return False
    observed = chatgpt_status(full.details)
    if chatgpt_is_redline(observed):
        return False
    normalized = observed.strip().lower().replace("_", " ").replace("-", " ")
    if not normalized:
        return False
    allowed_words = {
        "yes",
        "available",
        "unlock",
        "unlocked",
        "supported",
        "ok",
        "native",
        "success",
        "working",
        "解锁",
        "可用",
        "正常",
    }
    words = set(normalized.replace("(", " ").replace(")", " ").split())
    return normalized in allowed_words or bool(words & allowed_words)


def full_has_usable_reputation(full: FullResult | None, policy: PolicyConfig) -> bool:
    return (
        full is not None
        and full.completed
        and full_has_sufficient_risk_coverage(full, policy)
    )


def full_has_confirmed_redline(
    full: FullResult | None,
    policy: PolicyConfig | None = None,
) -> bool:
    if full is None or not full.completed:
        return False
    dnsbl_threshold = _dnsbl_severe_threshold(policy) if policy is not None else _DEFAULT_DNSBL_REDLINE_THRESHOLD
    if full.tor or dnsbl_listed_count(full) >= dnsbl_threshold:
        return True
    if sum(1 for value in valid_risk_sources(full).values() if _is_high_risk(value)) >= 2:
        return True
    return any(count >= 3 for count in _factor_source_counts(full).values())


def _full_country_majority(details: dict[str, Any]) -> str:
    factor = details.get("Factor")
    if not isinstance(factor, dict):
        return ""
    country_codes = next(
        (value for key, value in factor.items() if str(key).lower() == "countrycode"),
        None,
    )
    if not isinstance(country_codes, dict):
        return ""
    values = [
        str(value).strip().upper()
        for value in country_codes.values()
        if value is not None and str(value).strip().lower() not in {"", "null", "unknown", "n/a"}
    ]
    if not values:
        return ""
    counts = {value: values.count(value) for value in set(values)}
    winner, count = max(counts.items(), key=lambda item: (item[1], item[0]))
    return winner if count >= 2 and count > len(values) / 2 else ""


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _factor_source_counts(full: FullResult | None) -> dict[str, int]:
    counts = {name: 0 for name in ("proxy", "vpn", "server", "abuser", "robot", "tor")}
    if full is not None and full.completed and isinstance(full.details, dict):
        factor = full.details.get("Factor")
        if isinstance(factor, dict):
            for name in counts:
                value = next(
                    (item for key, item in factor.items() if str(key).lower() == name),
                    None,
                )
                if isinstance(value, dict):
                    counts[name] += sum(1 for item in value.values() if _as_bool(item))
                elif isinstance(value, list):
                    counts[name] += sum(1 for item in value if _as_bool(item))
                elif _as_bool(value):
                    counts[name] += 1
        for label in full.labels:
            normalized = str(label).strip().lower()
            if normalized in counts and counts[normalized] == 0:
                counts[normalized] = 1
        if full.tor and counts["tor"] == 0:
            counts["tor"] = 1
    return counts


def _claude_factor_source_counts(quick: QuickResult) -> dict[str, int]:
    counts = {name: 0 for name in ("proxy", "vpn", "server", "abuser", "robot", "tor")}
    for name, sources in quick.claude.factors.items():
        normalized = str(name).strip().lower()
        if normalized not in counts:
            continue
        if isinstance(sources, dict):
            counts[normalized] += sum(1 for item in sources.values() if _as_bool(item))
        elif isinstance(sources, list):
            counts[normalized] += sum(1 for item in sources if _as_bool(item))
        elif _as_bool(sources):
            counts[normalized] += 1
    return counts


def _route_risk_profile(
    risks: dict[str, str],
    factors: dict[str, int],
    minimum_sources: int,
    *,
    dnsbl_count: int = 0,
    dnsbl_threshold: int = _DEFAULT_DNSBL_REDLINE_THRESHOLD,
) -> dict[str, Any]:
    severities = [_risk_severity(value) for value in risks.values()]
    if severities:
        points = 25.0 * (
            1.0 - (0.6 * median(severities) + 0.4 * max(severities))
        )
    else:
        points = 25.0
    if len(risks) < minimum_sources:
        points = min(points, 10.0)

    single_penalty = min(
        6.0,
        2.0
        * sum(
            1
            for name in ("proxy", "vpn", "server", "abuser")
            if factors[name]
        ),
    )
    consensus_penalty = 3.0 * sum(
        1
        for name in ("proxy", "vpn", "server", "abuser")
        if factors[name] >= 2
    )
    robot_penalty = 1.0 if factors["robot"] else 0.0
    dnsbl_penalty = min(5.0, float(dnsbl_count))
    points = max(
        0.0,
        min(
            25.0,
            points
            - single_penalty
            - consensus_penalty
            - robot_penalty
            - dnsbl_penalty,
        ),
    )

    high_sources = sorted(
        name for name, value in risks.items() if _is_high_risk(value)
    )
    severe = bool(
        factors["tor"]
        or len(high_sources) >= 2
        or dnsbl_count >= dnsbl_threshold
        or any(
            factors[name] >= 3
            for name in ("proxy", "vpn", "server", "abuser")
        )
    )
    clean = bool(
        len(risks) >= minimum_sources
        and max(severities, default=1.0) < 0.5
        and dnsbl_count == 0
        and not any(
            factors[name]
            for name in ("proxy", "vpn", "server", "abuser", "tor")
        )
    )
    return {
        "grade": "C" if severe else ("A" if clean else "B"),
        "points": round(points, 2),
        "source_count": len(risks),
        "sources": sorted(risks),
        "factors": factors,
        "high_sources": high_sources,
    }


def _risk_profile(
    full: FullResult | None, quick: QuickResult, policy: PolicyConfig
) -> tuple[str, float, int, dict[str, int], dict[str, dict[str, Any]]]:
    generic = _route_risk_profile(
        dict(valid_risk_sources(full)),
        _factor_source_counts(full),
        policy.min_valid_risk_sources,
        dnsbl_count=dnsbl_listed_count(full),
        dnsbl_threshold=_dnsbl_severe_threshold(policy),
    )
    routes = {"generic": generic}
    split_claude_route = bool(
        quick.claude.exit_ip
        and quick.exit_ip
        and quick.claude.exit_ip != quick.exit_ip
    )
    if split_claude_route:
        claude_risks = {
            str(name): normalized
            for name, value in quick.claude.risk_sources.items()
            if (normalized := normalize_risk_value(value))
        }
        routes["claude"] = _route_risk_profile(
            claude_risks,
            _claude_factor_source_counts(quick),
            policy.claude_min_valid_risk_sources,
        )
    grade = max(
        (str(route["grade"]) for route in routes.values()),
        key=lambda value: GRADE_ORDER[value],
    )
    points = min(float(route["points"]) for route in routes.values())
    return (
        grade,
        round(points, 2),
        int(generic["source_count"]),
        dict(generic["factors"]),
        routes,
    )


def residential_profile(full: FullResult | None) -> tuple[str, float, dict[str, list[str]]]:
    evidence = {"positive": [], "strong": [], "negative": []}
    if full is None or not full.completed or not isinstance(full.details, dict):
        return "unknown", 0.0, evidence
    type_data = full.details.get("Type")
    if not isinstance(type_data, dict):
        return "unknown", 0.0, evidence
    usage = type_data.get("Usage") if isinstance(type_data.get("Usage"), dict) else {}
    company = type_data.get("Company") if isinstance(type_data.get("Company"), dict) else {}
    strong_terms = ("line isp", "fixed line isp", "residential", "broadband", "家宽", "住宅", "固网")
    positive_terms = (*strong_terms, "isp")
    negative_terms = ("hosting", "datacenter", "data center", "cdn", "server", "机房")
    for source, value in usage.items():
        normalized = " ".join(str(value or "").strip().lower().replace("_", " ").split())
        if any(term in normalized for term in negative_terms):
            evidence["negative"].append(str(source))
        elif any(term in normalized for term in positive_terms):
            evidence["positive"].append(str(source))
            if any(term in normalized for term in strong_terms):
                evidence["strong"].append(str(source))
    for source, value in company.items():
        normalized = " ".join(str(value or "").strip().lower().replace("_", " ").split())
        if any(term in normalized for term in negative_terms):
            evidence["negative"].append(f"company:{source}")
    if evidence["negative"]:
        return "unknown", 0.0, evidence
    if len(evidence["positive"]) >= 2 and evidence["strong"]:
        return "confirmed", 10.0, evidence
    if len(evidence["positive"]) >= 2 or evidence["strong"]:
        return "probable", 5.0, evidence
    return "unknown", 0.0, evidence


def _media_chatgpt_field(full: FullResult | None, field: str) -> str:
    if full is None or not full.completed or not isinstance(full.details, dict):
        return ""
    media = full.details.get("Media")
    if not isinstance(media, dict):
        return ""
    value = next((item for key, item in media.items() if str(key).lower() == "chatgpt"), None)
    if not isinstance(value, dict):
        return ""
    return str(next((item for key, item in value.items() if str(key).lower() == field.lower()), "") or "").strip()


def _chatgpt_availability(quick: QuickResult, full: FullResult | None) -> str:
    if quick.chatgpt_service_outage:
        return "unknown"
    if chatgpt_explicitly_allowed(full):
        return "available"
    observed = chatgpt_status(full.details) if full and full.completed else ""
    if chatgpt_is_redline(observed):
        return "unavailable"
    if observed:
        return "unknown"
    if quick.chatgpt_ok is True:
        return "available"
    if quick.chatgpt_ok is False:
        return "unavailable"
    return "unknown"


def _ai_profile(
    node: Node, quick: QuickResult, full: FullResult | None, policy: PolicyConfig
) -> tuple[str, float, str, str]:
    chatgpt = _chatgpt_availability(quick, full)
    claude = "unknown" if quick.claude.service_outage else quick.claude.status
    claude_available = claude == "available"
    claude_failed = claude in {"restricted", "unreachable"}
    chatgpt_available = chatgpt == "available"
    chatgpt_failed = chatgpt == "unavailable"
    if chatgpt_available and claude_available:
        grade = "A"
    elif chatgpt_failed and claude_failed:
        grade = "C"
    else:
        grade = "B"

    points = 0.0
    if chatgpt_explicitly_allowed(full):
        points += 8.0
    chatgpt_region = _media_chatgpt_field(full, "Region").upper()
    observed_exit_country = str(quick.country or "").upper()
    if chatgpt_region and observed_exit_country and chatgpt_region == observed_exit_country:
        points += 3.0
    if _media_chatgpt_field(full, "Type").strip().lower() == "native":
        points += 2.0
    if quick.chatgpt_ok is True and not quick.chatgpt_service_outage:
        points += 2.0
    if quick.claude.trace_ok and not quick.claude.service_outage:
        points += 4.0
    if quick.claude.supported is True and not quick.claude.service_outage:
        points += 3.0
    if quick.claude.anthropic_ok and not quick.claude.service_outage:
        points += 2.0
    same_route_usable = bool(
        quick.claude.exit_ip
        and quick.claude.exit_ip == quick.exit_ip
        and full_has_sufficient_risk_coverage(full, policy)
    )
    if not quick.claude.service_outage and quick.claude.route_stable and (
        quick.claude.intelligence_complete or same_route_usable
    ):
        points += 1.0
    return grade, min(25.0, points), chatgpt, claude


def _geo_points(node: Node, quick: QuickResult, full: FullResult | None, policy: PolicyConfig) -> float:
    expected = policy.expected_country.get(node.region, "").upper()
    full_country = _full_country_majority(full.details) if full and full.completed else ""
    observed = full_country or str(quick.country or "").upper()
    points = 5.0 if expected and observed == expected else 0.0
    details = full.details if full and full.completed and isinstance(full.details, dict) else {}
    info = details.get("Info") if isinstance(details.get("Info"), dict) else {}
    region = info.get("Region") if isinstance(info.get("Region"), dict) else {}
    registered = info.get("RegisteredRegion") if isinstance(info.get("RegisteredRegion"), dict) else {}
    if region.get("Code") and str(region.get("Code")).upper() == str(registered.get("Code") or "").upper():
        points += 2.0
    # A full-country majority requires at least two agreeing Geo providers, so
    # it is the concrete multi-source consistency signal used by this point.
    if full_country:
        points += 1.0
    if (info.get("ASN") or quick.asn) and info.get("Organization") and observed:
        points += 2.0
    return min(10.0, points)


def _latency_points(latency: float | None) -> float:
    if latency is None:
        return 0.0
    if latency <= 150:
        return 5.0
    if latency <= 300:
        return 4.0
    if latency <= 600:
        return 3.0
    if latency <= 1000:
        return 1.0
    return 0.0


def _streak_points(days: int) -> float:
    return float({0: 0, 1: 2, 2: 4, 3: 6, 4: 7, 5: 8}.get(max(0, days), 10))


def quality_components(
    node: Node,
    quick: QuickResult,
    full: FullResult | None,
    policy: PolicyConfig,
    healthy_streak_days: int = 0,
) -> tuple[dict[str, float], str, str, str, str, str, int]:
    ai_grade, ai_points, chatgpt, claude = _ai_profile(node, quick, full, policy)
    risk_grade, risk_points, risk_source_count, _, _ = _risk_profile(
        full, quick, policy
    )
    residential_grade, residential_points, _ = residential_profile(full)
    success_points = max(0.0, min(1.0, quick.success_rate)) * 10.0
    if quick.transient_recovery:
        success_points = min(7.0, success_points)
    reliability = success_points + (5.0 if quick.exit_ip_stable else 0.0) + _streak_points(healthy_streak_days)
    components = {
        "ai": round(ai_points, 2),
        "risk": round(risk_points, 2),
        "reliability": round(min(25.0, reliability), 2),
        "residential": residential_points,
        "geo": round(_geo_points(node, quick, full, policy), 2),
        "latency": _latency_points(quick.latency_ms),
        "risk_source_count": float(risk_source_count),
    }
    overall_grade = max((ai_grade, risk_grade), key=lambda value: GRADE_ORDER[value])
    expected = policy.expected_country.get(node.region, "").upper()
    full_country = _full_country_majority(full.details) if full and full.completed else ""
    observed = full_country or str(quick.country or "").upper()
    if quick.available and (not quick.exit_ip or not quick.exit_ip_stable):
        overall_grade = "C"
    if expected and observed and observed != expected:
        overall_grade = "C"
    return components, ai_grade, risk_grade, overall_grade, residential_grade, chatgpt, risk_source_count


def evaluate_node(
    node: Node,
    quick: QuickResult,
    full: FullResult | None,
    policy: PolicyConfig,
    consecutive_full_passes: int,
    previous_exit_ip: str = "",
    was_stable: bool = False,
    healthy_streak_days: int = 0,
) -> Evaluation:
    reasons: list[str] = []
    if not quick.available:
        reasons.append("unavailable")
    if quick.available and not quick.exit_ip:
        reasons.append("missing-public-egress-ip")
    if quick.available and not quick.exit_ip_stable:
        reasons.append("egress-ip-unstable")
    if quick.transient_recovery:
        reasons.append("transient-recovery")
    if quick.available and was_stable and previous_exit_ip and quick.exit_ip and previous_exit_ip != quick.exit_ip:
        reasons.append("stable-egress-ip-changed")

    expected = policy.expected_country.get(node.region, "").upper()
    full_country = _full_country_majority(full.details) if full and full.completed else ""
    quick_country = quick.country.upper() if quick.available and quick.country else ""
    observed_country = full_country or quick_country
    if full_country and quick_country and full_country != quick_country:
        reasons.append(f"quick-country-disagrees-with-full:{quick_country}!={full_country}")
    if expected and full_country and full_country != expected:
        reasons.append(f"country-mismatch:{observed_country}!={expected}")
    elif expected and not full_country and quick_country and quick_country != expected:
        reasons.append(f"quick-country-mismatch:{quick_country}!={expected}")
    elif expected and not observed_country:
        reasons.append("country-unconfirmed")
    if quick.available and quick.success_rate < policy.minimum_candidate_success_rate:
        reasons.append(f"insufficient-quick-success-rate:{quick.success_rate:.4f}")

    risk_grade, _, risk_source_count, factors, risk_routes = _risk_profile(
        full, quick, policy
    )
    if full and full.completed:
        if factors["tor"]:
            reasons.append("tor-exit")
        listed_count = dnsbl_listed_count(full)
        dnsbl_threshold = _dnsbl_severe_threshold(policy)
        if listed_count >= dnsbl_threshold:
            reasons.append(f"dnsbl-redline:{listed_count}>={dnsbl_threshold}")
        elif listed_count:
            reasons.append(f"dnsbl-listed:{listed_count}")
        high_sources = sorted(name for name, value in valid_risk_sources(full).items() if _is_high_risk(value))
        if len(high_sources) >= 2:
            reasons.append("multiple-high-risk-sources:" + ",".join(high_sources))
        if risk_source_count < policy.min_valid_risk_sources:
            reasons.append(f"insufficient-risk-coverage:{risk_source_count}/{policy.min_valid_risk_sources}")

    claude_route = risk_routes.get("claude")
    if claude_route is not None:
        claude_factors = claude_route["factors"]
        if claude_factors["tor"]:
            reasons.append("claude-tor-exit")
        claude_high_sources = claude_route["high_sources"]
        if len(claude_high_sources) >= 2:
            reasons.append(
                "claude-multiple-high-risk-sources:"
                + ",".join(claude_high_sources)
            )
        claude_source_count = int(claude_route["source_count"])
        if claude_source_count < policy.claude_min_valid_risk_sources:
            reasons.append(
                "claude-insufficient-risk-coverage:"
                f"{claude_source_count}/{policy.claude_min_valid_risk_sources}"
            )
        if claude_route["grade"] == "C" and not (
            claude_factors["tor"] or len(claude_high_sources) >= 2
        ):
            reasons.append("claude-risk-consensus-severe")

    components, ai_grade, risk_grade, overall_grade, residential_grade, chatgpt, _ = quality_components(
        node, quick, full, policy, healthy_streak_days
    )
    claude = "unknown" if quick.claude.service_outage else quick.claude.status
    if chatgpt != "available":
        reasons.append(f"chatgpt-{chatgpt}")
    if claude != "available":
        reasons.append(f"claude-{claude}")
    if (
        quick.claude.exit_ip
        and quick.claude.exit_ip != quick.exit_ip
        and (not quick.claude.intelligence_complete or quick.claude.intelligence_cached)
    ):
        reasons.append("claude-risk-incomplete")
    if (
        quick.claude.country
        and quick.claude.intelligence_country
        and quick.claude.country != quick.claude.intelligence_country
    ):
        reasons.append(
            "claude-intelligence-country-conflict:"
            f"{quick.claude.country}!={quick.claude.intelligence_country}"
        )
    if ai_grade == "C":
        reasons.append("ai-services-unavailable")
    if risk_grade == "C" and not any(
        reason in {
            "tor-exit",
            "claude-tor-exit",
            "ai-services-unavailable",
            "claude-risk-consensus-severe",
        }
        or reason.startswith(
            (
                "dnsbl-redline:",
                "multiple-high-risk-sources:",
                "claude-multiple-high-risk-sources:",
            )
        )
        for reason in reasons
    ):
        reasons.append("risk-consensus-severe")

    score = 0.0 if not quick.available else round(
        sum(value for key, value in components.items() if key != "risk_source_count"), 2
    )
    unavailable = not quick.available
    redline = quick.available and overall_grade == "C"
    if redline:
        confidence = "rejected"
    elif unavailable:
        confidence = "unavailable"
    elif (
        "country-unconfirmed" in reasons
        or any(
            reason.startswith(
                (
                    "quick-country-mismatch:",
                    "insufficient-risk-coverage:",
                    "claude-insufficient-risk-coverage:",
                    "claude-intelligence-country-conflict:",
                )
            )
            for reason in reasons
        )
    ):
        confidence = "low"
    elif (
        overall_grade == "A"
        and full_has_usable_reputation(full, policy)
        and quick.success_rate >= policy.minimum_candidate_success_rate
        and "country-unconfirmed" not in reasons
        and not any(reason.startswith("quick-country-mismatch:") for reason in reasons)
    ):
        confidence = "high"
    elif overall_grade in {"A", "B"} and full is not None and full.completed:
        confidence = "provisional"
    else:
        confidence = "low"
    _, _, residential_evidence = residential_profile(full)
    evidence = {
        "risk_sources": sorted(valid_risk_sources(full)),
        "risk_routes": risk_routes,
        "residential": residential_evidence,
        "ai": {
            "chatgpt": chatgpt,
            "claude": claude,
            "claude_exit_ip": quick.claude.exit_ip,
            "claude_country": quick.claude.country,
            "claude_intelligence_country": quick.claude.intelligence_country,
            "claude_risk_sources": sorted(quick.claude.risk_sources),
        },
        "geography": {
            "expected_country": expected,
            "quick_country": quick_country,
            "full_country": full_country,
        },
    }
    return Evaluation(
        decision="rejected" if redline else ("unavailable" if unavailable else "eligible"),
        score=score,
        confidence=confidence,
        reasons=list(dict.fromkeys(reasons)),
        components=components,
        ai_grade=ai_grade,
        risk_grade=risk_grade,
        overall_grade=overall_grade,
        residential_grade=residential_grade,
        evidence=evidence,
    )


def score_node(
    node: Node,
    quick: QuickResult,
    full: FullResult | None,
    policy: PolicyConfig,
    healthy_streak_days: int = 0,
) -> float:
    if not quick.available:
        return 0.0
    components, *_ = quality_components(node, quick, full, policy, healthy_streak_days)
    return round(sum(value for key, value in components.items() if key != "risk_source_count"), 2)


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return None


def select_full_audit_nodes(
    mode: str,
    nodes: list[Node],
    quick_results: dict[str, QuickResult],
    previous_state: dict[str, Any],
    policy: PolicyConfig,
    now: datetime | None = None,
) -> set[str]:
    available = [node for node in nodes if quick_results[node.key].available]
    if mode == "rebuild":
        return {node.key for node in available}
    if mode != "maintenance":
        raise ValueError(f"unsupported mode: {mode}")

    selected: set[str] = set()
    prior_nodes = previous_state.get("nodes", {})
    stable_keys = {
        str(value)
        for slots in previous_state.get("stable_slots", {}).values()
        for value in slots.values()
        if value
    }
    selected.update(stable_keys)

    for node in available:
        prior = prior_nodes.get(node.key)
        quick = quick_results[node.key]
        if not prior:
            selected.add(node.key)
            continue
        if prior.get("last_exit_ip") and prior.get("last_exit_ip") != quick.exit_ip:
            selected.add(node.key)
        prior_claude = prior.get("last_claude") if isinstance(prior.get("last_claude"), dict) else {}
        if str(prior_claude.get("exit_ip") or "") != str(quick.claude.exit_ip or ""):
            selected.add(node.key)
        if int(prior.get("consecutive_unavailable_valid_days", 0) or 0) > 0:
            selected.add(node.key)
        try:
            source_count = int(float(prior.get("last_risk_source_count", 0) or 0))
        except (TypeError, ValueError):
            source_count = 0
        if source_count < policy.min_valid_risk_sources:
            selected.add(node.key)
        if prior.get("risk_data_conflict"):
            selected.add(node.key)

    by_region: dict[str, list[Node]] = {}
    for node in available:
        if node.key not in stable_keys:
            by_region.setdefault(node.region, []).append(node)

    def prior_score(node: Node) -> float:
        try:
            return float(prior_nodes.get(node.key, {}).get("last_score") or 0)
        except (TypeError, ValueError):
            return 0.0

    def prior_grade(node: Node) -> int:
        return GRADE_ORDER.get(str(prior_nodes.get(node.key, {}).get("overall_grade") or "B"), 1)

    def review_age_key(node: Node) -> tuple[datetime, str]:
        checked_at = _parse_time(
            prior_nodes.get(node.key, {}).get("last_full_attempt_at")
            or prior_nodes.get(node.key, {}).get("last_full_checked_at")
        )
        return checked_at or datetime.min.replace(tzinfo=timezone.utc), node.key

    for region_nodes in by_region.values():
        region_nodes.sort(
            key=lambda node: (
                prior_grade(node),
                -prior_score(node),
                node.key,
            )
        )
        mandatory = {node.key for node in region_nodes if node.key in selected}
        challengers = [
            node
            for node in region_nodes
            if node.key in prior_nodes
            and prior_nodes[node.key].get("last_decision") in {None, "eligible"}
        ][: policy.promotion_challengers_per_region]
        selected.update(node.key for node in challengers)

        rotation = [node for node in region_nodes if node.key not in selected]
        sample_count = math.ceil(len(rotation) * policy.full_audit_daily_fraction)
        selected.update(
            node.key for node in sorted(rotation, key=review_age_key)[:sample_count]
        )

    return {key for key in selected if key in quick_results and quick_results[key].available}
