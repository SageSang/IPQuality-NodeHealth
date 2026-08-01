from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any

from .config import PolicyConfig
from .models import Evaluation, FullResult, Node, QuickResult


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
        and chatgpt_explicitly_allowed(full)
    )


def full_has_confirmed_redline(
    full: FullResult | None,
    policy: PolicyConfig | None = None,
) -> bool:
    if full is None or not full.completed:
        return False
    dnsbl_threshold = (
        policy.dnsbl_redline_threshold
        if policy is not None
        else _DEFAULT_DNSBL_REDLINE_THRESHOLD
    )
    if (
        full.tor
        or dnsbl_listed_count(full) >= dnsbl_threshold
        or chatgpt_is_redline(chatgpt_status(full.details))
    ):
        return True
    return sum(1 for value in valid_risk_sources(full).values() if _is_high_risk(value)) >= 2


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


def evaluate_node(
    node: Node,
    quick: QuickResult,
    full: FullResult | None,
    policy: PolicyConfig,
    consecutive_full_passes: int,
    previous_exit_ip: str = "",
    was_stable: bool = False,
) -> Evaluation:
    reasons: list[str] = []
    if not quick.available:
        reasons.append("unavailable")
    if quick.available and not quick.exit_ip:
        reasons.append("missing-public-egress-ip")
    if quick.available and not quick.exit_ip_stable:
        reasons.append("egress-ip-unstable")
    if (
        quick.available
        and was_stable
        and previous_exit_ip
        and quick.exit_ip
        and previous_exit_ip != quick.exit_ip
    ):
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
        reasons.append(
            f"insufficient-quick-success-rate:{quick.success_rate:.4f}"
        )

    if full and full.completed:
        if full.tor:
            reasons.append("tor-exit")
        listed_count = dnsbl_listed_count(full)
        if listed_count >= policy.dnsbl_redline_threshold:
            reasons.append(
                f"dnsbl-redline:{listed_count}>={policy.dnsbl_redline_threshold}"
            )
        elif listed_count:
            reasons.append(f"dnsbl-listed:{listed_count}")
        valid_risks = valid_risk_sources(full)
        high_sources = sorted(name for name, value in valid_risks.items() if _is_high_risk(value))
        if len(high_sources) >= 2:
            reasons.append("multiple-high-risk-sources:" + ",".join(high_sources))
        observed_chatgpt = chatgpt_status(full.details)
        if chatgpt_is_redline(observed_chatgpt):
            reasons.append(f"chatgpt-redline:{observed_chatgpt}")
        elif not chatgpt_explicitly_allowed(full):
            reasons.append(f"chatgpt-unconfirmed:{observed_chatgpt or 'unknown'}")
        if len(valid_risks) < policy.min_valid_risk_sources:
            reasons.append(
                f"insufficient-risk-coverage:{len(valid_risks)}/{policy.min_valid_risk_sources}"
            )

    score = score_node(node, quick, full, policy)
    # A stable endpoint can legitimately rotate to a new egress IP. That
    # resets confidence and triggers a fresh full audit, but is not proof that
    # the replacement IP is dangerous. Confirmed quality failures remain hard
    # redlines.
    warnings = {"unavailable", "stable-egress-ip-changed"}
    warning_prefixes = (
        "chatgpt-unconfirmed:",
        "insufficient-risk-coverage:",
        "insufficient-quick-success-rate:",
        "dnsbl-listed:",
        "quick-country-disagrees-with-full:",
        "quick-country-mismatch:",
    )
    warnings.add("country-unconfirmed")
    redline = any(
        reason not in warnings and not reason.startswith(warning_prefixes)
        for reason in reasons
    )
    unavailable = "unavailable" in reasons and not redline
    if redline:
        confidence = "rejected"
    elif unavailable:
        confidence = "unavailable"
    elif (
        full_has_usable_reputation(full, policy)
        and (not expected or observed_country == expected)
        and quick.success_rate >= policy.minimum_candidate_success_rate
        and consecutive_full_passes >= policy.min_full_passes_high_confidence
    ):
        confidence = "high"
    elif (
        full_has_usable_reputation(full, policy)
        and (not expected or observed_country == expected)
        and quick.success_rate >= policy.minimum_candidate_success_rate
    ):
        confidence = "provisional"
    else:
        confidence = "low"
    return Evaluation(
        decision="rejected" if redline else ("unavailable" if unavailable else "eligible"),
        score=score,
        confidence=confidence,
        reasons=reasons,
    )


def score_node(node: Node, quick: QuickResult, full: FullResult | None, policy: PolicyConfig) -> float:
    if not quick.available:
        return 0.0
    score = 25.0 + max(0.0, min(1.0, quick.success_rate)) * 10.0
    latency = quick.latency_ms
    if latency is not None:
        if latency <= 100:
            score += 20
        elif latency <= 200:
            score += 15
        elif latency <= 400:
            score += 10
        elif latency <= 800:
            score += 5

    expected = policy.expected_country.get(node.region, "").upper()
    full_country = _full_country_majority(full.details) if full and full.completed else ""
    quick_country = quick.country.upper() if quick.available and quick.country else ""
    observed_country = full_country or quick_country
    if expected and observed_country == expected:
        score += 10
    elif not expected:
        score += 5
    if quick.google_ok:
        score += 5
    if quick.chatgpt_ok:
        score += 5
    if quick.exit_ip_stable:
        score += 5

    if full and full.completed and full_has_sufficient_risk_coverage(full, policy):
        severities = [
            _risk_severity(value) for value in valid_risk_sources(full).values()
        ]
        risk_points = 20.0 * (1.0 - sum(severities) / len(severities))
        if any(label.lower() in {"datacenter", "server", "proxy", "vpn"} for label in full.labels):
            risk_points -= 2
        score += max(0.0, risk_points)
    else:
        score += 5
    if full and full.completed:
        score -= min(6.0, dnsbl_listed_count(full) * 2.0)
    return round(max(0.0, min(100.0, score)), 2)


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

    by_region: dict[str, list[Node]] = {}
    for node in available:
        if node.key not in stable_keys:
            by_region.setdefault(node.region, []).append(node)

    def prior_score(node: Node) -> float:
        try:
            return float(prior_nodes.get(node.key, {}).get("last_score") or 0)
        except (TypeError, ValueError):
            return 0.0

    def review_age_key(node: Node) -> tuple[datetime, str]:
        checked_at = _parse_time(
            prior_nodes.get(node.key, {}).get("last_full_checked_at")
        )
        return checked_at or datetime.min.replace(tzinfo=timezone.utc), node.key

    for region_nodes in by_region.values():
        region_nodes.sort(
            key=lambda node: (
                -prior_score(node),
                node.key,
            )
        )
        mandatory = {node.key for node in region_nodes if node.key in selected}
        rotation = [node for node in region_nodes if node.key not in mandatory]
        sample_count = math.ceil(
            len(rotation) * policy.full_audit_daily_fraction
        )
        for sample_index in range(sample_count):
            start = sample_index * len(rotation) // sample_count
            end = (sample_index + 1) * len(rotation) // sample_count
            block = rotation[start:end]
            selected.add(min(block, key=review_age_key).key)

        challengers = [
            node
            for node in region_nodes
            if node.key in prior_nodes
            and prior_nodes[node.key].get("last_decision") in {None, "eligible"}
        ][: policy.promotion_challengers_per_region]
        selected.update(node.key for node in challengers)

    return {key for key in selected if key in quick_results and quick_results[key].available}
