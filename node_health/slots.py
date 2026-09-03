from __future__ import annotations

from collections.abc import Iterable
from datetime import date, datetime, timedelta, timezone

from .config import PolicyConfig
from .models import NodeAssessment
from .policy import GRADE_ORDER


_RESIDENTIAL_ORDER = {"unknown": 0, "probable": 1, "confirmed": 2}


def _c_grade_risk_key(assessment: NodeAssessment) -> tuple[object, ...]:
    """Prefer the least risky usable fallback before considering total score."""
    if assessment.evaluation.overall_grade != "C":
        return (0, 0.0, 0)
    tor = any(
        reason in {"tor-exit", "claude-tor-exit"}
        for reason in assessment.evaluation.reasons
    )
    high_risk_or_dnsbl = any(
        reason.startswith(
            (
                "dnsbl-redline:",
                "multiple-high-risk-sources:",
                "claude-multiple-high-risk-sources:",
            )
        )
        for reason in assessment.evaluation.reasons
    )
    consensus = any(
        reason in {"risk-consensus-severe", "claude-risk-consensus-severe"}
        for reason in assessment.evaluation.reasons
    )
    severe_reasons = sum(
        1
        for reason in assessment.evaluation.reasons
        if reason == "tor-exit"
        or reason == "claude-tor-exit"
        or reason == "risk-consensus-severe"
        or reason == "claude-risk-consensus-severe"
        or reason.startswith("dnsbl-redline:")
        or reason.startswith("multiple-high-risk-sources:")
        or reason.startswith("claude-multiple-high-risk-sources:")
    )
    return (
        GRADE_ORDER.get(assessment.evaluation.risk_grade, 2),
        3 if tor else (2 if high_risk_or_dnsbl else (1 if consensus else 0)),
        severe_reasons,
        -float(assessment.evaluation.components.get("risk", 0.0) or 0.0),
    )


def ranking_key(assessment: NodeAssessment) -> tuple[object, ...]:
    latency = assessment.quick.latency_ms
    return (
        0 if assessment.quick.available else 1,
        GRADE_ORDER.get(assessment.evaluation.overall_grade, 2),
        *_c_grade_risk_key(assessment),
        -assessment.evaluation.score,
        latency if latency is not None else float("inf"),
        assessment.node.key,
    )


def complete_ranking_key(
    assessment: NodeAssessment, unavailable_replace_after_runs: int = 3
) -> tuple[object, ...]:
    del unavailable_replace_after_runs
    return ranking_key(assessment)


def _fresh_better_grade(candidate: NodeAssessment, incumbent: NodeAssessment) -> bool:
    return bool(
        candidate.quick.available
        and candidate.fresh_full_completed
        and candidate.fresh_full_usable
        and candidate.evidence_valid
        and GRADE_ORDER.get(candidate.evaluation.overall_grade, 2)
        < GRADE_ORDER.get(incumbent.evaluation.overall_grade, 2)
    )


def assign_region_slots(
    mode: str,
    assessments: Iterable[NodeAssessment],
    previous_slots: dict[str, str] | None,
    slot_count: int = 3,
    unavailable_replace_after_runs: int = 3,
) -> tuple[dict[str, str], list[str], dict[str, str]]:
    del unavailable_replace_after_runs
    items = list(assessments)
    ranked = sorted(items, key=ranking_key)
    available = [item for item in ranked if item.quick.available]
    rejected = {
        item.node.key: ";".join(item.evaluation.reasons) or "severe-quality"
        for item in items
        if item.evaluation.redline
    }

    if mode == "rebuild":
        chosen = available[:slot_count]
        slots = {str(index + 1): item.node.key for index, item in enumerate(chosen)}
    elif mode == "maintenance":
        previous_slots = previous_slots or {}
        by_key = {item.node.key: item for item in items}
        slots: dict[str, str] = {}
        used: set[str] = set()
        missing: list[str] = []
        for index in range(1, slot_count + 1):
            slot = str(index)
            key = str(previous_slots.get(slot) or "")
            current = by_key.get(key)
            preserve = bool(key and current is not None and key not in used)
            if preserve and current is not None and not current.quick.available:
                preserve = current.unavailable_grace_active
            if preserve:
                slots[slot] = key
                used.add(key)
            else:
                missing.append(slot)

        # Required vacancy/unavailability replacements consume candidates first.
        # Every healthy C incumbent released afterwards must have its own fresh
        # better candidate, preventing one challenger from cascading through slots.
        candidates = [item for item in available if item.node.key not in used]
        for slot, candidate in zip(missing, candidates):
            slots[slot] = candidate.node.key
            used.add(candidate.node.key)

        challengers = [item for item in available if item.node.key not in used]
        severe_slots: list[tuple[str, NodeAssessment]] = []
        for slot, key in slots.items():
            incumbent = by_key.get(key)
            if (
                incumbent is None
                or not incumbent.quick.available
                or incumbent.evaluation.overall_grade != "C"
            ):
                continue
            severe_slots.append((slot, incumbent))
        for slot, incumbent in sorted(
            severe_slots,
            key=lambda value: ranking_key(value[1]),
            reverse=True,
        ):
            candidate_index = next(
                (
                    index
                    for index, candidate in enumerate(challengers)
                    if _fresh_better_grade(candidate, incumbent)
                ),
                None,
            )
            if candidate_index is None:
                continue
            candidate = challengers.pop(candidate_index)
            used.discard(incumbent.node.key)
            slots[slot] = candidate.node.key
            used.add(candidate.node.key)
    else:
        raise ValueError(f"unsupported mode: {mode}")

    assigned = set(slots.values())
    dynamic = [item.node.key for item in ranked if item.node.key not in assigned]
    return slots, dynamic, rejected


def assign_all_regions(
    mode: str,
    assessments: list[NodeAssessment],
    previous: dict[str, dict[str, str]],
    slot_count: int,
    region_order: list[str] | None = None,
    previous_nodes: dict[str, dict[str, object]] | None = None,
    policy: PolicyConfig | None = None,
    previous_promotion_cooldown_at: dict[str, str] | None = None,
    now: datetime | None = None,
    previous_frozen_order: dict[str, list[str]] | None = None,
    frozen_regions: dict[str, str] | None = None,
    previous_ranked_order: dict[str, list[str]] | None = None,
    previous_rejected: dict[str, dict[str, str]] | None = None,
) -> tuple[dict[str, dict[str, object]], list[dict[str, str]]]:
    grouped: dict[str, list[NodeAssessment]] = {}
    for assessment in assessments:
        grouped.setdefault(assessment.node.region, []).append(assessment)
    by_key = {assessment.node.key: assessment for assessment in assessments}
    previous_nodes = previous_nodes or {}
    previous_promotion_cooldown_at = previous_promotion_cooldown_at or {}
    previous_frozen_order = previous_frozen_order or {}
    previous_ranked_order = previous_ranked_order or {}
    previous_rejected = previous_rejected or {}
    frozen_regions = frozen_regions or {}
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    regions: dict[str, dict[str, object]] = {}
    changes: list[dict[str, str]] = []
    configured_order = region_order or []
    present_regions = set(grouped) | set(previous)
    ordered_regions = [region for region in configured_order if region in present_regions]
    ordered_regions.extend(
        region for region in sorted(present_regions)
        if region not in ordered_regions and region != "other"
    )
    if "other" in present_regions and "other" not in ordered_regions:
        ordered_regions.append("other")

    for region in ordered_regions:
        region_items = grouped.get(region, [])
        region_slot_count = 0 if region == "other" else slot_count
        old = previous.get(region, {})
        if region in frozen_regions:
            slots = {str(slot): str(key) for slot, key in old.items() if key}
            current_keys = {item.node.key for item in region_items}
            prior_order = previous_ranked_order.get(region, previous_frozen_order.get(region, []))
            ranked = [str(key) for key in prior_order if str(key) in current_keys and str(key) not in slots.values()]
            seen = set(ranked) | set(slots.values())
            ranked.extend(item.node.key for item in region_items if item.node.key not in seen)
            rejected = {
                str(key): str(reason)
                for key, reason in previous_rejected.get(region, {}).items()
                if str(key) in current_keys
            }
            promotion_slots: set[str] = set()
        else:
            slots, ranked, rejected = assign_region_slots(mode, region_items, old, region_slot_count)
            if mode == "maintenance" and region == "other":
                current_keys = {item.node.key for item in region_items}
                frozen: list[str] = []
                seen: set[str] = set()
                for key in previous_frozen_order.get(region, []):
                    key = str(key)
                    if key in current_keys and key not in seen:
                        frozen.append(key)
                        seen.add(key)
                for item in region_items:
                    if item.node.key not in seen:
                        frozen.append(item.node.key)
                        seen.add(item.node.key)
                ranked = frozen

            required_slot_change = any(
                old.get(str(index), "") != slots.get(str(index), "")
                for index in range(1, region_slot_count + 1)
            )
            grace_active = any(
                item.unavailable_grace_active
                for item in region_items if item.node.key in slots.values()
            )
            promotion_slots = set()
            if mode == "maintenance" and region_slot_count and policy is not None and not required_slot_change and not grace_active:
                slots, promotion_slots = _apply_promotions(
                    slots,
                    region_items,
                    previous_promotion_cooldown_at.get(region, ""),
                    policy,
                    now,
                )
                assigned = set(slots.values())
                ranked = [item.node.key for item in sorted(region_items, key=ranking_key) if item.node.key not in assigned]

        regions[region] = {
            "stable_slots": slots,
            "stable_status": {
                slot: _stable_status(key, by_key.get(key), previous_nodes.get(key, {}))
                for slot, key in slots.items()
            },
            "ranked": ranked,
            "rejected": rejected,
            **({"outage_freeze": {"active": True, "reason": frozen_regions[region]}} if region in frozen_regions else {}),
        }
        if region in frozen_regions:
            continue

        for index in range(1, region_slot_count + 1):
            slot = str(index)
            before, after = old.get(slot, ""), slots.get(slot, "")
            if before == after:
                continue
            before_item = by_key.get(before)
            if mode == "rebuild":
                reason = "rebuild"
            elif slot in promotion_slots:
                reason = "superior-candidate"
            elif before and before_item is None:
                reason = "missing-from-inventory"
            elif before_item and not before_item.quick.available:
                reason = "confirmed-unavailable"
            elif before_item and before_item.evaluation.overall_grade == "C":
                reason = "quality-severe"
            else:
                reason = "vacant-slot-fill"
            before_prior = previous_nodes.get(before, {})
            after_prior = previous_nodes.get(after, {})
            after_item = by_key.get(after)
            before_score = before_item.evaluation.score if before_item else float(before_prior.get("last_score") or 0)
            after_score = after_item.evaluation.score if after_item else float(after_prior.get("last_score") or 0)
            changes.append({
                "region": region,
                "slot": slot,
                "before": before,
                "after": after,
                "before_name": before_item.node.name if before_item else str(before_prior.get("name") or "empty"),
                "after_name": after_item.node.name if after_item else str(after_prior.get("name") or "empty"),
                "before_score": f"{before_score:.2f}",
                "after_score": f"{after_score:.2f}",
                "score_margin": f"{after_score - before_score:.2f}",
                "candidate_healthy_days": str(after_item.healthy_streak_days if after_item else 0),
                "redline_reasons": ";".join(before_item.evaluation.reasons if before_item else []),
                "reason": reason,
            })
    return regions, changes


def _parse_changed_at(value: str) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _history_by_day(item: NodeAssessment) -> dict[str, dict[str, object]]:
    return {
        str(entry.get("day")): entry
        for entry in item.daily_quality_history
        if isinstance(entry, dict) and entry.get("day") and entry.get("evidence_valid")
    }


def _promotion_margin_holds(candidate: NodeAssessment, incumbent: NodeAssessment, days: int, margin: float) -> bool:
    candidate_history = _history_by_day(candidate)
    incumbent_history = _history_by_day(incumbent)
    common = sorted(set(candidate_history) & set(incumbent_history), reverse=True)
    if len(common) < days:
        return False
    compared = common[:days]
    try:
        dates = [date.fromisoformat(value) for value in compared]
    except ValueError:
        return False
    if any(dates[index] - dates[index + 1] != timedelta(days=1) for index in range(len(dates) - 1)):
        return False
    for day in compared:
        try:
            candidate_score = float(candidate_history[day].get("score"))
            incumbent_score = float(incumbent_history[day].get("score"))
        except (TypeError, ValueError):
            return False
        if candidate_score < incumbent_score + margin:
            return False
    return True


def _apply_promotions(
    original_slots: dict[str, str],
    assessments: list[NodeAssessment],
    promotion_cooldown_at: str,
    policy: PolicyConfig,
    now: datetime,
) -> tuple[dict[str, str], set[str]]:
    if not policy.promotion_enabled or policy.promotion_max_per_region_per_run <= 0:
        return original_slots, set()
    last_promotion = _parse_changed_at(promotion_cooldown_at)
    if last_promotion is not None:
        local_last_promotion = (
            last_promotion.astimezone(now.tzinfo)
            if now.tzinfo is not None
            else last_promotion
        )
        if (
            now.date() - local_last_promotion.date()
        ).days < policy.promotion_cooldown_days:
            return original_slots, set()

    slots = dict(original_slots)
    by_key = {item.node.key: item for item in assessments}
    promoted: set[str] = set()
    for _ in range(policy.promotion_max_per_region_per_run):
        incumbent_options: list[tuple[tuple[object, ...], str, NodeAssessment]] = []
        for slot, key in slots.items():
            item = by_key.get(key)
            if item is None or not item.quick.available:
                continue
            latency = item.quick.latency_ms if item.quick.latency_ms is not None else 0.0
            incumbent_options.append(((-GRADE_ORDER.get(item.evaluation.overall_grade, 2), item.evaluation.score, -latency, slot), slot, item))
        if not incumbent_options:
            break
        _, weakest_slot, incumbent = min(incumbent_options, key=lambda value: value[0])
        if not incumbent.evidence_valid or not incumbent.fresh_full_completed or not incumbent.fresh_full_usable:
            break
        assigned = set(slots.values())
        candidates = sorted((
            item for item in assessments
            if item.node.key not in assigned
            and item.quick.available
            and item.fresh_full_completed
            and item.fresh_full_usable
            and item.evidence_valid
            and item.healthy_streak_days >= policy.promotion_min_healthy_days
            and GRADE_ORDER.get(item.evaluation.overall_grade, 2) <= GRADE_ORDER.get(incumbent.evaluation.overall_grade, 2)
            and GRADE_ORDER.get(item.evaluation.ai_grade, 2) <= GRADE_ORDER.get(incumbent.evaluation.ai_grade, 2)
            and GRADE_ORDER.get(item.evaluation.risk_grade, 2) <= GRADE_ORDER.get(incumbent.evaluation.risk_grade, 2)
            and _RESIDENTIAL_ORDER.get(item.evaluation.residential_grade, 0) >= _RESIDENTIAL_ORDER.get(incumbent.evaluation.residential_grade, 0)
        ), key=ranking_key)
        candidate = next((item for item in candidates if _promotion_margin_holds(item, incumbent, policy.promotion_evidence_days, policy.promotion_score_margin)), None)
        if candidate is None:
            break
        slots[weakest_slot] = candidate.node.key
        promoted.add(weakest_slot)
    return slots, promoted


def _stable_status(key: str, assessment: NodeAssessment | None, previous: dict[str, object]) -> dict[str, object]:
    if assessment is None:
        return {
            "node_key": key,
            "name": str(previous.get("name") or "unknown"),
            "status": "absent",
            "reasons": ["missing-from-inventory"],
            "last_exit_ip": str(previous.get("last_exit_ip") or ""),
            "last_full_checked_at": str(previous.get("last_full_checked_at") or ""),
            "score": float(previous.get("last_score") or 0),
            "healthy_streak_days": int(previous.get("healthy_streak_days", 0) or 0),
            "consecutive_unavailable_valid_days": int(previous.get("consecutive_unavailable_valid_days", 0) or 0),
            "unavailable_grace_active": bool(previous.get("unavailable_grace_active")),
            "overall_grade": str(previous.get("overall_grade") or "B"),
        }
    if not assessment.quick.available:
        status = "protected-unavailable" if assessment.unavailable_grace_active else "unavailable"
    elif assessment.evaluation.eligible and not assessment.evaluation.reasons:
        status = "healthy"
    elif assessment.evaluation.eligible:
        status = "degraded"
    else:
        status = assessment.evaluation.decision
    return {
        "node_key": key,
        "name": assessment.node.name,
        "status": status,
        "reasons": list(assessment.evaluation.reasons),
        "last_exit_ip": str(assessment.quick.exit_ip or previous.get("last_exit_ip") or ""),
        "last_full_checked_at": str((assessment.full.checked_at if assessment.full and assessment.full.completed else "") or previous.get("last_full_checked_at") or ""),
        "score": float(previous.get("last_score") or 0) if not assessment.quick.available else assessment.evaluation.score,
        "healthy_streak_days": assessment.healthy_streak_days,
        "consecutive_unavailable_valid_days": assessment.consecutive_unavailable_valid_days,
        "unavailable_grace_active": assessment.unavailable_grace_active,
        "ai_grade": assessment.evaluation.ai_grade,
        "risk_grade": assessment.evaluation.risk_grade,
        "overall_grade": assessment.evaluation.overall_grade,
        "residential_grade": assessment.evaluation.residential_grade,
        "components": assessment.evaluation.components,
    }
