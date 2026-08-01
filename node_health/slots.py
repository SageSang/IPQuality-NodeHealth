from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timedelta, timezone

from .config import PolicyConfig
from .models import NodeAssessment
from .policy import chatgpt_explicitly_allowed


_CONFIDENCE_ORDER = {
    "high": 0,
    "provisional": 1,
    "low": 2,
    "unavailable": 3,
    "rejected": 4,
}


def ranking_key(assessment: NodeAssessment) -> tuple[object, ...]:
    latency = assessment.quick.latency_ms
    return (
        _CONFIDENCE_ORDER.get(assessment.evaluation.confidence, 9),
        -assessment.evaluation.score,
        latency if latency is not None else float("inf"),
        assessment.node.key,
    )


def assign_region_slots(
    mode: str,
    assessments: Iterable[NodeAssessment],
    previous_slots: dict[str, str] | None,
    slot_count: int = 3,
    unavailable_replace_after_runs: int = 3,
) -> tuple[dict[str, str], list[str], dict[str, str]]:
    items = list(assessments)
    eligible = {item.node.key: item for item in items if item.evaluation.eligible}
    ranked_eligible = sorted(eligible.values(), key=ranking_key)
    # Unreachable nodes are retained as a degraded tail. They must not fill
    # new stable slots, but a transient probe failure must not delete them.
    unavailable = sorted(
        [
            item
            for item in items
            if item.evaluation.decision == "unavailable"
            and not item.evaluation.redline
        ],
        key=ranking_key,
    )
    ranked = ranked_eligible + unavailable
    qualified = [
        item
        for item in ranked
        if item.full is not None
        and item.full.completed
        and item.fresh_full_completed
        and chatgpt_explicitly_allowed(item.full)
        and item.evaluation.confidence in {"high", "provisional"}
    ]
    rejected = {
        item.node.key: ";".join(item.evaluation.reasons) or "rejected"
        for item in items
        if item.evaluation.redline
    }

    if mode == "rebuild":
        chosen = qualified[:slot_count]
        slots = {str(index + 1): item.node.key for index, item in enumerate(chosen)}
    elif mode == "maintenance":
        previous_slots = previous_slots or {}
        by_key = {item.node.key: item for item in items}
        slots: dict[str, str] = {}
        used: set[str] = set()
        missing: list[str] = []
        for index in range(1, slot_count + 1):
            slot = str(index)
            key = previous_slots.get(slot, "")
            current = by_key.get(key)
            preserve = bool(key) and current is not None and not current.evaluation.redline
            if (
                preserve
                and not current.quick.available
                and current.consecutive_unavailable_runs >= unavailable_replace_after_runs
            ):
                preserve = False
            if preserve and key not in used:
                slots[slot] = key
                used.add(key)
                # Stable temporary failures remain allowlisted. Dynamic
                # unavailable nodes remain in the ranked tail.
                rejected.pop(key, None)
            else:
                missing.append(slot)
        candidates = [item for item in qualified if item.node.key not in used]
        for slot, candidate in zip(missing, candidates):
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
    previous_slot_changed_at: dict[str, dict[str, str]] | None = None,
    now: datetime | None = None,
) -> tuple[dict[str, dict[str, object]], list[dict[str, str]]]:
    grouped: dict[str, list[NodeAssessment]] = {}
    for assessment in assessments:
        grouped.setdefault(assessment.node.region, []).append(assessment)
    by_key = {assessment.node.key: assessment for assessment in assessments}
    previous_nodes = previous_nodes or {}
    previous_slot_changed_at = previous_slot_changed_at or {}
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    regions: dict[str, dict[str, object]] = {}
    changes: list[dict[str, str]] = []
    configured_order = region_order or []
    present_regions = set(grouped) | set(previous)
    ordered_regions = [region for region in configured_order if region in present_regions]
    ordered_regions.extend(
        region
        for region in sorted(present_regions)
        if region not in ordered_regions and region != "other"
    )
    if "other" in present_regions and "other" not in ordered_regions:
        ordered_regions.append("other")
    for region in ordered_regions:
        region_slot_count = 0 if region == "other" else slot_count
        slots, ranked, rejected = assign_region_slots(
            mode,
            grouped.get(region, []),
            previous.get(region, {}),
            region_slot_count,
            (
                policy.stable_unavailable_replace_after_runs
                if policy is not None
                else 3
            ),
        )
        old = previous.get(region, {})
        required_slot_change = any(
            old.get(str(index), "") != slots.get(str(index), "")
            for index in range(1, region_slot_count + 1)
        )
        promotion_slots: set[str] = set()
        if (
            mode == "maintenance"
            and region_slot_count
            and policy is not None
            and not required_slot_change
        ):
            slots, promotion_slots = _apply_promotions(
                slots,
                grouped.get(region, []),
                previous_slot_changed_at.get(region, {}),
                previous_nodes,
                policy,
                now,
            )
            assigned = set(slots.values())
            eligible_ranked = sorted(
                (
                    item
                    for item in grouped.get(region, [])
                    if item.evaluation.eligible and item.node.key not in assigned
                ),
                key=ranking_key,
            )
            unavailable_ranked = sorted(
                (
                    item
                    for item in grouped.get(region, [])
                    if item.evaluation.decision == "unavailable"
                    and not item.evaluation.redline
                    and item.node.key not in assigned
                ),
                key=ranking_key,
            )
            ranked = [item.node.key for item in eligible_ranked + unavailable_ranked]
        regions[region] = {
            "stable_slots": slots,
            "stable_status": {
                slot: _stable_status(key, by_key.get(key), previous_nodes.get(key, {}))
                for slot, key in slots.items()
            },
            "ranked": ranked,
            "rejected": rejected,
        }
        for index in range(1, region_slot_count + 1):
            slot = str(index)
            before, after = old.get(slot, ""), slots.get(slot, "")
            if mode == "rebuild" and before != after:
                reason = "rebuild"
            elif slot in promotion_slots:
                reason = "superior-candidate"
            elif before != after:
                before_assessment = by_key.get(before)
                reason = (
                    "missing-from-inventory"
                    if before and before_assessment is None
                    else (
                        "repeated-unavailable"
                        if before_assessment
                        and not before_assessment.quick.available
                        and policy is not None
                        and before_assessment.consecutive_unavailable_runs
                        >= policy.stable_unavailable_replace_after_runs
                        else (
                            "quality-redline"
                            if before_assessment and before_assessment.evaluation.redline
                            else "vacant-slot-fill"
                        )
                    )
                )
            else:
                continue
            if before != after:
                before_item = by_key.get(before)
                after_item = by_key.get(after)
                before_prior = previous_nodes.get(before, {})
                after_prior = previous_nodes.get(after, {})
                before_score = (
                    before_item.evaluation.score
                    if before_item is not None
                    else float(before_prior.get("last_score") or 0)
                )
                after_score = (
                    after_item.evaluation.score
                    if after_item is not None
                    else float(after_prior.get("last_score") or 0)
                )
                changes.append(
                    {
                        "region": region,
                        "slot": slot,
                        "before": before,
                        "after": after,
                        "before_name": (
                            before_item.node.name
                            if before_item is not None
                            else str(before_prior.get("name") or "unknown")
                        ) if before else "empty",
                        "after_name": (
                            after_item.node.name
                            if after_item is not None
                            else str(after_prior.get("name") or "unknown")
                        ) if after else "empty",
                        "before_score": f"{before_score:.2f}",
                        "after_score": f"{after_score:.2f}",
                        "score_margin": f"{after_score - before_score:.2f}",
                        "candidate_full_passes": str(
                            after_item.consecutive_full_passes if after_item is not None else 0
                        ),
                        "redline_reasons": ";".join(
                            before_item.evaluation.reasons if before_item is not None else []
                        ),
                        "reason": reason,
                    }
                )
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
    return parsed.astimezone(timezone.utc)


def _apply_promotions(
    original_slots: dict[str, str],
    assessments: list[NodeAssessment],
    changed_at: dict[str, str],
    previous_nodes: dict[str, dict[str, object]],
    policy: PolicyConfig,
    now: datetime,
) -> tuple[dict[str, str], set[str]]:
    if not policy.promotion_enabled or policy.promotion_max_per_region_per_run <= 0:
        return original_slots, set()
    slots = dict(original_slots)
    by_key = {item.node.key: item for item in assessments}
    promoted: set[str] = set()
    cooldown = timedelta(days=max(0, policy.promotion_cooldown_days))
    if any(
        changed is not None and now.astimezone(timezone.utc) - changed < cooldown
        for changed in (_parse_changed_at(value) for value in changed_at.values())
    ):
        return slots, promoted

    for _ in range(policy.promotion_max_per_region_per_run):
        weakest: list[tuple[float, str, NodeAssessment]] = []
        for slot, key in slots.items():
            if slot in promoted:
                continue
            item = by_key.get(key)
            if (
                item is None
                or not item.quick.available
                or not item.evaluation.eligible
            ):
                continue
            changed = _parse_changed_at(changed_at.get(slot, ""))
            if changed is not None and now.astimezone(timezone.utc) - changed < cooldown:
                continue
            weakest.append((item.evaluation.score, slot, item))
        if not weakest:
            break
        _, weakest_slot, weakest_item = min(weakest, key=lambda item: (item[0], item[1]))
        if (
            weakest_item.evaluation.confidence != "high"
            or not weakest_item.fresh_full_usable
            or weakest_item.full is None
            or not weakest_item.full.completed
            or not chatgpt_explicitly_allowed(weakest_item.full)
        ):
            break

        assigned = set(slots.values())
        candidates = sorted(
            (
                item
                for item in assessments
                if item.node.key not in assigned
                and item.quick.available
                and item.evaluation.eligible
                and item.evaluation.confidence == "high"
                and item.full is not None
                and item.full.completed
                and item.fresh_full_usable
                and chatgpt_explicitly_allowed(item.full)
                and item.consecutive_full_passes >= policy.promotion_min_full_passes
            ),
            key=ranking_key,
        )
        if not candidates:
            break
        stable_previous = previous_nodes.get(weakest_item.node.key, {}).get("last_score")
        candidate = None
        for possible in candidates:
            if (
                possible.evaluation.score
                < weakest_item.evaluation.score + policy.promotion_score_margin
            ):
                continue
            candidate_previous = previous_nodes.get(possible.node.key, {}).get("last_score")
            try:
                was_also_better = float(candidate_previous) >= (
                    float(stable_previous) + policy.promotion_score_margin
                )
            except (TypeError, ValueError):
                was_also_better = False
            if was_also_better:
                candidate = possible
                break
        if candidate is None:
            break
        slots[weakest_slot] = candidate.node.key
        promoted.add(weakest_slot)
    return slots, promoted


def _stable_status(
    key: str,
    assessment: NodeAssessment | None,
    previous: dict[str, object],
) -> dict[str, object]:
    if assessment is None:
        return {
            "node_key": key,
            "name": str(previous.get("name") or "unknown"),
            "status": "absent",
            "reasons": ["missing-from-inventory"],
            "last_exit_ip": str(previous.get("last_exit_ip") or ""),
            "last_full_checked_at": str(previous.get("last_full_checked_at") or ""),
            "score": float(previous.get("last_score") or 0),
            "consecutive_unavailable_runs": int(
                previous.get("consecutive_unavailable_runs", 0) or 0
            ),
        }
    if not assessment.quick.available:
        status = "unavailable"
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
        "last_full_checked_at": str(
            (assessment.full.checked_at if assessment.full and assessment.full.completed else "")
            or previous.get("last_full_checked_at")
            or ""
        ),
        "score": (
            float(previous.get("last_score") or 0)
            if status == "unavailable"
            else assessment.evaluation.score
        ),
        "consecutive_unavailable_runs": assessment.consecutive_unavailable_runs,
    }
