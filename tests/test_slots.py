from datetime import datetime, timezone

from node_health.config import PolicyConfig
from node_health.models import Evaluation, FullResult, Node, NodeAssessment, QuickResult
from node_health.slots import assign_all_regions, assign_region_slots


def assessment(
    key: str,
    score: float,
    *,
    decision: str = "eligible",
    completed: bool = True,
    confidence: str = "provisional",
    passes: int = 1,
    available: bool = True,
    chatgpt: str = "Yes",
    fresh_full_completed: bool = True,
    fresh_full_usable: bool = True,
    unavailable_runs: int = 0,
):
    full = FullResult(
        completed=completed,
        risk_sources={"one": "low", "two": "low"} if completed else {},
        details={"Media": {"ChatGPT": {"Status": chatgpt}}},
    )
    return NodeAssessment(
        node=Node(key, key, "united-states", {"name": key}),
        quick=QuickResult(available, exit_ip="8.8.8.8", latency_ms=score),
        full=full,
        evaluation=Evaluation(
            decision,
            score,
            confidence if completed else "low",
            [] if decision == "eligible" else [decision],
        ),
        consecutive_full_passes=passes,
        consecutive_unavailable_runs=unavailable_runs,
        fresh_full_completed=fresh_full_completed and completed,
        fresh_full_usable=fresh_full_usable and fresh_full_completed and completed,
        fresh_full_attempt=full,
    )


def test_maintenance_preserves_healthy_slots_and_replaces_only_failed_slot():
    items = [assessment(chr(97 + index), 100 - index) for index in range(7)]
    # b is no longer eligible; d is the highest unassigned candidate.
    items[1] = assessment("b", 99, decision="rejected")
    previous = {"1": "a", "2": "b", "3": "c"}
    slots, dynamic, rejected = assign_region_slots("maintenance", items, previous, 3)
    assert slots == {"1": "a", "2": "d", "3": "c"}
    assert dynamic == ["e", "f", "g"]
    assert rejected == {"b": "rejected"}


def test_low_confidence_node_never_fills_stable_slot():
    items = [assessment("a", 90, completed=False), assessment("b", 80)]
    slots, dynamic, _ = assign_region_slots("maintenance", items, {}, 3)
    assert slots == {"1": "b"}
    assert dynamic == ["a"]


def test_rebuild_reselects_top_three_without_old_slot_bias():
    items = [assessment(chr(97 + index), score) for index, score in enumerate([10, 20, 30, 40, 50, 60])]
    previous = {"1": "a", "2": "b", "3": "c"}
    slots, dynamic, _ = assign_region_slots("rebuild", items, previous, 3)
    assert slots == {"1": "f", "2": "e", "3": "d"}
    assert dynamic == ["c", "b", "a"]


def test_fresh_full_failure_cannot_fill_or_rebuild_a_stable_slot():
    old = assessment("old", 10, decision="rejected")
    cached_candidate = assessment(
        "candidate",
        99,
        confidence="high",
        passes=3,
        fresh_full_completed=False,
    )
    slots, dynamic, _ = assign_region_slots(
        "maintenance", [old, cached_candidate], {"1": "old"}, 1
    )
    assert slots == {}
    assert dynamic == ["candidate"]

    slots, dynamic, _ = assign_region_slots(
        "rebuild", [cached_candidate], {"1": "old"}, 1
    )
    assert slots == {}
    assert dynamic == ["candidate"]


def test_unchanged_rebuild_does_not_emit_slot_change_alerts():
    items = [assessment(chr(97 + index), score) for index, score in enumerate([10, 20, 30, 40, 50])]
    previous = {"united-states": {"1": "e", "2": "d", "3": "c"}}
    _, changes = assign_all_regions(
        "rebuild", items, previous, 3, ["united-states"]
    )
    assert changes == []


def test_missing_entire_region_releases_absent_slots_in_maintenance():
    previous = {"united-states": {"1": "a", "2": "b"}}
    regions, changes = assign_all_regions(
        "maintenance", [], previous, 3, ["united-states", "other"]
    )
    assert regions["united-states"]["stable_slots"] == {}
    assert [change["reason"] for change in changes] == [
        "missing-from-inventory",
        "missing-from-inventory",
    ]


def test_unavailable_stable_is_allowlisted_but_dynamic_unavailable_is_rejected():
    items = [
        assessment("a", 0, decision="unavailable", available=False),
        assessment("b", 80),
        assessment("c", 0, decision="unavailable", available=False),
    ]
    slots, dynamic, rejected = assign_region_slots("maintenance", items, {"1": "a"}, 3)
    assert slots["1"] == "a"
    assert "a" not in rejected
    assert rejected["c"] == "unavailable"
    assert dynamic == []


def test_unavailable_stable_is_replaced_only_at_consecutive_failure_threshold():
    candidate = assessment("b", 80, confidence="high", passes=3)
    policy = PolicyConfig(stable_unavailable_replace_after_runs=3)
    previous = {"united-states": {"1": "a"}}

    for unavailable_runs in (1, 2):
        current = assessment(
            "a",
            0,
            decision="unavailable",
            available=False,
            unavailable_runs=unavailable_runs,
        )
        regions, changes = assign_all_regions(
            "maintenance",
            [current, candidate],
            previous,
            1,
            ["united-states"],
            {"a": {"last_score": 90}, "b": {"last_score": 80}},
            policy,
        )
        assert regions["united-states"]["stable_slots"]["1"] == "a"
        assert changes == []

    current = assessment(
        "a",
        0,
        decision="unavailable",
        available=False,
        unavailable_runs=3,
    )
    regions, changes = assign_all_regions(
        "maintenance",
        [current, candidate],
        previous,
        1,
        ["united-states"],
        {"a": {"last_score": 90}, "b": {"last_score": 80}},
        policy,
    )
    assert regions["united-states"]["stable_slots"]["1"] == "b"
    assert [change["reason"] for change in changes] == ["repeated-unavailable"]


def test_conservative_promotion_requires_two_round_margin_and_respects_cooldown():
    items = [
        assessment("a", 50, confidence="high", passes=3),
        assessment("b", 60, confidence="high", passes=3),
        assessment("c", 61, confidence="high", passes=3),
        assessment("f", 80, confidence="high", passes=2),
        assessment("g", 79, confidence="high", passes=2),
    ]
    previous_slots = {
        "united-states": {"1": "a", "2": "b", "3": "c"}
    }
    previous_nodes = {
        item.node.key: {"last_score": item.evaluation.score} for item in items
    }
    policy = PolicyConfig(
        promotion_enabled=True,
        promotion_score_margin=12,
        promotion_min_full_passes=2,
        promotion_max_per_region_per_run=1,
        promotion_cooldown_days=7,
    )
    regions, changes = assign_all_regions(
        "maintenance",
        items,
        previous_slots,
        3,
        ["united-states"],
        previous_nodes,
        policy,
        {"united-states": {"1": "2026-07-01T00:00:00+00:00"}},
        datetime(2026, 7, 24, tzinfo=timezone.utc),
    )
    assert regions["united-states"]["stable_slots"]["1"] == "f"
    assert [change["reason"] for change in changes] == ["superior-candidate"]
    assert changes[0]["before_name"] == "a"
    assert changes[0]["after_name"] == "f"
    assert changes[0]["score_margin"] == "30.00"
    assert changes[0]["candidate_full_passes"] == "2"
    assert "a" in regions["united-states"]["ranked"]
    assert regions["united-states"]["stable_slots"]["2"] == "b"

    cooled, changes = assign_all_regions(
        "maintenance",
        items,
        previous_slots,
        3,
        ["united-states"],
        previous_nodes,
        policy,
        {"united-states": {"1": "2026-07-23T00:00:00+00:00"}},
        datetime(2026, 7, 24, tzinfo=timezone.utc),
    )
    assert cooled["united-states"]["stable_slots"] == previous_slots["united-states"]
    assert changes == []


def test_promotion_waits_when_the_weakest_stable_slot_lacks_fresh_high_evidence():
    previous_slots = {
        "united-states": {"1": "a", "2": "b", "3": "c"}
    }
    policy = PolicyConfig(
        promotion_enabled=True,
        promotion_score_margin=12,
        promotion_min_full_passes=2,
        promotion_max_per_region_per_run=1,
        promotion_cooldown_days=7,
    )
    previous_nodes = {
        key: {"last_score": score}
        for key, score in {"a": 50, "b": 60, "c": 61, "f": 80}.items()
    }

    for weakest in (
        assessment("a", 50, confidence="high", passes=3, fresh_full_usable=False),
        assessment("a", 50, confidence="provisional", passes=3),
    ):
        items = [
            weakest,
            assessment("b", 60, confidence="high", passes=3),
            assessment("c", 61, confidence="high", passes=3),
            assessment("f", 80, confidence="high", passes=2),
        ]
        regions, changes = assign_all_regions(
            "maintenance",
            items,
            previous_slots,
            3,
            ["united-states"],
            previous_nodes,
            policy,
            {"united-states": {"1": "2026-07-01T00:00:00+00:00"}},
            datetime(2026, 7, 24, tzinfo=timezone.utc),
        )
        assert regions["united-states"]["stable_slots"] == previous_slots["united-states"]
        assert changes == []


def test_promotion_requires_fresh_usable_evidence_from_the_candidate():
    items = [
        assessment("a", 50, confidence="high", passes=3),
        assessment("b", 60, confidence="high", passes=3),
        assessment("c", 61, confidence="high", passes=3),
        assessment("f", 80, confidence="high", passes=3, fresh_full_usable=False),
    ]
    previous_slots = {
        "united-states": {"1": "a", "2": "b", "3": "c"}
    }
    previous_nodes = {
        item.node.key: {"last_score": item.evaluation.score} for item in items
    }
    policy = PolicyConfig(
        promotion_enabled=True,
        promotion_score_margin=12,
        promotion_min_full_passes=2,
        promotion_max_per_region_per_run=1,
        promotion_cooldown_days=7,
    )

    regions, changes = assign_all_regions(
        "maintenance",
        items,
        previous_slots,
        3,
        ["united-states"],
        previous_nodes,
        policy,
        {"united-states": {"1": "2026-07-01T00:00:00+00:00"}},
        datetime(2026, 7, 24, tzinfo=timezone.utc),
    )

    assert regions["united-states"]["stable_slots"] == previous_slots["united-states"]
    assert changes == []


def test_redline_replacement_blocks_same_run_promotion_after_cooldown():
    items = [
        assessment("a", 50, confidence="high", passes=3),
        assessment("b", 60, decision="rejected", confidence="rejected", passes=0),
        assessment("c", 61, confidence="high", passes=3),
        assessment("f", 80, confidence="high", passes=2),
        assessment("g", 79, confidence="high", passes=2),
    ]
    previous_slots = {
        "united-states": {"1": "a", "2": "b", "3": "c"}
    }
    previous_nodes = {
        item.node.key: {"last_score": item.evaluation.score} for item in items
    }
    policy = PolicyConfig(
        promotion_enabled=True,
        promotion_score_margin=12,
        promotion_min_full_passes=2,
        promotion_max_per_region_per_run=1,
        promotion_cooldown_days=7,
    )

    regions, changes = assign_all_regions(
        "maintenance",
        items,
        previous_slots,
        3,
        ["united-states"],
        previous_nodes,
        policy,
        {"united-states": {"1": "2026-07-01T00:00:00+00:00"}},
        datetime(2026, 7, 24, tzinfo=timezone.utc),
    )

    assert regions["united-states"]["stable_slots"] == {
        "1": "a",
        "2": "f",
        "3": "c",
    }
    assert [change["reason"] for change in changes] == ["quality-redline"]


def test_vacant_slot_fill_blocks_same_run_promotion_after_cooldown():
    items = [
        assessment("a", 50, confidence="high", passes=3),
        assessment("b", 60, confidence="high", passes=3),
        assessment("c", 61, confidence="high", passes=3),
        assessment("f", 80, confidence="high", passes=2),
        assessment("g", 79, confidence="high", passes=2),
    ]
    previous_slots = {
        "united-states": {"1": "a", "2": "b"}
    }
    previous_nodes = {
        item.node.key: {"last_score": item.evaluation.score} for item in items
    }
    policy = PolicyConfig(
        promotion_enabled=True,
        promotion_score_margin=12,
        promotion_min_full_passes=2,
        promotion_max_per_region_per_run=1,
        promotion_cooldown_days=7,
    )

    regions, changes = assign_all_regions(
        "maintenance",
        items,
        previous_slots,
        3,
        ["united-states"],
        previous_nodes,
        policy,
        {"united-states": {"1": "2026-07-01T00:00:00+00:00"}},
        datetime(2026, 7, 24, tzinfo=timezone.utc),
    )

    assert regions["united-states"]["stable_slots"] == {
        "1": "a",
        "2": "b",
        "3": "f",
    }
    assert [change["reason"] for change in changes] == ["vacant-slot-fill"]
