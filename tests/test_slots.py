from datetime import datetime, timezone
from itertools import product

import pytest

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


def previous_day_scores(items):
    return {
        item.node.key: {
            "last_score": item.evaluation.score,
            "score_day": "2026-07-23",
        }
        for item in items
    }


def test_maintenance_preserves_healthy_slots_and_replaces_only_failed_slot():
    items = [assessment(chr(97 + index), 100 - index) for index in range(7)]
    # b is no longer eligible; d is the highest unassigned candidate.
    items[1] = assessment("b", 99, decision="rejected")
    previous = {"1": "a", "2": "b", "3": "c"}
    slots, dynamic, rejected = assign_region_slots("maintenance", items, previous, 3)
    assert slots == {"1": "a", "2": "d", "3": "c"}
    assert dynamic == ["e", "f", "g", "b"]
    assert rejected == {"b": "rejected"}


def test_low_confidence_node_fills_stable_slot_in_degraded_mode():
    items = [assessment("a", 90, completed=False), assessment("b", 80)]
    slots, dynamic, _ = assign_region_slots("maintenance", items, {}, 3)
    assert slots == {"1": "b", "2": "a"}
    assert dynamic == []


def test_rebuild_reselects_top_three_without_old_slot_bias():
    items = [assessment(chr(97 + index), score) for index, score in enumerate([10, 20, 30, 40, 50, 60])]
    previous = {"1": "a", "2": "b", "3": "c"}
    slots, dynamic, _ = assign_region_slots("rebuild", items, previous, 3)
    assert slots == {"1": "f", "2": "e", "3": "d"}
    assert dynamic == ["c", "b", "a"]


@pytest.mark.parametrize("node_count", [0, 1, 2, 3])
def test_region_with_fewer_than_three_nodes_uses_every_node_once(node_count):
    items = [
        assessment(chr(97 + index), 100 - index, confidence="high", passes=2)
        for index in range(node_count)
    ]

    slots, dynamic, rejected = assign_region_slots(
        "maintenance", items, {}, 3
    )

    assert len(slots) == node_count
    assert list(slots) == [str(index) for index in range(1, node_count + 1)]
    assert len(set(slots.values())) == node_count
    assert dynamic == []
    assert rejected == {}


def test_slot_assignment_partition_invariants_across_status_combinations():
    factories = {
        "safe": lambda key: assessment(key, 80, confidence="high", passes=2),
        "risk": lambda key: assessment(
            key, 70, decision="rejected", confidence="rejected"
        ),
        "offline-two": lambda key: assessment(
            key,
            60,
            decision="unavailable",
            available=False,
            unavailable_runs=2,
        ),
        "offline-three": lambda key: assessment(
            key,
            90,
            decision="unavailable",
            available=False,
            unavailable_runs=3,
        ),
    }
    labels = tuple(factories)
    checked = 0
    for node_count in range(6):
        for statuses in product(labels, repeat=node_count):
            items = [
                factories[status](f"node-{index}")
                for index, status in enumerate(statuses)
            ]
            keys = {item.node.key for item in items}
            previous = {
                str(index + 1): item.node.key
                for index, item in enumerate(items[:3])
            }
            for mode in ("maintenance", "rebuild"):
                slots, dynamic, rejected = assign_region_slots(
                    mode, items, previous, 3, 3
                )
                ordered = [*slots.values(), *dynamic]
                assert len(slots) == min(3, node_count)
                assert len(ordered) == node_count
                assert len(set(ordered)) == node_count
                assert set(ordered) == keys
                assert set(rejected) == {
                    item.node.key
                    for item, status in zip(items, statuses)
                    if status == "risk"
                }
                if statuses.count("safe") >= 3:
                    assert all(
                        statuses[int(key.rsplit("-", 1)[-1])]
                        in (
                            {"safe", "offline-two"}
                            if mode == "maintenance"
                            else {"safe"}
                        )
                        for key in slots.values()
                    )
                checked += 1
    assert checked == 2730


def test_fresh_full_failure_fills_slot_only_when_no_safe_candidate_exists():
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
    assert slots == {"1": "candidate"}
    assert dynamic == ["old"]

    slots, dynamic, _ = assign_region_slots(
        "rebuild", [cached_candidate], {"1": "old"}, 1
    )
    assert slots == {"1": "candidate"}
    assert dynamic == []


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


def test_unavailable_nodes_are_retained_at_the_dynamic_tail():
    items = [
        assessment("a", 0, decision="unavailable", available=False),
        assessment("b", 80),
        assessment("c", 0, decision="unavailable", available=False),
    ]
    slots, dynamic, rejected = assign_region_slots("maintenance", items, {"1": "a"}, 1)
    assert slots["1"] == "a"
    assert "a" not in rejected
    assert rejected == {}
    assert dynamic == ["b", "c"]


def test_unavailable_nodes_keep_historical_scores_when_ordering_tail():
    items = [
        assessment("healthy", 20),
        assessment("old-high", 90, decision="unavailable", available=False),
        assessment("old-low", 10, decision="unavailable", available=False),
    ]
    slots, dynamic, rejected = assign_region_slots("maintenance", items, {"1": "healthy"}, 1)
    assert slots == {"1": "healthy"}
    assert dynamic == ["old-high", "old-low"]
    assert rejected == {}


def test_unavailable_stable_is_replaced_only_after_three_consecutive_failures():
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
    assert regions["united-states"]["ranked"] == ["a"]
    assert [change["reason"] for change in changes] == ["consecutive-unavailable"]


def test_three_failures_move_dynamic_node_behind_more_recent_failures():
    items = [
        assessment(
            "failed-three",
            95,
            decision="unavailable",
            available=False,
            unavailable_runs=3,
        ),
        assessment(
            "failed-two",
            10,
            decision="unavailable",
            available=False,
            unavailable_runs=2,
        ),
    ]

    slots, dynamic, _ = assign_region_slots("maintenance", items, {}, 0, 3)

    assert slots == {}
    assert dynamic == ["failed-two", "failed-three"]


def test_three_failure_fallback_still_fills_slots_when_safe_nodes_are_insufficient():
    items = [
        assessment("safe", 80, confidence="high", passes=2),
        assessment("risk", 70, decision="rejected", confidence="rejected"),
        assessment(
            "failed-three",
            95,
            decision="unavailable",
            available=False,
            unavailable_runs=3,
        ),
    ]

    slots, dynamic, _ = assign_region_slots(
        "maintenance",
        items,
        {"1": "failed-three", "2": "safe", "3": "risk"},
        3,
        3,
    )

    assert slots == {"1": "safe", "2": "risk", "3": "failed-three"}
    assert dynamic == []


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
    previous_nodes = previous_day_scores(items)
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
        {"united-states": "2026-07-01T00:00:00+00:00"},
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
        {"united-states": "2026-07-23T00:00:00+00:00"},
        datetime(2026, 7, 24, tzinfo=timezone.utc),
    )
    assert cooled["united-states"]["stable_slots"] == previous_slots["united-states"]
    assert changes == []


def test_default_promotion_requires_two_distinct_days_and_ten_point_margin():
    previous_slots = {"united-states": {"1": "a", "2": "b", "3": "c"}}
    policy = PolicyConfig()

    def run(candidate_score: float, passes: int):
        items = [
            assessment("a", 60, confidence="high", passes=3),
            assessment("b", 70, confidence="high", passes=3),
            assessment("c", 75, confidence="high", passes=3),
            assessment("f", candidate_score, confidence="high", passes=passes),
        ]
        previous_nodes = previous_day_scores(items)
        return assign_all_regions(
            "maintenance",
            items,
            previous_slots,
            3,
            ["united-states"],
            previous_nodes,
            policy,
            {"united-states": "2026-07-01T00:00:00+00:00"},
            datetime(2026, 7, 24, tzinfo=timezone.utc),
        )

    regions, changes = run(80, 1)
    assert regions["united-states"]["stable_slots"] == previous_slots["united-states"]
    assert changes == []

    regions, changes = run(69, 2)
    assert regions["united-states"]["stable_slots"] == previous_slots["united-states"]
    assert changes == []

    regions, changes = run(70, 2)
    assert regions["united-states"]["stable_slots"]["1"] == "f"
    assert [change["reason"] for change in changes] == ["superior-candidate"]


def test_degraded_rerank_fills_three_slots_and_keeps_rejected_nodes():
    items = [
        assessment("safe", 80, confidence="high", passes=3),
        assessment("risk-low", 70, decision="rejected", confidence="rejected"),
        assessment("risk-high", 30, decision="rejected", confidence="rejected"),
        assessment(
            "offline",
            99,
            decision="unavailable",
            confidence="unavailable",
            available=False,
        ),
    ]
    slots, dynamic, rejected = assign_region_slots(
        "maintenance",
        items,
        {"1": "risk-high", "2": "safe", "3": "offline"},
        3,
    )

    assert slots == {"1": "safe", "2": "risk-low", "3": "risk-high"}
    assert dynamic == ["offline"]
    assert set(rejected) == {"risk-low", "risk-high"}


def test_all_rejected_nodes_fill_slots_by_risk_then_score():
    items = [
        assessment("worst", 95, decision="rejected", confidence="rejected"),
        assessment("best", 90, decision="rejected", confidence="rejected"),
        assessment("middle", 50, decision="rejected", confidence="rejected"),
    ]
    items[0].evaluation.reasons = ["tor-exit", "multiple-high-risk-sources:a,b"]

    slots, dynamic, rejected = assign_region_slots("maintenance", items, {}, 3)

    assert slots == {"1": "best", "2": "middle", "3": "worst"}
    assert dynamic == []
    assert set(rejected) == {"best", "middle", "worst"}


def test_two_simultaneous_redlines_replace_only_their_slots_with_best_dynamic_nodes():
    items = [
        assessment("a", 90, decision="rejected", confidence="rejected"),
        assessment("b", 80, decision="rejected", confidence="rejected"),
        assessment("c", 70, confidence="high", passes=2),
        assessment("d", 100, confidence="high", passes=2),
        assessment("e", 95, confidence="high", passes=2),
    ]

    slots, dynamic, rejected = assign_region_slots(
        "maintenance", items, {"1": "a", "2": "b", "3": "c"}, 3
    )

    assert slots == {"1": "d", "2": "e", "3": "c"}
    assert dynamic == ["a", "b"]
    assert set(rejected) == {"a", "b"}


def test_promotion_requires_previous_day_margin_even_when_current_margin_is_large():
    items = [
        assessment("a", 60, confidence="high", passes=3),
        assessment("b", 70, confidence="high", passes=3),
        assessment("c", 75, confidence="high", passes=3),
        assessment("f", 90, confidence="high", passes=2),
    ]
    previous_slots = {"united-states": {"1": "a", "2": "b", "3": "c"}}
    previous_nodes = previous_day_scores(items)
    previous_nodes["a"]["last_score"] = 60
    previous_nodes["f"]["last_score"] = 69

    regions, changes = assign_all_regions(
        "maintenance",
        items,
        previous_slots,
        3,
        ["united-states"],
        previous_nodes,
        PolicyConfig(),
        {},
        datetime(2026, 7, 24, tzinfo=timezone.utc),
    )

    assert regions["united-states"]["stable_slots"] == previous_slots["united-states"]
    assert changes == []


@pytest.mark.parametrize(
    ("cooldown_at", "promotes"),
    [
        ("2026-07-22T00:00:01+00:00", False),
        ("2026-07-22T00:00:00+00:00", True),
    ],
)
def test_quality_promotion_cooldown_has_exact_two_day_boundary(cooldown_at, promotes):
    items = [
        assessment("a", 60, confidence="high", passes=3),
        assessment("b", 70, confidence="high", passes=3),
        assessment("c", 75, confidence="high", passes=3),
        assessment("f", 90, confidence="high", passes=2),
    ]
    previous_slots = {"united-states": {"1": "a", "2": "b", "3": "c"}}
    regions, changes = assign_all_regions(
        "maintenance",
        items,
        previous_slots,
        3,
        ["united-states"],
        previous_day_scores(items),
        PolicyConfig(),
        {"united-states": cooldown_at},
        datetime(2026, 7, 24, tzinfo=timezone.utc),
    )

    assert (regions["united-states"]["stable_slots"]["1"] == "f") is promotes
    assert bool(changes) is promotes


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
            {"united-states": "2026-07-01T00:00:00+00:00"},
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
        {"united-states": "2026-07-01T00:00:00+00:00"},
        datetime(2026, 7, 24, tzinfo=timezone.utc),
    )

    assert regions["united-states"]["stable_slots"] == previous_slots["united-states"]
    assert changes == []


def test_redline_replacement_ignores_active_quality_promotion_cooldown():
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
        {"united-states": "2026-07-24T00:00:00+00:00"},
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
        {"united-states": "2026-07-01T00:00:00+00:00"},
        datetime(2026, 7, 24, tzinfo=timezone.utc),
    )

    assert regions["united-states"]["stable_slots"] == {
        "1": "a",
        "2": "b",
        "3": "f",
    }
    assert [change["reason"] for change in changes] == ["vacant-slot-fill"]
