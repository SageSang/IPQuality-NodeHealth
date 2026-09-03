from __future__ import annotations

import copy
from collections import defaultdict
from collections.abc import Callable, Iterable
from typing import Any

from .models import Node


SCHEMA_VERSION = 2


def _state_identity(key: str, payload: dict[str, Any]) -> dict[str, str]:
    return {
        "key": key,
        "source_id": str(payload.get("source_id") or ""),
        "original_name": str(payload.get("original_name") or payload.get("name") or ""),
        "normalized_name": str(payload.get("normalized_name") or ""),
        "logical_id": str(payload.get("logical_id") or ""),
        "region": str(payload.get("region") or "other"),
    }


def _unique_stage(
    old_keys: set[str],
    new_keys: set[str],
    old_nodes: dict[str, dict[str, Any]],
    new_nodes: dict[str, Node],
    old_group: Callable[[dict[str, str]], tuple[str, ...] | None],
    new_group: Callable[[Node], tuple[str, ...] | None],
) -> list[tuple[str, str]]:
    old_buckets: dict[tuple[str, ...], list[str]] = defaultdict(list)
    new_buckets: dict[tuple[str, ...], list[str]] = defaultdict(list)
    for key in old_keys:
        group = old_group(_state_identity(key, old_nodes[key]))
        if group and all(group):
            old_buckets[group].append(key)
    for key in new_keys:
        group = new_group(new_nodes[key])
        if group and all(group):
            new_buckets[group].append(key)
    return [
        (old_buckets[group][0], new_buckets[group][0])
        for group in sorted(set(old_buckets) & set(new_buckets))
        if len(old_buckets[group]) == 1 and len(new_buckets[group]) == 1
    ]


def _safe_name_pair(old: dict[str, str], new: Node) -> bool:
    old_source = old["source_id"]
    return not old_source or not new.source_id or old_source == new.source_id


def reconcile_previous_state(
    nodes: Iterable[Node], previous: dict[str, Any]
) -> tuple[list[Node], dict[str, Any], list[dict[str, str]]]:
    """Move durable slot/baseline state onto safely matched new connections.

    Connection reputation is intentionally not migrated. A rotated endpoint
    inherits only its logical placement and previous score baseline; quick/full
    evidence must be rebuilt for the new connection.
    """

    current_nodes = {node.key: node for node in nodes}
    prior_nodes = previous.get("nodes") if isinstance(previous.get("nodes"), dict) else {}
    if previous.get("schema_version") != SCHEMA_VERSION or not prior_nodes:
        return list(current_nodes.values()), previous, []

    unmatched_old = set(prior_nodes) - set(current_nodes)
    unmatched_new = set(current_nodes) - set(prior_nodes)
    matches: list[tuple[str, str, str]] = []

    stages = [
        (
            "source-logical-id",
            lambda old: (old["source_id"], old["logical_id"]),
            lambda new: (new.source_id, new.logical_id),
        ),
        (
            "source-original-name",
            lambda old: (old["source_id"], old["region"], old["original_name"]),
            lambda new: (new.source_id, new.region, new.original_name),
        ),
    ]
    for method, old_group, new_group in stages:
        found = _unique_stage(
            unmatched_old,
            unmatched_new,
            prior_nodes,
            current_nodes,
            old_group,
            new_group,
        )
        for old_key, new_key in found:
            unmatched_old.remove(old_key)
            unmatched_new.remove(new_key)
            matches.append((old_key, new_key, method))

    fallback_stages = [
        (
            "region-original-name",
            lambda old: (old["region"], old["original_name"]),
            lambda new: (new.region, new.original_name),
        ),
        (
            "region-normalized-name",
            lambda old: (old["region"], old["normalized_name"]),
            lambda new: (new.region, new.normalized_name),
        ),
    ]
    for method, old_group, new_group in fallback_stages:
        found = _unique_stage(
            unmatched_old,
            unmatched_new,
            prior_nodes,
            current_nodes,
            old_group,
            new_group,
        )
        for old_key, new_key in found:
            old_identity = _state_identity(old_key, prior_nodes[old_key])
            if not _safe_name_pair(old_identity, current_nodes[new_key]):
                continue
            unmatched_old.remove(old_key)
            unmatched_new.remove(new_key)
            matches.append((old_key, new_key, method))

    migrated = copy.deepcopy(previous)
    migrated_nodes = dict(prior_nodes)
    remap = {old_key: new_key for old_key, new_key, _ in matches}
    events: list[dict[str, str]] = []
    resolved_nodes = dict(current_nodes)
    for old_key, new_key, method in matches:
        node = current_nodes[new_key]
        old = prior_nodes[old_key]
        inherited_region = str(old.get("region") or node.region)
        if inherited_region != node.region:
            node = Node(
                key=node.key,
                name=node.name,
                region=inherited_region,
                proxy=node.proxy,
                source_id=node.source_id,
                original_name=node.original_name,
                normalized_name=node.normalized_name,
                logical_id=node.logical_id,
            )
            resolved_nodes[new_key] = node
        migrated_nodes.pop(old_key, None)
        migrated_nodes[new_key] = {
            "name": node.name,
            "region": node.region,
            "source_id": node.source_id,
            "original_name": node.original_name,
            "normalized_name": node.normalized_name,
            "logical_id": node.logical_id,
            "last_score": float(old.get("last_score") or 0),
            "last_exit_ip": "",
            "last_country": "",
            "last_full_exit_ip": "",
            "last_full": None,
            "last_full_checked_at": "",
            "last_full_attempt_at": "",
            "last_full_attempt_error": "",
            "consecutive_full_passes": 0,
            "consecutive_unavailable_runs": 0,
            "healthy_streak_days": 0,
            "last_healthy_day": "",
            "consecutive_unavailable_valid_days": 0,
            "last_unavailable_day": "",
            "unavailable_grace_active": False,
            "daily_quality_history": [],
            "last_claude": None,
            "last_decision": "identity-rotated-pending",
            "current_status": "identity-rotated-pending",
            "identity_rotated_from": old_key,
        }
        events.append(
            {
                "event": "identity-rotated-name-match",
                "method": method,
                "source_id": node.source_id,
                "name": node.original_name,
                "region": node.region,
                "before": old_key,
                "after": new_key,
            }
        )

    migrated["nodes"] = migrated_nodes
    stable_slots = migrated.get("stable_slots")
    if isinstance(stable_slots, dict):
        migrated["stable_slots"] = {
            region: {
                str(slot): remap.get(str(key), str(key))
                for slot, key in slots.items()
            }
            for region, slots in stable_slots.items()
            if isinstance(slots, dict)
        }
    frozen_order = migrated.get("frozen_order")
    if isinstance(frozen_order, dict):
        migrated_ranked: dict[str, list[str]] = {}
        for region, keys in frozen_order.items():
            if not isinstance(keys, list):
                continue
            seen: set[str] = set()
            migrated_keys: list[str] = []
            for key in keys:
                mapped = remap.get(str(key), str(key))
                if mapped not in seen:
                    migrated_keys.append(mapped)
                    seen.add(mapped)
            migrated_ranked[str(region)] = migrated_keys
        migrated["frozen_order"] = migrated_ranked
    ranked_order = migrated.get("ranked_order")
    if isinstance(ranked_order, dict):
        migrated_ranked = {}
        for region, keys in ranked_order.items():
            if not isinstance(keys, list):
                continue
            seen = set()
            migrated_keys = []
            for key in keys:
                mapped = remap.get(str(key), str(key))
                if mapped not in seen:
                    migrated_keys.append(mapped)
                    seen.add(mapped)
            migrated_ranked[str(region)] = migrated_keys
        migrated["ranked_order"] = migrated_ranked
    baselines = migrated.get("availability_baselines")
    if isinstance(baselines, dict):
        migrated_baselines: dict[str, Any] = {}
        for scope, payload in baselines.items():
            if not isinstance(payload, dict):
                continue
            keys = payload.get("node_keys")
            migrated_baselines[str(scope)] = {
                **payload,
                **(
                    {"node_keys": [remap.get(str(key), str(key)) for key in keys]}
                    if isinstance(keys, list)
                    else {}
                ),
            }
        migrated["availability_baselines"] = migrated_baselines
    return list(resolved_nodes.values()), migrated, events
