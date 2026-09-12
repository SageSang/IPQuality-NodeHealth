from __future__ import annotations

import copy
from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import replace
from typing import Any

from .identity import node_aliases, node_identity
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


def _state_identities(key: str, payload: dict[str, Any]) -> list[dict[str, str]]:
    aliases = payload.get("aliases")
    if isinstance(aliases, list) and aliases:
        return [
            _state_identity(key, {**alias, "region": alias.get("declared_region") or payload.get("region")})
            for alias in aliases if isinstance(alias, dict)
        ]
    return [_state_identity(key, payload)]


def _unique_stage(
    old_keys: set[str],
    new_keys: set[str],
    old_nodes: dict[str, dict[str, Any]],
    new_nodes: dict[str, Node],
    old_group: Callable[[dict[str, str]], tuple[str, ...] | None],
    new_group: Callable[[Node], tuple[str, ...] | None],
    require_compatible_source: bool = False,
) -> list[tuple[str, str]]:
    old_buckets: dict[tuple[str, ...], dict[str, list[dict[str, str]]]] = defaultdict(dict)
    new_buckets: dict[tuple[str, ...], dict[str, list[Node]]] = defaultdict(dict)
    for key in old_keys:
        for identity in _state_identities(key, old_nodes[key]):
            group = old_group(identity)
            if group and all(group):
                old_buckets[group].setdefault(key, []).append(identity)
    for key in new_keys:
        node = new_nodes[key]
        for alias in node_aliases(node):
            identity = replace(node, source_id=alias.source_id, original_name=alias.original_name,
                               normalized_name=alias.normalized_name, logical_id=alias.logical_id,
                               region=alias.declared_region)
            group = new_group(identity)
            if group and all(group):
                new_buckets[group].setdefault(key, []).append(identity)
    candidates: set[tuple[str, str]] = set()
    for group in sorted(set(old_buckets) & set(new_buckets)):
        old, new = old_buckets[group], new_buckets[group]
        if len(old) != 1 or len(new) != 1:
            continue
        old_key, new_key = next(iter(old)), next(iter(new))
        if require_compatible_source and not any(
            _safe_name_pair(before, after)
            for before in old[old_key] for after in new[new_key]
        ):
            continue
        candidates.add((old_key, new_key))
    # Alias matches must agree on one connection pair in both directions.
    old_targets: dict[str, set[str]] = defaultdict(set)
    new_sources: dict[str, set[str]] = defaultdict(set)
    for old_key, new_key in candidates:
        old_targets[old_key].add(new_key)
        new_sources[new_key].add(old_key)
    return sorted((old_key, new_key) for old_key, new_key in candidates
                  if len(old_targets[old_key]) == len(new_sources[new_key]) == 1)


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
            require_compatible_source=True,
        )
        for old_key, new_key in found:
            unmatched_old.remove(old_key)
            unmatched_new.remove(new_key)
            matches.append((old_key, new_key, method))

    migrated = copy.deepcopy(previous)
    migrated_nodes = dict(prior_nodes)
    remap = {old_key: new_key for old_key, new_key, _ in matches}
    events: list[dict[str, str]] = []
    resolved_nodes = dict(current_nodes)
    for old_key, new_key, method in matches:
        old = prior_nodes[old_key]
        node = _select_representative(current_nodes[new_key], old)
        inherited_region = str(old.get("region") or node.region)
        if inherited_region != node.region:
            node = replace(node, region=inherited_region)
        resolved_nodes[new_key] = node
        migrated_nodes.pop(old_key, None)
        migrated_nodes[new_key] = {
            "name": node.name,
            **node_identity(node),
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


def _select_representative(node: Node, prior: dict[str, Any]) -> Node:
    aliases = node_aliases(node)
    selected = next((alias for alias in aliases
                     if alias.entry_id == prior.get("representative_alias_id")), None)
    if selected is None:
        previous_name = str(prior.get("original_name") or prior.get("name") or "")
        previous_source = str(prior.get("source_id") or "")
        matching = [alias for alias in aliases
                    if alias.original_name == previous_name
                    and (not previous_source or not alias.source_id or previous_source == alias.source_id)]
        if len(matching) == 1:
            selected = matching[0]
    if selected is None:
        selected = min(aliases, key=lambda alias: (
            alias.source_id, alias.normalized_name, alias.original_name,
            alias.name, alias.duplicate_ordinal, alias.entry_id,
        ))
    return replace(node, name=selected.name, proxy={**node.proxy, "name": selected.name},
                   source_id=selected.source_id, original_name=selected.original_name,
                   normalized_name=selected.normalized_name, logical_id=selected.logical_id,
                   aliases=aliases, representative_alias_id=selected.entry_id)


def resolve_effective_regions(
    nodes: Iterable[Node], previous: dict[str, Any], mode: str = "maintenance"
) -> list[Node]:
    """Resolve one regional identity before probes, outage guards and ranking."""
    prior_nodes = previous.get("nodes", {})
    slots = previous.get("stable_slots", {})
    assigned: dict[str, set[str]] = defaultdict(set)
    for region, values in slots.items():
        if isinstance(values, dict):
            for key in values.values():
                if key:
                    assigned[str(key)].add(str(region))
    frozen_other = set(previous.get("frozen_order", {}).get("other", [])) if mode == "maintenance" else set()
    resolved: list[Node] = []
    for item in nodes:
        prior = prior_nodes.get(item.key, {})
        node = _select_representative(item, prior)
        declared = {alias.declared_region for alias in node.aliases}
        old_regions = assigned.get(node.key, set())
        if len(old_regions) == 1:
            region = next(iter(old_regions))
        elif node.key in frozen_other:
            region = "other"
        elif prior.get("region"):
            region = str(prior["region"])
        else:
            region = next(iter(declared)) if len(declared) == 1 else "other"
        resolved.append(replace(node, region=region, region_conflict=len(declared) > 1 or len(old_regions) > 1))
    return resolved
