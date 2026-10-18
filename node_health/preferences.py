"""Subscription-only preferences. Never feed this projection into scan state."""
from __future__ import annotations

import copy
import re
from typing import Any

from .models import Node, NodeAlias
from .reconcile import reconcile_previous_state

PREFERENCES_SCHEMA_VERSION = 1
MAX_PINNED_NODES = 3
NODE_KEY = re.compile(r"[0-9a-f]{64}\Z")


class PreferenceConflict(ValueError):
    pass


class PreferencesUnavailable(ValueError):
    pass


def empty_preferences() -> dict[str, Any]:
    return {"schema_version": 1, "revision": 0, "updated_at": None,
            "pinned_nodes": [], "identity_index": {}}


def validate_keys(keys: Any) -> list[str]:
    if (not isinstance(keys, list) or len(keys) > MAX_PINNED_NODES
            or any(not isinstance(key, str) or not NODE_KEY.fullmatch(key) for key in keys)
            or len(set(keys)) != len(keys)):
        raise ValueError("pinned_nodes must contain 0 to 3 unique node keys")
    return list(keys)


def identity_snapshot(index: dict[str, Any]) -> dict[str, Any]:
    """Keep only public identity metadata, never proxies, credentials or probes.

    Keep the whole identity population: matching only the pins could turn an
    ambiguous old name into an apparently unique identity after a rotation.
    """
    result = {}
    fields = ("source_id", "original_name", "normalized_name", "logical_id", "region",
              "representative_alias_id")
    alias_fields = ("entry_id", "name", "source_id", "original_name", "normalized_name",
                    "logical_id", "declared_region")
    for key, value in index.items():
        if not isinstance(key, str) or not NODE_KEY.fullmatch(key) or not isinstance(value, dict):
            raise ValueError("invalid identity index")
        item = {field: str(value.get(field) or "") for field in fields}
        aliases = []
        for alias in value.get("aliases", []):
            if not isinstance(alias, dict):
                raise ValueError("invalid identity alias")
            clean = {field: str(alias.get(field) or "") for field in alias_fields}
            ordinal = alias.get("duplicate_ordinal", 1)
            if type(ordinal) is not int or ordinal < 1:
                raise ValueError("invalid identity alias ordinal")
            clean["duplicate_ordinal"] = ordinal
            aliases.append(clean)
        item["aliases"] = aliases
        result[key] = item
    return result


def validate_preferences(value: Any) -> dict[str, Any]:
    try:
        if (not isinstance(value, dict) or type(value.get("schema_version")) is not int
                or value["schema_version"] != PREFERENCES_SCHEMA_VERSION
                or type(value.get("revision")) is not int or not 0 <= value["revision"] < 2**53
                or not isinstance(value.get("identity_index"), dict)
                or (value.get("updated_at") is not None and not isinstance(value["updated_at"], str))):
            raise ValueError("invalid preferences")
        keys = validate_keys(value.get("pinned_nodes"))
        index = identity_snapshot(value["identity_index"])
        if any(key not in index for key in keys):
            raise ValueError("missing pinned identity")
        return {"schema_version": 1, "revision": value["revision"],
                "updated_at": value.get("updated_at"), "pinned_nodes": keys,
                "identity_index": index}
    except (ValueError, TypeError, KeyError, AttributeError) as error:
        raise PreferencesUnavailable("subscription_preferences_unavailable") from error


def resolve_preferences(preferences: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    keys = preferences["pinned_nodes"]
    index = current.get("identity_index", {})
    resolved = {key: key for key in keys if key in index}
    if any(key not in resolved for key in keys) and index:
        # Reuse the existing mutually-unique, source-compatible identity rules
        # on disposable metadata only. No service/store state is modified.
        nodes = []
        for key, value in identity_snapshot(index).items():
            aliases = tuple(NodeAlias(**alias) for alias in value["aliases"])
            nodes.append(Node(key=key, name=value["original_name"], region=value["region"],
                              proxy={}, aliases=aliases,
                              **{field: value[field] for field in (
                                  "source_id", "original_name", "normalized_name", "logical_id",
                                  "representative_alias_id")}))
        _, _, events = reconcile_previous_state(nodes, {
            "schema_version": 2, "nodes": preferences["identity_index"],
        })
        resolved.update({event["before"]: event["after"] for event in events if event["before"] in keys})
    seen: set[str] = set()
    pins = []
    for position, key in enumerate(keys, 1):
        target = resolved.get(key)
        status = "active" if target else "missing_or_ambiguous"
        if target in seen:
            target, status = None, "duplicate_identity"
        if target:
            seen.add(target)
        pins.append({"node_key": key, "resolved_node_key": target,
                     "pin_position": position, "status": status})
    return {"schema_version": 1, "revision": preferences["revision"],
            "updated_at": preferences["updated_at"], "pinned_nodes": list(keys),
            "resolved_pinned_nodes": [pin["resolved_node_key"] for pin in pins if pin["resolved_node_key"]],
            "pins": pins, "scope": "subscription", "max_pinned_nodes": MAX_PINNED_NODES,
            "ranking_version": current.get("version"),
            "requires_subscription_refresh": True}


def public_preferences(preferences: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    view = resolve_preferences(preferences, current)
    return {"schema_version": 1, "status": "ready", "revision": view["revision"],
            "updated_at": view["updated_at"], "pinned_nodes": view["resolved_pinned_nodes"]}


def node_catalog(current: dict[str, Any], preferences: dict[str, Any]) -> dict[str, Any]:
    """Admin connection-level view, not a prediction of filtered live aliases."""
    index = current.get("identity_index", {})
    regions = current.get("regions", {})
    region_order = list(dict.fromkeys([*current.get("region_order", []), *regions]))
    order: list[str] = []
    slots = {}
    for region in region_order:
        payload = regions.get(region, {})
        for number in range(1, 4) if region != "other" else ():
            key = payload.get("stable_slots", {}).get(str(number))
            if key in index:
                slots[key] = number
                if key not in order:
                    order.append(key)
        for key in [*payload.get("ranked", []), *payload.get("rejected", {})]:
            if key in index and key not in order:
                order.append(key)
    order.extend(key for key in index if key not in order)
    view = resolve_preferences(preferences, current)
    positions = {pin["resolved_node_key"]: pin["pin_position"] for pin in view["pins"] if pin["resolved_node_key"]}
    effective = view["resolved_pinned_nodes"] + [key for key in order if key not in positions]
    effective_positions = {key: position for position, key in enumerate(effective, 1)}
    nodes = []
    for position, key in enumerate(order, 1):
        metadata = index[key]
        health = current.get("nodes", {}).get(key, {})
        nodes.append({"node_key": key, "name": health.get("name") or metadata.get("original_name"),
                      "region": metadata.get("region"), "source_id": metadata.get("source_id"),
                      "stable_slot": slots.get(key), "automatic_position": position,
                      "pin_position": positions.get(key), "subscription_position": effective_positions[key],
                      "score": health.get("score"), "overall_grade": health.get("overall_grade"),
                      "available": health.get("available"),
                      "score_provenance": copy.deepcopy(health.get("score_provenance", {})),
                      "confidence": health.get("confidence"),
                      "decision": health.get("decision"), "reasons": copy.deepcopy(health.get("reasons", []))})
    return {"nodes": nodes, "ranking_version": current.get("version"),
            "generated_at": current.get("generated_at"), "preference_revision": preferences["revision"],
            "position_scope": "published_connection_representatives", "pins": view["pins"]}
