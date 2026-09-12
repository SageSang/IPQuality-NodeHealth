"""Authoritative fixed-port projection, shared by publication and consumers."""
from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import asdict, is_dataclass
from typing import Any

from .config import AppConfig, DEFAULT_REGION_ORDER, DEFAULT_REGION_PORT_BASES
from .models import Node

CONSUMER_CONTRACT = "local-socks-explicit-v1"
MAP_SCHEMA_VERSION = 1


class MapError(ValueError):
    """A ranking can be published but cannot safely become a runtime target."""


def digest(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def port_plan(config: AppConfig) -> list[dict[str, Any]]:
    if (config.region_order != DEFAULT_REGION_ORDER
            or config.region_port_bases != DEFAULT_REGION_PORT_BASES
            or config.policy.stable_slots != 3):
        raise MapError("unsupported_port_plan")
    return [
        {"id": region, "base": config.region_port_bases[region],
         "capacity": 65536 - config.region_port_bases[region] if region == "other" else 200,
         "stable_count": 0 if region == "other" else 3}
        for region in config.region_order
    ]


def mapping_digest(document: dict[str, Any]) -> str:
    return digest({key: value for key, value in document.items()
                   if key not in {"mapping_version", "generated_at", "ranking_version", "application_status"}})


def inventory_fingerprint(entries: Sequence[dict[str, Any]]) -> str:
    return digest(sorted(
        ({key: entry[key] for key in ("entry_id", "node_key", "name", "source_id", "original_name", "duplicate_ordinal")}
         for entry in entries),
        key=lambda entry: entry["entry_id"],
    ))


def _entries(node: Node) -> list[dict[str, Any]]:
    # Legacy single-node callers use the same identity helper as inventory parsing.
    from .identity import alias_entry_id, original_name, source_id

    aliases = list(getattr(node, "aliases", ()) or ())
    if not aliases:
        source = source_id(node.proxy)
        original = original_name(node.proxy)
        aliases = [{"name": node.name, "source_id": source, "original_name": original,
                    "duplicate_ordinal": 1,
                    "entry_id": alias_entry_id(node.key, source, original, node.name, 1)}]
    result = []
    for alias in aliases:
        value = asdict(alias) if is_dataclass(alias) else dict(alias)
        result.append({
            "entry_id": value["entry_id"], "node_key": node.key, "name": value["name"],
            "source_id": value.get("source_id", ""), "original_name": value.get("original_name", value["name"]),
            "duplicate_ordinal": value.get("duplicate_ordinal", 1), "region": node.region,
        })
    return sorted(result, key=lambda entry: entry["entry_id"])


def build_port_mapping(current: dict[str, Any], nodes: Sequence[Node], config: AppConfig) -> dict[str, Any]:
    instance = str(getattr(config, "local_socks_server_instance_id", "") or "").strip()
    namespace = str(getattr(config, "local_socks_namespace", "node-health-production") or "").strip()
    if not instance or not namespace:
        raise MapError("mapping_source_identity_required")
    if not current.get("version"):
        raise MapError("ranking_version_required")
    regions = port_plan(config)
    by_key = {node.key: node for node in nodes}
    if len(by_key) != len(nodes):
        raise MapError("inventory_connections_not_grouped")
    entries_by_key = {node.key: _entries(node) for node in nodes}
    entries = sorted((entry for group in entries_by_key.values() for entry in group), key=lambda entry: entry["entry_id"])
    if len({entry["entry_id"] for entry in entries}) != len(entries):
        raise MapError("duplicate_entry_id")
    valid_regions = {region["id"] for region in regions}
    if any(node.region not in valid_regions for node in nodes):
        raise MapError("unknown_effective_region")
    used_entries: set[str] = set()
    stable_keys: set[str] = set()
    bindings: list[dict[str, Any]] = []
    for region in regions:
        region_id = region["id"]
        payload = current.get("regions", {}).get(region_id, {})
        slots = payload.get("stable_slots", {})
        if any(str(slot) not in {str(i) for i in range(1, region["stable_count"] + 1)} for slot in slots):
            raise MapError("invalid_stable_slot")
        for slot in range(1, region["stable_count"] + 1):
            key = slots.get(str(slot)) or None
            entry = None
            if key:
                node = by_key.get(key)
                if node is None or node.region != region_id or key in stable_keys:
                    raise MapError("unresolvable_stable_binding")
                stable_keys.add(key)
                preferred = getattr(node, "representative_alias_id", "")
                entry = next((value for value in entries_by_key[key] if value["entry_id"] == preferred), entries_by_key[key][0])
                used_entries.add(entry["entry_id"])
            bindings.append({"region": region_id, "port": region["base"] + slot - 1,
                             "role": "stable", "slot": slot, "entry_id": entry["entry_id"] if entry else None,
                             "node_key": key})
        ranked = payload.get("ranked", [])
        rank = {key: index for index, key in enumerate(ranked)}
        # Unused aliases of incumbents have no independent health rank. Their
        # deterministic tail preserves the entire input without occupying slots.
        dynamic = sorted(
            (entry for entry in entries if entry["region"] == region_id and entry["entry_id"] not in used_entries),
            key=lambda entry: (rank.get(entry["node_key"], len(rank)), entry["node_key"], entry["entry_id"]),
        )
        if len(dynamic) > region["capacity"] - region["stable_count"]:
            raise MapError("regional_port_capacity_exceeded")
        for index, entry in enumerate(dynamic):
            used_entries.add(entry["entry_id"])
            bindings.append({"region": region_id, "port": region["base"] + region["stable_count"] + index,
                             "role": "dynamic", "dynamic_index": index + 1,
                             "entry_id": entry["entry_id"], "node_key": entry["node_key"]})
    if len(used_entries) != len(entries):
        raise MapError("incomplete_instance_mapping")
    document = {
        "schema_version": MAP_SCHEMA_VERSION, "consumer_contract": CONSUMER_CONTRACT,
        "purpose": "production", "namespace": namespace, "server_instance_id": instance,
        "ranking_version": current["version"], "generated_at": current.get("generated_at", ""),
        "application_status": "target-only", "regions": regions,
        "port_plan_version": digest(regions), "entries": entries, "bindings": bindings,
        "inventory_fingerprint": inventory_fingerprint(entries),
    }
    document["mapping_version"] = mapping_digest(document)
    return document
