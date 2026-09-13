"""Private, exact scan input paired with its committed runtime mapping."""
from __future__ import annotations

import base64
import copy
import hashlib
import re

from .config import AppConfig
from .inventory import MAX_INVENTORY_BYTES, parse_clash_inventory
from .port_mapping import inventory_fingerprint, mapping_digest

BUNDLE_SCHEMA_VERSION = 1
MAX_BUNDLE_BYTES = 32 * 1024 * 1024


def valid_bundle_id(value: str) -> bool:
    return bool(re.fullmatch(r"s-[A-Za-z0-9][A-Za-z0-9._-]{0,125}", value))


def byte_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def build_runtime_bundle(payload: bytes, mapping: dict, revision: str, config: AppConfig) -> dict:
    if not valid_bundle_id(revision) or not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_INVENTORY_BYTES:
        raise ValueError("invalid runtime bundle input")
    if mapping.get("purpose") != "production" or mapping.get("mapping_version") != mapping_digest(mapping):
        raise ValueError("invalid runtime bundle mapping")
    nodes = parse_clash_inventory(payload, config.region_patterns)
    entries = [
        {"node_key": node.key, "entry_id": alias.entry_id, "name": alias.name,
         "source_id": alias.source_id, "original_name": alias.original_name,
         "duplicate_ordinal": alias.duplicate_ordinal}
        for node in nodes for alias in node.aliases
    ]
    if inventory_fingerprint(entries) != mapping.get("inventory_fingerprint"):
        raise ValueError("runtime bundle inventory mismatch")
    return {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "bundle_id": revision,
        "inventory_encoding": "base64",
        "inventory_sha256": byte_digest(payload),
        "inventory": base64.b64encode(payload).decode("ascii"),
        "mapping": copy.deepcopy(mapping),
    }
