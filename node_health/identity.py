from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from collections.abc import Mapping, Sequence
from typing import Any

from .models import Node, NodeAlias


SOURCE_ID_FIELDS = ("_nh_source_id", "_source_id")
ORIGINAL_NAME_FIELDS = ("_nh_original_name", "_original_name")
IDENTITY_METADATA_FIELDS = {*SOURCE_ID_FIELDS, *ORIGINAL_NAME_FIELDS}
# Freeze Python's existing whitespace semantics for the cross-language
# identity contract. U+FEFF is deliberately preserved, not treated as space.
IDENTITY_WHITESPACE = "\t\n\v\f\r\x1c\x1d\x1e\x1f \x85\xa0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000"
_IDENTITY_SPACES = re.compile(f"[{re.escape(IDENTITY_WHITESPACE)}]+")


def trim_identity_whitespace(value: str) -> str:
    return value.strip(IDENTITY_WHITESPACE)


def _collapse_identity_whitespace(value: str) -> str:
    return _IDENTITY_SPACES.sub(" ", trim_identity_whitespace(value))


def _json_compatible(value: Any) -> Any:
    """Normalize YAML values to the JSON value model used by the JS operator."""
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            return None
        if value == 0:
            return 0
        if value.is_integer() and abs(value) < 1e21:
            return int(value)
        return value
    if isinstance(value, Mapping):
        return {
            str(key): _json_compatible(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_json_compatible(item) for item in value]
    return str(value)


def canonical_proxy_json(proxy: Mapping[str, Any]) -> str:
    """Return the cross-language identity payload for a Clash proxy.

    Only top-level display/runtime fields are removed. Nested fields and secrets
    remain part of the digest, but the canonical payload is never published.
    """
    identity = {
        str(key): value
        for key, value in proxy.items()
        if str(key) != "name"
        and str(key) not in IDENTITY_METADATA_FIELDS
        and not str(key).startswith("_")
        # ClashMeta derives a random concrete port when a port-hopping range
        # is present. The range is the durable connection identity.
        and not (str(key) == "port" and proxy.get("ports"))
    }
    return json.dumps(
        _json_compatible(identity),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    )


def node_key(proxy: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_proxy_json(proxy).encode("utf-8")).hexdigest()


def normalize_source_id(value: Any) -> str:
    return _collapse_identity_whitespace(unicodedata.normalize("NFKC", str(value or ""))).lower()


def normalize_original_name(value: Any) -> str:
    return _collapse_identity_whitespace(unicodedata.normalize("NFKC", str(value or ""))).lower()


def source_id(proxy: Mapping[str, Any]) -> str:
    for field in SOURCE_ID_FIELDS:
        value = normalize_source_id(proxy.get(field))
        if value:
            return value
    return ""


def original_name(proxy: Mapping[str, Any]) -> str:
    for field in ORIGINAL_NAME_FIELDS:
        value = _collapse_identity_whitespace(str(proxy.get(field) or ""))
        if value:
            return value
    return _collapse_identity_whitespace(str(proxy.get("name") or ""))


def logical_id(source: str, normalized_name: str) -> str:
    if not source or not normalized_name:
        return ""
    return hashlib.sha256(f"{source}\0{normalized_name}".encode("utf-8")).hexdigest()


def alias_entry_id(
    connection_key: str,
    source: str,
    original: str,
    name: str,
    duplicate_ordinal: int = 1,
) -> str:
    payload = json.dumps(
        [connection_key, source, original, name, duplicate_ordinal],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def node_aliases(node: Node) -> tuple[NodeAlias, ...]:
    if node.aliases:
        return node.aliases
    original = node.original_name or original_name(node.proxy) or node.name
    normalized = node.normalized_name or normalize_original_name(original)
    return (NodeAlias(
        entry_id=alias_entry_id(node.key, node.source_id, original, node.name),
        name=node.name,
        source_id=node.source_id,
        original_name=original,
        normalized_name=normalized,
        logical_id=node.logical_id or logical_id(node.source_id, normalized),
        declared_region=node.region,
    ),)


def node_identity(node: Node) -> dict[str, Any]:
    aliases = node_aliases(node)
    return {
        "source_id": node.source_id,
        "original_name": node.original_name,
        "normalized_name": node.normalized_name,
        "logical_id": node.logical_id,
        "region": node.region,
        "aliases": [alias.to_dict() for alias in aliases],
        "representative_alias_id": node.representative_alias_id or aliases[0].entry_id,
        "region_conflict": node.region_conflict,
    }
