from __future__ import annotations

import hashlib
import json
import math
import unicodedata
from collections.abc import Mapping, Sequence
from typing import Any


SOURCE_ID_FIELDS = ("_nh_source_id", "_source_id")
ORIGINAL_NAME_FIELDS = ("_nh_original_name", "_original_name")
IDENTITY_METADATA_FIELDS = {*SOURCE_ID_FIELDS, *ORIGINAL_NAME_FIELDS}


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
    return " ".join(unicodedata.normalize("NFKC", str(value or "")).split()).lower()


def normalize_original_name(value: Any) -> str:
    return " ".join(unicodedata.normalize("NFKC", str(value or "")).split()).lower()


def source_id(proxy: Mapping[str, Any]) -> str:
    for field in SOURCE_ID_FIELDS:
        value = normalize_source_id(proxy.get(field))
        if value:
            return value
    return ""


def original_name(proxy: Mapping[str, Any]) -> str:
    for field in ORIGINAL_NAME_FIELDS:
        value = " ".join(str(proxy.get(field) or "").split())
        if value:
            return value
    return " ".join(str(proxy.get("name") or "").split())


def logical_id(source: str, normalized_name: str) -> str:
    if not source or not normalized_name:
        return ""
    return hashlib.sha256(f"{source}\0{normalized_name}".encode("utf-8")).hexdigest()
