from __future__ import annotations

import hashlib
import json
import re
import urllib.request
from collections import Counter
from collections.abc import Callable
from typing import Any

import yaml

from .config import AppConfig
from .identity import (
    alias_entry_id,
    logical_id,
    node_key,
    node_aliases,
    normalize_original_name,
    original_name,
    source_id,
)
from .models import Node, NodeAlias


Download = Callable[[str, dict[str, str], float], bytes]
MAX_INVENTORY_BYTES = 16 * 1024 * 1024


def download_bytes(url: str, headers: dict[str, str], timeout: float) -> bytes:
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read(MAX_INVENTORY_BYTES + 1)


def classify_region(name: str, patterns: dict[str, list[str]]) -> str:
    for region, expressions in patterns.items():
        if any(re.search(expression, name, flags=re.IGNORECASE) for expression in expressions):
            return region
    return "other"


def parse_clash_inventory(payload: bytes | str, patterns: dict[str, list[str]]) -> list[Node]:
    if isinstance(payload, bytes):
        payload = payload.decode("utf-8-sig")
    document = yaml.safe_load(payload) or {}
    if not isinstance(document, dict) or not isinstance(document.get("proxies"), list):
        raise ValueError("inventory must be a Clash YAML document containing a proxies list")

    grouped: dict[str, list[NodeAlias]] = {}
    proxies_by_key: dict[str, dict[str, Any]] = {}
    occurrences: Counter[tuple[str, str, str, str]] = Counter()
    for index, proxy in enumerate(document["proxies"]):
        if not isinstance(proxy, dict):
            raise ValueError(f"inventory proxy at index {index} is not an object")
        name = str(proxy.get("name", "")).strip()
        if not name:
            raise ValueError(f"inventory proxy at index {index} has no name")
        key = node_key(proxy)
        explicit_region = str(proxy.get("_region") or "").strip()
        if explicit_region and explicit_region not in {*patterns, "other"}:
            raise ValueError(
                f"inventory proxy {name!r} has unsupported _region {explicit_region!r}"
            )
        node_source_id = source_id(proxy)
        node_original_name = original_name(proxy)
        region = explicit_region or classify_region(node_original_name, patterns)
        node_normalized_name = normalize_original_name(node_original_name)
        signature = (key, node_source_id, node_original_name, name)
        occurrences[signature] += 1
        grouped.setdefault(key, []).append(
            NodeAlias(
                entry_id=alias_entry_id(*signature, occurrences[signature]),
                name=name,
                source_id=node_source_id,
                original_name=node_original_name,
                normalized_name=node_normalized_name,
                logical_id=logical_id(node_source_id, node_normalized_name),
                declared_region=region,
                duplicate_ordinal=occurrences[signature],
            )
        )
        proxies_by_key.setdefault(key, dict(proxy))
    nodes: list[Node] = []
    for key, aliases in grouped.items():
        aliases.sort(key=lambda alias: (
            alias.source_id, alias.normalized_name, alias.original_name,
            alias.name, alias.duplicate_ordinal, alias.entry_id,
        ))
        representative = aliases[0]
        regions = {alias.declared_region for alias in aliases}
        region = next(iter(regions)) if len(regions) == 1 else "other"
        nodes.append(Node(
            key=key,
            name=representative.name,
            region=region,
            proxy={**proxies_by_key[key], "name": representative.name},
            source_id=representative.source_id,
            original_name=representative.original_name,
            normalized_name=representative.normalized_name,
            logical_id=representative.logical_id,
            aliases=tuple(aliases),
            representative_alias_id=representative.entry_id,
            region_conflict=len(regions) > 1,
        ))
    return nodes


def inventory_digest(nodes: list[Node]) -> str:
    payload = json.dumps(
        sorted(
            (
                node.key,
                node.source_id,
                node.original_name,
                node.normalized_name,
                node.logical_id,
                node.region,
                tuple(sorted(alias.entry_id for alias in node_aliases(node))),
            )
            for node in nodes
        ),
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def fetch_inventory(config: AppConfig, downloader: Download = download_bytes) -> tuple[list[Node], str]:
    nodes, source_digest, _ = fetch_inventory_snapshot(config, downloader)
    return nodes, source_digest


def fetch_inventory_snapshot(
    config: AppConfig, downloader: Download = download_bytes
) -> tuple[list[Node], str, bytes]:
    payload = downloader(
        config.inventory.url,
        config.inventory.headers,
        config.inventory.timeout_seconds,
    )
    if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_INVENTORY_BYTES:
        raise ValueError("inventory exceeds size limit or is empty")
    nodes = parse_clash_inventory(payload, config.region_patterns)
    if not nodes:
        raise ValueError("inventory contains no usable proxies")
    return nodes, inventory_digest(nodes), payload
