from __future__ import annotations

import hashlib
import json
import re
import urllib.request
from collections.abc import Callable
from typing import Any

import yaml

from .config import AppConfig
from .identity import (
    logical_id,
    node_key,
    normalize_original_name,
    original_name,
    source_id,
)
from .models import Node


Download = Callable[[str, dict[str, str], float], bytes]


def download_bytes(url: str, headers: dict[str, str], timeout: float) -> bytes:
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


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

    nodes: list[Node] = []
    seen: dict[str, str] = {}
    for index, proxy in enumerate(document["proxies"]):
        if not isinstance(proxy, dict):
            raise ValueError(f"inventory proxy at index {index} is not an object")
        name = str(proxy.get("name", "")).strip()
        if not name:
            raise ValueError(f"inventory proxy at index {index} has no name")
        key = node_key(proxy)
        if key in seen:
            if seen[key] == name:
                continue
            raise ValueError(
                "inventory contains connection-identical proxies with different names; "
                f"normalize aliases before probing: {seen[key]!r}, {name!r}"
            )
        seen[key] = name
        explicit_region = str(proxy.get("_region") or "").strip()
        if explicit_region and explicit_region not in {*patterns, "other"}:
            raise ValueError(
                f"inventory proxy {name!r} has unsupported _region {explicit_region!r}"
            )
        region = explicit_region or classify_region(name, patterns)
        node_source_id = source_id(proxy)
        node_original_name = original_name(proxy)
        node_normalized_name = normalize_original_name(node_original_name)
        nodes.append(
            Node(
                key=key,
                name=name,
                region=region,
                proxy=dict(proxy),
                source_id=node_source_id,
                original_name=node_original_name,
                normalized_name=node_normalized_name,
                logical_id=logical_id(node_source_id, node_normalized_name),
            )
        )
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
            )
            for node in nodes
        ),
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def fetch_inventory(config: AppConfig, downloader: Download = download_bytes) -> tuple[list[Node], str]:
    payload = downloader(
        config.inventory.url,
        config.inventory.headers,
        config.inventory.timeout_seconds,
    )
    nodes = parse_clash_inventory(payload, config.region_patterns)
    if not nodes:
        raise ValueError("inventory contains no usable proxies")
    return nodes, inventory_digest(nodes)
