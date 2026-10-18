"""Provider field capabilities, shared by parsing and caching.

Network type is not an abuse verdict. Missing fields remain missing; in
particular a positive hosting flag cannot stand in for a complete risk lookup.
"""
from __future__ import annotations

from typing import Any


IPINFO_FIELDS = frozenset({"proxy", "vpn", "tor", "server"})
IPAPI_FIELDS = IPINFO_FIELDS | {"abuser"}


def risk_bool(value: Any) -> bool | None:
    return value if type(value) is bool else None


def ipinfo_factors(payload: dict[str, Any]) -> dict[str, bool]:
    data = payload.get("data") if isinstance(payload.get("data"), dict) else payload
    privacy = data.get("privacy") or data.get("anonymous")
    privacy = privacy if isinstance(privacy, dict) else {}
    result = {}
    for factor, keys in {
        "proxy": ("proxy", "is_proxy", "relay", "is_relay"),
        "vpn": ("vpn", "is_vpn"), "tor": ("tor", "is_tor"),
    }.items():
        values = [risk_bool(privacy[key]) for key in keys if key in privacy]
        if any(value is True for value in values):
            result[factor] = True
        elif values and all(value is False for value in values):
            result[factor] = False
    # An aggregate anonymous flag does not supply the missing Tor/VPN fields.
    if risk_bool(data.get("is_anonymous")) is True and not any(result.values()):
        result["proxy"] = True
    asn = data.get("as") or data.get("asn")
    asn = asn if isinstance(asn, dict) else {}
    values = [risk_bool(mapping[key]) for mapping, key in (
        (data, "is_hosting"), (privacy, "hosting"), (privacy, "is_hosting")
    ) if key in mapping]
    usage = str(asn.get("type") or "").strip().lower()
    if any(value is True for value in values) or usage == "hosting":
        result["server"] = True
    elif values and all(value is False for value in values):
        result["server"] = False
    elif not values and usage in {"isp", "business", "education", "government", "banking"}:
        result["server"] = False
    return result


def ipapi_factors(payload: dict[str, Any]) -> dict[str, bool]:
    return {factor: value for factor, field in {
        "proxy": "is_proxy", "vpn": "is_vpn", "tor": "is_tor",
        "server": "is_datacenter", "abuser": "is_abuser", "robot": "is_crawler",
    }.items() if (value := risk_bool(payload.get(field))) is not None}


def flags_risk(factors: dict[str, bool], required: frozenset[str]) -> str:
    if not required <= factors.keys():
        return ""
    if factors.get("tor") or factors.get("abuser"):
        return "high"
    if any(factors.get(name) for name in ("proxy", "vpn", "server", "robot")):
        return "medium"
    return "low"
