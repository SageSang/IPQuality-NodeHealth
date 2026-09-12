from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
from datetime import datetime, timedelta, timezone as utc_timezone, tzinfo
from typing import Any
from zoneinfo import ZoneInfo

from .config import PolicyConfig
from .models import ClaudeResult, FullResult
from .policy import (
    EVIDENCE_POLICY_VERSION,
    PROBE_CONTRACT_VERSION,
    RISK_EVIDENCE_VERSION,
    full_has_confirmed_redline,
    full_has_usable_reputation,
    risk_sources_conflict,
    valid_risk_sources,
)
from .probe import normalize_ipquality


class UnsupportedEvidenceVersion(ValueError):
    def __init__(self) -> None:
        super().__init__("unsupported evidence version")


_VERSION_LIMITS = {
    "evidence_policy_version": EVIDENCE_POLICY_VERSION,
    "minimum_evidence_reader_version": EVIDENCE_POLICY_VERSION,
    "qualification_version": EVIDENCE_POLICY_VERSION,
    "risk_evidence_version": RISK_EVIDENCE_VERSION,
    "chatgpt_evidence_version": PROBE_CONTRACT_VERSION,
    "probe_contract_version": PROBE_CONTRACT_VERSION,
}
_LEGACY_FIELDS = (
    "healthy_streak_days", "last_healthy_day", "unavailable_grace_active",
    "daily_quality_history", "last_full", "last_claude", "last_score",
    "ai_grade", "risk_grade", "overall_grade", "residential_grade",
    "score_components", "score_evidence", "last_decision", "current_status",
)


def _check_versions(value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "legacy_evidence":
                continue
            if key in _VERSION_LIMITS:
                if (not isinstance(item, int) or isinstance(item, bool)
                        or item < 0 or item > _VERSION_LIMITS[key]):
                    raise UnsupportedEvidenceVersion()
            _check_versions(item)
    elif isinstance(value, list):
        for item in value:
            _check_versions(item)


def ensure_supported_evidence(state: dict[str, Any]) -> None:
    _check_versions(state)


def _reparse_full(prior: dict[str, Any]) -> FullResult | None:
    cached = prior.get("last_full")
    if not isinstance(cached, dict) or cached.get("completed") is not True:
        return None
    details = cached.get("details")
    if not isinstance(details, dict):
        return None
    head = details.get("Head")
    if (not isinstance(head, dict) or not isinstance(details.get("Score"), dict)
            or not isinstance(details.get("Factor"), dict)):
        return None
    try:
        address = ipaddress.ip_address(str(head.get("IP") or ""))
    except ValueError:
        return None
    if not address.is_global:
        return None
    for value in (cached.get("audited_exit_ip"), prior.get("last_full_exit_ip")):
        if value:
            try:
                if ipaddress.ip_address(str(value)) != address:
                    return None
            except ValueError:
                return None
    mail = details.get("Mail")
    if mail is not None and not isinstance(mail, dict):
        return None
    if isinstance(mail, dict) and "DNSBlacklist" in mail and not isinstance(mail["DNSBlacklist"], dict):
        return None
    # This rebuilds source-level facts, not a new successful observation.
    checked_at = str(cached.get("checked_at") or prior.get("last_full_checked_at") or "")
    result = normalize_ipquality(copy.deepcopy(details), checked_at)
    result.checked_at = checked_at
    return result if result.audited_exit_ip == str(address) else None


def _legacy_claude(prior: Any) -> dict[str, Any]:
    old = prior if isinstance(prior, dict) else {}
    result = ClaudeResult()
    for field in ("exit_ip", "country", "intelligence_country", "asn", "organization", "checked_at"):
        value = old.get(field)
        if isinstance(value, str):
            setattr(result, field, value)
    return result.to_dict()


def _migration_metadata(previous: dict[str, Any], policy: PolicyConfig) -> dict[str, Any]:
    original_slots = []
    nodes = previous.get("nodes", {})
    seen: set[str] = set()
    for region, slots in sorted(previous.get("stable_slots", {}).items()):
        if not isinstance(slots, dict):
            continue
        for slot, key in sorted(slots.items()):
            prior = nodes.get(key, {})
            days = prior.get("healthy_streak_days", 0) if isinstance(prior, dict) else 0
            if (not key or key in seen or not isinstance(days, int) or isinstance(days, bool)
                    or days < policy.stable_protection_min_healthy_days):
                continue
            seen.add(key)
            original_slots.append({"region": str(region), "slot": str(slot), "node_key": str(key),
                                   "consumed": False, "first_unavailable_day": ""})
    identity = json.dumps([previous.get("state_revision") or previous.get("version") or "", original_slots],
                          sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return {"id": "evidence-v1-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24],
            "committed_at": "", "expires_at": "", "original_slots": original_slots}


def migrate_evidence_state(
    previous: dict[str, Any], policy: PolicyConfig, now: datetime
) -> dict[str, Any]:
    """Invalidate legacy qualifications without changing durable placement."""
    del now  # The first successful publication owns the migration deadline.
    _check_versions(previous)
    state = copy.deepcopy(previous)
    nodes = state.get("nodes")
    if not isinstance(nodes, dict):
        nodes = {}
        state["nodes"] = nodes
    first_migration = previous.get("evidence_policy_version", 0) < EVIDENCE_POLICY_VERSION
    if first_migration and nodes and "evidence_migration" not in state:
        state["evidence_migration"] = _migration_metadata(previous, policy)
    for key, prior in nodes.items():
        if not isinstance(prior, dict) or prior.get("qualification_version") == EVIDENCE_POLICY_VERSION:
            continue
        prior.setdefault("legacy_evidence", {
            "source_state_revision": str(previous.get("state_revision") or ""),
            **{field: copy.deepcopy(prior[field]) for field in _LEGACY_FIELDS if field in prior},
        })
        full = _reparse_full(prior)
        pending = ["chatgpt", "claude-risk"]
        if (not full_has_usable_reputation(full, policy)
                or (prior.get("last_exit_ip") and full and prior["last_exit_ip"] != full.audited_exit_ip)):
            pending.append("generic-risk")
        confirmed_risk = full_has_confirmed_redline(full, policy)
        prior.update({
            "qualification_version": EVIDENCE_POLICY_VERSION,
            "evidence_refresh_pending": pending,
            "healthy_streak_days": 0,
            "last_healthy_day": "",
            "unavailable_grace_active": False,
            "daily_quality_history": [],
            "consecutive_full_passes": 0,
            "last_full_pass_day": "",
            "last_full": full.to_dict() if full else None,
            "last_full_recomputed_from_legacy": full is not None,
            "last_full_checked_at": full.checked_at if full else "",
            "last_full_exit_ip": full.audited_exit_ip if full else "",
            "last_claude": _legacy_claude(prior.get("last_claude")),
            "last_score": None,
            "score_day": "",
            "previous_day_score": None,
            "previous_score_day": "",
            "score_components": {},
            "score_evidence": {"ranking_score_source": "pending-revalidation"},
            "ai_grade": "B",
            "risk_grade": "C" if confirmed_risk else "B",
            "overall_grade": "C" if confirmed_risk else "B",
            "residential_grade": "unknown",
            "last_risk_source_count": len(valid_risk_sources(full)),
            "risk_data_conflict": risk_sources_conflict(full),
            "last_decision": "rejected" if confirmed_risk else "pending-revalidation",
            "current_status": "absent" if prior.get("current_status") == "absent" else (
                "rejected" if confirmed_risk else "pending-revalidation"),
        })
        for rejected in state.get("rejected_by_region", {}).values():
            if isinstance(rejected, dict):
                rejected.pop(key, None)
        if confirmed_risk and prior.get("region"):
            state.setdefault("rejected_by_region", {}).setdefault(prior["region"], {})[key] = "verified-legacy-risk"
    state["evidence_policy_version"] = EVIDENCE_POLICY_VERSION
    state["minimum_evidence_reader_version"] = EVIDENCE_POLICY_VERSION
    return state


def finalize_evidence_migration(
    state: dict[str, Any], generated_at: datetime | str, timezone: str | tzinfo
) -> dict[str, Any]:
    """Fix M1's absolute deadline once, as part of the publish transaction."""
    _check_versions(state)
    result = copy.deepcopy(state)
    migration = result.get("evidence_migration")
    if not isinstance(migration, dict) or migration.get("committed_at"):
        return result
    parsed = datetime.fromisoformat(generated_at.replace("Z", "+00:00")) if isinstance(generated_at, str) else generated_at
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=utc_timezone.utc)
    zone = ZoneInfo(timezone) if isinstance(timezone, str) else timezone
    expires = parsed.astimezone(zone) + timedelta(days=7)
    migration["committed_at"] = parsed.astimezone(utc_timezone.utc).isoformat(timespec="seconds")
    migration["expires_at"] = expires.astimezone(utc_timezone.utc).isoformat(timespec="seconds")
    return result


def migration_grace_for_observation(
    state: dict[str, Any], *, node_key: str, region: str, now: datetime,
    current_day: str, available: bool, severe: bool, frozen: bool,
    normal_grace: bool, prior: dict[str, Any],
) -> bool:
    """Use at most one bounded M1 event without granting score or eligibility."""
    migration = state.get("evidence_migration")
    if not isinstance(migration, dict):
        return normal_grace
    entries = migration.get("original_slots", [])
    entry = next((item for item in entries if isinstance(item, dict) and item.get("node_key") == node_key), None)
    if entry is None:
        return normal_grace
    first_day = str(entry.get("first_unavailable_day") or "")
    was_migration_grace = bool(first_day and prior.get("unavailable_grace_active")
                               and first_day == prior.get("last_unavailable_day"))
    slots = state.get("stable_slots", {}).get(entry.get("region"), {})
    same_binding = region == entry.get("region") and slots.get(str(entry.get("slot"))) == node_key
    expired = False
    if migration.get("expires_at"):
        try:
            deadline = datetime.fromisoformat(migration["expires_at"].replace("Z", "+00:00"))
            expired = deadline.tzinfo is None or now >= deadline
        except (TypeError, ValueError):
            expired = True
    if not same_binding or expired or severe:
        entry["consumed"] = True
        entry["first_unavailable_day"] = ""
        return False if was_migration_grace else normal_grace
    if frozen:
        return normal_grace
    if available:
        if was_migration_grace:
            entry["first_unavailable_day"] = ""
        return False
    if entry.get("consumed"):
        return current_day == first_day if was_migration_grace else normal_grace
    entry["consumed"] = True
    if normal_grace:
        entry["first_unavailable_day"] = ""
        return True
    entry["first_unavailable_day"] = current_day
    return True


def invalidate_removed_migration_slots(state: dict[str, Any], current_keys: set[str]) -> None:
    migration = state.get("evidence_migration")
    if not isinstance(migration, dict):
        return
    for entry in migration.get("original_slots", []):
        if not isinstance(entry, dict):
            continue
        key = entry.get("node_key")
        slots = state.get("stable_slots", {}).get(entry.get("region"), {})
        if key not in current_keys or slots.get(str(entry.get("slot"))) != key:
            entry["consumed"] = True
            entry["first_unavailable_day"] = ""
