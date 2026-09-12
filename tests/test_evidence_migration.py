import copy
from datetime import datetime, timedelta, timezone

import pytest

from node_health.config import PolicyConfig
from node_health.evidence_migration import (
    UnsupportedEvidenceVersion,
    finalize_evidence_migration,
    migrate_evidence_state,
)


NOW = datetime(2026, 9, 12, 3, 0, tzinfo=timezone.utc)


def legacy_node(days=6, *, raw=True):
    full = {"completed": True, "audited_exit_ip": "8.8.8.8", "checked_at": "2026-09-10T03:00:00Z",
            "risk_sources": {"normalized-only": "low"}}
    if raw:
        full["details"] = {
            "Head": {"IP": "8.8.8.8"},
            "Score": {"one": "low", "two": 10, "three": "15%", "failed": None},
            "Factor": {"Tor": {"one": False, "two": None}, "Proxy": {"one": None, "two": False}},
            "Mail": {"DNSBlacklist": {"Blacklisted": 0}},
            "Media": {"ChatGPT": {"Status": "Yes", "Region": "US", "Type": "Native"}},
        }
    return {"region": "united-states", "name": "synthetic", "last_score": 90,
            "healthy_streak_days": days, "last_healthy_day": "2026-09-10",
            "last_full": full, "last_full_exit_ip": "8.8.8.8", "last_exit_ip": "8.8.8.8",
            "consecutive_unavailable_valid_days": 1, "last_unavailable_day": "2026-09-11",
            "unavailable_grace_active": True, "consecutive_full_passes": 6,
            "daily_quality_history": [{"day":"2026-09-10", "score":90, "evidence_valid":True}],
            "ai_grade": "A", "risk_grade": "A", "overall_grade": "A",
            "score_components": {"ai":25,"risk":25,"reliability":25},
            "last_decision": "eligible", "current_status": "eligible",
            "last_claude": {"status":"available", "trace_ok":True, "anthropic_ok":True,
                            "exit_ip":"1.1.1.1", "risk_sources":{"flags":"low"},
                            "factors":{"proxy":{"flags":False}}, "intelligence_complete":True}}


def legacy_state():
    return {"schema_version":2, "version":"runtime-kept", "state_revision":"synthetic-revision",
            "stable_slots":{"united-states":{"1":"stable", "2":"young"}},
            "frozen_order":{"other":["other-z","other-a"]},
            "ranked_order":{"united-states":["dynamic"],"other":["other-z","other-a"]},
            "slot_changed_at":{"united-states":{"1":"2026-09-01"}},
            "promotion_cooldown_at":{"united-states":"2026-09-08"},
            "availability_baselines":{"united-states":{"node_keys":["stable","young"],"available_ratio":1}},
            "nodes":{"stable":legacy_node(),"young":legacy_node(5),"dynamic":legacy_node(10)}}


def test_legacy_migration_is_pure_idempotent_and_preserves_placement():
    previous = legacy_state()
    untouched = copy.deepcopy(previous)
    migrated = migrate_evidence_state(previous, PolicyConfig(), NOW)
    assert previous == untouched
    for key in ("schema_version","version","state_revision","stable_slots","frozen_order","ranked_order",
                "slot_changed_at","promotion_cooldown_at","availability_baselines"):
        assert migrated[key] == previous[key]
    assert migrated["evidence_policy_version"] == migrated["minimum_evidence_reader_version"] == 1
    assert migrate_evidence_state(migrated, PolicyConfig(), NOW + timedelta(days=1)) == migrated
    assert migrate_evidence_state(previous, PolicyConfig(), NOW + timedelta(days=1)) == migrated


def test_raw_risk_recomputed_but_legacy_ai_and_qualification_not_revalidated():
    previous = legacy_state()
    migrated = migrate_evidence_state(previous, PolicyConfig(), NOW)
    node = migrated["nodes"]["stable"]
    assert node["last_full"]["risk_evidence_version"] == 1
    assert node["last_full"]["chatgpt_evidence_version"] == 0
    assert node["last_full"]["checked_at"] == previous["nodes"]["stable"]["last_full"]["checked_at"]
    assert node["last_risk_source_count"] == 3
    assert node["last_full"]["details"]["Factor"]["Proxy"]["one"] is None
    assert node["last_full_recomputed_from_legacy"] is True
    assert node["last_claude"]["status"] == "unknown"
    assert node["last_claude"]["risk_sources"] == {}
    assert node["last_claude"]["factors"] == {}
    assert node["last_claude"]["intelligence_complete"] is False
    assert node["last_claude"]["risk_evidence_version"] == 0
    assert node["qualification_version"] == 1
    assert node["healthy_streak_days"] == node["consecutive_full_passes"] == 0
    assert node["daily_quality_history"] == []
    assert node["unavailable_grace_active"] is False
    assert node["last_score"] is None
    assert node["score_components"] == {}
    assert node["consecutive_unavailable_valid_days"] == 1
    assert node["last_unavailable_day"] == "2026-09-11"
    assert node["evidence_refresh_pending"] == ["chatgpt","claude-risk"]
    assert node["legacy_evidence"]["daily_quality_history"] == previous["nodes"]["stable"]["daily_quality_history"]


@pytest.mark.parametrize("invalid", ["normalized_only", "private_ip", "ip_mismatch", "missing_factor", "invalid_dns"])
def test_incomplete_or_misbound_raw_risk_is_not_promoted_to_version_one(invalid):
    previous = legacy_state()
    node = previous["nodes"]["stable"]
    if invalid == "normalized_only":
        node["last_full"].pop("details")
    elif invalid == "private_ip":
        node["last_full"]["details"]["Head"]["IP"] = "127.0.0.1"
    elif invalid == "ip_mismatch":
        node["last_full"]["audited_exit_ip"] = "1.1.1.1"
    elif invalid == "missing_factor":
        node["last_full"]["details"].pop("Factor")
    else:
        node["last_full"]["details"]["Mail"]["DNSBlacklist"] = "unparseable"
    migrated = migrate_evidence_state(previous, PolicyConfig(), NOW)["nodes"]["stable"]
    assert migrated["last_full"] is None
    assert migrated["last_risk_source_count"] == 0
    assert "generic-risk" in migrated["evidence_refresh_pending"]
    assert migrated["legacy_evidence"]["last_full"] == node["last_full"]


def test_previous_egress_facts_keep_their_scope_and_request_fresh_risk():
    previous = legacy_state()
    previous["nodes"]["stable"]["last_exit_ip"] = "1.1.1.1"
    node = migrate_evidence_state(previous, PolicyConfig(), NOW)["nodes"]["stable"]
    assert node["last_full"]["audited_exit_ip"] == node["last_full_exit_ip"] == "8.8.8.8"
    assert node["last_exit_ip"] == "1.1.1.1"
    assert "generic-risk" in node["evidence_refresh_pending"]


def test_recomputed_risk_with_unknown_date_is_not_timestamped_as_fresh():
    previous=legacy_state()
    previous["nodes"]["stable"]["last_full"]["checked_at"]=""
    migrated=migrate_evidence_state(previous,PolicyConfig(),NOW)
    assert migrated["nodes"]["stable"]["last_full"]["checked_at"]==""
    assert migrated["nodes"]["stable"]["last_full_checked_at"]==""


def test_confirmed_raw_redline_survives_but_legacy_derived_rejection_does_not():
    previous = legacy_state()
    previous["nodes"]["stable"]["last_full"]["details"]["Factor"]["Tor"]["one"] = True
    previous["nodes"]["young"]["last_decision"] = "rejected"
    previous["rejected_by_region"] = {"united-states":{"young":"legacy-ai-failure"}}
    migrated = migrate_evidence_state(previous, PolicyConfig(), NOW)
    assert migrated["nodes"]["stable"]["risk_grade"] == "C"
    assert migrated["nodes"]["stable"]["last_decision"] == "rejected"
    assert migrated["nodes"]["young"]["last_decision"] == "pending-revalidation"
    assert migrated["rejected_by_region"] == {"united-states":{"stable":"verified-legacy-risk"}}


def test_m1_whitelist_is_original_qualified_slots_only_and_commit_sets_deadline_once():
    migrated = migrate_evidence_state(legacy_state(), PolicyConfig(), NOW)
    pending = migrated["evidence_migration"]
    assert pending["committed_at"] == pending["expires_at"] == ""
    assert pending["original_slots"] == [{"region":"united-states","slot":"1","node_key":"stable",
                                           "consumed":False,"first_unavailable_day":""}]
    published = finalize_evidence_migration(migrated, NOW, "Asia/Shanghai")
    assert pending["committed_at"] == ""
    assert published["evidence_migration"]["committed_at"] == "2026-09-12T03:00:00+00:00"
    assert published["evidence_migration"]["expires_at"] == "2026-09-19T03:00:00+00:00"
    published["evidence_migration"]["original_slots"][0]["consumed"] = True
    published["nodes"]["dynamic"]["healthy_streak_days"] = 20
    published["stable_slots"]["united-states"]["3"] = "dynamic"
    again = migrate_evidence_state(published, PolicyConfig(), NOW + timedelta(days=4))
    assert again["evidence_migration"] == published["evidence_migration"]
    assert finalize_evidence_migration(again, NOW + timedelta(days=4), "Asia/Shanghai") == again


def test_m1_expiration_uses_local_calendar_days_across_dst():
    migrated = migrate_evidence_state(legacy_state(), PolicyConfig(), NOW)
    published = finalize_evidence_migration(migrated, "2026-10-30T12:00:00-07:00", "America/Los_Angeles")
    assert published["evidence_migration"]["expires_at"] == "2026-11-06T20:00:00+00:00"


@pytest.mark.parametrize("path", [
    ("evidence_policy_version",), ("minimum_evidence_reader_version",),
    ("nodes","stable","qualification_version"),
    ("nodes","stable","last_full","risk_evidence_version"),
])
def test_future_versions_reject_without_altering_state(path):
    previous = legacy_state()
    target = previous
    for key in path[:-1]:target = target[key]
    target[path[-1]] = 99
    untouched = copy.deepcopy(previous)
    with pytest.raises(UnsupportedEvidenceVersion, match="^unsupported evidence version$"):
        migrate_evidence_state(previous, PolicyConfig(), NOW)
    assert previous == untouched


def test_empty_install_does_not_create_migration_entitlements():
    state = migrate_evidence_state({"schema_version":2,"nodes":{},"stable_slots":{},"frozen_order":{}}, PolicyConfig(), NOW)
    assert "evidence_migration" not in state
    assert state["stable_slots"] == {}
