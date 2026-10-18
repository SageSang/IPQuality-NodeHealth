import copy
import json
from datetime import datetime, timedelta, timezone

import pytest

from node_health.config import PolicyConfig
from node_health.evidence_migration import migrate_evidence_state
from node_health.policy import evaluate_node, full_has_confirmed_redline, valid_risk_sources
from node_health.preferences import empty_preferences, node_catalog
from node_health.probe import HTTPResult, ProbeFailure
from node_health.slots import _apply_promotions, _promotion_margin_holds
from node_health.identity import node_key
from test_d2_probe_contracts import probe
from test_d2_service_contracts import replace_committed_state
from test_probe_policy import full_result, node, quick
from test_service import make_service
from test_slots import assessment


NOW = datetime(2026, 7, 24, tzinfo=timezone.utc)


@pytest.mark.parametrize("factor", ["Proxy", "VPN", "Server"])
def test_network_type_consensus_is_penalized_but_never_a_redline(factor):
    full = full_result(completed=True, risk_sources={"one": "low", "two": "low", "three": "low"},
                       details={"Factor": {factor: {"one": True, "two": True, "three": True}}})
    evaluation = evaluate_node(node("a"), quick(), full, PolicyConfig(), 2)
    assert evaluation.risk_grade == "B"
    assert not full_has_confirmed_redline(full)
    clean = copy.deepcopy(full)
    clean.details["Factor"] = {}
    assert evaluation.components["risk"] < evaluate_node(node("a"), quick(), clean, PolicyConfig(), 2).components["risk"]


@pytest.mark.parametrize("kind", ["tor", "dnsbl", "abuser", "high-scores"])
def test_true_severe_evidence_keeps_both_redline_and_c_grade(kind):
    full = full_result(completed=True, risk_sources={"one": "low", "two": "low", "three": "low"})
    if kind == "tor":
        full.tor = True
    elif kind == "dnsbl":
        full.dnsbl_listed_count = 3
    elif kind == "abuser":
        full.details["Factor"] = {"Abuser": {"one": True, "two": True, "three": True}}
    else:
        full.risk_sources.update(one="high", two="high")
    assert full_has_confirmed_redline(full)
    assert evaluate_node(node("a"), quick(), full, PolicyConfig(), 2).risk_grade == "C"


def provider_payloads(network=True):
    return ({"privacy": {"proxy": False, "vpn": False, "tor": False, "hosting": network}},
            {"is_proxy": False, "is_vpn": False, "is_tor": False,
             "is_datacenter": network, "is_abuser": False})


@pytest.mark.parametrize("network,expected", [(True, "medium"), (False, "low")])
def test_normalization_and_cache_use_identical_complete_capabilities(network, expected):
    checker = probe()
    ipinfo, ipapi = provider_payloads(network)
    calls = []
    checker._http_get = lambda port, url, timeout=None: (calls.append(url) or HTTPResult(
        0, 200, 1, json.dumps(ipinfo if "ipinfo" in url else ipapi)))
    result = checker._claude_risk_intelligence(20000, "8.8.8.8")
    assert result["complete"]
    assert result["risk_sources"] == {"IPinfo-privacy": expected, "ipapi-flags": expected}
    assert checker._claude_risk_intelligence(20001, "8.8.8.8") == result
    assert len(calls) == 2
    assert all(row["capabilities"]["risk_usable"] for row in checker.diagnostics().values())
    checker.begin_scan()
    checker._claude_risk_intelligence(20000, "8.8.8.8")
    assert len(calls) == 4  # never call yesterday's cache fresh evidence


@pytest.mark.parametrize("ipinfo", [
    {"privacy": {"hosting": True}},
    {"data": {"is_hosting": True, "is_anonymous": True}},
    {"country_code": "US", "asn": "AS123"},
])
def test_partial_or_geo_only_sources_are_not_complete_and_not_cached(ipinfo):
    checker = probe()
    ipapi = {"is_datacenter": True}
    checker._http_get = lambda port, url, timeout=None: HTTPResult(0, 200, 1, json.dumps(ipinfo if "ipinfo" in url else ipapi))
    for _ in range(2):
        result = checker._claude_risk_intelligence(20000, "8.8.8.8")
        assert not result["complete"]
        assert result["risk_sources"] == {}
    for diagnostic in checker.diagnostics().values():
        assert diagnostic["partial_responses"] == 2
        assert diagnostic["last_status"] == "partial"
        assert not diagnostic["capabilities"]["risk_usable"]
        assert "last_success_at" not in diagnostic


def test_top_level_hosting_and_nested_flag_aliases_are_cacheable():
    checker = probe()
    ipinfo = {"data": {"is_hosting": True, "anonymous": {"is_proxy": False, "is_vpn": False, "is_tor": False}}}
    checker._http_get = lambda *_: HTTPResult(0, 200, 1, json.dumps(ipinfo))
    for _ in range(2):
        checker._provider_get(20000, "https://provider.invalid", resource_kind="ipinfo-risk", target_ip="8.8.8.8")
    diagnostic = checker.diagnostics()["provider.invalid"]
    assert diagnostic["requests"] == diagnostic["cache_hits"] == 1
    assert diagnostic["capabilities"]["missing_flags"] == []


@pytest.mark.parametrize("status,code", [(401, "provider_invalid_auth"), (403, "provider_forbidden"), (429, "provider_rate_limited")])
def test_provider_status_is_specific_and_diagnostics_do_not_expose_auth(status, code):
    checker = probe()
    checker._http_get = lambda *_: HTTPResult(0, status, 1, '{"token":"never-publish-this"}')
    with pytest.raises(ProbeFailure) as failure:
        checker._provider_get(20000, "https://provider.invalid?token=synthetic-secret")
    assert failure.value.code == code
    diagnostic = checker.diagnostics()["provider.invalid"]
    assert diagnostic["last_status"] == code
    assert diagnostic["last_http_status"] == status
    assert diagnostic["credential_configured"]
    assert "secret" not in json.dumps(diagnostic) and "never-publish" not in json.dumps(diagnostic)


def test_invalid_authenticated_account_is_not_retried_on_each_route():
    checker = probe()
    calls = []
    checker._http_get = lambda *args: (calls.append(args[0]) or HTTPResult(0, 401, 1))
    for port in (20000, 20001, 20002):
        with pytest.raises(ProbeFailure):
            checker._provider_get(port, "https://provider.invalid?token=synthetic")
    assert calls == [20000]


def test_missing_endpoint_never_calls_http():
    checker = probe()
    checker._http_get = lambda *_: pytest.fail("empty endpoint must not send a request")
    with pytest.raises(ProbeFailure) as failure:
        checker._provider_get(20000, "", resource_kind="ipinfo-risk")
    assert failure.value.code == "provider_missing_config"


def test_aliases_of_same_provider_cannot_supply_multiple_votes():
    full = full_result(completed=True, risk_sources={"ipapi": "high", "ipapi-flags": "high", "IPAPI": "high"})
    assert len(valid_risk_sources(full)) == 1
    assert not full_has_confirmed_redline(full)
    full.details["Factor"] = {"Abuser": {"ipapi": True, "ipapi-flags": True, "IPAPI": True}}
    assert not full_has_confirmed_redline(full)


@pytest.mark.parametrize("bad", [1, 0, True])
def test_old_or_invalid_qualification_history_cannot_promote(bad):
    candidate, incumbent = assessment("candidate", 95), assessment("incumbent", 65)
    for entry in candidate.daily_quality_history:
        entry["qualification_version"] = bad
    assert not _promotion_margin_holds(candidate, incumbent, 3, 15)


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), "not-a-number"])
def test_invalid_numeric_history_cannot_promote(bad):
    candidate, incumbent = assessment("candidate", 95), assessment("incumbent", 65)
    candidate.daily_quality_history[-1]["score"] = bad
    assert not _promotion_margin_holds(candidate, incumbent, 3, 15)


def test_promotion_diagnostics_distinguish_cooldown_days_and_margin():
    slots = {"1": "incumbent"}
    incumbent, candidate = assessment("incumbent", 65), assessment("candidate", 95)
    diagnostic = {}
    _apply_promotions(slots, [incumbent, candidate], NOW.isoformat(), PolicyConfig(), NOW, diagnostic)
    assert diagnostic["status"] == "cooldown"
    candidate.healthy_streak_days = 5
    _apply_promotions(slots, [incumbent, candidate], "", PolicyConfig(), NOW, diagnostic)
    assert diagnostic["candidate_blockers"]["insufficient-healthy-days"] == 1
    candidate.healthy_streak_days = 6
    candidate.daily_quality_history = []
    _apply_promotions(slots, [incumbent, candidate], "", PolicyConfig(), NOW, diagnostic)
    assert diagnostic["candidate_blockers"]["insufficient-common-days"] == 1


def make_v1(service):
    state = service.store.load_state()
    state["evidence_policy_version"] = state["minimum_evidence_reader_version"] = 1
    for prior in state["nodes"].values():
        prior["qualification_version"] = 1
        prior["healthy_streak_days"] = 15
        prior["last_score"] = 99
        prior["last_claude"]["risk_sources"] = {"IPinfo-privacy": "high", "ipapi-flags": "high"}
        for row in prior["daily_quality_history"]:
            row["qualification_version"] = 1
    replace_committed_state(service, state)
    return state


def test_v1_reset_discards_old_detection_and_keeps_durable_order(tmp_path):
    service, _, _, _ = make_service(tmp_path)
    service.run_once("rebuild")
    before = make_v1(service)
    untouched = copy.deepcopy(before)
    state = migrate_evidence_state(before, service.config.policy, NOW)
    assert before == untouched
    assert state["rebaseline_required"]
    for field in ("stable_slots", "frozen_order", "ranked_order", "slot_changed_at", "promotion_cooldown_at"):
        assert state[field] == before[field]
    for prior in state["nodes"].values():
        assert prior["last_full"] is prior["last_claude"] is prior["last_score"] is None
        assert prior["healthy_streak_days"] == 0
        assert prior["daily_quality_history"] == []
        assert prior["full_audit_pending"]
    assert migrate_evidence_state(state, service.config.policy, NOW + timedelta(days=1)) == state


def test_first_full_rebaseline_preserves_slots_and_ports_then_pending_recovers(tmp_path):
    service, quick_probe, full, _ = make_service(tmp_path, count=8)
    first = service.run_once("rebuild")
    old_slots = first["regions"]["united-states"]["stable_slots"]
    unavailable = old_slots["1"]
    before = make_v1(service)
    service.store.update_preferences([old_slots["3"]], 0)
    preferences_before = service.store.preferences_path.read_bytes()
    quick_probe.unavailable.add(unavailable)
    full.calls.clear()
    current = service.run_once("maintenance")
    assert current["regions"]["united-states"]["stable_slots"] == old_slots
    assert set(full.calls) == set(before["nodes"]) - {unavailable}
    assert current["quality_summary"]["detection_rebaseline"]
    state = service.store.load_state()
    assert state["nodes"][unavailable]["full_audit_pending"]
    assert "rebaseline_required" not in state
    assert max(prior["healthy_streak_days"] for prior in state["nodes"].values()) <= 1
    assert "evidence_migration" not in state
    # Rebuilding evidence must not reorder the local endpoint bindings.
    assert current["port_mapping"]["bindings"] == first["port_mapping"]["bindings"]
    assert service.store.preferences_path.read_bytes() == preferences_before
    quick_probe.unavailable.clear()
    full.calls.clear()
    service.run_once("maintenance")
    assert unavailable in full.calls
    assert not service.store.load_state()["nodes"][unavailable]["full_audit_pending"]


def test_rotation_defers_while_unavailable_and_forces_audit_after_restart(tmp_path):
    service, quick_probe, full, source = make_service(tmp_path)
    first = service.run_once("rebuild")
    old_key = first["regions"]["united-states"]["ranked"][-1]
    name = first["nodes"][old_key]["name"]
    source.rotate_connection(name)
    new_key = node_key(next(proxy for proxy in source.proxies if proxy["name"] == name))
    quick_probe.unavailable.add(new_key)
    full.calls.clear()
    current = service.run_once("maintenance")
    assert new_key not in full.calls
    assert current["quality_summary"]["rotation_audits_deferred"] == 1
    state = service.store.load_state()
    assert state["nodes"][new_key]["rotation_audit_pending"]
    assert not state["nodes"][new_key]["last_full"]
    assert state["nodes"][new_key]["healthy_streak_days"] == 0
    # A new service instance has no in-memory knowledge of the rotation.
    from node_health.service import NodeHealthService
    recovered = NodeHealthService(service.config, downloader=source.download, environment=service.environment,
                                  quick_probe=quick_probe, full_auditor=full, clock=service.clock, sleeper=lambda _: None)
    quick_probe.unavailable.clear()
    full.calls.clear()
    recovered.run_once("maintenance")
    assert new_key in full.calls
    assert not recovered.store.load_state()["nodes"][new_key]["rotation_audit_pending"]


def test_catalog_distinguishes_observation_from_retained_score(tmp_path):
    service, quick_probe, full, _ = make_service(tmp_path)
    first = service.run_once("rebuild")
    key = first["regions"]["united-states"]["stable_slots"]["1"]
    full.incomplete.add(key)
    quick_probe.latencies[key] = 900
    current = service.run_once("maintenance")
    catalog = node_catalog(current, empty_preferences())
    row = next(row for row in catalog["nodes"] if row["node_key"] == key)
    assert row["available"]
    assert row["score"] == first["nodes"][key]["score"]
    provenance = row["score_provenance"]
    assert provenance["ranking_score_source"] == "previous"
    assert provenance["observed_score"] != row["score"]
    assert provenance["scoring_policy_version"] == 2
    assert not provenance["evidence_valid"]


def test_rebaseline_failure_does_not_commit_reset_or_lose_order(tmp_path, monkeypatch):
    service, _, _, _ = make_service(tmp_path)
    service.run_once("rebuild")
    before = make_v1(service)
    publish = service.store.publish
    monkeypatch.setattr(service.store, "publish", lambda *a, **kw: (_ for _ in ()).throw(OSError("test write failure")))
    with pytest.raises(OSError):
        service.run_once("maintenance")
    assert service.store.load_state() == before
    monkeypatch.setattr(service.store, "publish", publish)
    current = service.run_once("maintenance")
    assert current["quality_summary"]["detection_rebaseline"]
    assert current["regions"]["united-states"]["stable_slots"] == before["stable_slots"]["united-states"]


def test_incomplete_baseline_stays_pending_until_fresh_full_succeeds(tmp_path):
    service, _, full, _ = make_service(tmp_path)
    service.run_once("rebuild")
    before = make_v1(service)
    key = before["ranked_order"]["united-states"][-1]
    full.incomplete.add(key)
    service.run_once("maintenance")
    prior = service.store.load_state()["nodes"][key]
    assert prior["full_audit_pending"]
    assert prior["healthy_streak_days"] == 0
    assert prior["last_full"] is None
    assert "baseline-audit-pending" in service.store.load_current()["nodes"][key]["reasons"]
    full.incomplete.clear()
    full.calls.clear()
    service.run_once("maintenance")
    assert key in full.calls
    assert not service.store.load_state()["nodes"][key]["full_audit_pending"]


def test_reset_first_scan_preserves_other_and_dynamic_order_even_if_scores_change(tmp_path):
    service, quick_probe, _, source = make_service(tmp_path, count=12)
    for proxy in source.proxies[6:]:
        proxy["name"] = proxy["name"].replace("US", "Unknown")
    first = service.run_once("rebuild")
    make_v1(service)
    for index, key in enumerate(first["nodes"]):
        quick_probe.latencies[key] = 2000 - index * 150
    current = service.run_once("maintenance")
    assert {region: (value["stable_slots"], value["ranked"]) for region, value in current["regions"].items()} == {
        region: (value["stable_slots"], value["ranked"]) for region, value in first["regions"].items()}
    assert current["port_mapping"]["bindings"] == first["port_mapping"]["bindings"]


def test_partial_tor_flag_still_rejects_without_becoming_complete_evidence():
    checker = probe()
    checker._http_get = lambda *_: HTTPResult(0, 200, 1, '{"privacy":{"tor":true}}')
    intelligence = checker._claude_risk_intelligence(20000, "1.1.1.1")
    assert not intelligence["complete"]
    observation = quick()
    observation.claude.exit_ip = "1.1.1.1"
    observation.claude.factors = intelligence["factors"]
    observation.claude.risk_evidence_version = 1
    evaluation = evaluate_node(node("a"), observation, full_result(completed=True), PolicyConfig(), 2)
    assert evaluation.risk_grade == "C"
    assert "claude-tor-exit" in evaluation.reasons
