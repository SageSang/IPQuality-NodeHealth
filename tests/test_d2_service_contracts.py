import copy
import json
import math
import threading
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

import pytest

from node_health.app import create_server
from node_health.evidence_migration import UnsupportedEvidenceVersion
from node_health.models import ClaudeResult, SiteProbeResult
from node_health.storage import atomic_write_json
from test_service import make_service, _wait_for_audit


def replace_committed_state(service, state):
    atomic_write_json(service.store.state_path, state)
    current = service.store.load_current()
    atomic_write_json(service.store.snapshots_dir / f"{current['state_revision']}.json", state)


def make_legacy(service, qualified_key=None):
    state = copy.deepcopy(service.store.load_state())
    state.pop("evidence_policy_version", None)
    state.pop("minimum_evidence_reader_version", None)
    state.pop("evidence_migration", None)
    for key, node in state["nodes"].items():
        node.pop("qualification_version", None)
        node.pop("evidence_refresh_pending", None)
        node["healthy_streak_days"] = 6 if key == qualified_key else 0
        full = node.get("last_full")
        if full:
            full.pop("risk_evidence_version", None)
            full.pop("chatgpt_evidence_version", None)
            full.pop("chatgpt", None)
            full["details"].update({
                "Head": {"IP": full["audited_exit_ip"]},
                "Score": dict(full["risk_sources"]),
                "Factor": {"CountryCode": {"one": "US", "two": "US", "three": "US"}},
            })
        for field in ("site_probe", "anthropic_probe", "risk_evidence_version"):
            node["last_claude"].pop(field, None)
    replace_committed_state(service, state)
    return state


def test_migration_publishes_version_and_m1_once_without_rebuild(tmp_path):
    service, quick, _, _ = make_service(tmp_path, count=5)
    first = service.run_once("rebuild")
    before = first["regions"]["united-states"]["stable_slots"]
    key = before["1"]
    make_legacy(service, key)
    quick.unavailable.add(key)

    migrated = service.run_once("maintenance")
    state = service.store.load_state()
    migration = state["evidence_migration"]
    assert migrated["mode"] == "maintenance"
    assert migrated["regions"]["united-states"]["stable_slots"] == before
    assert state["evidence_policy_version"] == state["minimum_evidence_reader_version"] == 1
    assert state["nodes"][key]["healthy_streak_days"] == 0
    assert state["nodes"][key]["unavailable_grace_active"] is True
    assert migration["original_slots"][0]["consumed"] is True
    deadline = migration["expires_at"]
    assert migrated["evidence_migration"] == migration

    service.run_once("maintenance")
    again = service.store.load_state()
    assert again["nodes"][key]["consecutive_unavailable_valid_days"] == 1
    assert again["nodes"][key]["unavailable_grace_active"] is True
    assert again["evidence_migration"]["expires_at"] == deadline

    service.clock = lambda: datetime(2026, 7, 25, 0, 2, tzinfo=timezone.utc)
    next_day = service.run_once("maintenance")
    assert next_day["regions"]["united-states"]["stable_slots"]["1"] != key
    assert service.store.load_state()["evidence_migration"]["expires_at"] == deadline


def test_m1_hard_deadline_overrides_same_day_grace(tmp_path):
    service, quick, _, _ = make_service(tmp_path, count=5)
    first = service.run_once("rebuild")
    key = first["regions"]["united-states"]["stable_slots"]["1"]
    make_legacy(service, key)
    service.run_once("maintenance")
    deadline = datetime.fromisoformat(service.store.load_state()["evidence_migration"]["expires_at"])
    service.clock = lambda: deadline - timedelta(hours=1)
    quick.unavailable.add(key)
    service.run_once("maintenance")
    assert service.store.load_state()["nodes"][key]["unavailable_grace_active"] is True
    service.clock = lambda: deadline
    expired = service.run_once("maintenance")
    assert expired["regions"]["united-states"]["stable_slots"]["1"] != key


def test_m1_recovery_does_not_grant_a_second_exception(tmp_path):
    service, quick, _, _ = make_service(tmp_path, count=5)
    first = service.run_once("rebuild")
    key = first["regions"]["united-states"]["stable_slots"]["1"]
    make_legacy(service, key)
    quick.unavailable.add(key)
    service.run_once("maintenance")
    quick.unavailable.clear()
    service.clock = lambda: datetime(2026, 7, 25, 0, 2, tzinfo=timezone.utc)
    service.run_once("maintenance")
    assert service.store.load_state()["nodes"][key]["unavailable_grace_active"] is False
    quick.unavailable.add(key)
    service.clock = lambda: datetime(2026, 7, 26, 0, 2, tzinfo=timezone.utc)
    after = service.run_once("maintenance")
    assert after["regions"]["united-states"]["stable_slots"]["1"] != key


def test_failed_commit_does_not_start_migration_deadline(tmp_path, monkeypatch):
    from node_health import storage
    service, _, _, _ = make_service(tmp_path, count=5)
    first = service.run_once("rebuild")
    make_legacy(service, first["regions"]["united-states"]["stable_slots"]["1"])
    write = storage.atomic_write_json
    def fail_commit(path, value):
        if path == service.store.current_path:
            raise OSError("synthetic commit failure")
        return write(path, value)
    with monkeypatch.context() as context:
        context.setattr(storage, "atomic_write_json", fail_commit)
        with pytest.raises(OSError):
            service.run_once()
    assert "evidence_migration" not in service.store.load_state()
    service.clock = lambda: datetime(2026, 7, 25, 0, 2, tzinfo=timezone.utc)
    service.run_once()
    assert service.store.load_state()["evidence_migration"]["committed_at"] == "2026-07-25T00:02:00+00:00"


def test_future_evidence_stops_before_inventory_and_preserves_files(tmp_path):
    service, _, _, _ = make_service(tmp_path)
    service.run_once("rebuild")
    state = service.store.load_state()
    state["minimum_evidence_reader_version"] = 99
    replace_committed_state(service, state)
    before = service.store.current_path.read_bytes()
    def unexpected_fetch(*_):
        pytest.fail("future evidence state must not fetch inventory")
    service.downloader = unexpected_fetch
    with pytest.raises(UnsupportedEvidenceVersion):
        service.run_once()
    assert service.store.current_path.read_bytes() == before


def test_migration_refresh_uses_rotation_not_a_new_full_pool(tmp_path):
    service, _, auditor, _ = make_service(tmp_path, count=20)
    service.run_once("rebuild")
    legacy = make_legacy(service)
    auditor.calls.clear()
    service.run_once()
    assert len(auditor.calls) <= 3 + math.ceil((20 - 3) * 0.5)
    assert set(legacy["stable_slots"]["united-states"].values()) <= set(auditor.calls)


def test_one_of_three_never_builds_six_day_qualification(tmp_path):
    service, quick, _, _ = make_service(tmp_path, count=4)
    check = quick.check
    def low_success(node, port):
        result = check(node, port)
        result.success_count = 1
        result.sample_count = 3
        result.success_rate = 0.3333
        return result
    quick.check = low_success
    for day in range(24, 30):
        service.clock = lambda day=day: datetime(2026, 7, day, 0, 2, tzinfo=timezone.utc)
        service.run_once()
    for node in service.store.load_state()["nodes"].values():
        assert node["healthy_streak_days"] == 0
        assert node["unavailable_grace_active"] is False
        assert all(not row["evidence_valid"] for row in node["daily_quality_history"])
        assert all(row["qualification_version"] == 1 for row in node["daily_quality_history"])


def test_exact_key_rename_and_outage_share_effective_region(tmp_path):
    service, quick, _, source = make_service(tmp_path, count=6)
    for proxy in source.proxies[3:]:
        proxy["name"] = proxy["name"].replace("US", "Other")
    first = service.run_once("rebuild")
    old = first["regions"]["united-states"]["stable_slots"]
    quick.unavailable.update(old.values())
    for proxy in source.proxies[:3]:
        proxy["name"] = proxy["name"].replace("US", "Renamed")
    after = service.run_once()
    assert after["regions"]["united-states"]["stable_slots"] == old
    assert after["outage_protection"]["regions"]["united-states"]["frozen"] is True


def test_map_api_report_and_txt_share_complete_alias_projection(tmp_path):
    service, _, _, source = make_service(tmp_path, count=4)
    source.proxies.append({**source.proxies[0], "name": "US extra 0"})
    current = service.run_once("rebuild")
    mapping = current["port_mapping"]
    assert current["source"]["node_count"] == 4
    assert current["source"]["input_count"] == 5
    assert len(mapping["entries"]) == 5
    assert len([item for item in mapping["bindings"] if item["entry_id"]]) == 5
    report = json.loads((service.store.scheduled_reports_dir / "latest.json").read_text())
    assert report["port_mapping"] == mapping
    assert report["runtime_target_status"] == "ready"
    exports = (service.store.local_socks_reports_dir / "latest/all-plain.txt").read_text().splitlines()
    expected = [f"socks5://{service.config.local_socks_advertise_host}:{item['port']}"
                for item in mapping["bindings"] if item["entry_id"]]
    assert exports == expected
    server = create_server(service.config, service)
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
    thread.start()
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{server.server_port}/local-socks-map.json") as response:
            actual = json.load(response)
        assert actual == mapping
        assert "password" not in json.dumps(actual)
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=3)


@pytest.mark.parametrize("audit", [False, True])
def test_retry_wait_reports_real_pending_scope_and_time(tmp_path, audit):
    service, quick, _, source = make_service(tmp_path, count=1)
    quick.unavailable_names.add("US node 0")
    waits = []
    def observe_wait(delay):
        progress = service.status()["progress"]
        assert progress["phase"] == "waiting-retry"
        assert progress["percent_scope"] == "phase"
        assert progress["retry_pending_nodes"] == 1
        assert progress["completed_nodes"] == 0
        assert datetime.fromisoformat(progress["next_retry_at"]) == service.clock() + timedelta(seconds=delay)
        if audit:
            status = service.store.load_audit_status(service.status()["active_audit_id"])
            assert status["progress"] == progress
        waits.append(progress["retry_round"])
    service.sleeper = observe_wait
    if audit:
        service.audit_downloader = lambda *_: source.download()
        audit_id = service.trigger_subscription_audit("https://inventory.invalid/test.yaml")
        assert _wait_for_audit(service, audit_id)["status"] == "completed_with_warnings"
    else:
        from node_health.service import NoPublishSafetyAbort
        with pytest.raises(NoPublishSafetyAbort):
            service.run_once()
    assert waits == [1, 2]


def test_chatgpt_outage_does_not_mask_fresh_claude_restriction(tmp_path):
    service, quick, _, _ = make_service(tmp_path, count=5)
    before = service.run_once("rebuild")
    keys = list(before["nodes"])
    quick.chatgpt_fail.update(keys)
    key = keys[0]
    index = int(before["nodes"][key]["name"].rsplit(" ", 1)[-1]) + 1
    exit_ip = f"8.8.8.{index}"
    quick.claude_results[key] = ClaudeResult(
        status="restricted", trace_ok=True, anthropic_ok=True, supported=False,
        exit_ip=exit_ip, country="CN",
    )
    after = service.run_once()
    assert "chatgpt" in after["outage_protection"]["ai_services"]
    assert after["nodes"][key]["ai_grade"] == "B"
    assert after["nodes"][key]["components"]["ai"] < before["nodes"][key]["components"]["ai"]


def test_same_service_egress_country_conflict_pauses_qualification(tmp_path):
    service, quick, _, _ = make_service(tmp_path, count=1)
    service.run_once("rebuild")
    check=quick.check
    def conflict(node, port):
        result=check(node,port)
        result.chatgpt.country="JP"
        return result
    quick.check=conflict
    service.clock=lambda: datetime(2026,7,25,0,2,tzinfo=timezone.utc)
    current=service.run_once()
    key=next(iter(current["nodes"]))
    assert "chatgpt-intelligence-country-conflict" in current["nodes"][key]["reasons"]
    state=service.store.load_state()["nodes"][key]
    assert state["healthy_streak_days"]==1
    assert state["daily_quality_history"][-1]["evidence_valid"] is False


def test_missing_current_service_exit_does_not_reuse_cached_ai_success(tmp_path):
    service, quick, _, _ = make_service(tmp_path, count=1)
    service.run_once("rebuild")
    check=quick.check
    def unknown_route(node, port):
        result=check(node,port)
        result.chatgpt=SiteProbeResult(attempted=True,probe_contract_version=1,http_status=503)
        result.chatgpt_ok=None
        return result
    quick.check=unknown_route
    current=service.run_once()
    key=next(iter(current["nodes"]))
    assert current["nodes"][key]["ai_grade"]=="B"
    assert service.store.load_state()["nodes"][key]["daily_quality_history"][-1]["evidence_valid"] is False
