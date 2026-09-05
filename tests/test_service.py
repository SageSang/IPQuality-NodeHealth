import contextlib
import json
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

import pytest

from node_health.app import DailyScheduler, create_server
from node_health.config import AppConfig, HttpConfig, InventoryConfig, PolicyConfig, ProbeConfig, ScheduleConfig
from node_health.identity import node_key
from node_health.models import ClaudeResult, FullResult, Node, QuickResult
from node_health.service import (
    NodeHealthService,
    NoPublishSafetyAbort,
    ScanStartError,
    _updated_promotion_cooldown,
)


def inventory(count=7):
    proxies = [
        {
            "name": f"US node {index}",
            "type": "ss",
            "server": f"node-{index}.example",
            "port": 443,
            "cipher": "aes-128-gcm",
            "password": f"secret-{index}",
        }
        for index in range(count)
    ]
    # JSON is valid YAML and avoids test output ever echoing the real inventory.
    return json.dumps({"proxies": proxies}).encode()


class InventorySource:
    def __init__(self, count):
        self.proxies = json.loads(inventory(count))["proxies"]

    def download(self, *_):
        return json.dumps({"proxies": self.proxies}).encode()

    def remove_name(self, name):
        self.proxies = [proxy for proxy in self.proxies if proxy["name"] != name]

    def rotate_connection(self, name):
        for proxy in self.proxies:
            if proxy["name"] == name:
                proxy["server"] = "rotated-" + proxy["server"]
                proxy["password"] = "rotated-" + proxy["password"]
                return
        raise AssertionError(f"unknown test node: {name}")


class FakeEnvironment:
    @contextlib.contextmanager
    def open(self, nodes):
        yield {node.key: 20000 + index for index, node in enumerate(nodes)}


class FakeQuick:
    def __init__(self):
        self.unavailable = set()
        self.unavailable_names = set()
        self.unstable = set()
        self.exit_ips = {}
        self.latencies = {}
        self.chatgpt_fail = set()
        self.claude_unreachable = set()
        self.claude_results = {}
        self.diagnosed_services = []

    def diagnose_ai_service(self, service):
        self.diagnosed_services.append(service)
        return {
            "direct": {service: True},
            "official_status": {"indicator": "none", "description": "All Systems Operational"},
            "diagnostic_only": True,
            "errors": [],
        }

    def check(self, node, port):
        available = node.key not in self.unavailable and node.name not in self.unavailable_names
        index = int(node.name.rsplit(" ", 1)[-1]) + 1
        return QuickResult(
            available=available,
            exit_ip=self.exit_ips.get(node.key, f"8.8.8.{index}"),
            country="US",
            asn="AS15169",
            latency_ms=self.latencies.get(node.key, float(index) * 20),
            success_rate=1.0 if available else 0,
            exit_ip_stable=node.key not in self.unstable,
            google_ok=True,
            chatgpt_ok=node.key not in self.chatgpt_fail,
            claude=self.claude_results.get(node.key) or (
                ClaudeResult(
                    status="unreachable",
                    trace_ok=False,
                    anthropic_ok=False,
                    supported=None,
                    route_stable=True,
                    error="connection refused",
                )
                if node.key in self.claude_unreachable
                else ClaudeResult(
                    status="available",
                    trace_ok=True,
                    anthropic_ok=True,
                    exit_ip=self.exit_ips.get(node.key, f"8.8.8.{index}"),
                    country="US",
                    supported=True,
                    route_stable=True,
                )
            ),
            checked_at="2026-07-24T00:00:00+00:00",
            error="" if available else "timeout",
        )


class FakeFull:
    def __init__(self):
        self.incomplete = set()
        self.statuses = {}
        self.exit_ips = {}
        self.risk_sources = {}
        self.calls = []
        self.started_event = None
        self.release_event = None
        self.checked_at = "2026-07-24T00:01:00+00:00"

    def check(self, node, port):
        self.calls.append(node.key)
        if self.started_event is not None:
            self.started_event.set()
        if self.release_event is not None:
            self.release_event.wait(timeout=5)
        completed = node.key not in self.incomplete
        index = int(node.name.rsplit(" ", 1)[-1]) + 1
        status = self.statuses.get(node.key, "Yes")
        return FullResult(
            completed=completed,
            audited_exit_ip=self.exit_ips.get(node.key, f"8.8.8.{index}"),
            risk_sources=self.risk_sources.get(
                node.key,
                {"source-a": "low", "source-b": "low", "source-c": "low"} if completed else {},
            ),
            details={
                "Info": {
                    "ASN": "15169",
                    "Organization": "Google LLC",
                    "Latitude": "34.0522",
                    "Longitude": "-118.2437",
                    "Map": "https://check.place/34.0522,-118.2437,15,en",
                    "TimeZone": "America/Los_Angeles",
                    "City": {
                        "Name": "Los Angeles",
                        "PostalCode": "90001",
                        "SubCode": "CA",
                        "Subdivisions": "California",
                    },
                    "Region": {"Code": "US", "Name": "United States"},
                    "RegisteredRegion": {
                        "Code": "US",
                        "Name": "United States",
                    },
                    "Type": "Geo-consistent",
                },
                "Media": {"ChatGPT": {"Status": status, "Region": "US", "Type": "Native"}},
            }
            if completed
            else {},
            checked_at=self.checked_at,
            error="" if completed else "provider timeout",
        )


def make_config(tmp_path):
    return AppConfig(
        inventory=InventoryConfig("https://inventory.invalid/all.yaml"),
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "data" / "reports",
        region_patterns={"united-states": [r"\bUS\b"]},
        probe=ProbeConfig(concurrency=4, full_concurrency=2),
        policy=PolicyConfig(
            stable_slots=3,
            full_audit_top_candidates=10,
            expected_country={"united-states": "US"},
        ),
        schedule=ScheduleConfig(enabled=False),
        http=HttpConfig(host="127.0.0.1", port=0, api_token="test-token"),
    )


def make_service(tmp_path, count=7):
    config = make_config(tmp_path)
    quick = FakeQuick()
    full = FakeFull()
    source = InventorySource(count)
    service = NodeHealthService(
        config,
        downloader=source.download,
        environment=FakeEnvironment(),
        quick_probe=quick,
        full_auditor=full,
        clock=lambda: datetime(2026, 7, 24, 0, 2, tzinfo=timezone.utc),
        sleeper=lambda _seconds: None,
    )
    return service, quick, full, source


def test_initial_unavailable_node_retries_and_transient_recovery_pauses_streak(tmp_path):
    service, _, _, _ = make_service(tmp_path, count=1)
    recovering = FakeQuick()
    calls = 0

    def check(node, port):
        nonlocal calls
        calls += 1
        result = FakeQuick.check(recovering, node, port)
        if calls == 1:
            return QuickResult(available=False, checked_at=result.checked_at, error="timeout")
        return result

    recovering.check = check
    delays = []
    service.quick_probe = recovering
    service.sleeper = delays.append

    current = service.run_once("rebuild")
    key = current["regions"]["united-states"]["stable_slots"]["1"]
    state = service.store.load_state()["nodes"][key]

    assert calls == 2
    assert delays == [120.0]
    assert state["transient_recovery"] is True
    assert state["healthy_streak_days"] == 0
    assert state["score_components"]["reliability"] == 12


def test_only_quality_promotion_starts_or_resets_promotion_cooldown():
    previous = {
        "promotion_cooldown_at": {
            "united-states": "2026-07-23T00:00:00+00:00"
        }
    }
    generated_at = "2026-07-24T00:02:00+00:00"

    for reason in (
        "quality-redline",
        "consecutive-unavailable",
        "missing-from-inventory",
        "degraded-quality-rerank",
        "rebuild",
    ):
        assert _updated_promotion_cooldown(
            previous,
            [{"region": "united-states", "reason": reason}],
            generated_at,
        ) == previous["promotion_cooldown_at"]

    assert _updated_promotion_cooldown(
        previous,
        [{"region": "united-states", "reason": "superior-candidate"}],
        generated_at,
    ) == {"united-states": generated_at}


def test_no_history_maintenance_becomes_full_rebuild_and_publishes_reports(tmp_path):
    service, _, full, _ = make_service(tmp_path)
    service.config.local_socks_advertise_host = "192.0.2.4"
    current = service.run_once("maintenance")
    assert current["requested_mode"] == "maintenance"
    assert current["mode"] == "rebuild"
    assert current["schema_version"] == 2
    assert len(current["identity_index"]) == 7
    published_keys = [
        key
        for region in current["regions"].values()
        for key in [
            *region["stable_slots"].values(),
            *region["ranked"],
        ]
    ]
    assert len(published_keys) == current["source"]["node_count"] == 7
    assert len(set(published_keys)) == 7
    assert len(full.calls) == 7
    assert len(current["regions"]["united-states"]["stable_slots"]) == 3
    assert (tmp_path / "data" / "current.json").exists()
    report = (tmp_path / "data" / "reports" / "2026-07-24.md").read_text(encoding="utf-8")
    assert "62800" in report
    assert "socks5://192.0.2.4:62800{US node 0}" in report
    assert "出口 IP" in report
    assert "Los Angeles" in report
    report_json = json.loads(
        (tmp_path / "data" / "reports" / "2026-07-24.json").read_text(
            encoding="utf-8"
        )
    )
    geo = report_json["nodes"][0]["geo"]
    assert geo == {
        "asn": "15169",
        "city_name": "Los Angeles",
        "country_code": "US",
        "country_name": "United States",
        "exit_ip": "8.8.8.1",
        "latitude": 34.0522,
        "location_type": "Geo-consistent",
        "longitude": -118.2437,
        "map_url": "https://check.place/34.0522,-118.2437,15,en",
        "observed_at": "2026-07-24T00:01:00+00:00",
        "organization": "Google LLC",
        "postal_code": "90001",
        "registered_country_code": "US",
        "registered_country_name": "United States",
        "result_source": "fresh",
        "source": "ipquality.Info",
        "subdivision_code": "CA",
        "subdivision_name": "California",
        "timezone": "America/Los_Angeles",
    }
    for item in report_json["nodes"]:
        local_socks = item.get("local_socks")
        if local_socks:
            assert local_socks["name"] == item["name"]
            assert local_socks["url"].endswith("{" + item["name"] + "}")

    latest_txt = (
        tmp_path
        / "data"
        / "reports"
        / "local-socks"
        / "latest"
        / "united-states.txt"
    ).read_text(encoding="utf-8")
    archived_txt = (
        tmp_path
        / "data"
        / "reports"
        / "scheduled"
        / "2026"
        / "07"
        / "24"
        / current["state_revision"]
        / "local-socks"
        / "united-states.txt"
    ).read_text(encoding="utf-8")
    assert archived_txt == latest_txt
    assert "socks5://192.0.2.4:62800{US node 0}" in latest_txt
    assert len(latest_txt.splitlines()) == 7
    assert "unresolved" not in latest_txt
    assert "{dynamic-" not in latest_txt
    all_latest_txt = (
        tmp_path
        / "data"
        / "reports"
        / "local-socks"
        / "latest"
        / "all.txt"
    ).read_text(encoding="utf-8")
    all_archived_txt = (
        tmp_path
        / "data"
        / "reports"
        / "scheduled"
        / "2026"
        / "07"
        / "24"
        / current["state_revision"]
        / "local-socks"
        / "all.txt"
    ).read_text(encoding="utf-8")
    assert all_archived_txt == all_latest_txt
    assert all_latest_txt == latest_txt
    all_plain_latest_txt = (
        tmp_path
        / "data"
        / "reports"
        / "local-socks"
        / "latest"
        / "all-plain.txt"
    ).read_text(encoding="utf-8")
    all_plain_archived_txt = (
        tmp_path
        / "data"
        / "reports"
        / "scheduled"
        / "2026"
        / "07"
        / "24"
        / current["state_revision"]
        / "local-socks"
        / "all-plain.txt"
    ).read_text(encoding="utf-8")
    assert all_plain_archived_txt == all_plain_latest_txt
    assert all_plain_latest_txt == "".join(
        f"{line.split('{', 1)[0]}\n" for line in all_latest_txt.splitlines()
    )
    assert "{" not in all_plain_latest_txt
    assert "geo" not in current["nodes"][next(iter(current["nodes"]))]


def test_other_order_is_frozen_during_maintenance_and_rebuilt_on_demand(tmp_path):
    service, _, full, source = make_service(tmp_path, count=4)
    for index, proxy in enumerate(source.proxies):
        proxy["name"] = f"Rare node {index}"

    first = service.run_once("rebuild")
    frozen = first["regions"]["other"]["ranked"]
    assert len(frozen) == 4
    assert first["regions"]["other"]["stable_slots"] == {}

    redline_key = frozen[0]
    full.statuses[redline_key] = "Block"
    service.config.policy.full_audit_daily_fraction = 1.0
    maintained = service.run_once("maintenance")
    assert maintained["regions"]["other"]["ranked"] == frozen
    assert maintained["nodes"][redline_key]["ai_grade"] == "B"
    assert redline_key not in maintained["regions"]["other"]["rejected"]
    state = json.loads(
        (tmp_path / "data" / "state.json").read_text(encoding="utf-8")
    )
    assert state["frozen_order"]["other"] == frozen

    rebuilt = service.run_once("rebuild")
    assert rebuilt["regions"]["other"]["ranked"] != frozen
    assert rebuilt["regions"]["other"]["ranked"][-1] == redline_key


def test_state_without_frozen_order_inherits_current_other_without_rebuild(tmp_path):
    service, _, _, source = make_service(tmp_path, count=4)
    for index, proxy in enumerate(source.proxies):
        proxy["name"] = f"Rare node {index}"
    first = service.run_once("rebuild")
    frozen = first["regions"]["other"]["ranked"]
    state_revision = first["state_revision"]
    for path in (
        tmp_path / "data" / "state.json",
        tmp_path / "data" / "state-snapshots" / f"{state_revision}.json",
    ):
        legacy = json.loads(path.read_text(encoding="utf-8"))
        legacy.pop("frozen_order")
        path.write_text(json.dumps(legacy), encoding="utf-8")

    current = service.run_once("maintenance")

    assert current["requested_mode"] == "maintenance"
    assert current["mode"] == "maintenance"
    assert current["regions"]["other"]["ranked"] == frozen
    state = json.loads(
        (tmp_path / "data" / "state.json").read_text(encoding="utf-8")
    )
    assert state["frozen_order"]["other"] == frozen


def test_other_connection_rotation_keeps_frozen_position_and_forces_full_audit(
    tmp_path,
):
    service, _, full, source = make_service(tmp_path, count=4)
    for index, proxy in enumerate(source.proxies):
        proxy["name"] = f"Rare node {index}"

    first = service.run_once("rebuild")
    frozen = first["regions"]["other"]["ranked"]
    old_key = frozen[1]
    name = first["identity_index"][old_key]["original_name"]
    source.rotate_connection(name)
    rotated_proxy = next(proxy for proxy in source.proxies if proxy["name"] == name)
    new_key = node_key(rotated_proxy)
    assert new_key != old_key

    full.calls.clear()
    maintained = service.run_once("maintenance")

    expected = list(frozen)
    expected[1] = new_key
    assert maintained["regions"]["other"]["ranked"] == expected
    assert new_key in full.calls
    assert maintained["identity_events"][0]["before"] == old_key
    assert maintained["identity_events"][0]["after"] == new_key


def test_unsampled_dynamic_nodes_keep_their_previous_score(tmp_path):
    service, quick, full, _ = make_service(tmp_path, count=12)
    first = service.run_once("rebuild")
    stable = set(first["regions"]["united-states"]["stable_slots"].values())
    dynamic = set(first["regions"]["united-states"]["ranked"])
    previous_scores = {
        key: first["nodes"][key]["score"] for key in dynamic
    }

    for key in dynamic:
        quick.latencies[key] = 5000
    full.calls.clear()
    second = service.run_once("maintenance")
    audited = set(full.calls)
    unsampled = dynamic - audited

    assert stable.issubset(audited)
    assert unsampled
    assert all(
        second["nodes"][key]["score"] == previous_scores[key]
        for key in unsampled
    )
    assert any(
        second["nodes"][key]["score"] != previous_scores[key]
        for key in dynamic & audited
    )
    report = json.loads(
        (tmp_path / "data" / "reports" / "2026-07-24.json").read_text(
            encoding="utf-8"
        )
    )
    report_nodes = {item["node_key"]: item for item in report["nodes"]}
    assert all(
        report_nodes[key]["geo"]["result_source"] == "cached" for key in unsampled
    )


def test_rotated_connection_is_forced_into_same_round_full_audit(tmp_path):
    service, _, full, source = make_service(tmp_path)
    first = service.run_once("rebuild")
    stable = set(first["regions"]["united-states"]["stable_slots"].values())
    old_key = next(
        key
        for key in first["regions"]["united-states"]["ranked"]
        if key not in stable
    )
    name = first["nodes"][old_key]["name"]
    source.rotate_connection(name)
    rotated_proxy = next(proxy for proxy in source.proxies if proxy["name"] == name)
    new_key = node_key(rotated_proxy)
    service.config.policy.full_audit_daily_fraction = 0
    service.config.policy.promotion_challengers_per_region = 0
    full.calls.clear()

    current = service.run_once("maintenance")

    assert new_key in full.calls
    assert old_key not in current["nodes"]
    assert new_key in current["nodes"]
    assert current["identity_events"] == [
        {
            "event": "identity-rotated-name-match",
            "method": "region-original-name",
            "source_id": "",
            "name": name,
            "region": "united-states",
            "before": old_key,
            "after": new_key,
        }
    ]


def test_rotated_stable_connection_keeps_slot_and_is_forced_into_full_audit(tmp_path):
    service, _, full, source = make_service(tmp_path)
    first = service.run_once("rebuild")
    slot = "2"
    old_key = first["regions"]["united-states"]["stable_slots"][slot]
    name = first["nodes"][old_key]["name"]
    first_state = json.loads(
        (tmp_path / "data" / "state.json").read_text(encoding="utf-8")
    )
    old_changed_at = first_state["slot_changed_at"]["united-states"][slot]
    source.rotate_connection(name)
    rotated_proxy = next(proxy for proxy in source.proxies if proxy["name"] == name)
    new_key = node_key(rotated_proxy)
    full.calls.clear()

    current = service.run_once("maintenance")
    state = json.loads(
        (tmp_path / "data" / "state.json").read_text(encoding="utf-8")
    )

    assert current["regions"]["united-states"]["stable_slots"][slot] == new_key
    assert new_key in full.calls
    assert state["slot_changed_at"]["united-states"][slot] == old_changed_at
    assert current["identity_events"][0]["before"] == old_key
    assert current["identity_events"][0]["after"] == new_key
    report = json.loads(
        (tmp_path / "data" / "reports" / "2026-07-24.json").read_text(
            encoding="utf-8"
        )
    )
    assert report["slot_changes"] == []


def test_full_passes_count_distinct_calendar_days_not_same_day_reruns(tmp_path):
    service, _, full, _ = make_service(tmp_path, count=1)
    first = service.run_once("rebuild")
    key = first["regions"]["united-states"]["stable_slots"]["1"]

    service.run_once("maintenance")
    same_day = json.loads(
        (tmp_path / "data" / "state.json").read_text(encoding="utf-8")
    )
    assert same_day["nodes"][key]["consecutive_full_passes"] == 1
    assert same_day["nodes"][key]["last_full_pass_day"] == "2026-07-24"
    assert same_day["nodes"][key]["healthy_streak_days"] == 1

    service.clock = lambda: datetime(2026, 7, 25, 0, 2, tzinfo=timezone.utc)
    full.checked_at = "2026-07-25T00:01:00+00:00"
    service.run_once("maintenance")
    next_day = json.loads(
        (tmp_path / "data" / "state.json").read_text(encoding="utf-8")
    )
    assert next_day["nodes"][key]["consecutive_full_passes"] == 2
    assert next_day["nodes"][key]["last_full_pass_day"] == "2026-07-25"
    assert next_day["nodes"][key]["healthy_streak_days"] == 2


def test_outage_pause_preserves_earned_grace_after_recovery(tmp_path, monkeypatch):
    service, quick, full, _ = make_service(tmp_path, count=5)
    first = service.run_once("rebuild")
    key = first["regions"]["united-states"]["stable_slots"]["1"]
    previous = service.store.load_state()
    for item in previous["nodes"].values():
        item["healthy_streak_days"] = 6
        item["last_healthy_day"] = "2026-07-24"
    quick.chatgpt_fail.update(first["nodes"])
    quick.claude_unreachable.update(first["nodes"])
    service.clock = lambda: datetime(2026, 7, 25, tzinfo=timezone.utc)
    full.checked_at = "2026-07-25T00:01:00+00:00"
    with monkeypatch.context() as context:
        context.setattr(service.store, "load_state", lambda: previous)
        service.run_once("maintenance")
    assert service.store.load_state()["nodes"][key]["healthy_streak_days"] == 6
    quick.chatgpt_fail.clear()
    quick.claude_unreachable.clear()
    service.clock = lambda: datetime(2026, 7, 26, tzinfo=timezone.utc)
    full.checked_at = "2026-07-26T00:01:00+00:00"
    service.run_once("maintenance")
    assert service.store.load_state()["nodes"][key]["healthy_streak_days"] == 7
    quick.unavailable.add(key)
    service.clock = lambda: datetime(2026, 7, 27, tzinfo=timezone.utc)
    full.checked_at = "2026-07-27T00:01:00+00:00"
    current = service.run_once("maintenance")
    assert key in current["regions"]["united-states"]["stable_slots"].values()
    assert service.store.load_state()["nodes"][key]["unavailable_grace_active"] is True


def test_scheduled_report_persists_duration_and_evidence_coverage(tmp_path):
    service, _, _, _ = make_service(tmp_path, count=1)
    current = service.run_once("rebuild")
    report = json.loads((service.config.reports_dir / "scheduled/latest.json").read_text())
    assert report["started_at"] == current["started_at"]
    assert report["duration_seconds"] == 0
    assert report["quality_summary"]["evidence_valid"] == 1


def test_dynamic_unavailable_counter_is_consecutive_and_resets_on_recovery(tmp_path):
    service, quick, _, _ = make_service(tmp_path, count=4)
    first = service.run_once("rebuild")
    key = first["regions"]["united-states"]["ranked"][0]
    quick.unavailable.add(key)

    for expected in (1, 2):
        current = service.run_once("maintenance")
        state = json.loads(
            (tmp_path / "data" / "state.json").read_text(encoding="utf-8")
        )
        assert state["nodes"][key]["consecutive_unavailable_runs"] == expected
        assert current["regions"]["united-states"]["ranked"][-1] == key

    quick.unavailable.remove(key)
    service.run_once("maintenance")
    recovered = json.loads(
        (tmp_path / "data" / "state.json").read_text(encoding="utf-8")
    )
    assert recovered["nodes"][key]["consecutive_unavailable_runs"] == 0


def test_unchanged_runtime_projection_keeps_version_stable(tmp_path):
    service, _, _, _ = make_service(tmp_path)
    first = service.run_once("rebuild")
    service.clock = lambda: datetime(2026, 7, 25, 0, 2, tzinfo=timezone.utc)
    second = service.run_once("maintenance")
    assert second["version"] == first["version"]
    assert second["generated_at"] != first["generated_at"]


def test_runtime_version_ignores_rejected_reason_text_but_tracks_membership():
    first = {
        "united-states": {
            "stable_slots": {"1": "stable"},
            "ranked": ["candidate"],
            "rejected": {"risky": "reason-one"},
        }
    }
    reason_changed = {
        "united-states": {
            "stable_slots": {"1": "stable"},
            "ranked": ["candidate"],
            "rejected": {"risky": "reason-two"},
        }
    }
    membership_changed = {
        "united-states": {
            "stable_slots": {"1": "stable"},
            "ranked": ["candidate"],
            "rejected": {"different": "reason-one"},
        }
    }

    baseline = NodeHealthService._runtime_version("source", first)
    assert NodeHealthService._runtime_version("source", reason_changed) == baseline
    assert NodeHealthService._runtime_version("source", membership_changed) != baseline


def test_maintenance_keeps_temporarily_unavailable_stable_slot(tmp_path):
    service, quick, _, _ = make_service(tmp_path)
    first = service.run_once("rebuild")
    before = first["regions"]["united-states"]["stable_slots"]
    failed_slot = "2"
    original_load_state = service.store.load_state
    previous = original_load_state()
    previous["nodes"][before[failed_slot]]["healthy_streak_days"] = 6
    previous["nodes"][before[failed_slot]]["last_healthy_day"] = "2026-07-24"
    prior_score = previous["nodes"][before[failed_slot]]["last_score"]
    service.store.load_state = lambda: previous
    quick.unavailable.add(before[failed_slot])
    service.clock = lambda: datetime(2026, 7, 25, 0, 2, tzinfo=timezone.utc)

    second = service.run_once("maintenance")
    service.store.load_state = original_load_state
    after = second["regions"]["united-states"]["stable_slots"]
    assert second["mode"] == "maintenance"
    assert after == before
    region = second["regions"]["united-states"]
    assert region["stable_status"][failed_slot]["status"] == "protected-unavailable"
    assert region["stable_status"][failed_slot]["last_exit_ip"]
    assert region["stable_status"][failed_slot]["last_full_checked_at"]
    assert region["stable_status"][failed_slot]["score"] == prior_score
    assert before[failed_slot] not in region["rejected"]
    state = json.loads((tmp_path / "data" / "state.json").read_text(encoding="utf-8"))
    assert state["nodes"][before[failed_slot]]["last_score"] == prior_score
    assert state["nodes"][before[failed_slot]]["consecutive_unavailable_runs"] == 1
    assert state["nodes"][before[failed_slot]]["consecutive_unavailable_valid_days"] == 1
    assert state["nodes"][before[failed_slot]]["unavailable_grace_active"] is True
    latest = (tmp_path / "data" / "reports" / "alerts" / "latest-run.md").read_text(
        encoding="utf-8"
    )
    assert "不可达" in latest


def test_maintenance_quality_redline_replaces_only_one_slot(tmp_path):
    service, quick, _, _ = make_service(tmp_path)
    first = service.run_once("rebuild")
    before = first["regions"]["united-states"]["stable_slots"]
    failed_slot = "2"
    quick.unstable.add(before[failed_slot])

    second = service.run_once("maintenance")
    after = second["regions"]["united-states"]["stable_slots"]
    assert after[failed_slot] != before[failed_slot]
    for slot in {"1", "3"}:
        assert after[slot] == before[slot]
    changes = [change for change in json.loads(
        (tmp_path / "data" / "reports" / "2026-07-24.json").read_text(encoding="utf-8")
    )["slot_changes"] if change["slot"] == failed_slot]
    assert changes[0]["reason"] == "quality-severe"
    assert changes[0]["before_name"].startswith("US node")
    assert changes[0]["after_name"].startswith("US node")
    assert changes[0]["redline_reasons"] == "egress-ip-unstable"
    history = list((tmp_path / "data" / "reports" / "alerts").glob("2026-07-24-*.md"))
    assert len(history) >= 2
    assert any("确认严重质量风险" in path.read_text(encoding="utf-8") for path in history)


def test_missing_inventory_node_is_immediately_replaced(tmp_path):
    service, _, _, source = make_service(tmp_path)
    first = service.run_once("rebuild")
    before = first["regions"]["united-states"]["stable_slots"]
    ghost_key = before["3"]
    source.remove_name(first["nodes"][ghost_key]["name"])

    second = service.run_once("maintenance")
    region = second["regions"]["united-states"]
    assert region["stable_slots"]["1"] == before["1"]
    assert region["stable_slots"]["2"] == before["2"]
    assert region["stable_slots"]["3"] != ghost_key
    assert ghost_key not in second["nodes"]
    report = (tmp_path / "data" / "reports" / "2026-07-24.md").read_text(encoding="utf-8")
    assert "节点已从订阅中消失" in report
    changes = (tmp_path / "data" / "reports" / "alerts" / "slot-changes-latest.md").read_text(
        encoding="utf-8"
    )
    assert "节点已从订阅中消失" in changes


def test_protected_stable_is_replaced_on_second_valid_unavailable_day(tmp_path):
    service, quick, _, _ = make_service(tmp_path)
    first = service.run_once("rebuild")
    before = first["regions"]["united-states"]["stable_slots"]
    failed_slot = "2"
    failed_key = before[failed_slot]
    original_load_state = service.store.load_state
    previous = original_load_state()
    previous["nodes"][failed_key]["healthy_streak_days"] = 6
    previous["nodes"][failed_key]["last_healthy_day"] = "2026-07-24"
    service.store.load_state = lambda: previous
    quick.unavailable.add(failed_key)

    service.clock = lambda: datetime(2026, 7, 25, 0, 2, tzinfo=timezone.utc)
    current = service.run_once("maintenance")
    service.store.load_state = original_load_state
    assert current["regions"]["united-states"]["stable_slots"] == before
    first_failure_state = service.store.load_state()
    assert first_failure_state["nodes"][failed_key]["unavailable_grace_active"] is True

    service.store.load_state = lambda: first_failure_state
    service.clock = lambda: datetime(2026, 7, 26, 0, 2, tzinfo=timezone.utc)
    current = service.run_once("maintenance")
    service.store.load_state = original_load_state
    after = current["regions"]["united-states"]["stable_slots"]
    assert after[failed_slot] != failed_key
    assert current["regions"]["united-states"]["ranked"][-1] == failed_key
    report = json.loads(
        (tmp_path / "data" / "reports" / "2026-07-26.json").read_text(
            encoding="utf-8"
        )
    )
    changes = [
        change for change in report["slot_changes"] if change["slot"] == failed_slot
    ]
    assert [change["reason"] for change in changes] == ["confirmed-unavailable"]


def test_protected_stable_recovery_keeps_slot_and_restarts_at_day_one(tmp_path):
    service, quick, full, _ = make_service(tmp_path)
    first = service.run_once("rebuild")
    before = first["regions"]["united-states"]["stable_slots"]
    failed_key = before["2"]
    previous = service.store.load_state()
    previous["nodes"][failed_key]["healthy_streak_days"] = 6
    previous["nodes"][failed_key]["last_healthy_day"] = "2026-07-24"
    original_load_state = service.store.load_state
    service.store.load_state = lambda: previous
    quick.unavailable.add(failed_key)
    service.clock = lambda: datetime(2026, 7, 25, 0, 2, tzinfo=timezone.utc)
    service.run_once("maintenance")
    service.store.load_state = original_load_state

    quick.unavailable.remove(failed_key)
    full.checked_at = "2026-07-26T00:01:00+00:00"
    service.clock = lambda: datetime(2026, 7, 26, 0, 2, tzinfo=timezone.utc)
    recovered = service.run_once("maintenance")
    state = service.store.load_state()["nodes"][failed_key]

    assert recovered["regions"]["united-states"]["stable_slots"] == before
    assert state["healthy_streak_days"] == 1
    assert state["consecutive_unavailable_valid_days"] == 0
    assert state["unavailable_grace_active"] is False


def test_global_all_unavailable_freezes_slots_order_and_counters(tmp_path):
    service, quick, full, _ = make_service(tmp_path, count=5)
    first = service.run_once("rebuild")
    before_state = service.store.load_state()
    quick.unavailable.update(first["nodes"])
    full.checked_at = "2026-07-25T00:01:00+00:00"
    service.clock = lambda: datetime(2026, 7, 25, 0, 2, tzinfo=timezone.utc)

    frozen = service.run_once("maintenance")
    after_state = service.store.load_state()

    assert frozen["regions"]["united-states"]["stable_slots"] == first["regions"]["united-states"]["stable_slots"]
    assert frozen["regions"]["united-states"]["ranked"] == first["regions"]["united-states"]["ranked"]
    assert frozen["outage_protection"]["regions"]["__global__"]["reason"] == "all-nodes-unavailable"
    for key in first["nodes"]:
        for field in (
            "consecutive_full_passes",
            "last_full_pass_day",
            "healthy_streak_days",
            "consecutive_unavailable_valid_days",
            "unavailable_grace_active",
            "daily_quality_history",
        ):
            assert after_state["nodes"][key][field] == before_state["nodes"][key][field]


def test_availability_collapse_threshold_freezes_without_all_nodes_failing(tmp_path):
    service, quick, full, _ = make_service(tmp_path, count=10)
    first = service.run_once("rebuild")
    before_state = service.store.load_state()
    keys = list(first["nodes"])
    quick.unavailable.update(keys[:9])
    full.checked_at = "2026-07-25T00:01:00+00:00"
    service.clock = lambda: datetime(2026, 7, 25, 0, 2, tzinfo=timezone.utc)

    frozen = service.run_once("maintenance")
    diagnostic = frozen["outage_protection"]["regions"]["__global__"]
    after_state = service.store.load_state()

    assert diagnostic["reason"] == "availability-collapse"
    assert diagnostic["available_ratio"] == 0.1
    assert frozen["regions"]["united-states"]["stable_slots"] == first["regions"]["united-states"]["stable_slots"]
    assert frozen["regions"]["united-states"]["ranked"] == first["regions"]["united-states"]["ranked"]
    assert after_state["availability_baselines"] == before_state["availability_baselines"]
    for key in keys:
        assert after_state["nodes"][key]["consecutive_full_passes"] == before_state["nodes"][key]["consecutive_full_passes"]
        assert after_state["nodes"][key]["last_full_pass_day"] == before_state["nodes"][key]["last_full_pass_day"]


def test_ai_service_outage_preserves_previous_ai_grade_and_blocks_history_growth(tmp_path):
    service, quick, full, _ = make_service(tmp_path, count=5)
    first = service.run_once("rebuild")
    before_state = service.store.load_state()
    keys = set(first["nodes"])
    quick.chatgpt_fail.update(keys)
    quick.claude_unreachable.update(keys)
    full.checked_at = "2026-07-25T00:01:00+00:00"
    service.clock = lambda: datetime(2026, 7, 25, 0, 2, tzinfo=timezone.utc)

    protected = service.run_once("maintenance")
    after_state = service.store.load_state()

    assert set(protected["outage_protection"]["ai_services"]) == {"chatgpt", "claude"}
    assert set(quick.diagnosed_services) == {"chatgpt", "claude"}
    assert protected["regions"]["united-states"]["stable_slots"] == first["regions"]["united-states"]["stable_slots"]
    for key in keys:
        assert protected["nodes"][key]["ai_grade"] == first["nodes"][key]["ai_grade"]
        assert protected["nodes"][key]["components"]["ai"] == first["nodes"][key]["components"]["ai"]
        assert after_state["nodes"][key]["healthy_streak_days"] == before_state["nodes"][key]["healthy_streak_days"]
        assert after_state["nodes"][key]["daily_quality_history"][-1]["evidence_valid"] is False
        assert (
            after_state["nodes"][key]["last_full"]["details"]["Media"]["ChatGPT"]["Status"]
            == "Yes"
        )


def test_chatgpt_outage_denominator_excludes_unsupported_exit_countries(tmp_path):
    service, _, _, _ = make_service(tmp_path)
    nodes = [
        Node(str(index), str(index), "other", {"name": str(index)})
        for index in range(5)
    ]
    results = {
        node.key: QuickResult(
            available=True,
            country="CN" if index < 4 else "US",
            chatgpt_ok=False if index < 4 else True,
            claude=ClaudeResult(status="available", supported=True),
        )
        for index, node in enumerate(nodes)
    }

    status = service._apply_ai_service_outage_guard(nodes, results)

    assert "chatgpt" not in status
    assert not any(result.chatgpt_service_outage for result in results.values())


def test_ai_service_outage_guard_requires_minimum_sample(tmp_path):
    service, _, _, _ = make_service(tmp_path, count=1)
    node = Node("one", "one", "united-states", {"name": "one"})
    result = QuickResult(
        available=True,
        exit_ip="8.8.8.8",
        country="US",
        chatgpt_ok=False,
        claude=ClaudeResult(status="unreachable", supported=True),
    )

    status = service._apply_ai_service_outage_guard([node], {node.key: result})

    assert status == {}
    assert result.chatgpt_service_outage is False
    assert result.claude.service_outage is False


def test_ai_service_outage_guard_deduplicates_shared_service_egresses(tmp_path):
    service, _, _, _ = make_service(tmp_path, count=5)
    nodes = [
        Node(str(index), str(index), "united-states", {"name": str(index)})
        for index in range(5)
    ]
    results = {
        node.key: QuickResult(
            available=True,
            exit_ip="8.8.8.8",
            country="US",
            chatgpt_ok=False,
            claude=ClaudeResult(
                status="unreachable",
                exit_ip="1.1.1.1",
                country="US",
                supported=True,
            ),
        )
        for node in nodes
    }

    status = service._apply_ai_service_outage_guard(nodes, results)

    assert status == {}
    assert not any(result.chatgpt_service_outage for result in results.values())
    assert not any(result.claude.service_outage for result in results.values())


def test_ai_outage_country_fallback_requires_same_exit_ip(tmp_path):
    service, _, _, _ = make_service(tmp_path, count=5)
    nodes = [
        Node(str(index), str(index), "united-states", {"name": str(index)})
        for index in range(5)
    ]
    results = {
        node.key: QuickResult(
            available=True,
            exit_ip=f"8.8.8.{index + 1}",
            country="",
            chatgpt_ok=False,
            claude=ClaudeResult(status="available", supported=True),
        )
        for index, node in enumerate(nodes)
    }
    previous = {
        "nodes": {
            node.key: {
                "last_exit_ip": f"8.8.8.{index + 1}",
                "last_country": "US",
            }
            for index, node in enumerate(nodes)
        }
    }

    status = service._apply_ai_service_outage_guard(nodes, results, previous)

    assert status["chatgpt"]["sample_size"] == 5
    previous["nodes"][nodes[0].key]["last_exit_ip"] = "9.9.9.9"
    for result in results.values():
        result.chatgpt_service_outage = False
    status = service._apply_ai_service_outage_guard(nodes, results, previous)
    assert "chatgpt" not in status


def test_observed_country_is_persisted_with_the_exit_ip(tmp_path):
    service, _, _, _ = make_service(tmp_path, count=1)

    current = service.run_once("rebuild")
    key = next(iter(current["nodes"]))
    state = service.store.load_state()["nodes"][key]

    assert state["last_country"] == "US"
    assert state["last_exit_ip"]


def test_outage_guard_uses_only_same_exit_full_country_majority(tmp_path):
    service, _, _, _ = make_service(tmp_path, count=5)
    nodes = [Node(str(index), str(index), "united-states", {}) for index in range(5)]
    results = {node.key: QuickResult(True, exit_ip=f"8.8.8.{index+1}", chatgpt_ok=False) for index, node in enumerate(nodes)}
    previous = {"nodes": {node.key: {
        "last_exit_ip": results[node.key].exit_ip,
        "last_full": FullResult(True, audited_exit_ip=results[node.key].exit_ip,
            details={"Factor": {"CountryCode": {"one": "US", "two": "US"}}}).to_dict(),
    } for node in nodes}}
    assert service._apply_ai_service_outage_guard(nodes, results, previous)["chatgpt"]["sample_size"] == 5
    previous["nodes"][nodes[0].key]["last_full"]["audited_exit_ip"] = "1.1.1.1"
    assert "chatgpt" not in service._apply_ai_service_outage_guard(nodes, results, previous)


def test_claude_degraded_fleet_triggers_service_outage_guard(tmp_path):
    service, _, _, _ = make_service(tmp_path)
    nodes = [
        Node(str(index), str(index), "united-states", {"name": str(index)})
        for index in range(5)
    ]
    results = {
        node.key: QuickResult(
            available=True,
            exit_ip=f"8.8.8.{int(node.key) + 1}",
            country="US",
            chatgpt_ok=True,
            claude=ClaudeResult(
                status="degraded",
                trace_ok=True,
                anthropic_ok=False,
                exit_ip=f"1.1.1.{int(node.key) + 1}",
                country="US",
                supported=True,
            ),
        )
        for node in nodes
    }

    status = service._apply_ai_service_outage_guard(nodes, results)

    assert status["claude"]["failure_ratio"] == 1
    assert all(result.claude.service_outage for result in results.values())
    assert all(result.claude.status == "unknown" for result in results.values())


def test_claude_outage_country_fallback_is_scoped_to_claude_egress(tmp_path):
    service, _, _, _ = make_service(tmp_path, count=5)
    nodes = [
        Node(str(index), str(index), "united-states", {"name": str(index)})
        for index in range(5)
    ]
    results = {
        node.key: QuickResult(
            available=True,
            exit_ip=f"8.8.8.{index + 1}",
            country="US",
            chatgpt_ok=True,
            claude=ClaudeResult(
                status="unreachable",
                exit_ip=f"1.1.1.{index + 1}",
                country="",
                supported=None,
            ),
        )
        for index, node in enumerate(nodes)
    }

    assert "claude" not in service._apply_ai_service_outage_guard(nodes, results)

    previous = {
        "nodes": {
            node.key: {
                "last_claude": ClaudeResult(
                    exit_ip=f"1.1.1.{index + 1}", country="US"
                ).to_dict()
            }
            for index, node in enumerate(nodes)
        }
    }
    status = service._apply_ai_service_outage_guard(nodes, results, previous)

    assert status["claude"]["sample_size"] == 5


def test_outage_freeze_preserves_trusted_ai_and_score_state(tmp_path):
    service, quick, _, _ = make_service(tmp_path, count=5)
    first = service.run_once("rebuild")
    before = service.store.load_state()
    keys = set(first["nodes"])
    quick.unavailable.update(keys)
    for key in keys:
        quick.claude_results[key] = ClaudeResult(status="unknown")
    service.clock = lambda: datetime(2026, 7, 25, 0, 2, tzinfo=timezone.utc)

    frozen = service.run_once("maintenance")
    after = service.store.load_state()

    assert frozen["outage_protection"]["regions"]["__global__"]["frozen"] is True
    for key in keys:
        assert after["nodes"][key]["last_claude"] == before["nodes"][key]["last_claude"]
        assert after["nodes"][key]["ai_grade"] == before["nodes"][key]["ai_grade"]
        assert after["nodes"][key]["score_components"] == before["nodes"][key]["score_components"]
        assert after["nodes"][key]["last_score"] == before["nodes"][key]["last_score"]
        assert after["nodes"][key]["last_decision"] == before["nodes"][key]["last_decision"]
        assert after["nodes"][key]["last_frozen_observation"]["available"] is False


def test_outage_freeze_preserves_rejected_membership_and_runtime_version(tmp_path):
    service, quick, full, source = make_service(tmp_path, count=5)
    risky_key = node_key(source.proxies[0])
    full.risk_sources[risky_key] = {
        "source-a": "high",
        "source-b": "high",
        "source-c": "high",
    }
    first = service.run_once("rebuild")
    before_rejected = first["regions"]["united-states"]["rejected"]
    quick.unavailable.update(first["nodes"])
    service.clock = lambda: datetime(2026, 7, 25, 0, 2, tzinfo=timezone.utc)

    frozen = service.run_once("maintenance")

    assert risky_key in before_rejected
    assert frozen["regions"]["united-states"]["rejected"] == before_rejected
    assert frozen["version"] == first["version"]


def test_existing_vacant_slot_full_audits_every_available_candidate(tmp_path):
    service, _, full, _ = make_service(tmp_path, count=7)
    first = service.run_once("rebuild")
    previous = service.store.load_state()
    del previous["stable_slots"]["united-states"]["3"]
    original_load_state = service.store.load_state
    service.store.load_state = lambda: previous
    full.calls.clear()
    service.clock = lambda: datetime(2026, 7, 25, 0, 2, tzinfo=timezone.utc)

    service.run_once("maintenance")
    service.store.load_state = original_load_state

    assert set(full.calls) == set(first["nodes"])


def test_report_exit_ip_redaction_covers_nested_claude_full_and_region_fields(tmp_path):
    service, _, _, _ = make_service(tmp_path, count=3)
    service.config.report.include_exit_ip = False

    service.run_once("rebuild")
    json_report = (
        tmp_path / "data" / "reports" / "2026-07-24.json"
    ).read_text(encoding="utf-8")
    markdown_report = (
        tmp_path / "data" / "reports" / "2026-07-24.md"
    ).read_text(encoding="utf-8")

    assert "8.8.8." not in json_report
    assert "8.8.8." not in markdown_report


def test_incomplete_claude_split_route_risk_uses_cache_but_pauses_streak(tmp_path):
    service, quick, full, _ = make_service(tmp_path, count=1)
    first = service.run_once("rebuild")
    key = next(iter(first["nodes"]))
    previous = service.store.load_state()
    previous["nodes"][key]["last_claude"] = ClaudeResult(
        status="available",
        trace_ok=True,
        anthropic_ok=True,
        exit_ip="1.1.1.1",
        country="US",
        supported=True,
        asn="AS13335",
        organization="Cloudflare",
        risk_sources={"IPinfo-privacy": "low", "ipapi-flags": "low"},
        factors={},
        residential="probable",
        intelligence_complete=True,
    ).to_dict()
    original_load_state = service.store.load_state
    service.store.load_state = lambda: previous
    quick.claude_results[key] = ClaudeResult(
        status="available",
        trace_ok=True,
        anthropic_ok=True,
        exit_ip="1.1.1.1",
        country="US",
        supported=True,
        intelligence_complete=False,
        error="ipinfo timeout; ipapi timeout",
    )
    full.checked_at = "2026-07-25T00:01:00+00:00"
    service.clock = lambda: datetime(2026, 7, 25, 0, 2, tzinfo=timezone.utc)

    current = service.run_once("maintenance")
    service.store.load_state = original_load_state
    state = service.store.load_state()["nodes"][key]

    assert "claude-risk-incomplete" in current["nodes"][key]["reasons"]
    assert state["last_claude"]["intelligence_cached"] is True
    assert state["last_claude"]["risk_sources"] == {
        "IPinfo-privacy": "low",
        "ipapi-flags": "low",
    }
    assert state["healthy_streak_days"] == previous["nodes"][key]["healthy_streak_days"]
    assert state["daily_quality_history"][-1]["evidence_valid"] is False


def test_replaced_node_recovers_without_original_slot_rights(tmp_path):
    service, quick, _, _ = make_service(tmp_path)
    first = service.run_once("rebuild")
    key = first["regions"]["united-states"]["stable_slots"]["1"]
    quick.unavailable.add(key)
    service.run_once("maintenance")

    quick.unavailable.remove(key)
    current = service.run_once("maintenance")
    state = json.loads((tmp_path / "data" / "state.json").read_text(encoding="utf-8"))
    assert current["regions"]["united-states"]["stable_slots"]["1"] != key
    assert key in current["regions"]["united-states"]["ranked"]
    assert state["nodes"][key]["consecutive_unavailable_runs"] == 0


def test_legacy_v2_state_keeps_slots_and_initializes_new_history_incrementally(tmp_path):
    service, _, full, _ = make_service(tmp_path)
    first = service.run_once("rebuild")
    legacy = service.store.load_state()
    legacy.pop("ranked_order", None)
    for payload in legacy["nodes"].values():
        for field in (
            "healthy_streak_days",
            "last_healthy_day",
            "consecutive_unavailable_valid_days",
            "last_unavailable_day",
            "unavailable_grace_active",
            "daily_quality_history",
            "last_claude",
            "ai_grade",
            "risk_grade",
            "overall_grade",
            "residential_grade",
            "score_components",
        ):
            payload.pop(field, None)
    original_load_state = service.store.load_state
    service.store.load_state = lambda: legacy
    full.checked_at = "2026-07-25T00:01:00+00:00"
    service.clock = lambda: datetime(2026, 7, 25, 0, 2, tzinfo=timezone.utc)

    migrated = service.run_once("maintenance")
    service.store.load_state = original_load_state
    state = service.store.load_state()

    assert migrated["mode"] == "maintenance"
    assert migrated["regions"]["united-states"]["stable_slots"] == first["regions"]["united-states"]["stable_slots"]
    for payload in state["nodes"].values():
        assert payload["healthy_streak_days"] == 1
        assert len(payload["daily_quality_history"]) == 1
        assert payload["last_claude"]["status"] == "available"


def test_unchanged_rebuild_refreshes_slot_timestamps_without_slot_change_alert(tmp_path):
    service, _, _, _ = make_service(tmp_path)
    first = service.run_once("rebuild")
    first_slots = first["regions"]["united-states"]["stable_slots"]
    service.clock = lambda: datetime(2026, 7, 25, 0, 2, tzinfo=timezone.utc)
    second = service.run_once("rebuild")
    assert second["regions"]["united-states"]["stable_slots"] == first_slots
    report = json.loads(
        (tmp_path / "data" / "reports" / "2026-07-25.json").read_text(encoding="utf-8")
    )
    assert report["slot_changes"] == []
    assert any("local_socks" in item for item in report["nodes"])
    state = json.loads((tmp_path / "data" / "state.json").read_text(encoding="utf-8"))
    assert all(
        value.startswith("2026-07-25")
        for value in state["slot_changed_at"]["united-states"].values()
    )


def test_rebuild_publishes_when_some_full_audits_are_incomplete(tmp_path):
    service, _, full, _ = make_service(tmp_path, count=2)
    # Discover deterministic keys through one parser-free quick setup by marking
    # the second audit call incomplete after it starts.
    original = full.check

    def fail_second(node, port):
        result = original(node, port)
        if len(full.calls) == 2:
            result.completed = False
            result.error = "provider timeout"
        return result

    full.check = fail_second
    current = service.run_once("rebuild")
    assert (tmp_path / "data" / "current.json").exists()
    assert service.status()["status"] == "ok"
    assert current["mode"] == "rebuild"


def test_rebuild_tolerates_isolated_incomplete_audit_but_never_slots_it(tmp_path):
    service, _, full, source = make_service(tmp_path, count=7)
    incomplete_key = node_key(source.proxies[-1])
    full.incomplete.add(incomplete_key)

    current = service.run_once("rebuild")

    stable = set(current["regions"]["united-states"]["stable_slots"].values())
    assert incomplete_key not in stable
    assert incomplete_key in current["regions"]["united-states"]["ranked"]
    assert current["nodes"][incomplete_key]["confidence"] == "low"


def test_rebuild_publishes_when_reputation_providers_are_temporarily_empty(tmp_path):
    service, _, full, source = make_service(tmp_path)
    first = service.run_once("rebuild")
    for proxy in source.proxies:
        full.risk_sources[node_key(proxy)] = {
            "source-a": "null",
            "source-b": "unknown",
        }
    service.clock = lambda: datetime(2026, 7, 25, 0, 2, tzinfo=timezone.utc)

    current = service.run_once("rebuild")

    persisted = json.loads(
        (tmp_path / "data" / "current.json").read_text(encoding="utf-8")
    )
    assert persisted["version"] == current["version"]
    assert persisted["generated_at"] != first["generated_at"]


def test_incomplete_maintenance_full_audit_breaks_consecutive_passes(tmp_path):
    service, _, full, _ = make_service(tmp_path)
    first = service.run_once("rebuild")
    candidate_key = first["regions"]["united-states"]["ranked"][0]
    full.incomplete.add(candidate_key)

    service.run_once("maintenance")
    state = json.loads((tmp_path / "data" / "state.json").read_text(encoding="utf-8"))
    assert state["nodes"][candidate_key]["consecutive_full_passes"] == 0

    full.incomplete.clear()
    service.run_once("maintenance")
    state = json.loads((tmp_path / "data" / "state.json").read_text(encoding="utf-8"))
    assert state["nodes"][candidate_key]["consecutive_full_passes"] == 1


def test_changed_exit_ip_never_reuses_old_full_after_repeated_failures(tmp_path):
    service, quick, full, _ = make_service(tmp_path, count=1)
    first = service.run_once("rebuild")
    key = first["regions"]["united-states"]["stable_slots"]["1"]
    old_exit_ip = "8.8.8.1"
    new_exit_ip = "1.1.1.1"

    quick.exit_ips[key] = new_exit_ip
    full.incomplete.add(key)
    second = service.run_once("maintenance")
    third = service.run_once("maintenance")

    assert second["nodes"][key]["confidence"] == "low"
    assert third["nodes"][key]["confidence"] == "low"
    assert "stable-egress-ip-changed" in second["nodes"][key]["reasons"]
    state = json.loads((tmp_path / "data" / "state.json").read_text(encoding="utf-8"))
    assert state["nodes"][key]["last_exit_ip"] == new_exit_ip
    assert state["nodes"][key]["last_full_exit_ip"] == old_exit_ip
    assert state["nodes"][key]["last_full"]["audited_exit_ip"] == old_exit_ip
    assert state["nodes"][key]["consecutive_full_passes"] == 0


def test_transient_chatgpt_failure_pauses_history_and_preserves_trusted_full(tmp_path):
    service, _, full, _ = make_service(tmp_path, count=1)
    first = service.run_once("rebuild")
    key = first["regions"]["united-states"]["stable_slots"]["1"]
    full.statuses[key] = "Failed"

    current = service.run_once("maintenance")
    state = json.loads((tmp_path / "data" / "state.json").read_text(encoding="utf-8"))

    assert current["nodes"][key]["decision"] == "eligible"
    assert current["nodes"][key]["confidence"] == "high"
    assert "fresh-ai-unconfirmed:Failed" in current["nodes"][key]["reasons"]
    assert state["nodes"][key]["consecutive_full_passes"] == 0
    assert (
        state["nodes"][key]["last_full"]["details"]["Media"]["ChatGPT"]["Status"]
        == "Yes"
    )


def test_incomplete_fresh_full_degrades_stable_slot_without_losing_trusted_full(tmp_path):
    service, _, full, _ = make_service(tmp_path, count=1)
    first = service.run_once("rebuild")
    key = first["regions"]["united-states"]["stable_slots"]["1"]
    full.incomplete.add(key)

    current = service.run_once("maintenance")
    state = json.loads((tmp_path / "data" / "state.json").read_text(encoding="utf-8"))
    slot = current["regions"]["united-states"]
    latest = (tmp_path / "data" / "reports" / "alerts" / "latest-run.md").read_text(
        encoding="utf-8"
    )

    assert slot["stable_slots"]["1"] == key
    assert slot["stable_status"]["1"]["status"] == "degraded"
    assert "full-audit-incomplete" in slot["stable_status"]["1"]["reasons"]
    assert state["nodes"][key]["last_full"]["completed"] is True
    assert "本轮深度检测未完成" in latest


def test_risk_redline_remains_latched_until_a_fresh_clean_full(tmp_path):
    service, _, full, _ = make_service(tmp_path)
    first = service.run_once("rebuild")
    key = first["regions"]["united-states"]["stable_slots"]["1"]
    full.risk_sources[key] = {"source-a": "high", "source-b": "high", "source-c": "high"}

    blocked = service.run_once("maintenance")
    assert blocked["nodes"][key]["decision"] == "rejected"
    assert key not in blocked["regions"]["united-states"]["stable_slots"].values()

    service.config.policy.promotion_challengers_per_region = 0
    service.config.policy.full_audit_daily_fraction = 0
    full.risk_sources[key] = {"source-a": "low", "source-b": "low", "source-c": "low"}
    full.calls.clear()
    still_blocked = service.run_once("maintenance")
    state = json.loads((tmp_path / "data" / "state.json").read_text(encoding="utf-8"))

    assert key not in full.calls
    assert still_blocked["nodes"][key]["decision"] == "rejected"
    assert key in still_blocked["regions"]["united-states"]["ranked"]
    assert key in still_blocked["regions"]["united-states"]["rejected"]
    assert (
        state["nodes"][key]["last_full"]["risk_sources"]["source-a"]
        == "high"
    )


def test_ambiguous_fresh_full_cannot_clear_a_latched_redline(tmp_path):
    service, _, full, _ = make_service(tmp_path)
    first = service.run_once("rebuild")
    key = first["regions"]["united-states"]["stable_slots"]["1"]
    full.risk_sources[key] = {"source-a": "high", "source-b": "high", "source-c": "high"}
    service.run_once("maintenance")

    full.statuses[key] = "Failed"
    full.risk_sources[key] = {"source-a": "low", "source-b": "low", "source-c": "low"}
    ambiguous = service.run_once("maintenance")
    state = json.loads((tmp_path / "data" / "state.json").read_text(encoding="utf-8"))

    assert ambiguous["nodes"][key]["decision"] == "rejected"
    assert key in ambiguous["regions"]["united-states"]["ranked"]
    assert key in ambiguous["regions"]["united-states"]["rejected"]
    assert (
        state["nodes"][key]["last_full"]["risk_sources"]["source-a"]
        == "high"
    )


def test_absent_dynamic_redline_is_remembered_when_node_returns(tmp_path):
    service, _, full, source = make_service(tmp_path)
    first = service.run_once("rebuild")
    key = first["regions"]["united-states"]["ranked"][0]
    proxy = next(item for item in source.proxies if node_key(item) == key)
    full.risk_sources[key] = {"source-a": "high", "source-b": "high", "source-c": "high"}
    blocked = service.run_once("maintenance")
    assert blocked["nodes"][key]["decision"] == "rejected"

    source.remove_name(proxy["name"])
    service.run_once("maintenance")
    absent_state = json.loads(
        (tmp_path / "data" / "state.json").read_text(encoding="utf-8")
    )
    assert absent_state["nodes"][key]["current_status"] == "absent"

    source.proxies.append(proxy)
    full.statuses[key] = "Failed"
    full.risk_sources[key] = {"source-a": "low", "source-b": "low", "source-c": "low"}
    returned = service.run_once("maintenance")

    assert returned["nodes"][key]["decision"] == "rejected"
    assert key in returned["regions"]["united-states"]["ranked"]
    assert key in returned["regions"]["united-states"]["rejected"]


def test_stable_warning_is_degraded_without_changing_the_slot(tmp_path):
    service, quick, full, _ = make_service(tmp_path)
    first = service.run_once("rebuild")
    before = first["regions"]["united-states"]["stable_slots"]
    key = before["1"]
    quick.exit_ips[key] = "1.1.1.1"
    full.exit_ips[key] = "1.1.1.1"

    current = service.run_once("maintenance")
    region = current["regions"]["united-states"]

    assert region["stable_slots"] == before
    assert region["stable_status"]["1"]["status"] == "degraded"
    assert "stable-egress-ip-changed" in region["stable_status"]["1"]["reasons"]
    report = (tmp_path / "data" / "reports" / "2026-07-24.md").read_text(encoding="utf-8")
    latest = (tmp_path / "data" / "reports" / "alerts" / "latest-run.md").read_text(
        encoding="utf-8"
    )
    assert "降级" in report
    assert "降级" in latest


def test_first_rebuild_all_unavailable_aborts_without_publishing(tmp_path):
    service, quick, _, _ = make_service(tmp_path, count=100)
    quick.unavailable_names.update(f"US node {index}" for index in range(100))
    with pytest.raises(NoPublishSafetyAbort):
        service.run_once("rebuild")
    assert not (tmp_path / "data" / "current.json").exists()


def test_http_endpoints_and_token(tmp_path):
    service, _, _, _ = make_service(tmp_path, count=1)
    service.run_once("rebuild")
    server = create_server(service.config, service)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        with urllib.request.urlopen(base + "/healthz") as response:
            health = json.load(response)
            assert health["status"] == "ok"
            assert health["progress"] is None
            assert health["started_at"] is None
        with urllib.request.urlopen(base + "/current.json") as response:
            ranking = json.load(response)
            assert ranking["mode"] == "rebuild"
            assert "nodes" not in ranking
            assert "stable_status" not in ranking["regions"]["united-states"]
            assert ranking["regions"]["united-states"]["stable_slots"]
            assert len(ranking["identity_index"]) == 1
            assert all(
                "server" not in identity and "password" not in identity
                for identity in ranking["identity_index"].values()
            )

        unauthorized = urllib.request.Request(base + "/api/run?mode=maintenance", data=b"", method="POST")
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(unauthorized)
        assert error.value.code == 401

        wrong_media = urllib.request.Request(
            base + "/api/v1/audits",
            data=b"{}",
            headers={"Authorization": "Bearer test-token"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(wrong_media)
        assert error.value.code == 415

        oversized = urllib.request.Request(
            base + "/api/v1/audits",
            data=b"x" * (16 * 1024 + 1),
            headers={
                "Authorization": "Bearer test-token",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(oversized)
        assert error.value.code == 413

        request = urllib.request.Request(
            base + "/api/run?mode=maintenance",
            data=b"",
            headers={"Authorization": "Bearer test-token"},
            method="POST",
        )
        with urllib.request.urlopen(request) as response:
            assert response.status == 202
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_healthz_reports_live_scheduled_scan_progress(tmp_path):
    service, _, full, _ = make_service(tmp_path, count=1)
    full.started_event = threading.Event()
    full.release_event = threading.Event()
    server = create_server(service.config, service)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        request = urllib.request.Request(
            base + "/api/run?mode=rebuild",
            data=b"",
            headers={"Authorization": "Bearer test-token"},
            method="POST",
        )
        with urllib.request.urlopen(request) as response:
            assert response.status == 202
        assert full.started_event.wait(timeout=2)

        with urllib.request.urlopen(base + "/healthz") as response:
            health = json.load(response)
        assert health["running"] is True
        assert health["running_mode"] == "rebuild"
        assert health["started_at"] == "2026-07-24T00:02:00+00:00"
        assert health["progress"] == {
            "phase": "full-scan",
            "inventory_nodes": 1,
            "completed_nodes": 0,
            "total_nodes": 1,
            "remaining_nodes": 1,
            "percent": 0.0,
        }

        full.release_event.set()
        deadline = time.monotonic() + 3
        while service.status()["running"] and time.monotonic() < deadline:
            time.sleep(0.01)
        assert service.status()["running"] is False
        assert service.status()["progress"] is None
        assert service.status()["last_success"] is not None
    finally:
        full.release_event.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_trigger_start_failure_releases_lock_and_returns_http_503(tmp_path, monkeypatch):
    service, _, _, _ = make_service(tmp_path, count=1)

    def fail_start():
        raise ScanStartError("failed to start background scan: thread unavailable")

    server = create_server(service.config, service)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    monkeypatch.setattr(service, "trigger", lambda _mode: fail_start())
    try:
        request = urllib.request.Request(
            base + "/api/run?mode=maintenance",
            data=b"",
            headers={"Authorization": "Bearer test-token"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request)
        assert error.value.code == 503
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)

    monkeypatch.undo()

    original_start = threading.Thread.start

    def raise_on_start(_thread):
        raise RuntimeError("thread unavailable")

    monkeypatch.setattr(threading.Thread, "start", raise_on_start)
    with pytest.raises(ScanStartError, match="thread unavailable"):
        service.trigger("maintenance")

    status = service.status()
    assert status["status"] == "degraded"
    assert status["running"] is False
    assert status["running_mode"] is None
    assert "thread unavailable" in status["last_error"]

    monkeypatch.setattr(threading.Thread, "start", original_start)
    assert service.run_once("rebuild")["mode"] == "rebuild"


def test_scheduler_retries_worker_start_failure_without_stopping(tmp_path, monkeypatch):
    service, _, _, _ = make_service(tmp_path, count=1)
    scheduler = DailyScheduler(service, service.config)
    now = datetime(2026, 7, 24, 5, 30, tzinfo=timezone.utc)

    def fail_start(_mode):
        raise ScanStartError("thread unavailable")

    monkeypatch.setattr(service, "trigger", fail_start)

    scheduler._trigger_due_scan("2026-07-24", now)
    assert scheduler.attempts == 1
    assert scheduler.pending_date == ""
    assert scheduler.retry_after == now.replace(hour=6, minute=30)
    assert scheduler.last_date != "2026-07-24"

    scheduler._trigger_due_scan("2026-07-24", now)
    scheduler._trigger_due_scan("2026-07-24", now)
    assert scheduler.attempts == 3
    assert scheduler.last_date == "2026-07-24"
    assert scheduler.retry_after is None


def test_service_restores_last_success_from_published_current(tmp_path):
    service, _, _, _ = make_service(tmp_path, count=1)
    current = service.run_once("rebuild")
    restarted, _, _, _ = make_service(tmp_path, count=1)
    assert restarted.status()["last_success"] == current["generated_at"]


def _wait_for_audit(service, audit_id, timeout=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = service.store.load_audit_status(audit_id)
        if status.get("status") in {
            "completed",
            "completed_with_warnings",
            "failed",
            "interrupted",
        }:
            return status
        time.sleep(0.01)
    raise AssertionError(f"audit did not complete: {audit_id}")


def test_subscription_audit_checks_all_nodes_without_changing_ranking_state(tmp_path):
    service, quick, full, source = make_service(tmp_path, count=4)
    service.audit_downloader = lambda *_: source.download()
    unavailable_key = node_key(source.proxies[-1])
    quick.unavailable.add(unavailable_key)

    audit_id = service.trigger_subscription_audit(
        "https://inventory.invalid/sub-store?target=ClashMeta&token=private-token",
        "Airport <script>alert(1)</script>",
    )

    assert audit_id
    status = _wait_for_audit(service, audit_id)
    assert status["status"] == "completed_with_warnings"
    assert status["progress"] == {
        "phase": "completed",
        "inventory_nodes": 4,
        "completed_nodes": 4,
        "total_nodes": 4,
        "remaining_nodes": 0,
        "percent": 100.0,
    }
    assert status["summary"]["nodes"] == 4
    assert status["summary"]["available"] == 3
    assert unavailable_key not in full.calls
    assert not (tmp_path / "data" / "current.json").exists()
    assert not (tmp_path / "data" / "state.json").exists()

    report_path = service.store.audit_report_path(audit_id, "json")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["report_kind"] == "subscription-audit"
    assert report["summary"]["nodes"] == 4
    assert len(report["nodes"]) == 4
    assert report["nodes"][0]["connection"]["protocol"] == "ss"
    assert {item["full_result_source"] for item in report["nodes"]} == {"fresh", "none"}
    serialized = report_path.read_text(encoding="utf-8")
    assert "private-token" not in serialized
    assert "secret-" not in serialized
    assert report["nodes"][0]["full"]["details"]["Media"]["ChatGPT"]["Status"] == "Yes"
    markdown = service.store.audit_report_path(audit_id, "md").read_text(encoding="utf-8")
    assert "IPQuality 原始结果" in markdown
    assert "本次临时审计不会修改正式环境的稳定槽位" in markdown
    assert "<script>" not in markdown
    audit_txt = (
        service.store.audit_report_dir(audit_id)
        / "local-socks"
        / "united-states.txt"
    ).read_text(encoding="utf-8")
    audit_all_txt = (
        service.store.audit_report_dir(audit_id)
        / "local-socks"
        / "all.txt"
    ).read_text(encoding="utf-8")
    assert "{US node 0}" in audit_txt
    assert "{dynamic-" not in audit_txt
    assert audit_all_txt == audit_txt
    audit_all_plain_txt = (
        service.store.audit_report_dir(audit_id)
        / "local-socks"
        / "all-plain.txt"
    ).read_text(encoding="utf-8")
    assert audit_all_plain_txt == "".join(
        f"{line.split('{', 1)[0]}\n" for line in audit_all_txt.splitlines()
    )


def test_subscription_audit_retries_transient_quick_failure(tmp_path):
    service, quick, full, source = make_service(tmp_path, count=1)
    service.audit_downloader = lambda *_: source.download()
    target_key = node_key(source.proxies[0])
    original_check = quick.check
    calls = 0

    def flaky_check(node, port):
        nonlocal calls
        calls += 1
        if node.key == target_key and calls == 1:
            return QuickResult(
                available=False,
                checked_at="2026-07-24T00:00:00+00:00",
                error="timeout",
            )
        return original_check(node, port)

    quick.check = flaky_check
    audit_id = service.trigger_subscription_audit(
        "https://inventory.invalid/audit", "Transient audit"
    )
    status = _wait_for_audit(service, audit_id)
    report = json.loads(
        service.store.audit_report_path(audit_id, "json").read_text(
            encoding="utf-8"
        )
    )

    assert status["status"] == "completed"
    assert calls == 2
    assert target_key in full.calls
    assert report["nodes"][0]["quick"]["transient_recovery"] is True
    assert report["nodes"][0]["quick"]["retry_count"] == 1


def test_subscription_audit_applies_ai_service_outage_guard(tmp_path):
    service, quick, _, source = make_service(tmp_path, count=5)
    service.audit_downloader = lambda *_: source.download()
    keys = {node_key(proxy) for proxy in source.proxies}
    quick.chatgpt_fail.update(keys)
    quick.claude_unreachable.update(keys)

    audit_id = service.trigger_subscription_audit(
        "https://inventory.invalid/audit", "AI outage audit"
    )
    status = _wait_for_audit(service, audit_id)
    report = json.loads(
        service.store.audit_report_path(audit_id, "json").read_text(
            encoding="utf-8"
        )
    )

    assert status["status"] == "completed_with_warnings"
    assert set(report["outage_protection"]["ai_services"]) == {
        "chatgpt",
        "claude",
    }
    assert set(quick.diagnosed_services) == {"chatgpt", "claude"}
    assert status["summary"]["ai_service_outages"] == ["chatgpt", "claude"]
    assert report["summary"]["rejected"] == 0


def test_claude_country_conflict_pauses_quality_evidence(tmp_path):
    service, quick, _, source = make_service(tmp_path, count=1)
    key = node_key(source.proxies[0])
    quick.claude_results[key] = ClaudeResult(
        status="available",
        trace_ok=True,
        anthropic_ok=True,
        exit_ip="1.1.1.1",
        country="US",
        intelligence_country="CN",
        supported=True,
        intelligence_complete=True,
        risk_sources={"IPinfo-privacy": "low", "ipapi-flags": "low"},
    )

    current = service.run_once("rebuild")
    state = service.store.load_state()["nodes"][key]

    assert current["nodes"][key]["confidence"] == "low"
    assert any(
        reason.startswith("claude-intelligence-country-conflict:")
        for reason in current["nodes"][key]["reasons"]
    )
    assert state["healthy_streak_days"] == 0
    assert state["daily_quality_history"][-1]["evidence_valid"] is False


def test_subscription_audit_http_api_and_authenticated_report_download(tmp_path):
    service, _, _, source = make_service(tmp_path, count=1)
    service.audit_downloader = lambda *_: source.download()
    server = create_server(service.config, service)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        body = json.dumps(
            {
                "name": "Airport API",
                "subscription_url": "https://inventory.invalid/sub-store?target=ClashMeta",
            }
        ).encode()
        unauthorized = urllib.request.Request(
            base + "/api/v1/audits",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(unauthorized)
        assert error.value.code == 401

        request = urllib.request.Request(
            base + "/api/v1/audits",
            data=body,
            headers={
                "Authorization": "Bearer test-token",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(request) as response:
            accepted = json.load(response)
        status = _wait_for_audit(service, accepted["id"])
        assert status["status"] == "completed"

        status_request = urllib.request.Request(
            base + accepted["status_url"],
            headers={"Authorization": "Bearer test-token"},
        )
        with urllib.request.urlopen(status_request) as response:
            api_status = json.load(response)
        assert api_status["report_urls"]["json"].endswith("/report.json")

        report_request = urllib.request.Request(
            base + api_status["report_urls"]["json"],
            headers={"Authorization": "Bearer test-token"},
        )
        with urllib.request.urlopen(report_request) as response:
            assert json.load(response)["report_kind"] == "subscription-audit"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_subscription_audit_worker_start_failure_releases_shared_lock(tmp_path, monkeypatch):
    service, _, _, source = make_service(tmp_path, count=1)
    service.audit_downloader = lambda *_: source.download()
    real_start = threading.Thread.start
    monkeypatch.setattr(
        threading.Thread,
        "start",
        lambda _thread: (_ for _ in ()).throw(RuntimeError("thread unavailable")),
    )

    with pytest.raises(ScanStartError, match="thread unavailable"):
        service.trigger_subscription_audit("https://inventory.invalid/audit", "Airport")

    monkeypatch.setattr(threading.Thread, "start", real_start)
    assert service.run_once("rebuild")["mode"] == "rebuild"
