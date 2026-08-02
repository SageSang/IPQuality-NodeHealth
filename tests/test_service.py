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
from node_health.models import FullResult, QuickResult
from node_health.service import NodeHealthService, ScanStartError


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
            chatgpt_ok=True,
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
                {"source-a": "low", "source-b": "low"} if completed else {},
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
                "Media": {"ChatGPT": {"Status": status}},
            }
            if completed
            else {},
            checked_at="2026-07-24T00:01:00+00:00",
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
    )
    return service, quick, full, source


def test_no_history_maintenance_becomes_full_rebuild_and_publishes_reports(tmp_path):
    service, _, full, _ = make_service(tmp_path)
    service.config.local_socks_advertise_host = "192.0.2.4"
    current = service.run_once("maintenance")
    assert current["requested_mode"] == "maintenance"
    assert current["mode"] == "rebuild"
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
        / current["version"]
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
        / current["version"]
        / "local-socks"
        / "all.txt"
    ).read_text(encoding="utf-8")
    assert all_archived_txt == all_latest_txt
    assert all_latest_txt == latest_txt
    assert "geo" not in current["nodes"][next(iter(current["nodes"]))]


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


def test_unchanged_runtime_projection_keeps_version_stable(tmp_path):
    service, _, _, _ = make_service(tmp_path)
    first = service.run_once("rebuild")
    service.clock = lambda: datetime(2026, 7, 25, 0, 2, tzinfo=timezone.utc)
    second = service.run_once("maintenance")
    assert second["version"] == first["version"]
    assert second["generated_at"] != first["generated_at"]


def test_maintenance_keeps_temporarily_unavailable_stable_slot(tmp_path):
    service, quick, _, _ = make_service(tmp_path)
    first = service.run_once("rebuild")
    before = first["regions"]["united-states"]["stable_slots"]
    failed_slot = "2"
    prior_score = json.loads(
        (tmp_path / "data" / "state.json").read_text(encoding="utf-8")
    )["nodes"][before[failed_slot]]["last_score"]
    quick.unavailable.add(before[failed_slot])

    second = service.run_once("maintenance")
    after = second["regions"]["united-states"]["stable_slots"]
    assert second["mode"] == "maintenance"
    assert after == before
    region = second["regions"]["united-states"]
    assert region["stable_status"][failed_slot]["status"] == "unavailable"
    assert region["stable_status"][failed_slot]["last_exit_ip"]
    assert region["stable_status"][failed_slot]["last_full_checked_at"]
    assert region["stable_status"][failed_slot]["score"] == prior_score
    assert before[failed_slot] not in region["rejected"]
    state = json.loads((tmp_path / "data" / "state.json").read_text(encoding="utf-8"))
    assert state["nodes"][before[failed_slot]]["last_score"] == prior_score
    assert state["nodes"][before[failed_slot]]["consecutive_unavailable_runs"] == 1
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
    assert changes[0]["reason"] == "quality-redline"
    assert changes[0]["before_name"].startswith("US node")
    assert changes[0]["after_name"].startswith("US node")
    assert changes[0]["redline_reasons"] == "egress-ip-unstable"
    history = list((tmp_path / "data" / "reports" / "alerts").glob("2026-07-24-*.md"))
    assert len(history) >= 2
    assert any("触发质量红线" in path.read_text(encoding="utf-8") for path in history)


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


def test_three_consecutive_unavailable_runs_replace_only_that_slot(tmp_path):
    service, quick, _, _ = make_service(tmp_path)
    first = service.run_once("rebuild")
    before = first["regions"]["united-states"]["stable_slots"]
    failed_slot = "2"
    failed_key = before[failed_slot]
    quick.unavailable.add(failed_key)

    for expected_runs in (1, 2):
        current = service.run_once("maintenance")
        assert current["regions"]["united-states"]["stable_slots"] == before
        state = json.loads(
            (tmp_path / "data" / "state.json").read_text(encoding="utf-8")
        )
        assert state["nodes"][failed_key]["consecutive_unavailable_runs"] == expected_runs

    current = service.run_once("maintenance")
    after = current["regions"]["united-states"]["stable_slots"]
    assert after[failed_slot] != failed_key
    assert after["1"] == before["1"]
    assert after["3"] == before["3"]
    report = json.loads(
        (tmp_path / "data" / "reports" / "2026-07-24.json").read_text(
            encoding="utf-8"
        )
    )
    assert any(
        change["slot"] == failed_slot
        and change["reason"] == "repeated-unavailable"
        for change in report["slot_changes"]
    )


def test_reachable_stable_node_resets_unavailable_counter(tmp_path):
    service, quick, _, _ = make_service(tmp_path)
    first = service.run_once("rebuild")
    key = first["regions"]["united-states"]["stable_slots"]["1"]
    quick.unavailable.add(key)
    service.run_once("maintenance")

    quick.unavailable.remove(key)
    current = service.run_once("maintenance")
    state = json.loads((tmp_path / "data" / "state.json").read_text(encoding="utf-8"))
    assert current["regions"]["united-states"]["stable_slots"]["1"] == key
    assert state["nodes"][key]["consecutive_unavailable_runs"] == 0


def test_unchanged_rebuild_resets_cooldown_without_slot_change_alert(tmp_path):
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
    assert persisted["version"] != first["version"]


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


def test_transient_chatgpt_failure_resets_passes_but_preserves_trusted_full(tmp_path):
    service, _, full, _ = make_service(tmp_path, count=1)
    first = service.run_once("rebuild")
    key = first["regions"]["united-states"]["stable_slots"]["1"]
    full.statuses[key] = "Failed"

    current = service.run_once("maintenance")
    state = json.loads((tmp_path / "data" / "state.json").read_text(encoding="utf-8"))

    assert current["nodes"][key]["decision"] == "eligible"
    assert current["nodes"][key]["confidence"] == "low"
    assert "chatgpt-unconfirmed:Failed" in current["nodes"][key]["reasons"]
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


def test_chatgpt_redline_remains_latched_until_a_fresh_clean_full(tmp_path):
    service, _, full, _ = make_service(tmp_path)
    first = service.run_once("rebuild")
    key = first["regions"]["united-states"]["stable_slots"]["1"]
    full.statuses[key] = "Block"

    blocked = service.run_once("maintenance")
    assert blocked["nodes"][key]["decision"] == "rejected"
    assert key not in blocked["regions"]["united-states"]["stable_slots"].values()

    service.config.policy.full_audit_top_candidates = 0
    full.statuses.pop(key)
    full.calls.clear()
    still_blocked = service.run_once("maintenance")
    state = json.loads((tmp_path / "data" / "state.json").read_text(encoding="utf-8"))

    assert key not in full.calls
    assert still_blocked["nodes"][key]["decision"] == "rejected"
    assert key not in still_blocked["regions"]["united-states"]["ranked"]
    assert (
        state["nodes"][key]["last_full"]["details"]["Media"]["ChatGPT"]["Status"]
        == "Block"
    )


def test_ambiguous_fresh_full_cannot_clear_a_latched_redline(tmp_path):
    service, _, full, _ = make_service(tmp_path)
    first = service.run_once("rebuild")
    key = first["regions"]["united-states"]["stable_slots"]["1"]
    full.statuses[key] = "Block"
    service.run_once("maintenance")

    full.statuses[key] = "Failed"
    ambiguous = service.run_once("maintenance")
    state = json.loads((tmp_path / "data" / "state.json").read_text(encoding="utf-8"))

    assert ambiguous["nodes"][key]["decision"] == "rejected"
    assert key not in ambiguous["regions"]["united-states"]["ranked"]
    assert (
        state["nodes"][key]["last_full"]["details"]["Media"]["ChatGPT"]["Status"]
        == "Block"
    )


def test_absent_dynamic_redline_is_remembered_when_node_returns(tmp_path):
    service, _, full, source = make_service(tmp_path)
    first = service.run_once("rebuild")
    key = first["regions"]["united-states"]["ranked"][0]
    proxy = next(item for item in source.proxies if node_key(item) == key)
    full.statuses[key] = "Block"
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
    returned = service.run_once("maintenance")

    assert returned["nodes"][key]["decision"] == "rejected"
    assert key not in returned["regions"]["united-states"]["ranked"]


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


def test_first_rebuild_publishes_even_when_all_nodes_are_unavailable(tmp_path):
    service, quick, _, _ = make_service(tmp_path, count=100)
    quick.unavailable_names.update(f"US node {index}" for index in range(100))
    current = service.run_once("rebuild")
    assert (tmp_path / "data" / "current.json").exists()
    region = current["regions"]["united-states"]
    assert region["stable_slots"] == {}
    assert len(region["ranked"]) == 100


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
