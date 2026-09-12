import json
import logging
import subprocess
import threading
import time
import urllib.error
import urllib.request

import pytest
import yaml

from node_health.app import create_server
from node_health.config import AppConfig, HttpConfig, InventoryConfig
from node_health.errors import safe_failure, sanitize_error_fields
from node_health.service import NodeHealthService
from node_health.storage import StateStore, atomic_write_json


SECRET = "SYNTHETIC_REVIEW_CREDENTIAL"
AUDIT_ID = "20260912T000000Z-1234abcd"


def config(tmp_path):
    return AppConfig(
        inventory=InventoryConfig("https://inventory.invalid/all.yaml"),
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        http=HttpConfig(host="127.0.0.1", port=0, api_token="test-admin"),
    )


def test_parse_failure_never_exposes_source_in_health_or_logs(tmp_path, caplog):
    payload = f"proxies:\n- name: example\n  password: [{SECRET}\n".encode()
    service = NodeHealthService(config(tmp_path), downloader=lambda *_: payload)
    caplog.set_level(logging.INFO, logger="node_health")
    with pytest.raises(yaml.YAMLError):
        service.run_once()
    server = create_server(service.config, service)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{server.server_port}/healthz") as response:
            assert response.status == 200
            health = json.load(response)
        assert health["status"] == "degraded"
        assert health["last_error_detail"]["code"] == "inventory_invalid_yaml"
        assert health["last_error_detail"]["line"] == 4
        assert SECRET not in json.dumps(health)
        with pytest.raises(urllib.error.HTTPError):
            urllib.request.urlopen(f"http://127.0.0.1:{server.server_port}/missing?token={SECRET}")
        assert SECRET not in caplog.text
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)


@pytest.mark.parametrize("error", [
    RuntimeError(f"response contained {SECRET}"),
    urllib.error.URLError(f"https://inventory.invalid/?token={SECRET}"),
    subprocess.TimeoutExpired(["curl", "-H", f"Authorization: Bearer {SECRET}"], 5),
])
def test_external_failures_are_not_formatted(error):
    failure = safe_failure(error, "quick-scan")
    assert SECRET not in str(failure)
    assert SECRET not in json.dumps(failure.to_dict())


def test_audit_failure_is_safe_in_status_persistence_and_logs(tmp_path, caplog):
    def fail_download(*_):
        raise RuntimeError(f"https://inventory.invalid/?token={SECRET}")

    service = NodeHealthService(config(tmp_path), audit_downloader=fail_download)
    caplog.set_level(logging.INFO, logger="node_health")
    audit_id = service.trigger_subscription_audit("https://inventory.invalid/temporary.yaml")
    deadline = time.monotonic() + 3
    while service.status()["running"] and time.monotonic() < deadline:
        time.sleep(0.01)
    status = service.store.load_audit_status(audit_id)
    assert status["status"] == "failed"
    assert status["error_detail"]["phase"] == "downloading"
    assert SECRET not in json.dumps(status)
    assert SECRET not in json.dumps(service.status())
    assert SECRET not in caplog.text
    assert SECRET not in service.store.audit_status_path(audit_id).read_text()


def test_legacy_report_views_preserve_originals_without_leaking_errors(tmp_path):
    store = StateStore(config(tmp_path))
    report = {"summary": {"nodes": 1}, "nodes": [{"name": "example", "quick": {"error": SECRET}}]}
    atomic_write_json(store.audit_status_path(AUDIT_ID), {"id": AUDIT_ID, "status": "failed", "error": SECRET})
    atomic_write_json(store.audit_report_path(AUDIT_ID, "json"), report)
    markdown_path = store.audit_report_path(AUDIT_ID, "md")
    markdown_path.write_text(f"old report: {SECRET}")
    assert SECRET not in json.dumps(store.load_audit_status(AUDIT_ID))
    assert SECRET.encode() not in store.read_safe_audit_report(AUDIT_ID, "json")
    assert SECRET.encode() not in store.read_safe_audit_report(AUDIT_ID, "md")
    assert SECRET in markdown_path.read_text()
    assert SECRET in store.audit_report_path(AUDIT_ID, "json").read_text()


def test_nested_error_projection_retains_safe_diagnostics():
    failure = safe_failure(ValueError(SECRET), "full-scan")
    original = {"full": {"error": str(failure), "details": {"error": SECRET}}, "error_detail": failure.to_dict()}
    projected = sanitize_error_fields(original)
    assert projected["full"]["error"] == str(failure)
    assert projected["error_detail"]["diagnostic_id"] == failure.diagnostic_id
    assert SECRET not in json.dumps(projected)
    assert original["full"]["details"]["error"] == SECRET
