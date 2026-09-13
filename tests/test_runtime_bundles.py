import base64
import copy
import json
import threading
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from node_health import storage
from node_health.app import create_server
from node_health.runtime_bundle import byte_digest
from node_health.storage import StateStore
from test_service import make_service


def decoded(body):
    bundle = json.loads(body)
    payload = base64.b64decode(bundle["inventory"], validate=True)
    assert byte_digest(payload) == bundle["inventory_sha256"]
    return bundle, payload


def test_scan_keeps_exact_input_despite_upstream_changes_and_duplicate_aliases(tmp_path):
    service, quick, _, source = make_service(tmp_path, count=2)
    source.proxies += [copy.deepcopy(source.proxies[0]), {**source.proxies[0], "name": "US alias 0"}]
    payload = b"\xef\xbb\xbf" + json.dumps({"proxies": source.proxies}, indent=2).encode()
    calls = []

    def download(*_):
        calls.append(True)
        return payload if len(calls) == 1 else b'{"proxies": []}'

    service.downloader = download
    check = quick.check

    def changing_check(node, port):
        if len(source.proxies) > 1:
            source.proxies[0]["port"] = 8443
            source.proxies[1]["server"] = "changed.example"
            source.proxies[:] = source.proxies[:1]
        return check(node, port)

    quick.check = changing_check
    current = service.run_once()
    bundle, captured = decoded(service.store.read_runtime_bundle())
    assert captured == payload
    assert len(calls) == 1
    assert len(bundle["mapping"]["entries"]) == 4
    assert bundle["mapping"] == current["port_mapping"]
    assert bundle["bundle_id"] == current["state_revision"]
    assert (service.store.runtime_bundles_dir.stat().st_mode & 0o777) == 0o700
    assert all((path.stat().st_mode & 0o777) == 0o600 for path in service.store.runtime_bundles_dir.iterdir())


def test_generations_are_unique_retained_by_commit_and_do_not_change_health(tmp_path):
    service, _, _, _ = make_service(tmp_path, count=1)
    first = service.run_once()
    first_body = service.store.read_runtime_bundle()
    state = service.store.load_state()
    service.run_once()
    second = service.store.load_current()
    assert first["state_revision"] != second["state_revision"]
    assert first["port_mapping"]["mapping_version"] == second["port_mapping"]["mapping_version"]
    assert service.store.read_runtime_bundle(first["state_revision"]) == first_body
    after = service.store.load_state()
    for key in state["nodes"]:
        for field in ("healthy_streak_days", "qualification_version"):
            assert state["nodes"][key].get(field) == after["nodes"][key].get(field)
    assert state.get("evidence_migration") == after.get("evidence_migration")
    service.run_once()
    with pytest.raises(FileNotFoundError):
        service.store.read_runtime_bundle(first["state_revision"])
    assert len(list(service.store.runtime_bundles_dir.glob("*.json"))) == 2
    assert service.store.read_runtime_bundle(second["state_revision"])


def test_failed_current_commit_preserves_old_bundle_and_restart_cleans_orphans(tmp_path, monkeypatch):
    service, _, _, source = make_service(tmp_path, count=1)
    service.run_once()
    old_body = service.store.read_runtime_bundle()
    old_current = service.store.load_current()
    old_state = service.store.load_state()
    original = storage.atomic_write_json

    def fail_current(path, value):
        if path == service.store.current_path:
            raise OSError("synthetic commit failure")
        original(path, value)

    source.proxies[0]["port"] = 8443
    monkeypatch.setattr(storage, "atomic_write_json", fail_current)
    with pytest.raises(OSError):
        service.run_once()
    assert service.store.load_current() == old_current
    assert service.store.load_state() == old_state
    assert service.store.read_runtime_bundle() == old_body
    orphan = service.store.runtime_bundles_dir / "s-uncommitted.json"
    orphan.write_bytes(old_body)
    with pytest.raises(FileNotFoundError):
        service.store.read_runtime_bundle("s-uncommitted")
    restored = StateStore(service.config)
    assert not orphan.exists()
    assert restored.read_runtime_bundle() == old_body


def test_startup_gc_failure_does_not_block_committed_data(tmp_path, monkeypatch, caplog):
    service, _, _, _ = make_service(tmp_path, count=1)
    service.run_once()
    before = service.store.read_runtime_bundle()
    state = service.store.load_state()

    def fail_gc(self):
        raise OSError("synthetic private value")

    monkeypatch.setattr(StateStore, "_prune_runtime_bundles", fail_gc)
    restored = StateStore(service.config)
    assert restored.load_state() == state
    assert restored.read_runtime_bundle() == before
    assert "synthetic private value" not in caplog.text


def test_private_parent_and_file_are_synced_before_current_commit(tmp_path, monkeypatch):
    service, _, _, _ = make_service(tmp_path, count=1)
    events = []
    sync = storage._fsync_directory
    write = storage.atomic_write_json

    def synced(path):
        events.append(("sync", path))
        sync(path)

    def written(path, value):
        events.append(("write", path))
        write(path, value)

    monkeypatch.setattr(storage, "_fsync_directory", synced)
    monkeypatch.setattr(storage, "atomic_write_json", written)
    service.run_once()
    assert events.index(("sync", service.config.data_dir)) < events.index(("sync", service.store.runtime_bundles_dir))
    assert events.index(("sync", service.store.runtime_bundles_dir)) < events.index(("write", service.store.current_path))


def test_reader_holds_generation_until_complete_before_publication_and_gc(tmp_path, monkeypatch):
    service, _, _, _ = make_service(tmp_path, count=1)
    service.run_once()
    old = service.store.read_runtime_bundle()
    old_id = json.loads(old)["bundle_id"]
    service.run_once()
    read_started, release = threading.Event(), threading.Event()
    publish_attempted, publish_entered = threading.Event(), threading.Event()
    original = Path.open
    publish, locked_publish = service.store.publish, service.store._publish

    def delayed_open(path, *args, **kwargs):
        if path.parent == service.store.runtime_bundles_dir and args == ("rb",):
            read_started.set()
            assert release.wait(5)
        return original(path, *args, **kwargs)

    def attempting_publish(*args, **kwargs):
        publish_attempted.set()
        return publish(*args, **kwargs)

    def entered_publish(*args, **kwargs):
        publish_entered.set()
        return locked_publish(*args, **kwargs)

    monkeypatch.setattr(Path, "open", delayed_open)
    monkeypatch.setattr(service.store, "publish", attempting_publish)
    monkeypatch.setattr(service.store, "_publish", entered_publish)
    with ThreadPoolExecutor(2) as pool:
        reader = pool.submit(service.store.read_runtime_bundle, old_id)
        assert read_started.wait(3)
        publisher = pool.submit(service.run_once)
        try:
            assert publish_attempted.wait(3)
            assert not publish_entered.wait(0.1)
        finally:
            release.set()
        assert reader.result(timeout=5) == old
        publisher.result(timeout=5)
    assert publish_entered.is_set()
    assert not (service.store.runtime_bundles_dir / f"{old_id}.json").exists()
    decoded(service.store.read_runtime_bundle())


@pytest.fixture
def bundle_api(tmp_path):
    service, _, _, _ = make_service(tmp_path, count=1)
    service.run_once()
    server = create_server(service.config, service)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield service, f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)


def get(url, token=None):
    request = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"} if token else {})
    try:
        response = urllib.request.urlopen(request, timeout=3)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, response.headers, response.read()


def test_private_api_auth_version_corruption_and_public_secrecy(bundle_api, caplog):
    service, url = bundle_api
    endpoint = url + "/api/v1/runtime-bundles/latest"
    for token in (None, "wrong"):
        status, headers, body = get(endpoint, token)
        assert status == 401
        assert headers["Cache-Control"] == "no-store"
        assert b"secret-0" not in body
    status, headers, body = get(endpoint, "test-token")
    assert status == 200 and headers["Cache-Control"] == "no-store"
    bundle, payload = decoded(body)
    assert b"secret-0" in payload
    assert get(url + "/api/v1/runtime-bundles/" + bundle["bundle_id"], "test-token")[2] == body
    for route in ("/current.json", "/local-socks-map.json", "/healthz", "/version"):
        _, _, public = get(url + route)
        assert b"secret-0" not in public and bundle["inventory"].encode() not in public
    for path in service.config.reports_dir.rglob("*"):
        if path.is_file():
            assert b"secret-0" not in path.read_bytes()
    service.config.http.api_token = ""
    assert get(endpoint)[0] == 401
    service.config.http.api_token = "test-token"
    path = service.store.runtime_bundles_dir / f'{bundle["bundle_id"]}.json'
    path.write_bytes(b"synthetic corrupted secret")
    assert get(endpoint, "test-token")[0] == 503
    path.unlink()
    assert get(endpoint, "test-token")[0] == 404
    assert "test-token" not in caplog.text and "secret-0" not in caplog.text


def test_legacy_state_does_not_invent_bundle_or_force_rebuild(tmp_path):
    service, _, _, _ = make_service(tmp_path, count=1)
    service.run_once()
    current = service.store.load_current()
    current.pop("runtime_bundle")
    current.pop("previous_runtime_bundle")
    storage.atomic_write_json(service.store.current_path, current)
    state = service.store.load_state()
    restored = StateStore(service.config)
    with pytest.raises(FileNotFoundError):
        restored.read_runtime_bundle()
    assert restored.load_state() == state
    assert service.run_once("maintenance")["mode"] == "maintenance"
    assert restored.read_runtime_bundle()


def test_oversized_input_fails_before_probing_or_publication(tmp_path, monkeypatch):
    from node_health import inventory
    service, quick, _, _ = make_service(tmp_path, count=1)
    monkeypatch.setattr(inventory, "MAX_INVENTORY_BYTES", 4)
    quick.check = lambda *_: pytest.fail("oversized inventory must not start probing")
    with pytest.raises(ValueError, match="size limit"):
        service.run_once()
    assert not service.store.current_path.exists()
    assert not service.store.runtime_bundles_dir.exists()
