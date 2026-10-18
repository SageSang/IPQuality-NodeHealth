import copy
import json
import subprocess
import threading
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest

from node_health import storage
from node_health.app import create_server, public_ranking_document
from node_health.preferences import (
    PreferenceConflict, PreferencesUnavailable, empty_preferences, identity_snapshot,
    node_catalog, public_preferences, resolve_preferences, validate_preferences,
)
from node_health.storage import StateStore
from test_service import make_service


@pytest.fixture
def published(tmp_path):
    service, quick, full, source = make_service(tmp_path)
    service.run_once()
    return service, quick, full, source


def ordered_keys(service):
    return [item["node_key"] for item in node_catalog(service.store.load_current(), empty_preferences())["nodes"]]


def snapshot_files(service):
    return {str(path.relative_to(service.config.data_dir)): path.read_bytes()
            for path in service.config.data_dir.rglob("*") if path.is_file()
            and path != service.store.preferences_path}


@pytest.mark.parametrize("indexes,expected", [([4], [4, 0, 1, 2, 3, 5, 6]),
                                            ([1], [1, 0, 2, 3, 4, 5, 6]),
                                            ([4, 1], [4, 1, 0, 2, 3, 5, 6])])
def test_pins_change_only_subscription_projection(published, indexes, expected):
    service, *_ = published
    keys = ordered_keys(service)
    before = snapshot_files(service)
    current = service.store.load_current()
    original = copy.deepcopy(current)
    prefs, _ = service.store.update_preferences([keys[index] for index in indexes], 0)
    catalog = node_catalog(current, prefs)
    actual = sorted(catalog["nodes"], key=lambda item: item["subscription_position"])
    assert [item["node_key"] for item in actual] == [keys[index] for index in expected]
    assert {item["node_key"]: item["stable_slot"] for item in catalog["nodes"] if item["stable_slot"]} == {
        key: index + 1 for index, key in enumerate(keys[:3])}
    assert current == original
    assert snapshot_files(service) == before
    assert public_preferences(prefs, current)["pinned_nodes"] == [keys[index] for index in indexes]
    saved = service.store.preferences_path.read_bytes()
    for proxy in published[3].proxies:
        assert proxy["password"].encode() not in saved
        assert proxy["server"].encode() not in saved
    restored = StateStore(service.config)
    assert restored.load_preferences() == prefs
    cleared, _ = restored.update_preferences([], 1)
    assert cleared["revision"] == 2
    assert public_preferences(cleared, current)["pinned_nodes"] == []
    assert snapshot_files(service) == before


@pytest.mark.parametrize("keys", [None, "abc", [True], ["wrong"], ["a" * 64] * 2,
                                  [f"{i:064x}" for i in range(4)], ["f" * 64]])
def test_invalid_or_unknown_keys_do_not_write(published, keys):
    service, *_ = published
    with pytest.raises(ValueError):
        service.store.update_preferences(keys, 0)
    assert not service.store.preferences_path.exists()


def test_concurrent_compare_and_swap_and_idempotency(published):
    service, *_ = published
    keys = ordered_keys(service)
    barrier = threading.Barrier(2)

    def put(key):
        barrier.wait()
        try:
            return service.store.update_preferences([key], 0)[0]
        except PreferenceConflict:
            return None

    with ThreadPoolExecutor(2) as pool:
        results = list(pool.map(put, keys[:2]))
    assert sum(value is not None for value in results) == 1
    saved = service.store.preferences_path.read_bytes()
    value = service.store.load_preferences()
    same, _ = service.store.update_preferences(value["pinned_nodes"], 1)
    assert same == value
    assert service.store.preferences_path.read_bytes() == saved
    with pytest.raises(PreferenceConflict):
        service.store.update_preferences([], 0)


def test_scan_does_not_wait_for_or_overwrite_pin(published):
    service, quick, *_ = published
    keys = ordered_keys(service)
    entered, release = threading.Event(), threading.Event()
    original = quick.check

    def blocked(*args):
        entered.set()
        assert release.wait(10)
        return original(*args)

    quick.check = blocked
    with ThreadPoolExecutor(2) as pool:
        scan = pool.submit(service.run_once)
        try:
            assert entered.wait(5)
            put = pool.submit(service.store.update_preferences, [keys[4]], 0)
            prefs, _ = put.result(timeout=3)
            saved = service.store.preferences_path.read_bytes()
        finally:
            release.set()
        scan.result(timeout=20)
    assert service.store.preferences_path.read_bytes() == saved
    assert public_preferences(prefs, service.store.load_current())["pinned_nodes"] == [keys[4]]


def test_rotation_and_missing_pin_survive_multiple_scans(published):
    service, _, _, source = published
    old = ordered_keys(service)[4]
    name = service.store.load_current()["nodes"][old]["name"]
    prefs, _ = service.store.update_preferences([old], 0)
    source.rotate_connection(name)
    current = service.run_once()
    new = next(key for key, node in current["nodes"].items() if node["name"] == name)
    assert new != old
    assert resolve_preferences(prefs, current)["resolved_pinned_nodes"] == [new]
    assert resolve_preferences(prefs, service.run_once())["resolved_pinned_nodes"] == [new]
    proxy = next(proxy for proxy in source.proxies if proxy["name"] == name)
    source.remove_name(name)
    missing = service.run_once()
    assert resolve_preferences(prefs, missing)["pins"][0]["status"] == "missing_or_ambiguous"
    kept, _ = service.store.update_preferences([old, ordered_keys(service)[0]], 1)
    assert kept["pinned_nodes"][0] == old
    source.proxies.append(proxy)
    assert resolve_preferences(kept, service.run_once())["resolved_pinned_nodes"][0] == new


def test_rename_and_failed_probe_do_not_revoke_pin(published):
    service, quick, _, source = published
    key = ordered_keys(service)[4]
    prefs, _ = service.store.update_preferences([key], 0)
    name = service.store.load_current()["nodes"][key]["name"]
    next(proxy for proxy in source.proxies if proxy["name"] == name)["name"] = "US renamed 4"
    quick.unavailable.add(key)
    current = service.run_once()
    assert public_preferences(prefs, current)["pinned_nodes"] == [key]


def test_edit_retains_rotated_pin_and_rejects_duplicate_logical_target(published):
    service, _, _, source = published
    keys = ordered_keys(service)
    old, other = keys[4], keys[0]
    name = service.store.load_current()["nodes"][old]["name"]
    initial, _ = service.store.update_preferences([old], 0)
    source.rotate_connection(name)
    current = service.run_once()
    new = resolve_preferences(initial, current)["resolved_pinned_nodes"][0]
    with pytest.raises(ValueError):
        service.store.update_preferences([old, new], 1)
    edited, _ = service.store.update_preferences([old, other], 1)
    assert edited["pinned_nodes"] == [new, other]
    assert resolve_preferences(edited, current)["resolved_pinned_nodes"] == [new, other]


def metadata(name, source="airport-a"):
    return {"source_id": source, "original_name": name, "normalized_name": name.lower(),
            "logical_id": name, "region": "united-states"}


def test_identity_population_ambiguity_and_source_conflict():
    a, b, c = [str(i) * 64 for i in range(3)]
    prefs = {**empty_preferences(), "pinned_nodes": [a],
             "identity_index": identity_snapshot({a: metadata("same"), b: metadata("same")})}
    assert resolve_preferences(prefs, {"identity_index": {c: metadata("same")}})["resolved_pinned_nodes"] == []
    prefs["identity_index"].pop(b)
    assert resolve_preferences(prefs, {"identity_index": {c: metadata("same", "airport-b")}})["resolved_pinned_nodes"] == []
    assert resolve_preferences(prefs, {"identity_index": {c: metadata("same")}})["resolved_pinned_nodes"] == [c]


@pytest.mark.parametrize("bad", ["{", "null", "[]", '{"schema_version":99}',
                                json.dumps({**empty_preferences(), "revision": True})])
def test_corruption_is_not_overwritten(published, bad):
    service, *_ = published
    service.store.preferences_path.write_text(bad)
    with pytest.raises(PreferencesUnavailable):
        service.store.load_preferences()
    with pytest.raises(PreferencesUnavailable):
        service.store.update_preferences([], 0)
    assert service.store.preferences_path.read_text() == bad


def test_failed_write_preserves_prior_preferences(published, monkeypatch):
    service, *_ = published
    key = ordered_keys(service)[0]
    service.store.update_preferences([key], 0)
    before = service.store.preferences_path.read_bytes()

    def fail(*_):
        raise OSError("private storage failure")

    monkeypatch.setattr(storage, "atomic_write_json", fail)
    with pytest.raises(OSError):
        service.store.update_preferences([], 1)
    assert service.store.preferences_path.read_bytes() == before


def test_no_ranking_yet_allows_read_and_clear_but_not_new_pin(tmp_path):
    service, *_ = make_service(tmp_path)
    assert service.store.load_preferences() == empty_preferences()
    prefs, current = service.store.update_preferences([], 0)
    assert prefs == empty_preferences() and current == {}
    with pytest.raises(ValueError):
        service.store.update_preferences(["a" * 64], 0)


def test_unreadable_current_is_not_a_client_validation_error(published):
    service, *_ = published
    key = ordered_keys(service)[0]
    service.store.current_path.write_text("{")
    with pytest.raises(PreferencesUnavailable):
        service.store.update_preferences([key], 0)
    assert not service.store.preferences_path.exists()


@pytest.fixture
def api(published):
    service, *_ = published
    server = create_server(service.config, service)
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
    thread.start()
    try:
        yield service, server, f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def request(base, path, method="GET", body=None, token="test-token", revision='"0"', **headers):
    headers.setdefault("Content-Type", "application/json")
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    if revision is not None:
        headers["If-Match"] = revision
    data = None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
    req = urllib.request.Request(base + path, data=data, method=method, headers=headers)
    try:
        response = urllib.request.urlopen(req, timeout=5)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, dict(response.headers), json.load(response)


def test_api_read_after_write_versions_and_secrecy(api):
    service, _, base = api
    path = "/api/v1/subscription-preferences"
    status, headers, original = request(base, path)
    assert (status, headers["ETag"], original["pinned_nodes"]) == (200, '"0"', [])
    before = public_ranking_document(service.store.load_current())
    key = ordered_keys(service)[4]
    status, headers, result = request(base, path, "PUT", {"pinned_nodes": [key]})
    assert status == 200 and headers["ETag"] == '"1"'
    assert result["requires_subscription_refresh"] is True
    status, headers, ranked = request(base, "/current.json", token=None)
    assert status == 200 and headers["Cache-Control"] == "no-store"
    assert ranked.pop("subscription_preferences")["pinned_nodes"] == [key]
    assert ranked == before
    status, _, catalog = request(base, "/api/v1/nodes")
    chosen = next(node for node in catalog["nodes"] if node["node_key"] == key)
    assert status == 200 and chosen["stable_slot"] is None and chosen["pin_position"] == 1
    assert "secret-" not in json.dumps([result, catalog, ranked])
    assert request(base, path, "PUT", {"pinned_nodes": []})[0] == 412
    assert request(base, path, "PUT", {"pinned_nodes": []}, revision='"1"')[0] == 200
    assert request(base, "/current.json")[2]["subscription_preferences"]["pinned_nodes"] == []


@pytest.mark.parametrize("token", [None, "wrong"])
def test_management_auth_required(api, token):
    _, _, base = api
    for path in ("/api/v1/nodes", "/api/v1/subscription-preferences"):
        assert request(base, path, token=token)[0] == 401
    assert request(base, "/api/v1/subscription-preferences", "PUT", {"pinned_nodes": []}, token=token)[0] == 401


def test_empty_server_token_never_opens_preferences(api):
    service, server, base = api
    server.config = replace(service.config, http=replace(service.config.http, api_token=""))
    assert request(base, "/api/v1/nodes", token=None)[0] == 401
    assert request(base, "/api/v1/subscription-preferences", "PUT", {"pinned_nodes": []})[0] == 401


@pytest.mark.parametrize("body,revision,code", [({}, '"0"', 422), ({"pinned_nodes": []}, None, 428),
                                               ({"pinned_nodes": []}, "*", 400), (b"{", '"0"', 400),
                                               ({"pinned_nodes": ["f" * 64]}, '"0"', 422),
                                               ({"pinned_nodes": [], "stable_slots": {}}, '"0"', 422)])
def test_api_rejects_bad_updates(api, body, revision, code):
    service, _, base = api
    assert request(base, "/api/v1/subscription-preferences", "PUT", body, revision=revision)[0] == code
    assert not service.store.preferences_path.exists()


def test_corrupt_preferences_keep_auto_ranking_and_fail_admin(api):
    service, _, base = api
    service.store.preferences_path.write_text("{")
    assert request(base, "/api/v1/subscription-preferences")[0] == 503
    assert request(base, "/api/v1/subscription-preferences", "PUT", {"pinned_nodes": []})[0] == 503
    status, _, body = request(base, "/current.json")
    assert status == 200 and body.pop("subscription_preferences")["status"] == "unavailable"
    assert body == public_ranking_document(service.store.load_current())


def test_api_payload_limits_and_safe_disk_failure(api, monkeypatch):
    service, _, base = api
    path = "/api/v1/subscription-preferences"
    assert request(base, path, "PUT", b" " * (16 * 1024 + 1))[0] == 413
    assert request(base, path, "PUT", {"pinned_nodes": []}, **{"Content-Type": "text/plain"})[0] == 415
    key = ordered_keys(service)[0]

    def fail(*_):
        raise OSError("SECRET private disk path")

    monkeypatch.setattr(storage, "atomic_write_json", fail)
    status, _, body = request(base, path, "PUT", {"pinned_nodes": [key]})
    assert status == 503 and "SECRET" not in json.dumps(body)
    assert not service.store.preferences_path.exists()


def test_real_http_to_javascript_operator_same_url_refresh(api, published):
    service, _, base = api
    source = published[3]
    module = Path(__file__).resolve().parents[1] / "integrations/sub-store/health-ranking-operator.js"
    script = """
const op = require(process.argv[1]);
const proxies = JSON.parse(require('fs').readFileSync(0, 'utf8'));
op.operator(proxies, 'ClashMeta', {options: {rankingUrl: process.argv[2]},
  ProxyUtils: {produce: values => values}}).then(result => {
    process.stdout.write(JSON.stringify(result.map(proxy => proxy.name)));
}).catch(() => process.exit(1));
"""

    def fetch():
        result = subprocess.run(["node", "-e", script, str(module), base + "/current.json"],
                                input=json.dumps(list(reversed(source.proxies))), text=True,
                                capture_output=True, check=True, timeout=15)
        return json.loads(result.stdout)

    baseline = fetch()
    current = service.store.load_current()
    key = next(key for key, value in current["nodes"].items() if value["name"] == baseline[4])
    assert request(base, "/api/v1/subscription-preferences", "PUT", {"pinned_nodes": [key]})[0] == 200
    assert fetch() == [baseline[4], *baseline[:4], *baseline[5:]]
    assert request(base, "/api/v1/subscription-preferences", "PUT", {"pinned_nodes": []}, revision='"1"')[0] == 200
    assert fetch() == baseline
