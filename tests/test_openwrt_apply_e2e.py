"""Real controller/renderer tests; the isolated core only models local readiness."""
import json
import shutil
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from node_health.port_mapping import mapping_digest
from runtime_harness import CORE_SOURCE, Runtime, proxy
from test_port_mapping import mapping_case
from node_health.runtime_bundle import build_runtime_bundle, byte_digest


@pytest.fixture(scope="module")
def fake_core(tmp_path_factory):
    if not sys.platform.startswith("linux") or not all(shutil.which(name) for name in ("cc", "node", "flock", "sh")):
        pytest.skip("Linux, cc, Node, flock and sh are required for the runtime E2E")
    directory=tmp_path_factory.mktemp("protocol-core")
    source=directory / "core.c"
    source.write_text(CORE_SOURCE)
    binary=directory / "core"
    subprocess.run(["cc", "-O2", str(source), "-o", str(binary)],check=True,capture_output=True)
    return binary


@pytest.fixture
def runtime(tmp_path, fake_core):
    for port in (62000,62001,62002,62003,62004):
        with socket.socket() as check:
            check.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            try:check.bind(("127.0.0.1",port))
            except OSError:pytest.skip("fixed fixture ports are already in use")
    instance=Runtime(tmp_path,fake_core)
    try:yield instance
    finally:instance.close()


@pytest.mark.parametrize("mode", ["listening","zero","missing","interrupted"])
def test_apply_ranking_validates_listeners_and_rolls_back(runtime,mode):
    old_config=runtime.config.read_bytes()
    changed=[proxy("Hong Kong A","bad.example" if mode=="missing" else "new.example")]
    runtime.set_target(changed)
    extra={"APPROVED_INITIAL_MAPPING_VERSION":runtime.mapping["mapping_version"]}
    if mode=="interrupted":extra["TEST_INTERRUPT_NEW"]="1"
    if mode=="zero":
        runtime.mapping["entries"]=[]
        for binding in runtime.mapping["bindings"]:binding.update(entry_id=None,node_key=None)
        runtime.mapping["mapping_version"]=mapping_digest(runtime.mapping)
        runtime.map_path.write_text(json.dumps(runtime.mapping))
        runtime.source.write_text(json.dumps({"proxies":[]}))
    result=runtime.run(**extra)
    if mode=="listening":
        assert result.returncode==0,result.stderr
        assert runtime.receipt()["mapping_version"]==runtime.mapping["mapping_version"]
        assert (runtime.export / "all-plain.txt").read_text()=="socks5://192.0.2.4:62000\n"
        runtime.wait_socket(62000)
    else:
        # D2 rejects an empty/unusable target rather than pretending it is an apply.
        assert result.returncode!=0
        assert runtime.config.read_bytes()==old_config
        assert (runtime.export / "sentinel.txt").read_text()=="old-export\n"
        runtime.wait_socket(62000)
        assert not (runtime.cache / "pending.json").exists()


def test_noop_and_label_only_changes_do_not_restart(runtime):
    assert runtime.run().returncode==0
    pid=runtime.pid.read_text(); content=runtime.config.read_bytes()
    assert runtime.run().returncode==0
    assert runtime.pid.read_text()==pid
    runtime.set_target([{**runtime.proxies[0],"name":"Hong Kong renamed"}])
    assert runtime.run().returncode==0
    assert runtime.pid.read_text()==pid
    assert runtime.config.read_bytes()==content
    assert "Hong Kong renamed" in (runtime.export / "all.txt").read_text()


def test_upstream_backoff_does_not_skip_local_runtime_recovery(runtime):
    assert runtime.run().returncode==0
    receipt=runtime.receipt()
    runtime.close(); runtime.backoff()
    result=runtime.run(apply=False)
    assert result.returncode==0,result.stderr
    runtime.wait_socket(62000)
    assert runtime.receipt()==receipt
    assert (runtime.cache / "backoff.json").exists()


@pytest.mark.parametrize("phase", ["before-pending","after-pending","before-config","after-config",
                                     "before-exports","after-exports","before-receipt","after-receipt"])
def test_sigkill_recovers_the_committed_generation(runtime,phase):
    old_config=runtime.config.read_bytes()
    runtime.set_target([proxy("Hong Kong A","new.example")])
    result=runtime.run(APPROVED_INITIAL_MAPPING_VERSION=runtime.mapping["mapping_version"],TEST_CRASH_PHASE=phase)
    assert result.returncode!=0
    runtime.backoff()
    recovered=runtime.run(apply=False)
    assert recovered.returncode==0,recovered.stderr
    runtime.wait_socket(62000)
    assert not (runtime.cache / "pending.json").exists()
    if phase=="after-receipt":
        assert runtime.receipt()["kind"]=="managed"
        assert runtime.receipt()["mapping_version"]==runtime.mapping["mapping_version"]
    else:
        assert runtime.receipt()["kind"]=="legacy-baseline"
        assert runtime.config.read_bytes()==old_config
        assert (runtime.export / "sentinel.txt").read_text()=="old-export\n"


def test_export_failure_does_not_prevent_runtime_rollback(runtime):
    old=runtime.config.read_bytes()
    runtime.set_target([proxy("Hong Kong A","new.example")])
    result=runtime.run(APPROVED_INITIAL_MAPPING_VERSION=runtime.mapping["mapping_version"],TEST_EXPORT_FAILURE="1")
    assert result.returncode!=0
    assert runtime.config.read_bytes()==old
    runtime.wait_socket(62000)
    runtime.backoff()
    assert runtime.run(apply=False).returncode==0
    assert not (runtime.cache / "pending.json").exists()


def test_successful_restart_command_must_replace_the_process(runtime):
    old=runtime.config.read_bytes()
    runtime.set_target([proxy("Hong Kong A","new.example")])
    result=runtime.run(APPROVED_INITIAL_MAPPING_VERSION=runtime.mapping["mapping_version"],TEST_IGNORE_NEW_RESTART="1")
    assert result.returncode!=0
    assert runtime.config.read_bytes()==old
    runtime.wait_socket(62000)


def test_initial_binding_difference_requires_specific_approval(runtime):
    old=runtime.config.read_bytes()
    runtime.set_target([proxy("Hong Kong A","new.example")])
    assert runtime.run().returncode!=0
    assert runtime.config.read_bytes()==old
    assert runtime.log.read_text()==""
    assert runtime.receipt()["kind"]=="legacy-baseline"


def test_lock_and_export_dependency_protection(runtime):
    import fcntl
    lock=runtime.cache / "apply.lock"
    with lock.open("w") as stream:
        fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
        assert runtime.run().returncode==75
        assert runtime.run(apply=False).returncode==75
    dependency=runtime.export / "yaml.cjs"
    shutil.copy2(runtime.yaml,dependency)
    assert runtime.run(JS_YAML_PATH=str(dependency)).returncode!=0
    assert dependency.is_file()
    assert runtime.log.read_text()==""


def test_candidate_validation_failure_does_not_restart(runtime):
    old=runtime.config.read_bytes()
    assert runtime.run(TEST_REJECT_CANDIDATE="1").returncode!=0
    assert runtime.config.read_bytes()==old
    assert runtime.log.read_text()==""


def test_missing_flock_fails_before_runtime_or_cache_mutation(runtime):
    before={path.name for path in runtime.cache.iterdir()}
    config=runtime.config.read_bytes()
    assert runtime.run(FLOCK_BIN="/missing/flock").returncode!=0
    assert runtime.run(apply=False,FLOCK_BIN="/missing/flock").returncode!=0
    assert {path.name for path in runtime.cache.iterdir()}==before
    assert runtime.config.read_bytes()==config
    assert runtime.log.read_text()==""


def test_early_module_failure_does_not_echo_dependency_paths(runtime):
    secret="synthetic-token-in-path"
    result=runtime.run(STABLE_CONVERTER=str(runtime.directory/secret))
    assert result.returncode!=0
    assert "dependency_invalid" in result.stderr
    assert secret not in result.stderr
    assert runtime.log.read_text()==""


@pytest.fixture
def bundle_source(runtime):
    bundle = build_runtime_bundle(runtime.source.read_bytes(), runtime.mapping, "s-test-generation", mapping_case(runtime.proxies)[0])
    state = {"body": json.dumps(bundle).encode(), "status": 200, "requests": []}
    token = runtime.directory / "runtime-token"
    token.write_text("synthetic-runtime-token\n")
    token.chmod(0o600)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass
        def do_GET(self):
            state["requests"].append((self.path, self.headers.get("Authorization")))
            self.send_response(state["status"])
            self.send_header("Content-Length", str(len(state["body"])))
            if state["status"] == 302:
                self.send_header("Location", state.get("redirect", "/credential-trap"))
            self.end_headers()
            self.wfile.write(state["body"])

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    runtime.env["RUNTIME_BUNDLE_URL"] = f"http://127.0.0.1:{server.server_port}/api/v1/runtime-bundles/latest"
    runtime.env["RUNTIME_TOKEN_FILE"] = str(token)
    try:
        yield state, bundle, token
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)


def test_poll_uses_only_atomic_bundle_and_preserves_profile(runtime, bundle_source):
    state, _, _ = bundle_source
    assert runtime.run().returncode == 0
    pid = runtime.pid.read_text()
    before = json.loads(runtime.config.read_text())
    result = runtime.run(apply=False)
    assert result.returncode == 0, result.stderr
    assert runtime.pid.read_text() == pid
    assert state["requests"] == [("/api/v1/runtime-bundles/latest", "Bearer synthetic-runtime-token")]
    assert runtime.receipt()["mapping_version"] == runtime.mapping["mapping_version"]
    config = json.loads(runtime.config.read_text())
    for key in ("dns", "ipv6", "allow-lan", "rules"):
        assert config[key] == before[key]
    assert not list(runtime.cache.glob("download.*"))


@pytest.mark.parametrize("failure", ["missing", "unauthorized", "redirect", "cross-origin", "sha", "inventory", "json", "version", "stale"])
def test_bad_bundle_never_falls_back_or_changes_runtime(runtime, bundle_source, failure):
    import base64
    state, bundle, _ = bundle_source
    old = runtime.config.read_bytes()
    pid = runtime.pid.read_text()
    if failure in ("missing", "unauthorized"):
        state["status"] = 404 if failure == "missing" else 401
    elif failure in ("redirect", "cross-origin"):
        state["status"] = 302
        if failure == "cross-origin":
            state["redirect"] = "http://127.0.0.1:1/credential-trap"
    elif failure == "sha":
        bundle["inventory_sha256"] = "sha256:" + "0" * 64
    elif failure == "inventory":
        payload = json.dumps({"proxies": [proxy("Hong Kong A", "rotated.example")]}).encode()
        bundle["inventory"] = base64.b64encode(payload).decode()
        bundle["inventory_sha256"] = byte_digest(payload)
    elif failure == "version":
        bundle["schema_version"] = 999
    elif failure == "stale":
        bundle["mapping"]["generated_at"] = "2020-01-01T00:00:00Z"
    state["body"] = b'{"synthetic-private-response":' if failure == "json" else json.dumps(bundle).encode()
    result = runtime.run(apply=False)
    assert result.returncode != 0
    assert len(state["requests"]) == 1
    assert runtime.config.read_bytes() == old
    assert runtime.pid.read_text() == pid
    assert runtime.log.read_text() == ""
    assert "synthetic-runtime-token" not in result.stderr
    assert "synthetic-private-response" not in result.stderr
    assert not list(runtime.cache.glob("download.*"))


@pytest.mark.parametrize("mode", ["missing", "public", "empty", "symlink", "header-injection"])
def test_private_token_validation_precedes_network(runtime, bundle_source, mode):
    state, _, token = bundle_source
    if mode == "missing":
        token.unlink()
    elif mode == "public":
        token.chmod(0o644)
    elif mode == "empty":
        token.write_text("")
    elif mode == "symlink":
        target = token.with_suffix(".actual")
        token.rename(target)
        token.symlink_to(target)
    else:
        token.write_text("token\nInjected: value")
    result = runtime.run(apply=False)
    assert result.returncode != 0
    assert "runtime_auth_invalid" in result.stderr
    assert not state["requests"]
    assert runtime.log.read_text() == ""


def test_failed_download_still_recovers_local_service(runtime, bundle_source):
    state, _, _ = bundle_source
    assert runtime.run().returncode == 0
    receipt = runtime.receipt()
    runtime.close()
    state["status"] = 503
    result = runtime.run(apply=False)
    assert result.returncode != 0
    runtime.wait_socket(62000)
    assert runtime.receipt() == receipt


def test_exact_generation_response_must_match_requested_id(runtime, bundle_source):
    state, _, _ = bundle_source
    url = runtime.env["RUNTIME_BUNDLE_URL"].replace("/latest", "/s-other-generation")
    assert runtime.run(apply=False, RUNTIME_BUNDLE_URL=url).returncode != 0
    assert len(state["requests"]) == 1
    assert runtime.log.read_text() == ""
