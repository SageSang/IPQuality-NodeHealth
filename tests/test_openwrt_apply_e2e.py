"""Real controller/renderer tests; the isolated core only models local readiness."""
import json
import shutil
import socket
import subprocess
import sys

import pytest

from node_health.port_mapping import mapping_digest
from runtime_harness import CORE_SOURCE, Runtime, proxy


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
