import json
from datetime import datetime, timedelta, timezone

import pytest

from node_health.storage import atomic_write_json, StateStore
from node_health.config import AppConfig, InventoryConfig
from node_health.evidence_migration import UnsupportedEvidenceVersion
from test_evidence_migration import legacy_state, NOW
from tools.rehearse_migration import rehearse
from tools.check_release_gate import check_gate


def input_copy(path):
    state=legacy_state()
    current={"schema_version":2,"version":state["version"],"state_revision":state["state_revision"]}
    atomic_write_json(path/"current.json",current)
    atomic_write_json(path/"state.json",state)
    atomic_write_json(path/"state-snapshots"/f"{state['state_revision']}.json",state)
    return state


def test_preview_preserves_input_and_proves_repeat_migration(tmp_path):
    source=tmp_path/"input"; input_copy(source)
    original={str(path.relative_to(source)):path.read_bytes() for path in source.rglob("*.json")}
    result=rehearse(source,tmp_path/"output",at=NOW,zone="Asia/Shanghai")
    assert all(result["placement_preserved"].values())
    assert result["idempotent"] and result["failed_attempt_reentry_equal"]
    assert result["migration_whitelist_count"]==1
    assert result["positive_health_after_pure_migration"]==0
    assert result["runtime_or_network_probe_executed"] is False
    assert {str(path.relative_to(source)):path.read_bytes() for path in source.rglob("*.json")}==original
    assert '"node_key"' not in json.dumps(result)
    assert "8.8.8.8" not in json.dumps(result)
    assert "1.1.1.1" not in json.dumps(result)


def test_preview_refuses_overlap_and_disables_unprovable_restored_grace(tmp_path):
    source=tmp_path/"input"; input_copy(source)
    with pytest.raises(ValueError):rehearse(source,source/"output",at=NOW,zone="Asia/Shanghai")
    rehearse(source,tmp_path/"restored",at=NOW,zone="Asia/Shanghai",restored_backup=True)
    state=json.loads((tmp_path/"restored/state.migrated.json").read_text())
    assert all(item["consumed"] for item in state["evidence_migration"]["original_slots"])


def test_future_evidence_refuses_startup_recovery_writes(tmp_path):
    source=tmp_path/"input"; state=input_copy(source)
    state["minimum_evidence_reader_version"]=99
    atomic_write_json(source/"state-snapshots"/f"{state['state_revision']}.json",state)
    audit=source/"audit-jobs/20260912T000000Z-1234abcd.json"
    atomic_write_json(audit,{"status":"running"})
    before=audit.read_bytes()
    with pytest.raises(UnsupportedEvidenceVersion):
        StateStore(AppConfig(InventoryConfig("https://inventory.invalid"),data_dir=source,reports_dir=tmp_path/"reports"))
    assert audit.read_bytes()==before
    assert not (tmp_path/"reports").exists()


def calibration_double():
    # This is a temporary unit-test double, never the production calibration file.
    return {"calibration_kind":"real","reviewed":True,"original_result_class":"available",
            "environment_class":"unit-test-double","probe_contract_version":1,"site":"chatgpt",
            "captured_at":(datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat(),
            "response":{"http_status":200,"transport_code":0,"host":"chatgpt.com",
                        "sanitized_body":"ip=8.8.8.8\nloc=US\nh=chatgpt.com\n"}}


@pytest.mark.parametrize("mutation", ["missing","synthetic","unreviewed","failed-transport","not-positive"])
def test_release_gate_rejects_missing_or_unreviewed_calibration(tmp_path,mutation):
    path=tmp_path/"calibration.json"
    value=calibration_double()
    if mutation=="synthetic":value["calibration_kind"]="synthetic"
    elif mutation=="unreviewed":value["reviewed"]=False
    elif mutation=="failed-transport":value["response"]["transport_code"]=28
    elif mutation=="not-positive":value["response"]["http_status"]=503
    if mutation!="missing":path.write_text(json.dumps(value))
    with pytest.raises((ValueError,FileNotFoundError)):check_gate(path)


def test_release_gate_validation_replays_without_network(tmp_path):
    path=tmp_path/"calibration.json";path.write_text(json.dumps(calibration_double()))
    assert check_gate(path)["network_executed"] is False
