from datetime import datetime, timezone

import pytest

from node_health import storage
from node_health.config import AppConfig, InventoryConfig, ReportConfig
from node_health.storage import StateStore, _listener_port


def test_report_ports_match_converter_block_capacity():
    assert _listener_port("united-states", 62800, 0) == 62800
    assert _listener_port("united-states", 62800, 199) == 62999
    assert _listener_port("united-states", 62800, 200) is None
    assert _listener_port("other", 64200, 1335) == 65535
    assert _listener_port("other", 64200, 1336) is None


def make_store(tmp_path, *, retention_days=180):
    config = AppConfig(
        inventory=InventoryConfig("https://inventory.invalid/all.yaml"),
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        report=ReportConfig(retention_days=retention_days),
    )
    return StateStore(config)


def ranking(version, generated_at):
    return {
        "schema_version": 2,
        "version": version,
        "generated_at": generated_at.isoformat(),
        "requested_mode": "maintenance",
        "mode": "maintenance",
        "source": {"digest": version, "node_count": 0},
        "region_order": [],
        "regions": {},
        "nodes": {},
    }


def state(version, stable_key):
    return {
        "schema_version": 2,
        "version": version,
        "updated_at": "2026-07-25T00:00:00+00:00",
        "stable_slots": {"united-states": {"1": stable_key}},
        "slot_changed_at": {},
        "nodes": {stable_key: {"name": stable_key}},
    }


def publish(store, version, stable_key, generated_at, changes=None):
    store.publish(
        ranking(version, generated_at),
        state(version, stable_key),
        [],
        changes or [],
        generated_at,
    )


def test_interrupted_current_commit_recovers_snapshot_selected_by_old_current(
    tmp_path, monkeypatch
):
    store = make_store(tmp_path)
    first_time = datetime(2026, 7, 24, 0, 0, tzinfo=timezone.utc)
    second_time = datetime(2026, 7, 25, 0, 0, tzinfo=timezone.utc)
    publish(store, "v1", "stable-v1", first_time)

    real_atomic_write_json = storage.atomic_write_json

    def interrupt_current(path, value):
        if path == store.current_path and value.get("version") == "v2":
            raise OSError("simulated interruption at the external commit point")
        return real_atomic_write_json(path, value)

    monkeypatch.setattr(storage, "atomic_write_json", interrupt_current)
    with pytest.raises(OSError, match="external commit point"):
        publish(store, "v2", "stable-v2", second_time)

    restarted = StateStore(store.config)
    assert restarted.load_current()["version"] == "v1"
    recovered = restarted.load_state()
    assert recovered["version"] == "v1"
    assert recovered["stable_slots"] == {"united-states": {"1": "stable-v1"}}


def test_atomic_write_syncs_parent_directory(tmp_path, monkeypatch):
    synced = []
    monkeypatch.setattr(storage, "_fsync_directory", lambda path: synced.append(path))
    target = tmp_path / "state.json"

    storage.atomic_write_text(target, "{}\n")

    assert target.read_text(encoding="utf-8") == "{}\n"
    assert synced == [tmp_path]


def test_atomic_write_retries_transient_replace_permission_error(tmp_path, monkeypatch):
    target = tmp_path / "state.json"
    real_replace = storage.os.replace
    attempts = 0

    def transient_replace(source, destination):
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise PermissionError("destination is briefly busy")
        return real_replace(source, destination)

    monkeypatch.setattr(storage.os, "replace", transient_replace)
    monkeypatch.setattr(storage.time, "sleep", lambda _: None)

    storage.atomic_write_text(target, "{}\n")

    assert attempts == 3
    assert target.read_text(encoding="utf-8") == "{}\n"


def test_retention_failure_after_commit_does_not_fail_publication(tmp_path, monkeypatch):
    store = make_store(tmp_path)

    def fail_cleanup(*_args, **_kwargs):
        raise OSError("simulated cleanup failure")

    monkeypatch.setattr(store, "_prune_state_snapshots", fail_cleanup)
    publish(store, "v1", "stable-v1", datetime(2026, 7, 25, tzinfo=timezone.utc))

    assert store.load_current()["version"] == "v1"
    assert store.load_state()["version"] == "v1"


def test_no_change_run_does_not_overwrite_latest_slot_change(tmp_path):
    store = make_store(tmp_path)
    first_time = datetime(2026, 7, 24, 0, 0, tzinfo=timezone.utc)
    second_time = datetime(2026, 7, 25, 0, 0, tzinfo=timezone.utc)
    change = {
        "region": "united-states",
        "slot": "1",
        "before": "old-key",
        "after": "new-key",
        "before_name": "Old node",
        "after_name": "New node",
        "reason": "quality-redline",
    }
    publish(store, "v1", "new-key", first_time, [change])

    latest_path = store.config.reports_dir / "alerts" / "slot-changes-latest.md"
    first_latest = latest_path.read_text(encoding="utf-8")
    assert "Old node" in first_latest
    assert "New node" in first_latest

    publish(store, "v2", "new-key", second_time)

    assert latest_path.read_text(encoding="utf-8") == first_latest
    latest_run = (
        store.config.reports_dir / "alerts" / "latest-run.md"
    ).read_text(encoding="utf-8")
    assert "本轮稳定槽位没有变化。" in latest_run


def test_report_retention_deletes_only_exact_old_daily_report_names(tmp_path):
    store = make_store(tmp_path, retention_days=2)
    reports = store.config.reports_dir
    reports.mkdir(parents=True)

    delete_names = {"2026-07-22.md", "2026-07-22.json"}
    keep_names = {
        "2026-07-23.md",  # The cutoff day itself is retained.
        "2026-07-25.json",
        "2026-7-22.md",
        "prefix-2026-07-22.md",
        "2026-07-22.md.backup",
        "2026-02-30.md",
        "notes.md",
    }
    for name in delete_names | keep_names:
        (reports / name).write_text(name, encoding="utf-8")

    alerts = reports / "alerts"
    alerts.mkdir()
    alert_history = alerts / "2026-07-22-old-version.md"
    alert_history.write_text("keep alert history", encoding="utf-8")

    store._prune_daily_reports(
        datetime(2026, 7, 25, 0, 0, tzinfo=timezone.utc)
    )

    assert all(not (reports / name).exists() for name in delete_names)
    assert all((reports / name).exists() for name in keep_names)
    assert alert_history.exists()


def test_each_scheduled_run_has_an_immutable_versioned_archive(tmp_path):
    store = make_store(tmp_path)
    generated_at = datetime(2026, 7, 25, 8, 30, tzinfo=timezone.utc)

    publish(store, "v1", "stable-v1", generated_at)

    archive = store.config.reports_dir / "scheduled" / "2026" / "07" / "25" / "v1"
    assert (archive / "report.json").exists()
    assert (archive / "report.md").exists()
    assert (store.config.reports_dir / "scheduled" / "latest.json").exists()
    assert (store.config.reports_dir / "scheduled" / "latest.md").exists()


def test_store_marks_running_audit_interrupted_after_restart(tmp_path):
    store = make_store(tmp_path)
    audit_id = "20260725T083000Z-a1b2c3d4"
    store.create_audit_status(
        {
            "schema_version": 1,
            "id": audit_id,
            "status": "running",
            "phase": "full-scan",
        }
    )

    restarted = StateStore(store.config)

    status = restarted.load_audit_status(audit_id)
    assert status["status"] == "interrupted"
    assert status["phase"] == "interrupted"


def test_report_retention_prunes_old_scheduled_and_audit_archives(tmp_path):
    store = make_store(tmp_path, retention_days=2)
    old_scheduled = store.scheduled_reports_dir / "2026" / "07" / "22" / "v1"
    old_audit = store.audit_reports_dir / "2026" / "07" / "22" / "20260722T010000Z-a1b2c3d4"
    current_audit = store.audit_reports_dir / "2026" / "07" / "25" / "20260725T010000Z-b1c2d3e4"
    for path in (old_scheduled, old_audit, current_audit):
        path.mkdir(parents=True)
        (path / "report.json").write_text("{}", encoding="utf-8")
    store.audit_jobs_dir.mkdir(parents=True)
    (store.audit_jobs_dir / "20260722T010000Z-a1b2c3d4.json").write_text("{}", encoding="utf-8")
    (store.audit_jobs_dir / "20260725T010000Z-b1c2d3e4.json").write_text("{}", encoding="utf-8")

    store._prune_report_archives(datetime(2026, 7, 25, tzinfo=timezone.utc))

    assert not old_scheduled.exists()
    assert not old_audit.exists()
    assert current_audit.exists()
    assert not (store.audit_jobs_dir / "20260722T010000Z-a1b2c3d4.json").exists()
    assert (store.audit_jobs_dir / "20260725T010000Z-b1c2d3e4.json").exists()
