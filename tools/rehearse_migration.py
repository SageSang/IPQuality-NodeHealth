#!/usr/bin/env python3
"""Rehearse evidence migration into a new private directory, never the input."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from node_health.config import PolicyConfig
from node_health.evidence_migration import finalize_evidence_migration, migrate_evidence_state


PLACEMENT_FIELDS = ("stable_slots", "frozen_order", "ranked_order", "slot_changed_at", "promotion_cooldown_at")


def load_selected_state(directory: Path) -> tuple[dict, dict[str, str]]:
    current_bytes = (directory / "current.json").read_bytes()
    current = json.loads(current_bytes)
    selected = str(current.get("state_revision") or current.get("version") or "")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", selected):
        raise ValueError("invalid current selector")
    snapshot = directory / "state-snapshots" / f"{selected}.json"
    path = snapshot if snapshot.is_file() else directory / "state.json"
    state_bytes = path.read_bytes()
    state = json.loads(state_bytes)
    if state.get("schema_version") != 2 or state.get("version") != current.get("version"):
        raise ValueError("incoherent state selector")
    if current.get("state_revision") and state.get("state_revision") != selected:
        raise ValueError("incoherent state revision")
    if (directory / "current.json").read_bytes() != current_bytes:
        raise ValueError("source changed during read")
    hashes = {"current.json": hashlib.sha256(current_bytes).hexdigest(),
              path.relative_to(directory).as_posix(): hashlib.sha256(state_bytes).hexdigest()}
    return state, hashes


def rehearse(directory: Path, output: Path, *, at: datetime, zone: str, restored_backup: bool = False,
             policy: PolicyConfig | None = None) -> dict:
    directory, output = directory.resolve(), output.resolve()
    if output.is_relative_to(directory) or directory.is_relative_to(output):
        raise ValueError("output must not overlap input")
    if output.exists():
        raise FileExistsError("output already exists")
    policy = policy or PolicyConfig()
    state, hashes = load_selected_state(directory)
    raw_digest = hashlib.sha256(json.dumps(state, sort_keys=True).encode()).hexdigest()
    migrated = migrate_evidence_state(state, policy, at)
    retry = migrate_evidence_state(state, policy, at + timedelta(hours=1))
    if restored_backup and isinstance(migrated.get("evidence_migration"), dict):
        for entry in migrated["evidence_migration"].get("original_slots", []):
            entry.update(consumed=True, first_unavailable_day="")
        migrated["evidence_migration"]["restored_backup_exceptions_disabled"] = True
    finalized = finalize_evidence_migration(migrated, at, zone)
    repeated = migrate_evidence_state(finalized, policy, at + timedelta(days=1))
    nodes = state.get("nodes", {})
    stable = {key for slots in state.get("stable_slots", {}).values() for key in slots.values()}
    positive = {key: int(node.get("healthy_streak_days", 0) or 0) for key, node in nodes.items()
                if int(node.get("healthy_streak_days", 0) or 0) > 0}
    histogram = Counter()
    for days in positive.values():
        histogram[{1:2,2:4,3:6,4:7,5:8}.get(days,10)] += 1
    summary = {
        "status": "preview-only", "input_generated_at": state.get("updated_at"),
        "simulation_commit_at": at.isoformat(), "source_hashes": hashes,
        "nodes": len(nodes), "stable_slots": len(stable),
        "stable_slot_count_before": sum(len(slots) for slots in state.get("stable_slots", {}).values()),
        "stable_slot_count_after": sum(len(slots) for slots in finalized.get("stable_slots", {}).values()),
        "other_count": len(state.get("frozen_order", {}).get("other", [])),
        "other_count_after": len(finalized.get("frozen_order", {}).get("other", [])),
        "placement_preserved": {field: state.get(field) == finalized.get(field) for field in PLACEMENT_FIELDS},
        "old_positive_health_counts": len(positive), "old_positive_stable_counts": len(set(positive) & stable),
        "old_streak_reward_histogram_not_net_score_delta": dict(histogram),
        "migration_whitelist_count": len(finalized.get("evidence_migration", {}).get("original_slots", [])),
        "migration_unconsumed_count": sum(not entry.get("consumed") for entry in finalized.get("evidence_migration", {}).get("original_slots", [])),
        "migration_expires_at_simulated": finalized.get("evidence_migration", {}).get("expires_at"),
        "active_grace_before": sum(node.get("unavailable_grace_active") is True for node in nodes.values()),
        "active_grace_after": sum(node.get("unavailable_grace_active") is True for node in finalized["nodes"].values()),
        "positive_health_after_pure_migration": sum((node.get("healthy_streak_days") or 0) > 0 for node in finalized["nodes"].values()),
        "raw_risk_caches_recomputed": sum(node.get("last_full_recomputed_from_legacy") is True for node in finalized["nodes"].values()),
        "idempotent": repeated == finalized,
        "failed_attempt_reentry_equal": retry == migrate_evidence_state(state, policy, at),
        "input_object_unchanged": raw_digest == hashlib.sha256(json.dumps(state, sort_keys=True).encode()).hexdigest(),
        "restored_backup": restored_backup,
        "runtime_or_network_probe_executed": False,
        "policy": {name: getattr(policy, name) for name in ("min_valid_risk_sources", "stable_protection_min_healthy_days", "stable_unavailable_grace_days")},
    }
    if not all(summary["placement_preserved"].values()) or not summary["idempotent"]:
        raise ValueError("migration invariants failed")
    _, after_hashes = load_selected_state(directory)
    if after_hashes != hashes:
        raise ValueError("input changed during preview")
    output.mkdir(parents=True, mode=0o700)
    for name, value in (("state.migrated.json", finalized), ("summary.json", summary)):
        descriptor = os.open(output / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--at", default=None)
    parser.add_argument("--timezone", default="Asia/Shanghai")
    parser.add_argument("--restored-backup", action="store_true")
    parser.add_argument("--policy-file", type=Path, help="JSON PolicyConfig overrides for this offline rehearsal")
    args = parser.parse_args()
    try:
        at = datetime.fromisoformat(args.at.replace("Z", "+00:00")) if args.at else datetime.now(timezone.utc)
        if at.tzinfo is None:
            raise ValueError("simulation time must have timezone")
        policy = PolicyConfig(**json.loads(args.policy_file.read_text())) if args.policy_file else PolicyConfig()
        result = rehearse(args.input_dir, args.output_dir, at=at, zone=args.timezone,
                          restored_backup=args.restored_backup, policy=policy)
    except Exception:
        print(json.dumps({"status":"failed", "code":"preview_failed", "input_write_attempted":False}))
        return 1
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
