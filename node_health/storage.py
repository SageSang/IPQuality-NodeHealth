from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import shutil
import tempfile
import time
import uuid
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .config import AppConfig
from .models import NodeAssessment
from .audit import audit_day_parts, validate_audit_id
from .reconcile import SCHEMA_VERSION
from .slots import ranking_key


_FIXED_REGION_PORT_BLOCK_SIZE = 200
_MAX_PORT = 65535
LOGGER = logging.getLogger("node_health.storage")


def _seed_frozen_order(
    state: dict[str, Any], current: dict[str, Any]
) -> dict[str, Any]:
    """Seed ordering baselines from the already-published ranking.

    This keeps an image-only upgrade maintenance-safe: the first run after
    deployment preserves the active regional order during an outage and keeps
    the existing `other` freeze instead of forcing an unsolicited rebuild. The
    next explicit rebuild will replace them through the normal ranking path.
    """

    seeded = dict(state)
    regions = current.get("regions", {}) if isinstance(current.get("regions"), dict) else {}
    if not isinstance(state.get("frozen_order"), dict):
        other = regions.get("other", {})
        ranked = other.get("ranked", []) if isinstance(other, dict) else []
        keys: list[str] = []
        if isinstance(ranked, list):
            for entry in ranked:
                if isinstance(entry, str):
                    key = entry
                elif isinstance(entry, dict):
                    key = str(
                        entry.get("node_key")
                        or entry.get("nodeKey")
                        or entry.get("key")
                        or ""
                    )
                else:
                    key = ""
                if key and key not in keys:
                    keys.append(key)
        seeded["frozen_order"] = {"other": keys} if keys else {}
    if not isinstance(state.get("ranked_order"), dict):
        seeded["ranked_order"] = {
            str(region): [str(key) for key in payload.get("ranked", [])]
            for region, payload in regions.items()
            if isinstance(payload, dict) and isinstance(payload.get("ranked"), list)
        }
    if not isinstance(state.get("rejected_by_region"), dict):
        seeded["rejected_by_region"] = {
            str(region): {
                str(key): str(reason)
                for key, reason in payload.get("rejected", {}).items()
            }
            for region, payload in regions.items()
            if isinstance(payload, dict)
            and isinstance(payload.get("rejected"), dict)
        }
    return seeded


def read_json(path: Path, default: dict[str, Any] | None = None) -> dict[str, Any]:
    # A reader can briefly race an atomic replace on Windows or a NAS mount.
    # Retry only transient access failures; malformed JSON remains an error.
    for attempt in range(5):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else (default or {})
        except FileNotFoundError:
            return default or {}
        except PermissionError:
            if attempt == 4:
                raise
            time.sleep(0.01 * (attempt + 1))
        except json.JSONDecodeError as error:
            raise ValueError(f"invalid JSON state file: {path}") from error
    return default or {}


def atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        _replace_with_retry(temporary_name, path)
        _fsync_directory(path.parent)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def _replace_with_retry(source: str, destination: Path) -> None:
    # Windows and some NAS-backed filesystems can briefly deny replacement
    # while another thread is opening the destination for a status read.
    for attempt in range(10):
        try:
            os.replace(source, destination)
            return
        except PermissionError:
            if attempt == 9:
                raise
            time.sleep(0.01 * (attempt + 1))


def _fsync_directory(path: Path) -> None:
    if os.name != "posix":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    atomic_write_text(
        path,
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )


def write_text_exclusive(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        _fsync_directory(path.parent)
    except Exception:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise


class StateStore:
    def __init__(self, config: AppConfig):
        self.config = config
        self.state_path = config.data_dir / "state.json"
        self.current_path = config.data_dir / "current.json"
        self.snapshots_dir = config.data_dir / "state-snapshots"
        self.audit_jobs_dir = config.data_dir / "audit-jobs"
        self.scheduled_reports_dir = config.reports_dir / "scheduled"
        self.audit_reports_dir = config.reports_dir / "audits"
        self.local_socks_reports_dir = config.reports_dir / "local-socks"
        self._recover_interrupted_audits()
        self._recover_committed_alerts()

    def _recover_interrupted_audits(self) -> None:
        if not self.audit_jobs_dir.exists():
            return
        for path in self.audit_jobs_dir.glob("*.json"):
            try:
                status = read_json(path, {})
            except ValueError:
                continue
            if status.get("status") not in {"queued", "running"}:
                continue
            status.update(
                {
                    "status": "interrupted",
                    "phase": "interrupted",
                    "error": "container stopped before the audit completed",
                }
            )
            atomic_write_json(path, status)

    def _committed_alert_archive_dir(
        self, current: dict[str, Any]
    ) -> Path | None:
        revision = str(current.get("state_revision") or "")
        if self._snapshot_path(revision) is None:
            return None
        try:
            generated_at = datetime.fromisoformat(
                str(current.get("generated_at") or "").replace("Z", "+00:00")
            )
        except ValueError:
            return None
        return (
            self.scheduled_reports_dir
            / generated_at.strftime("%Y")
            / generated_at.strftime("%m")
            / generated_at.strftime("%d")
            / revision
        )

    def _finalize_committed_alerts(self, current: dict[str, Any]) -> None:
        """Publish report, export and alert views selected by current.json."""
        archive_dir = self._committed_alert_archive_dir(current)
        if archive_dir is None:
            return
        # Every latest view follows the durable current.json commit, just as
        # alerts do. Replay on startup and before another revision can commit.
        day = str(current.get("generated_at") or "")[:10]
        for extension, enabled in (("json", self.config.report.json), ("md", self.config.report.markdown)):
            source = archive_dir / f"report.{extension}"
            if enabled and source.is_file():
                content = source.read_text(encoding="utf-8")
                atomic_write_text(self.scheduled_reports_dir / f"latest.{extension}", content)
                atomic_write_text(self.config.reports_dir / f"{day}.{extension}", content)
        exports = archive_dir / "local-socks"
        if exports.is_dir():
            for source in sorted(exports.glob("*.txt"), key=lambda path: path.name == "README.txt"):
                atomic_write_text(self.local_socks_reports_dir / "latest" / source.name, source.read_text(encoding="utf-8"))
        latest_source = archive_dir / "alert-latest-run.md"
        if not latest_source.exists():
            return
        latest_content = latest_source.read_text(encoding="utf-8")
        alerts_dir = self.config.reports_dir / "alerts"
        atomic_write_text(alerts_dir / "latest-run.md", latest_content)

        change_source = archive_dir / "alert-slot-change.md"
        if not change_source.exists():
            slot_latest = alerts_dir / "slot-changes-latest.md"
            if not slot_latest.exists():
                atomic_write_text(slot_latest, latest_content)
            return

        change_content = change_source.read_text(encoding="utf-8")
        atomic_write_text(alerts_dir / "slot-changes-latest.md", change_content)
        day = str(current.get("generated_at") or "")[:10]
        revision = str(current["state_revision"])
        history_path = alerts_dir / f"{day}-{revision}.md"
        if history_path.exists():
            if history_path.read_text(encoding="utf-8") != change_content:
                raise FileExistsError(
                    f"alert history content mismatch: {history_path}"
                )
            return
        write_text_exclusive(history_path, change_content)

    def _recover_committed_alerts(
        self,
        current: dict[str, Any] | None = None,
        *,
        required: bool = False,
    ) -> None:
        selected = current if current is not None else read_json(self.current_path, {})
        if not selected:
            return
        try:
            self._finalize_committed_alerts(selected)
        except (OSError, ValueError) as error:
            # Startup and post-commit recovery stay best-effort because
            # current.json is already authoritative. Before a newer publish,
            # however, the caller requires success so an older committed slot
            # change cannot be permanently skipped by the next revision.
            LOGGER.warning(
                "committed %s but report/export/alert finalization is pending: %s",
                selected.get("state_revision") or selected.get("version"),
                error,
            )
            if required:
                raise

    def audit_status_path(self, audit_id: str) -> Path:
        return self.audit_jobs_dir / f"{validate_audit_id(audit_id)}.json"

    def audit_report_dir(self, audit_id: str) -> Path:
        year, month, day = audit_day_parts(audit_id)
        return self.audit_reports_dir / year / month / day / audit_id

    def create_audit_status(self, status: dict[str, Any]) -> None:
        audit_id = validate_audit_id(str(status.get("id") or ""))
        path = self.audit_status_path(audit_id)
        if path.exists():
            raise FileExistsError(f"audit already exists: {audit_id}")
        write_text_exclusive(
            path,
            json.dumps(status, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        )

    def load_audit_status(self, audit_id: str) -> dict[str, Any]:
        return read_json(self.audit_status_path(audit_id), {})

    def update_audit_status(self, audit_id: str, **changes: Any) -> dict[str, Any]:
        path = self.audit_status_path(audit_id)
        status = read_json(path, {})
        if not status:
            raise FileNotFoundError(f"audit not found: {audit_id}")
        status.update(changes)
        atomic_write_json(path, status)
        return status

    def _snapshot_path(self, identifier: str) -> Path | None:
        if not identifier or len(identifier) > 128 or any(
            character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
            for character in identifier
        ):
            return None
        return self.snapshots_dir / f"{identifier}.json"

    def load_state(self) -> dict[str, Any]:
        empty = {
            "schema_version": SCHEMA_VERSION,
            "stable_slots": {},
            "frozen_order": {},
            "nodes": {},
        }
        current = read_json(self.current_path, {})
        if current and current.get("schema_version") != SCHEMA_VERSION:
            current = {}
        current_version = str(current.get("version") or "")
        current_revision = str(current.get("state_revision") or "")
        snapshot_path = self._snapshot_path(current_revision or current_version)
        if snapshot_path is not None:
            try:
                snapshot = read_json(snapshot_path, {})
            except ValueError:
                snapshot = {}
            if (
                snapshot.get("schema_version") == SCHEMA_VERSION
                and snapshot.get("version") == current_version
                and (
                    not current_revision
                    or snapshot.get("state_revision") == current_revision
                )
            ):
                return _seed_frozen_order(snapshot, current)
        state = read_json(self.state_path, empty)
        if state.get("schema_version") != SCHEMA_VERSION:
            state = empty
        if current_revision:
            selected = (
                state
                if state.get("state_revision") == current_revision
                else empty
            )
        elif not current_version:
            selected = state if not state.get("version") else empty
        else:
            selected = state if state.get("version") == current_version else empty
        return _seed_frozen_order(selected, current)

    def load_current(self) -> dict[str, Any]:
        return read_json(self.current_path, {})

    def publish(
        self,
        current: dict[str, Any],
        state: dict[str, Any],
        assessments: list[NodeAssessment],
        slot_changes: list[dict[str, str]],
        generated_at: datetime,
    ) -> None:
        # Finish any alert left between the previous current.json commit and
        # its best-effort alert publication before preparing a newer scan.
        self._recover_committed_alerts(required=True)
        revision = str(current.get("state_revision") or "")
        if self._snapshot_path(revision) is None:
            stamp = generated_at.astimezone(timezone.utc).strftime(
                "%Y%m%dT%H%M%S%fZ"
            )
            revision = f"s-{stamp}-{uuid.uuid4().hex[:12]}"
        current["state_revision"] = revision
        state["state_revision"] = revision
        report_json = build_report_json(
            current,
            assessments,
            slot_changes,
            self.config.report.include_exit_ip,
            self.config.report.include_raw_details,
            self.config.region_port_bases,
            self.config.policy.stable_slots,
            self.config.local_socks_advertise_host,
        )
        report_markdown = build_report_markdown(
            current,
            assessments,
            slot_changes,
            self.config.region_port_bases,
            self.config.policy.stable_slots,
            self.config.report.include_exit_ip,
            self.config.report.include_raw_details,
            self.config.local_socks_advertise_host,
        )
        alert_markdown = _alert_markdown(current, assessments, slot_changes)
        local_socks_exports = build_local_socks_exports(
            current,
            assessments,
            self.config.region_port_bases,
            self.config.policy.stable_slots,
            self.config.local_socks_advertise_host,
        )

        # Reports are prepared first, then state, then the externally visible
        # current.json commit point. A crash cannot expose a ranking without
        # its matching durable state.
        archive_dir = (
            self.scheduled_reports_dir
            / generated_at.strftime("%Y")
            / generated_at.strftime("%m")
            / generated_at.strftime("%d")
            / revision
        )
        if self.config.report.json:
            atomic_write_json(archive_dir / "report.json", report_json)
        if self.config.report.markdown:
            atomic_write_text(archive_dir / "report.md", report_markdown)
        self._write_local_socks_exports(
            archive_dir / "local-socks", local_socks_exports, str(current["version"])
        )
        # Alert consumers watch reports/alerts directly. Stage the content in
        # this revision's archive so a failed current.json commit cannot emit
        # a false slot-change notification. Finalization below is idempotent
        # and restart-recoverable.
        atomic_write_text(archive_dir / "alert-latest-run.md", alert_markdown)
        if slot_changes:
            atomic_write_text(archive_dir / "alert-slot-change.md", alert_markdown)

        previous_current = read_json(self.current_path, {})
        previous_state = self.load_state()
        previous_version = str(previous_current.get("version") or "")
        previous_revision = str(previous_current.get("state_revision") or "")
        previous_snapshot = self._snapshot_path(previous_revision or previous_version)
        if (
            previous_snapshot is not None
            and previous_state.get("version") == previous_version
            and (
                not previous_revision
                or previous_state.get("state_revision") == previous_revision
            )
            and not previous_snapshot.exists()
        ):
            atomic_write_json(previous_snapshot, previous_state)

        snapshot_path = self._snapshot_path(revision)
        if snapshot_path is None:
            raise ValueError("state revision is unsafe for a snapshot path")
        # The immutable snapshot is the durable side of the commit. If writing
        # current.json fails, the previous current still points to its unique
        # state revision and cannot select this scan's newer state.
        atomic_write_json(snapshot_path, state)
        atomic_write_json(self.state_path, state)
        atomic_write_json(self.current_path, current)
        self._recover_committed_alerts(current)
        try:
            self._prune_state_snapshots(keep=3)
            self._prune_daily_reports(generated_at)
        except OSError as error:
            # current.json is already the durable commit point. Retention is
            # best-effort and must not turn a published version into a failed
            # scan that the scheduler retries.
            LOGGER.warning("published %s but retention cleanup failed: %s", current["version"], error)

    def publish_audit(
        self,
        audit_id: str,
        current: dict[str, Any],
        assessments: list[NodeAssessment],
        generated_at: datetime,
    ) -> dict[str, str]:
        report_json = build_report_json(
            current,
            assessments,
            [],
            self.config.report.include_exit_ip,
            self.config.report.include_raw_details,
            self.config.region_port_bases,
            self.config.policy.stable_slots,
            self.config.local_socks_advertise_host,
        )
        report_markdown = build_report_markdown(
            current,
            assessments,
            [],
            self.config.region_port_bases,
            self.config.policy.stable_slots,
            self.config.report.include_exit_ip,
            self.config.report.include_raw_details,
            self.config.local_socks_advertise_host,
        )
        local_socks_exports = build_local_socks_exports(
            current,
            assessments,
            self.config.region_port_bases,
            self.config.policy.stable_slots,
            self.config.local_socks_advertise_host,
        )
        directory = self.audit_report_dir(audit_id)
        json_path = directory / "report.json"
        markdown_path = directory / "report.md"
        atomic_write_json(json_path, report_json)
        atomic_write_text(markdown_path, report_markdown)
        local_socks_path = directory / "local-socks"
        self._write_local_socks_exports(
            local_socks_path, local_socks_exports, str(current["version"])
        )
        try:
            self._prune_report_archives(generated_at)
        except OSError as error:
            LOGGER.warning("audit %s published but retention cleanup failed: %s", audit_id, error)
        return {
            "json": json_path.relative_to(self.config.reports_dir).as_posix(),
            "markdown": markdown_path.relative_to(self.config.reports_dir).as_posix(),
            "local_socks": local_socks_path.relative_to(
                self.config.reports_dir
            ).as_posix(),
        }

    def _write_local_socks_exports(
        self, directory: Path, exports: dict[str, str], version: str
    ) -> None:
        for region, content in exports.items():
            atomic_write_text(directory / f"{region}.txt", content)
        atomic_write_text(
            directory / "README.txt",
            f"Generated by node-health ranking {version}\n"
            "Each SOCKS5 URL contains the real source node name.\n"
            "all.txt concatenates every regional listener in region order.\n"
            "all-plain.txt contains the same endpoints without display names.\n",
        )

    def audit_report_path(self, audit_id: str, extension: str) -> Path:
        if extension not in {"json", "md"}:
            raise ValueError("unsupported audit report extension")
        return self.audit_report_dir(audit_id) / f"report.{extension}"

    def _prune_state_snapshots(self, keep: int) -> None:
        snapshots = sorted(
            self.snapshots_dir.glob("*.json"),
            key=lambda path: path.stat().st_mtime_ns,
            reverse=True,
        )
        for path in snapshots[max(1, keep):]:
            path.unlink(missing_ok=True)

    def _prune_daily_reports(self, generated_at: datetime) -> None:
        cutoff = generated_at.date() - timedelta(days=self.config.report.retention_days)
        for path in self.config.reports_dir.iterdir():
            if not path.is_file() or path.suffix not in {".json", ".md"}:
                continue
            if re.fullmatch(r"\d{4}-\d{2}-\d{2}", path.stem) is None:
                continue
            try:
                report_day = datetime.strptime(path.stem, "%Y-%m-%d").date()
            except ValueError:
                continue
            if report_day < cutoff:
                path.unlink(missing_ok=True)
        self._prune_report_archives(generated_at)

    def _prune_report_archives(self, generated_at: datetime) -> None:
        cutoff = generated_at.date() - timedelta(days=self.config.report.retention_days)
        for root in (self.scheduled_reports_dir, self.audit_reports_dir):
            if not root.exists():
                continue
            for day_path in root.glob("[0-9][0-9][0-9][0-9]/[0-9][0-9]/[0-9][0-9]"):
                try:
                    report_day = datetime.strptime(
                        "/".join(day_path.parts[-3:]), "%Y/%m/%d"
                    ).date()
                except ValueError:
                    continue
                if report_day < cutoff:
                    shutil.rmtree(day_path)
            for path in sorted(root.glob("[0-9][0-9][0-9][0-9]/[0-9][0-9]"), reverse=True):
                if path.is_dir() and not any(path.iterdir()):
                    path.rmdir()
            for path in sorted(root.glob("[0-9][0-9][0-9][0-9]"), reverse=True):
                if path.is_dir() and not any(path.iterdir()):
                    path.rmdir()

        if self.audit_jobs_dir.exists():
            for path in self.audit_jobs_dir.glob("*.json"):
                match = re.fullmatch(r"(\d{8})T\d{6}Z-[0-9a-f]{8}", path.stem)
                if not match:
                    continue
                try:
                    report_day = datetime.strptime(match.group(1), "%Y%m%d").date()
                except ValueError:
                    continue
                if report_day < cutoff:
                    path.unlink(missing_ok=True)


def _assessment_detail(
    assessment: NodeAssessment,
    include_exit_ip: bool,
    include_raw_details: bool,
) -> dict[str, Any]:
    quick = assessment.quick.to_dict()
    full = assessment.full.to_dict() if assessment.full else None
    fresh_full_attempt = (
        assessment.fresh_full_attempt.to_dict()
        if assessment.fresh_full_attempt
        else None
    )
    if full is not None and not include_raw_details:
        full.pop("details", None)
    if fresh_full_attempt is not None and not include_raw_details:
        fresh_full_attempt.pop("details", None)
    evaluation = assessment.evaluation.to_dict()
    if not include_exit_ip:
        quick = _redact_exit_ips(quick)
        full = _redact_exit_ips(full)
        fresh_full_attempt = _redact_exit_ips(fresh_full_attempt)
        evaluation = _redact_exit_ips(evaluation)
    return {
        "node_key": assessment.node.key,
        "name": assessment.node.name,
        "region": assessment.node.region,
        "connection": _connection_detail(assessment),
        "geo": _geo_detail(assessment, include_exit_ip),
        "quick": quick,
        "full": full,
        "full_result_source": (
            "none"
            if assessment.full is None
            else (
                "fresh"
                if assessment.fresh_full_attempt is not None
                and assessment.full is assessment.fresh_full_attempt
                else "cached"
            )
        ),
        "fresh_full_attempt": fresh_full_attempt,
        "evaluation": evaluation,
        "consecutive_full_passes": assessment.consecutive_full_passes,
        "consecutive_unavailable_runs": assessment.consecutive_unavailable_runs,
        "healthy_streak_days": assessment.healthy_streak_days,
        "last_healthy_day": assessment.last_healthy_day,
        "consecutive_unavailable_valid_days": assessment.consecutive_unavailable_valid_days,
        "unavailable_grace_active": assessment.unavailable_grace_active,
        "daily_quality_history": assessment.daily_quality_history,
        "evidence_valid": assessment.evidence_valid,
        "fresh_full_completed": assessment.fresh_full_completed,
        "fresh_full_usable": assessment.fresh_full_usable,
    }


_IPV4_LITERAL = re.compile(
    r"(?<![0-9A-Za-z_])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9A-Za-z_])"
)
_IPV6_LITERAL = re.compile(
    r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])"
)


def _redact_ip_literals(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        candidate = match.group(0)
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            return candidate
        return "[redacted-ip]"

    return _IPV6_LITERAL.sub(replace, _IPV4_LITERAL.sub(replace, value))


def _redact_exit_ips(value: Any) -> Any:
    if isinstance(value, list):
        return [_redact_exit_ips(item) for item in value]
    if isinstance(value, str):
        return _redact_ip_literals(value)
    if not isinstance(value, dict):
        return value
    sensitive = {
        "ip",
        "exit_ip",
        "audited_exit_ip",
        "last_exit_ip",
        "claude_exit_ip",
    }
    redacted: dict[Any, Any] = {}
    for key, item in value.items():
        if str(key).lower() in sensitive:
            continue
        safe_key: Any = _redact_ip_literals(key) if isinstance(key, str) else key
        if safe_key in redacted:
            suffix = 2
            candidate = f"{safe_key}#{suffix}"
            while candidate in redacted:
                suffix += 1
                candidate = f"{safe_key}#{suffix}"
            safe_key = candidate
        redacted[safe_key] = _redact_exit_ips(item)
    return redacted


def _clean_geo_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text or text.lower() in {"null", "none", "n/a"}:
        return None
    return text


def _geo_number(value: Any) -> float | None:
    text = _clean_geo_text(value)
    if text is None:
        return None
    try:
        return float(text)
    except (TypeError, ValueError):
        return None


def _geo_detail(
    assessment: NodeAssessment, include_exit_ip: bool
) -> dict[str, Any]:
    full = assessment.full
    details = full.details if full and isinstance(full.details, dict) else {}
    info_value = details.get("Info")
    info = info_value if isinstance(info_value, dict) else {}
    city_value = info.get("City")
    city = city_value if isinstance(city_value, dict) else {}
    country_value = info.get("Region")
    country = country_value if isinstance(country_value, dict) else {}
    registered_value = info.get("RegisteredRegion")
    registered = registered_value if isinstance(registered_value, dict) else {}
    has_full_geo = bool(info)
    result_source = (
        "fresh"
        if has_full_geo
        and assessment.fresh_full_attempt is not None
        and assessment.full is assessment.fresh_full_attempt
        else ("cached" if has_full_geo else "quick")
    )
    payload: dict[str, Any] = {
        "country_code": (
            _clean_geo_text(country.get("Code"))
            or _clean_geo_text(assessment.quick.country)
        ),
        "country_name": _clean_geo_text(country.get("Name")),
        "registered_country_code": _clean_geo_text(registered.get("Code")),
        "registered_country_name": _clean_geo_text(registered.get("Name")),
        "subdivision_code": _clean_geo_text(city.get("SubCode")),
        "subdivision_name": _clean_geo_text(city.get("Subdivisions")),
        "city_name": _clean_geo_text(city.get("Name")),
        "postal_code": _clean_geo_text(city.get("PostalCode")),
        "asn": (
            _clean_geo_text(info.get("ASN"))
            or _clean_geo_text(assessment.quick.asn)
        ),
        "organization": _clean_geo_text(info.get("Organization")),
        "timezone": _clean_geo_text(info.get("TimeZone")),
        "latitude": _geo_number(info.get("Latitude")),
        "longitude": _geo_number(info.get("Longitude")),
        "map_url": _clean_geo_text(info.get("Map")),
        "location_type": _clean_geo_text(info.get("Type")),
        "observed_at": (
            _clean_geo_text(full.checked_at)
            or _clean_geo_text(assessment.quick.checked_at)
            if has_full_geo and full is not None
            else _clean_geo_text(assessment.quick.checked_at)
        ),
        "source": "ipquality.Info" if has_full_geo else "quick-probe",
        "result_source": result_source,
    }
    if include_exit_ip:
        payload["exit_ip"] = (
            _clean_geo_text(full.audited_exit_ip)
            or _clean_geo_text(assessment.quick.exit_ip)
            if has_full_geo and full is not None
            else _clean_geo_text(assessment.quick.exit_ip)
        )
    return payload


def _connection_detail(assessment: NodeAssessment) -> dict[str, Any]:
    proxy = assessment.node.proxy
    aliases = {
        "protocol": proxy.get("type"),
        "server": proxy.get("server"),
        "port": proxy.get("port"),
        "network": proxy.get("network"),
        "tls": proxy.get("tls"),
        "server_name": proxy.get("servername") or proxy.get("sni"),
        "udp": proxy.get("udp"),
    }
    return {key: value for key, value in aliases.items() if value not in {None, ""}}


def _local_socks_detail(
    position: tuple[int, int | None, str] | None,
    advertise_host: str,
    name: str,
) -> dict[str, Any] | None:
    if position is None or position[1] is None:
        return None
    port = position[1]
    return {
        "host": advertise_host,
        "port": port,
        "protocol": "socks5",
        "name": name,
        "url": f"socks5://{advertise_host}:{port}{{{name}}}",
    }


def _report_order(
    current: dict[str, Any], port_bases: dict[str, int], slot_count: int
) -> dict[str, tuple[int, int | None, str]]:
    order: dict[str, tuple[int, int | None, str]] = {}
    for region, payload in current.get("regions", {}).items():
        base = port_bases.get(region)
        for slot, key in payload.get("stable_slots", {}).items():
            index = int(slot) - 1
            order[str(key)] = (index, _listener_port(region, base, index), f"{int(slot):03d}")
        dynamic_start = 0 if region == "other" else slot_count
        for index, key in enumerate(payload.get("ranked", [])):
            absolute = dynamic_start + index
            order[str(key)] = (
                absolute,
                _listener_port(region, base, absolute),
                f"dynamic-{index + 1:03d}",
            )
    return order


def build_local_socks_exports(
    current: dict[str, Any],
    assessments: list[NodeAssessment],
    port_bases: dict[str, int],
    slot_count: int,
    advertise_host: str,
) -> dict[str, str]:
    """Build ordered regional and aggregate TXT payloads using source names.

    Regional files remain the canonical fixed-port views with source names.
    ``all.txt`` keeps that named format; ``all-plain.txt`` contains only the
    SOCKS5 endpoint and is useful for clients that reject display labels.
    """
    order = _report_order(current, port_bases, slot_count)
    entries: dict[str, list[tuple[int, str, str]]] = {
        region: [] for region in current.get("region_order", port_bases)
    }
    for item in assessments:
        position = order.get(item.node.key)
        if position is None or position[1] is None:
            continue
        name = re.sub(r"[\r\n]+", " ", item.node.name).strip()
        if not name:
            continue
        plain_line = f"socks5://{advertise_host}:{position[1]}"
        entries.setdefault(item.node.region, []).append(
            (position[0], plain_line, f"{plain_line}{{{name}}}")
        )
    rendered = {
        region: "".join(f"{named}\n" for _, _, named in sorted(lines))
        for region, lines in entries.items()
    }
    rendered_plain = {
        region: "".join(f"{plain}\n" for _, plain, _ in sorted(lines))
        for region, lines in entries.items()
    }
    ordered_regions = list(current.get("region_order", port_bases))
    for region in rendered:
        if region not in ordered_regions:
            ordered_regions.append(region)
    rendered["all"] = "".join(rendered.get(region, "") for region in ordered_regions)
    rendered["all-plain"] = "".join(
        rendered_plain.get(region, "") for region in ordered_regions
    )
    return rendered


def _report_summary(assessments: list[NodeAssessment]) -> dict[str, Any]:
    by_region: dict[str, int] = {}
    for item in assessments:
        by_region[item.node.region] = by_region.get(item.node.region, 0) + 1
    grades = {grade: sum(1 for item in assessments if item.evaluation.overall_grade == grade) for grade in ("A", "B", "C")}
    residential = {
        grade: sum(1 for item in assessments if item.evaluation.residential_grade == grade)
        for grade in ("confirmed", "probable", "unknown")
    }
    return {
        "nodes": len(assessments),
        "available": sum(1 for item in assessments if item.quick.available),
        "unavailable": sum(1 for item in assessments if not item.quick.available),
        "full_completed": sum(
            1
            for item in assessments
            if item.fresh_full_attempt and item.fresh_full_attempt.completed
        ),
        "full_incomplete": sum(
            1
            for item in assessments
            if item.fresh_full_attempt and not item.fresh_full_attempt.completed
        ),
        "eligible": sum(1 for item in assessments if item.evaluation.eligible),
        "rejected": sum(1 for item in assessments if item.evaluation.redline),
        "transient_recoveries": sum(1 for item in assessments if item.quick.transient_recovery),
        "quality_grades": grades,
        "residential": residential,
        "regions": dict(sorted(by_region.items())),
    }


def build_report_json(
    current: dict[str, Any],
    assessments: list[NodeAssessment],
    slot_changes: list[dict[str, str]],
    include_exit_ip: bool,
    include_raw_details: bool,
    port_bases: dict[str, int],
    slot_count: int,
    advertise_host: str,
) -> dict[str, Any]:
    order = _report_order(current, port_bases, slot_count)
    return {
        "schema_version": 1,
        "report_kind": current.get("report_kind", "scheduled"),
        "version": current["version"],
        "state_revision": current.get("state_revision"),
        "generated_at": current["generated_at"],
        "started_at": current.get("started_at"),
        "completed_at": current.get("completed_at", current["generated_at"]),
        "duration_seconds": current.get("duration_seconds"),
        "probe_diagnostics": current.get("probe_diagnostics", {}),
        "ai_guard_samples": current.get("ai_guard_samples", {}),
        "quality_summary": current.get("quality_summary", {}),
        "name": current.get("name"),
        "mode": current["mode"],
        "source": current.get("source", {}),
        "summary": _report_summary(assessments),
        "slot_changes": (
            slot_changes if include_exit_ip else _redact_exit_ips(slot_changes)
        ),
        "regions": (
            current.get("regions", {})
            if include_exit_ip
            else _redact_exit_ips(current.get("regions", {}))
        ),
        "outage_protection": (
            current.get("outage_protection", {})
            if include_exit_ip
            else _redact_exit_ips(current.get("outage_protection", {}))
        ),
        "nodes": [
            {
                **_assessment_detail(item, include_exit_ip, include_raw_details),
                **(
                    {"local_socks": detail}
                    if (detail := _local_socks_detail(
                        order.get(item.node.key), advertise_host, item.node.name
                    ))
                    else {}
                ),
            }
            for item in sorted(assessments, key=_report_sort_key)
        ],
    }


def _report_sort_key(assessment: NodeAssessment) -> tuple[object, ...]:
    return (assessment.node.region, *ranking_key(assessment))


def _markdown_escape(value: Any) -> str:
    text = " ".join(str(value or "").split())
    for character in "\\`*_{}[]<>()#+-.!|":
        text = text.replace(character, "\\" + character)
    return text


def _json_fence(value: Any) -> list[str]:
    payload = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)
    longest = max((len(match.group(0)) for match in re.finditer(r"`+", payload)), default=0)
    fence = "`" * max(3, longest + 1)
    return [f"{fence}json", payload, fence]


def _slot_lookup(current: dict[str, Any]) -> dict[str, str]:
    lookup: dict[str, str] = {}
    for region, payload in current.get("regions", {}).items():
        for slot, key in payload.get("stable_slots", {}).items():
            lookup[str(key)] = f"{region}/{int(slot):03d}"
    return lookup


def _listener_port(region: str, base: int | None, offset: int) -> int | None:
    if base is None or offset < 0:
        return None
    port = base + offset
    if port > _MAX_PORT:
        return None
    if region != "other" and offset >= _FIXED_REGION_PORT_BLOCK_SIZE:
        return None
    return port


_REGION_ZH = {
    "__global__": "全局",
    "hong-kong": "香港",
    "taiwan": "台湾",
    "japan": "日本",
    "singapore": "新加坡",
    "united-states": "美国",
    "south-korea": "韩国",
    "united-kingdom": "英国",
    "germany": "德国",
    "france": "法国",
    "canada": "加拿大",
    "australia": "澳大利亚",
    "other": "其他",
}

_OUTAGE_REASON_ZH = {
    "all-nodes-unavailable": "最终复检后全部节点不可达",
    "availability-collapse": "可用率低于阈值且较上一有效基线大幅下降",
    "global-all-nodes-unavailable": "全局最终复检后全部节点不可达",
    "global-availability-collapse": "全局可用率异常大幅下降",
}

_STATUS_ZH = {
    "healthy": "健康",
    "degraded": "降级",
    "unavailable": "不可达",
    "protected-unavailable": "宽限保护中",
    "absent": "订阅中已消失",
    "eligible": "可用",
    "rejected": "已拒绝",
    "unknown": "未知",
}

_CONFIDENCE_ZH = {
    "high": "高",
    "provisional": "暂定",
    "low": "低",
    "unavailable": "不可达",
    "rejected": "已拒绝",
    "unknown": "未知",
}

_MODE_ZH = {
    "rebuild": "全量重建",
    "maintenance": "日常维护",
    "subscription-audit": "临时订阅审计",
}

_COUNTRY_CODE_ZH = {
    "HK": "中国香港",
    "TW": "中国台湾",
    "JP": "日本",
    "SG": "新加坡",
    "US": "美国",
    "KR": "韩国",
    "GB": "英国",
    "DE": "德国",
    "FR": "法国",
    "CA": "加拿大",
    "AU": "澳大利亚",
}

_RESULT_SOURCE_ZH = {
    "fresh": "本轮深检",
    "cached": "历史缓存",
    "quick": "快速检测",
    "none": "无",
}

_CHANGE_REASON_ZH = {
    "rebuild": "全量重建",
    "superior-candidate": "长期高质量候补晋级",
    "missing-from-inventory": "节点已从订阅中消失",
    "repeated-unavailable": "连续多次不可达",
    "quality-redline": "触发质量红线",
    "degraded-quality-rerank": "合格可用节点不足，按整体质量重排",
    "vacant-slot-fill": "填补空槽位",
    "confirmed-unavailable": "当日复检后确认不可达",
    "quality-severe": "确认严重质量风险且有更好候补",
}

_REASON_ZH = {
    "unavailable": "快速检测不可达",
    "missing-public-egress-ip": "未取得公网出口 IP",
    "egress-ip-unstable": "出口 IP 不稳定",
    "stable-egress-ip-changed": "稳定槽出口 IP 已变化",
    "country-unconfirmed": "无法确认出口国家",
    "tor-exit": "检测到 Tor 出口",
    "claude-tor-exit": "Claude 专用出口检测到 Tor",
    "full-audit-incomplete": "本轮深度检测未完成",
    "transient-recovery": "延迟复检后恢复",
    "ai-services-unavailable": "ChatGPT 与 Claude 均确认不可用",
    "risk-consensus-severe": "多个来源共同确认严重风险",
    "claude-risk-consensus-severe": "Claude 专用出口多个来源共同确认严重风险",
    "chatgpt-available": "ChatGPT 可用",
    "chatgpt-unavailable": "ChatGPT 不可用",
    "chatgpt-unknown": "ChatGPT 状态未知",
    "claude-degraded": "Claude 部分可达",
    "claude-restricted": "Claude 出口地区不受支持",
    "claude-unreachable": "Claude 与 Anthropic 均不可达",
    "claude-unknown": "Claude 状态未知",
    "chatgpt-service-outage": "ChatGPT 本轮触发服务级异常保护，沿用历史 AI 结果",
    "claude-service-outage": "Claude 本轮触发服务级异常保护，沿用历史 AI 结果",
    "claude-risk-incomplete": "Claude 专用出口风险数据不完整，沿用可信缓存并暂停累计",
}

_REASON_PREFIX_ZH = {
    "quick-country-disagrees-with-full:": "快速检测与深检国家不一致",
    "country-mismatch:": "深检国家与目标地区不一致",
    "quick-country-mismatch:": "快速检测国家与目标地区不一致",
    "insufficient-quick-success-rate:": "快速检测成功率不足",
    "dnsbl-redline:": "DNSBL 命中数量达到红线",
    "dnsbl-listed:": "DNSBL 存在少量命中",
    "multiple-high-risk-sources:": "多个风险源判定为高风险",
    "chatgpt-redline:": "ChatGPT 可用性触发红线",
    "chatgpt-unconfirmed:": "无法确认 ChatGPT 可用性",
    "insufficient-risk-coverage:": "有效风险数据源不足",
    "claude-insufficient-risk-coverage:": "Claude 专用出口有效风险数据源不足",
    "claude-multiple-high-risk-sources:": "Claude 专用出口多个风险源判定为高风险",
    "claude-intelligence-country-conflict:": "Claude 服务出口国家与风险情报国家不一致",
    "fresh-ai-unconfirmed:": "本轮 AI 深检结果不确定，沿用历史可信结果",
}


def _zh_region(value: Any) -> str:
    text = str(value or "other")
    return _REGION_ZH.get(text, text)


def _zh_status(value: Any) -> str:
    text = str(value or "unknown")
    return _STATUS_ZH.get(text, text)


def _zh_confidence(value: Any) -> str:
    text = str(value or "unknown")
    return _CONFIDENCE_ZH.get(text, text)


def _zh_reason(value: Any) -> str:
    text = str(value or "")
    if text in _REASON_ZH:
        return _REASON_ZH[text]
    for prefix, label in _REASON_PREFIX_ZH.items():
        if text.startswith(prefix):
            detail = text[len(prefix):]
            return f"{label}（{detail}）" if detail else label
    return text or "无"


def _zh_reasons(values: Iterable[Any]) -> str:
    translated = [_zh_reason(value) for value in values]
    return "；".join(translated) if translated else "无"


def _zh_bool(value: Any) -> str:
    if value is True:
        return "是"
    if value is False:
        return "否"
    return "未知"


def _zh_result_source(value: Any) -> str:
    text = str(value or "none")
    return _RESULT_SOURCE_ZH.get(text, text)


def build_report_markdown(
    current: dict[str, Any],
    assessments: list[NodeAssessment],
    slot_changes: list[dict[str, str]],
    port_bases: dict[str, int],
    slot_count: int,
    include_exit_ip: bool,
    include_raw_details: bool,
    advertise_host: str,
) -> str:
    if not include_exit_ip:
        slot_changes = _redact_exit_ips(slot_changes)
    lookup = _slot_lookup(current)
    order = _report_order(current, port_bases, slot_count)
    report_kind = str(current.get("report_kind") or "scheduled")
    title = (
        f"订阅节点审计：{_markdown_escape(current.get('name') or current['version'])}"
        if report_kind == "subscription-audit"
        else f"节点健康检测报告 {current['generated_at']}"
    )
    summary = _report_summary(assessments)
    lines = [
        f"# {title}",
        "",
        f"- 报告类型：`{'临时订阅审计' if report_kind == 'subscription-audit' else '正式定时检测'}`",
        f"- 运行模式：`{_MODE_ZH.get(current['mode'], current['mode'])}`",
        f"- 版本：`{current['version']}`",
        *(
            [f"- 状态修订：`{current['state_revision']}`"]
            if current.get("state_revision")
            else []
        ),
        f"- 订阅节点总数：{current['source']['node_count']}",
        f"- 快速检测可达：{summary['available']}；不可达：{summary['unavailable']}",
        f"- 深度检测完成：{summary['full_completed']}；未完成：{summary['full_incomplete']}",
        f"- 综合等级：A={summary['quality_grades']['A']}；B={summary['quality_grades']['B']}；C={summary['quality_grades']['C']}",
        f"- 家宽识别：确认={summary['residential']['confirmed']}；高概率={summary['residential']['probable']}；未知/冲突={summary['residential']['unknown']}",
        f"- 延迟复检恢复：{summary['transient_recoveries']}",
        "",
        "## 稳定槽位变更" if report_kind != "subscription-audit" else "## 本次审计建议",
        "",
    ]
    if report_kind == "subscription-audit":
        lines.append(
            "每个地区的前三个槽位仅为本次报告给出的建议；"
            "本次临时审计不会修改正式环境的稳定槽位。"
        )
    elif slot_changes:
        lines.extend(
            [
                "| 地区 | 槽位 | 变更前 | 变更后 | 原因 | 详情 |",
                "|---|---:|---|---|---|---|",
            ]
        )
        for change in slot_changes:
            before_name = str(change.get("before_name") or "未知")
            after_name = str(change.get("after_name") or "未知")
            before_name = "空槽位" if before_name == "empty" else before_name
            after_name = "空槽位" if after_name == "empty" else after_name
            before_name = before_name.replace("|", "\\|")
            after_name = after_name.replace("|", "\\|")
            before_label = f"{before_name} (`{change['before'] or '-'}`)"
            after_label = f"{after_name} (`{change['after'] or '-'}`)"
            details = (
                f"分数 {change.get('before_score', '-')} -> {change.get('after_score', '-')} "
                f"（差值 {change.get('score_margin', '-')}）；"
                f"候补健康连续 {change.get('candidate_healthy_days', '-')} 天"
            )
            if change.get("redline_reasons"):
                details += f"；红线原因 {_zh_reason(change['redline_reasons'])}"
            lines.append(
                f"| {_zh_region(change['region'])} | {change['slot']} | {before_label} | "
                f"{after_label} | {_CHANGE_REASON_ZH.get(change.get('reason', ''), change.get('reason', '-'))} | {details} |"
            )
    else:
        lines.append("本轮稳定槽位没有变化。")

    outage = current.get("outage_protection", {})
    if not include_exit_ip:
        outage = _redact_exit_ips(outage)
    frozen_scopes = [
        f"{_zh_region(scope)}={_OUTAGE_REASON_ZH.get(str(value.get('reason')), value.get('reason'))}"
        for scope, value in (outage.get("regions", {}) if isinstance(outage, dict) else {}).items()
        if isinstance(value, dict) and value.get("frozen")
    ]
    ai_outages = list((outage.get("ai_services", {}) if isinstance(outage, dict) else {}))
    lines.extend([
        "",
        "## 异常保护",
        "",
        f"- 排名冻结：{_markdown_escape('；'.join(frozen_scopes) if frozen_scopes else '无')}",
        f"- AI 服务级异常：{_markdown_escape('、'.join(ai_outages) if ai_outages else '无')}",
    ])
    if isinstance(outage, dict):
        for service, payload in (outage.get("ai_services", {}) or {}).items():
            if not isinstance(payload, dict):
                continue
            diagnostic = payload.get("diagnostics", {})
            lines.append(
                f"- {service} 失败比例：`{float(payload.get('failure_ratio') or 0):.0%}`；"
                f"直连/官方状态诊断（仅供排障，不参与排序）："
                f"`{json.dumps(diagnostic, ensure_ascii=False, sort_keys=True)}`"
            )

    lines.extend(
        [
            "",
            "## 建议优先槽位" if report_kind == "subscription-audit" else "## 稳定槽位状态",
            "",
            "| 地区 | 槽位 | 端口 | SOCKS5 | 节点 | 状态 | 健康天数 | 确认不可达天数 | 宽限 | 等级 | 最近出口 IP | 最近深检时间 | 分数 | 原因 |",
            "|---|---:|---:|---|---|---|---:|---:|---|---|---|---|---:|---|",
        ]
    )
    for region in current.get("region_order", []):
        payload = current.get("regions", {}).get(region, {})
        base = port_bases.get(region)
        for slot, key in sorted(
            payload.get("stable_slots", {}).items(), key=lambda item: int(item[0])
        ):
            status = payload.get("stable_status", {}).get(slot, {})
            name = str(status.get("name") or current.get("nodes", {}).get(key, {}).get("name") or "unknown")
            reasons = _zh_reasons(status.get("reasons", []))
            port = base + int(slot) - 1 if base is not None else "-"
            socks5 = (
                f"socks5://{advertise_host}:{port}{{{name}}}" if port != "-" else "-"
            )
            escaped_name = name.replace("|", "\\|")
            escaped_reasons = reasons.replace("|", "\\|")
            last_exit_ip = str(status.get("last_exit_ip") or "-") if include_exit_ip else "[omitted]"
            last_full = str(status.get("last_full_checked_at") or "-")
            score = float(status.get("score") or 0)
            lines.append(
                f"| {_zh_region(region)} | {slot} | {port} | `{socks5}` | {escaped_name} | "
                f"{_zh_status(status.get('status', 'unknown'))} | "
                f"{int(status.get('healthy_streak_days', 0) or 0)} | "
                f"{int(status.get('consecutive_unavailable_valid_days', 0) or 0)} | "
                f"{_zh_bool(status.get('unavailable_grace_active'))} | "
                f"{status.get('overall_grade', 'B')} | "
                f"{last_exit_ip} | {last_full} | "
                f"{score:.2f} | {escaped_reasons} |"
            )

    lines.extend(
        [
            "",
            "## 当前顺序与检测结果",
            "",
            "| 地区 | 当前位置 | 端口 | SOCKS5 | 节点 | 出口 IP | 国家 | "
            "州/省 | 城市 | ASN | 运营商 | 延迟 | 成功率 | "
            "等级 | AI/风险/可靠/家宽/地理/延迟 | 分数 | 置信度 | 判定 |",
            "|---|---|---:|---|---|---|---|---|---|---|---|---:|---:|---|---|---:|---|---|",
        ]
    )
    region_indexes = {
        region: index for index, region in enumerate(current.get("region_order", []))
    }

    def current_order(item: NodeAssessment) -> tuple[object, ...]:
        position = order.get(item.node.key)
        return (
            region_indexes.get(item.node.region, 9999),
            item.node.region,
            0 if position is not None else 1,
            position[0] if position is not None else 999999,
            -item.evaluation.score,
            item.node.name,
        )

    for item in sorted(assessments, key=current_order):
        order_item = order.get(item.node.key)
        position = lookup.get(
            item.node.key,
            order_item[2]
            if order_item is not None
            else ("未排序" if item.evaluation.eligible else "已移除"),
        )
        if position.startswith(f"{item.node.region}/"):
            position = f"{_zh_region(item.node.region)}/{position.rsplit('/', 1)[-1]}"
        elif position.startswith("dynamic-"):
            position = "动态-" + position.removeprefix("dynamic-")
        port = (
            str(order_item[1])
            if order_item is not None and order_item[1] is not None
            else "-"
        )
        socks5 = (
            f"socks5://{advertise_host}:{port}{{{item.node.name}}}" if port != "-" else "-"
        )
        latency = "-" if item.quick.latency_ms is None else f"{item.quick.latency_ms:.1f} ms"
        reason = _zh_reasons(item.evaluation.reasons)
        decision = _zh_status(item.evaluation.decision)
        if item.evaluation.reasons:
            decision += f"（{reason}）"
        name = item.node.name.replace("|", "\\|")
        geo = _geo_detail(item, include_exit_ip)
        components = item.evaluation.components
        component_text = "/".join(
            f"{float(components.get(name, 0)):.0f}"
            for name in ("ai", "risk", "reliability", "residential", "geo", "latency")
        )
        country_code = str(geo.get("country_code") or "").upper()
        country = str(
            _COUNTRY_CODE_ZH.get(country_code)
            or geo.get("country_name")
            or country_code
            or "-"
        ).replace("|", "\\|")
        subdivision = str(geo.get("subdivision_name") or "-").replace("|", "\\|")
        city = str(geo.get("city_name") or "-").replace("|", "\\|")
        asn = str(geo.get("asn") or "-").replace("|", "\\|")
        organization = str(geo.get("organization") or "-").replace("|", "\\|")
        lines.append(
            f"| {_zh_region(item.node.region)} | {position} | {port} | `{socks5}` | {name} | "
            f"{(item.quick.exit_ip or '-') if include_exit_ip else '[omitted]'} | "
            f"{country} | {subdivision} | {city} | {asn} | {organization} | "
            f"{latency} | {item.quick.success_rate:.0%} | {item.evaluation.overall_grade} | {component_text} | {item.evaluation.score:.2f} | "
            f"{_zh_confidence(item.evaluation.confidence)} | {decision} |"
        )

    lines.extend(["", "## 节点详细检测", ""])
    for item in sorted(assessments, key=_report_sort_key):
        detail = _assessment_detail(item, include_exit_ip, include_raw_details)
        socks5_detail = _local_socks_detail(
            order.get(item.node.key), advertise_host, item.node.name
        )
        socks5 = socks5_detail["url"] if socks5_detail else "-"
        quick = detail["quick"]
        full = detail["full"]
        fresh = detail["fresh_full_attempt"]
        connection = detail["connection"]
        geo = detail["geo"]
        evaluation = detail["evaluation"]
        reasons = _zh_reasons(item.evaluation.reasons)
        connection_text = ", ".join(
            f"{key}={value}" for key, value in connection.items()
        ) or "未提供"
        availability = "可达" if quick.get("available") else "不可达"
        latency_value = quick.get("latency_ms")
        latency_text = latency_value if latency_value is not None else "-"
        full_attempt_status = (
            "已完成"
            if fresh and fresh.get("completed")
            else ("失败" if fresh else "未执行")
        )
        lines.extend(
            [
                f"### {_markdown_escape(item.node.name)}",
                "",
                f"- 节点标识：`{item.node.key}`",
                f"- 地区：`{_zh_region(item.node.region)}`",
                f"- 连接参数：{_markdown_escape(connection_text)}",
                f"- 本地 SOCKS5：`{socks5}`",
                f"- 判定：`{_zh_status(item.evaluation.decision)}`；置信度："
                f"`{_zh_confidence(item.evaluation.confidence)}`；综合等级：`{item.evaluation.overall_grade}`；"
                f"AI=`{item.evaluation.ai_grade}`；风险=`{item.evaluation.risk_grade}`；家宽=`{item.evaluation.residential_grade}`；"
                f"分数：`{item.evaluation.score:.2f}`",
                f"- 本轮观察分：`{item.evaluation.evidence.get('observed_score', item.evaluation.score)}`；"
                f"生效排名分来源：`{item.evaluation.evidence.get('ranking_score_source', 'current')}`；"
                f"历史分日期：`{item.evaluation.evidence.get('ranking_score_day') or '-'}`",
                f"- 分项得分：`{json.dumps(item.evaluation.components, ensure_ascii=False, sort_keys=True)}`",
                f"- 评分证据：`{json.dumps(evaluation.get('evidence', {}), ensure_ascii=False, sort_keys=True)}`",
                f"- 原因：{_markdown_escape(reasons)}",
                f"- 健康连续天数：`{item.healthy_streak_days}`；确认不可达天数："
                f"`{item.consecutive_unavailable_valid_days}`；宽限保护："
                f"`{_zh_bool(item.unavailable_grace_active)}`",
                f"- 快速检测时间：`{quick.get('checked_at') or '-'}`",
                f"- 连通性：`{availability}`；成功率："
                f"`{float(quick.get('success_rate') or 0):.0%}`；延迟：`{latency_text} ms`",
                f"- 出口：`{quick.get('exit_ip') or '-'}`；国家："
                f"`{quick.get('country') or '-'}`；ASN："
                f"`{_markdown_escape(quick.get('asn') or '-')}`；出口 IP 稳定："
                f"`{_zh_bool(quick.get('exit_ip_stable'))}`",
                f"- 地理位置：国家=`{_markdown_escape(_COUNTRY_CODE_ZH.get(str(geo.get('country_code') or '').upper()) or geo.get('country_name') or geo.get('country_code') or '-')}`；"
                f"州/省=`{_markdown_escape(geo.get('subdivision_name') or '-')}`；"
                f"城市=`{_markdown_escape(geo.get('city_name') or '-')}`；"
                f"邮编=`{_markdown_escape(geo.get('postal_code') or '-')}`",
                f"- 地理信息依据：运营商=`{_markdown_escape(geo.get('organization') or '-')}`；"
                f"时区=`{_markdown_escape(geo.get('timezone') or '-')}`；"
                f"来源=`{geo.get('source')}`；结果来源=`{_zh_result_source(geo.get('result_source'))}`；"
                f"观测时间=`{geo.get('observed_at') or '-'}`",
                f"- 服务检查：Google=`{_zh_bool(quick.get('google_ok'))}`；"
                f"ChatGPT=`{_zh_bool(quick.get('chatgpt_ok'))}`",
                f"- Claude：状态=`{quick.get('claude', {}).get('status', 'unknown')}`；"
                f"出口=`{quick.get('claude', {}).get('exit_ip') or '-'}`；国家="
                f"`{quick.get('claude', {}).get('country') or '-'}`；情报国家="
                f"`{quick.get('claude', {}).get('intelligence_country') or '-'}`；支持地区="
                f"`{_zh_bool(quick.get('claude', {}).get('supported'))}`；路由稳定="
                f"`{_zh_bool(quick.get('claude', {}).get('route_stable'))}`",
                f"- 快速检测错误：{_markdown_escape(quick.get('error') or '无')}",
                f"- 可信深检结果：`{'有' if full else '无'}` "
                f"（`{_zh_result_source(detail['full_result_source'])}`）；本轮深检："
                f"`{full_attempt_status}`",
                "",
            ]
        )
        if full:
            risk_sources = ", ".join(
                f"{key}={value}" for key, value in (full.get("risk_sources") or {}).items()
            ) or "无"
            labels = (
                ", ".join(str(value) for value in full.get("labels") or []) or "无"
            )
            lines.extend(
                [
                    f"- 深度检测时间：`{full.get('checked_at') or '-'}`；"
                    f"深检出口：`{full.get('audited_exit_ip') or '-'}`",
                    f"- 风险数据源：{_markdown_escape(risk_sources)}",
                    f"- 风险标记：Tor=`{_zh_bool(full.get('tor'))}`；DNSBL 是否命中="
                    f"`{_zh_bool(full.get('dnsbl_blacklisted'))}`；DNSBL 命中数量="
                    f"`{full.get('dnsbl_listed_count', 0)}`；"
                    f"标签={_markdown_escape(labels)}",
                    f"- 深度检测错误：{_markdown_escape(full.get('error') or '无')}",
                    "",
                ]
            )
        if fresh and (not fresh.get("completed") or fresh.get("error")):
            lines.extend(
                [
                    "- 本轮深度检测错误："
                    f"{_markdown_escape(fresh.get('error') or 'unknown')}",
                    "",
                ]
            )
        if fresh and fresh != full:
            lines.extend(
                [
                    f"- 本轮深检时间：`{fresh.get('checked_at') or '-'}`；"
                    f"深检出口：`{fresh.get('audited_exit_ip') or '-'}`；"
                    f"是否完成：`{_zh_bool(fresh.get('completed'))}`",
                    "",
                ]
            )
        if include_raw_details and full and full.get("details") is not None:
            lines.extend(
                ["#### IPQuality 原始结果", "", *_json_fence(full["details"]), ""]
            )
        if (
            include_raw_details
            and fresh
            and fresh != full
            and fresh.get("details") is not None
        ):
            lines.extend(
                [
                    "#### 本轮深度检测原始结果",
                    "",
                    *_json_fence(fresh["details"]),
                    "",
                ]
            )
    return "\n".join(lines).rstrip() + "\n"


def _alert_markdown(
    current: dict[str, Any],
    assessments: list[NodeAssessment],
    slot_changes: list[dict[str, str]],
) -> str:
    by_key = {
        key: str(payload.get("name") or "unknown")
        for key, payload in current.get("nodes", {}).items()
    }
    lines = [
        "# 最新稳定槽位状态",
        "",
        f"生成时间：{current['generated_at']}",
        "",
    ]
    if not slot_changes:
        lines.append("本轮稳定槽位没有变化。")
    for change in slot_changes:
        before_name = change.get("before_name") or (
            by_key.get(change["before"], "unknown") if change["before"] else "empty"
        )
        after_name = change.get("after_name") or (
            by_key.get(change["after"], "unknown") if change["after"] else "empty"
        )
        lines.append(
            f"- `{_zh_region(change['region'])}/{int(change['slot']):03d}`："
            f"{before_name} (`{change['before'] or '-'}`) -> {after_name} (`{change['after'] or '-'}`); "
            f"原因：`{_CHANGE_REASON_ZH.get(change.get('reason', ''), change.get('reason', '未知'))}`；"
            f"分数：{change.get('before_score', '-')} -> {change.get('after_score', '-')} "
            f"（差值 {change.get('score_margin', '-')}）"
        )
    attention: list[str] = []
    for region, payload in current.get("regions", {}).items():
        for slot, status in payload.get("stable_status", {}).items():
            if status.get("status") not in {
                "unavailable",
                "protected-unavailable",
                "absent",
                "degraded",
            }:
                continue
            reasons = _zh_reasons(status.get("reasons", []))
            attention.append(
                f"- `{_zh_region(region)}/{int(slot):03d}`：{status.get('name', '未知')}，"
                f"状态为`{_zh_status(status.get('status'))}`；原因：{reasons}"
            )
    lines.extend(["", "## 需要关注的稳定槽位", ""])
    lines.extend(attention or ["没有降级、不可达或已从订阅消失的稳定槽位。"])
    return "\n".join(lines).rstrip() + "\n"
