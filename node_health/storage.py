from __future__ import annotations

import json
import logging
import os
import re
import shutil
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .config import AppConfig
from .models import NodeAssessment
from .audit import audit_day_parts, validate_audit_id


_FIXED_REGION_PORT_BLOCK_SIZE = 200
_MAX_PORT = 65535
LOGGER = logging.getLogger("node_health.storage")


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
        self._recover_interrupted_audits()

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

    def _snapshot_path(self, version: str) -> Path | None:
        if not version or len(version) > 128 or any(
            character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
            for character in version
        ):
            return None
        return self.snapshots_dir / f"{version}.json"

    def load_state(self) -> dict[str, Any]:
        empty = {"schema_version": 1, "stable_slots": {}, "nodes": {}}
        state = read_json(self.state_path, empty)
        current = read_json(self.current_path, {})
        current_version = str(current.get("version") or "")
        snapshot_path = self._snapshot_path(current_version)
        if snapshot_path is not None:
            try:
                snapshot = read_json(snapshot_path, {})
            except ValueError:
                snapshot = {}
            if snapshot.get("version") == current_version:
                return snapshot
        if not current_version:
            return state if not state.get("version") else empty
        return state if state.get("version") == current_version else empty

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
        day = generated_at.date().isoformat()
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

        # Reports are prepared first, then state, then the externally visible
        # current.json commit point. A crash cannot expose a ranking without
        # its matching durable state.
        if self.config.report.json:
            atomic_write_json(self.config.reports_dir / f"{day}.json", report_json)
        if self.config.report.markdown:
            atomic_write_text(self.config.reports_dir / f"{day}.md", report_markdown)
        archive_dir = (
            self.scheduled_reports_dir
            / generated_at.strftime("%Y")
            / generated_at.strftime("%m")
            / generated_at.strftime("%d")
            / str(current["version"])
        )
        if self.config.report.json:
            atomic_write_json(archive_dir / "report.json", report_json)
            atomic_write_json(self.scheduled_reports_dir / "latest.json", report_json)
        if self.config.report.markdown:
            atomic_write_text(archive_dir / "report.md", report_markdown)
            atomic_write_text(self.scheduled_reports_dir / "latest.md", report_markdown)
        alerts_dir = self.config.reports_dir / "alerts"
        atomic_write_text(alerts_dir / "latest-run.md", alert_markdown)
        slot_latest = alerts_dir / "slot-changes-latest.md"
        if slot_changes or not slot_latest.exists():
            atomic_write_text(slot_latest, alert_markdown)
        if slot_changes:
            history_name = f"{day}-{current['version']}.md"
            write_text_exclusive(alerts_dir / history_name, alert_markdown)

        previous_current = read_json(self.current_path, {})
        previous_state = read_json(self.state_path, {})
        previous_version = str(previous_current.get("version") or "")
        previous_snapshot = self._snapshot_path(previous_version)
        if (
            previous_snapshot is not None
            and previous_state.get("version") == previous_version
            and not previous_snapshot.exists()
        ):
            atomic_write_json(previous_snapshot, previous_state)

        snapshot_path = self._snapshot_path(str(current.get("version") or ""))
        if snapshot_path is None:
            raise ValueError("current version is unsafe for a state snapshot path")
        # The immutable snapshot is the durable side of the commit. If writing
        # current.json fails, the previous current still selects its matching
        # snapshot after restart.
        atomic_write_json(snapshot_path, state)
        atomic_write_json(self.state_path, state)
        atomic_write_json(self.current_path, current)
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
        directory = self.audit_report_dir(audit_id)
        json_path = directory / "report.json"
        markdown_path = directory / "report.md"
        atomic_write_json(json_path, report_json)
        atomic_write_text(markdown_path, report_markdown)
        try:
            self._prune_report_archives(generated_at)
        except OSError as error:
            LOGGER.warning("audit %s published but retention cleanup failed: %s", audit_id, error)
        return {
            "json": json_path.relative_to(self.config.reports_dir).as_posix(),
            "markdown": markdown_path.relative_to(self.config.reports_dir).as_posix(),
        }

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
    if not include_exit_ip:
        quick.pop("exit_ip", None)
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
    return {
        "node_key": assessment.node.key,
        "name": assessment.node.name,
        "region": assessment.node.region,
        "connection": _connection_detail(assessment),
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
        "evaluation": assessment.evaluation.to_dict(),
        "consecutive_full_passes": assessment.consecutive_full_passes,
        "consecutive_unavailable_runs": assessment.consecutive_unavailable_runs,
        "fresh_full_completed": assessment.fresh_full_completed,
        "fresh_full_usable": assessment.fresh_full_usable,
    }


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


def _report_summary(assessments: list[NodeAssessment]) -> dict[str, Any]:
    by_region: dict[str, int] = {}
    for item in assessments:
        by_region[item.node.region] = by_region.get(item.node.region, 0) + 1
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
        "generated_at": current["generated_at"],
        "started_at": current.get("started_at"),
        "completed_at": current.get("completed_at", current["generated_at"]),
        "name": current.get("name"),
        "mode": current["mode"],
        "source": current.get("source", {}),
        "summary": _report_summary(assessments),
        "slot_changes": slot_changes,
        "regions": current.get("regions", {}),
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
    return (
        assessment.node.region,
        0 if assessment.evaluation.eligible else 1,
        -assessment.evaluation.score,
        assessment.node.name,
    )


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
    lookup = _slot_lookup(current)
    order = _report_order(current, port_bases, slot_count)
    report_kind = str(current.get("report_kind") or "scheduled")
    title = (
        f"Subscription audit: {_markdown_escape(current.get('name') or current['version'])}"
        if report_kind == "subscription-audit"
        else f"Node health report {current['generated_at']}"
    )
    summary = _report_summary(assessments)
    lines = [
        f"# {title}",
        "",
        f"- Report kind: `{report_kind}`",
        f"- Mode: `{current['mode']}`",
        f"- Version: `{current['version']}`",
        f"- Inventory nodes: {current['source']['node_count']}",
        f"- Available: {summary['available']}; unavailable: {summary['unavailable']}",
        f"- Full audits completed: {summary['full_completed']}; incomplete: {summary['full_incomplete']}",
        "",
        "## Stable slot changes" if report_kind != "subscription-audit" else "## Audit recommendations",
        "",
    ]
    if report_kind == "subscription-audit":
        lines.append(
            "The first slots in each region are recommendations for this report only; "
            "this audit did not modify the production stable slots."
        )
    elif slot_changes:
        lines.extend(
            [
                "| Region | Slot | Before | After | Reason | Details |",
                "|---|---:|---|---|---|---|",
            ]
        )
        for change in slot_changes:
            before_name = str(change.get("before_name") or "unknown").replace("|", "\\|")
            after_name = str(change.get("after_name") or "unknown").replace("|", "\\|")
            before_label = f"{before_name} (`{change['before'] or '-'}`)"
            after_label = f"{after_name} (`{change['after'] or '-'}`)"
            details = (
                f"score {change.get('before_score', '-')} -> {change.get('after_score', '-')} "
                f"(margin {change.get('score_margin', '-')}); "
                f"candidate full passes {change.get('candidate_full_passes', '-')}"
            )
            if change.get("redline_reasons"):
                details += f"; redline {change['redline_reasons']}"
            lines.append(
                f"| {change['region']} | {change['slot']} | {before_label} | "
                f"{after_label} | {change.get('reason', '-')} | {details} |"
            )
    else:
        lines.append("No stable-slot changes.")

    lines.extend(
        [
            "",
            "## Recommended top slots" if report_kind == "subscription-audit" else "## Stable slot status",
            "",
            "| Region | Slot | Port | SOCKS5 | Node | Status | Unavailable runs | Last exit IP | Last full | Score | Reasons |",
            "|---|---:|---:|---|---|---|---:|---|---|---:|---|",
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
            reasons = ", ".join(str(value) for value in status.get("reasons", [])) or "-"
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
                f"| {region} | {slot} | {port} | `{socks5}` | {escaped_name} | "
                f"{status.get('status', 'unknown')} | "
                f"{int(status.get('consecutive_unavailable_runs', 0) or 0)} | "
                f"{last_exit_ip} | {last_full} | "
                f"{score:.2f} | {escaped_reasons} |"
            )

    lines.extend(
        [
            "",
            "## Current order and checks",
            "",
            "| Region | Position | Port | SOCKS5 | Node | Exit IP | ASN | Latency | "
            "Success | Score | Confidence | Decision |",
            "|---|---|---:|---|---|---|---|---:|---:|---:|---|---|",
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
            else ("unranked" if item.evaluation.eligible else "removed"),
        )
        port = (
            str(order_item[1])
            if order_item is not None and order_item[1] is not None
            else "-"
        )
        socks5 = (
            f"socks5://{advertise_host}:{port}{{{item.node.name}}}" if port != "-" else "-"
        )
        latency = "-" if item.quick.latency_ms is None else f"{item.quick.latency_ms:.1f} ms"
        reason = ", ".join(item.evaluation.reasons)
        decision = item.evaluation.decision + (f" ({reason})" if reason else "")
        name = item.node.name.replace("|", "\\|")
        asn = item.quick.asn.replace("|", "\\|")
        lines.append(
            f"| {item.node.region} | {position} | {port} | `{socks5}` | {name} | "
            f"{(item.quick.exit_ip or '-') if include_exit_ip else '[omitted]'} | {asn or '-'} | "
            f"{latency} | {item.quick.success_rate:.0%} | {item.evaluation.score:.2f} | "
            f"{item.evaluation.confidence} | {decision} |"
        )

    lines.extend(["", "## Detailed checks", ""])
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
        reasons = ", ".join(item.evaluation.reasons) or "none"
        connection_text = ", ".join(
            f"{key}={value}" for key, value in connection.items()
        ) or "not reported"
        availability = "available" if quick.get("available") else "unavailable"
        latency_value = quick.get("latency_ms")
        latency_text = latency_value if latency_value is not None else "-"
        full_attempt_status = (
            "completed"
            if fresh and fresh.get("completed")
            else ("failed" if fresh else "not-run")
        )
        lines.extend(
            [
                f"### {_markdown_escape(item.node.name)}",
                "",
                f"- Node key: `{item.node.key}`",
                f"- Region: `{_markdown_escape(item.node.region)}`",
                f"- Connection: {_markdown_escape(connection_text)}",
                f"- Local SOCKS5: `{socks5}`",
                f"- Decision: `{item.evaluation.decision}`; confidence: "
                f"`{item.evaluation.confidence}`; score: `{item.evaluation.score:.2f}`",
                f"- Reasons: {_markdown_escape(reasons)}",
                f"- Consecutive unavailable runs: `{item.consecutive_unavailable_runs}`",
                f"- Quick checked at: `{quick.get('checked_at') or '-'}`",
                f"- Connectivity: `{availability}`; success: "
                f"`{float(quick.get('success_rate') or 0):.0%}`; latency: `{latency_text} ms`",
                f"- Exit: `{quick.get('exit_ip') or '-'}`; country: "
                f"`{quick.get('country') or '-'}`; ASN: "
                f"`{_markdown_escape(quick.get('asn') or '-')}`; stable IP: "
                f"`{quick.get('exit_ip_stable')}`",
                f"- Service checks: Google=`{quick.get('google_ok')}`; "
                f"ChatGPT=`{quick.get('chatgpt_ok')}`",
                f"- Quick error: {_markdown_escape(quick.get('error') or 'none')}",
                f"- Trusted full result: `{'present' if full else 'none'}` "
                f"(`{detail['full_result_source']}`); current full attempt: "
                f"`{full_attempt_status}`",
                "",
            ]
        )
        if full:
            risk_sources = ", ".join(
                f"{key}={value}" for key, value in (full.get("risk_sources") or {}).items()
            ) or "none"
            labels = (
                ", ".join(str(value) for value in full.get("labels") or []) or "none"
            )
            lines.extend(
                [
                    f"- Full checked at: `{full.get('checked_at') or '-'}`; "
                    f"audited exit: `{full.get('audited_exit_ip') or '-'}`",
                    f"- Risk sources: {_markdown_escape(risk_sources)}",
                    f"- Risk flags: Tor=`{full.get('tor')}`; DNSBL any listing="
                    f"`{full.get('dnsbl_blacklisted')}`; DNSBL listed count="
                    f"`{full.get('dnsbl_listed_count', 0)}`; "
                    f"labels={_markdown_escape(labels)}",
                    f"- Full error: {_markdown_escape(full.get('error') or 'none')}",
                    "",
                ]
            )
        if fresh and (not fresh.get("completed") or fresh.get("error")):
            lines.extend(
                [
                    "- Current full-attempt error: "
                    f"{_markdown_escape(fresh.get('error') or 'unknown')}",
                    "",
                ]
            )
        if fresh and fresh != full:
            lines.extend(
                [
                    f"- Current full attempt checked at: `{fresh.get('checked_at') or '-'}`; "
                    f"audited exit: `{fresh.get('audited_exit_ip') or '-'}`; "
                    f"completed: `{fresh.get('completed')}`",
                    "",
                ]
            )
        if include_raw_details and full and full.get("details") is not None:
            lines.extend(
                ["#### Raw IPQuality result", "", *_json_fence(full["details"]), ""]
            )
        if (
            include_raw_details
            and fresh
            and fresh != full
            and fresh.get("details") is not None
        ):
            lines.extend(
                [
                    "#### Raw current full-attempt result",
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
        "# Latest stable-slot changes",
        "",
        f"Generated: {current['generated_at']}",
        "",
    ]
    if not slot_changes:
        lines.append("No stable-slot changes in this run.")
    for change in slot_changes:
        before_name = change.get("before_name") or (
            by_key.get(change["before"], "unknown") if change["before"] else "empty"
        )
        after_name = change.get("after_name") or (
            by_key.get(change["after"], "unknown") if change["after"] else "empty"
        )
        lines.append(
            f"- `{change['region']}/{int(change['slot']):03d}`: "
            f"{before_name} (`{change['before'] or '-'}`) -> {after_name} (`{change['after'] or '-'}`); "
            f"reason: `{change.get('reason', 'unknown')}`; "
            f"score: {change.get('before_score', '-')} -> {change.get('after_score', '-')} "
            f"(margin {change.get('score_margin', '-')})"
        )
    attention: list[str] = []
    for region, payload in current.get("regions", {}).items():
        for slot, status in payload.get("stable_status", {}).items():
            if status.get("status") not in {"unavailable", "absent", "degraded"}:
                continue
            reasons = ", ".join(str(value) for value in status.get("reasons", [])) or "-"
            attention.append(
                f"- `{region}/{int(slot):03d}`: {status.get('name', 'unknown')} is "
                f"`{status.get('status')}`; reasons: {reasons}"
            )
    lines.extend(["", "## Stable slot attention", ""])
    lines.extend(attention or ["No degraded, unavailable, or absent stable slots."])
    return "\n".join(lines).rstrip() + "\n"
