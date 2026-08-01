from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import math
import threading
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from .config import AppConfig
from .audit import (
    download_subscription,
    new_audit_id,
    normalize_audit_name,
    source_fingerprint,
    validate_subscription_url,
)
from .inventory import (
    Download,
    download_bytes,
    fetch_inventory,
    inventory_digest,
    parse_clash_inventory,
)
from .models import Evaluation, FullResult, Node, NodeAssessment, QuickResult
from .policy import (
    evaluate_node,
    full_has_confirmed_redline,
    full_has_usable_reputation,
    select_full_audit_nodes,
)
from .probe import (
    CurlQuickProbe,
    FullAuditor,
    IPQualityAuditor,
    MihomoProbeEnvironment,
    ProbeEnvironment,
    QuickProbe,
    run_parallel,
)
from .slots import assign_all_regions
from .storage import StateStore

LOGGER = logging.getLogger("node_health")


class AlreadyRunning(RuntimeError):
    pass


class ScanStartError(RuntimeError):
    pass


def _full_from_dict(value: Any) -> FullResult | None:
    if not isinstance(value, dict):
        return None
    allowed = {
        "completed",
        "audited_exit_ip",
        "tor",
        "dnsbl_blacklisted",
        "dnsbl_listed_count",
        "risk_sources",
        "labels",
        "details",
        "checked_at",
        "error",
    }
    try:
        result = FullResult(**{key: item for key, item in value.items() if key in allowed})
        if not result.audited_exit_ip and isinstance(result.details, dict):
            head = result.details.get("Head")
            if isinstance(head, dict):
                result.audited_exit_ip = str(head.get("IP") or "").strip()
        return result
    except TypeError:
        return None


def _all_stable_keys(state: dict[str, Any]) -> set[str]:
    return {
        str(key)
        for slots in state.get("stable_slots", {}).values()
        if isinstance(slots, dict)
        for key in slots.values()
        if key
    }


def _stable_region_by_key(state: dict[str, Any]) -> dict[str, str]:
    return {
        str(key): str(region)
        for region, slots in state.get("stable_slots", {}).items()
        if isinstance(slots, dict)
        for key in slots.values()
        if key
    }


def _has_usable_slots(state: dict[str, Any]) -> bool:
    return bool(_all_stable_keys(state))


class NodeHealthService:
    def __init__(
        self,
        config: AppConfig,
        *,
        downloader: Download = download_bytes,
        environment: ProbeEnvironment | None = None,
        quick_probe: QuickProbe | None = None,
        full_auditor: FullAuditor | None = None,
        audit_downloader: Callable[[str, float, int], bytes] | None = None,
        store: StateStore | None = None,
        clock: Callable[[], datetime] | None = None,
    ):
        self.config = config
        self.downloader = downloader
        self.environment = environment or MihomoProbeEnvironment(config)
        self.quick_probe = quick_probe or CurlQuickProbe(config)
        self.full_auditor = full_auditor or IPQualityAuditor(config)
        self.audit_downloader = audit_downloader or download_subscription
        self.store = store or StateStore(config)
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self._run_lock = threading.Lock()
        self._status_lock = threading.Lock()
        self._running_mode = ""
        self._last_error = ""
        self._last_success = str(self.store.load_current().get("generated_at") or "")
        self._active_audit_id = ""

    def status(self) -> dict[str, Any]:
        with self._status_lock:
            return {
                "status": "degraded" if self._last_error else "ok",
                "running": bool(self._running_mode),
                "running_mode": self._running_mode or None,
                "last_success": self._last_success or None,
                "last_error": self._last_error or None,
                "active_audit_id": self._active_audit_id or None,
            }

    def run_once(self, mode: str = "maintenance") -> dict[str, Any]:
        if mode not in {"maintenance", "rebuild"}:
            raise ValueError("mode must be maintenance or rebuild")
        if not self._run_lock.acquire(blocking=False):
            raise AlreadyRunning("a node-health scan is already running")
        with self._status_lock:
            self._running_mode = mode
            self._last_error = ""
        try:
            current = self._run_locked(mode)
            with self._status_lock:
                self._last_success = current["generated_at"]
            return current
        except Exception as error:
            LOGGER.exception("node-health scan failed")
            with self._status_lock:
                self._last_error = str(error)
            raise
        finally:
            with self._status_lock:
                self._running_mode = ""
            self._run_lock.release()

    def trigger(self, mode: str = "maintenance") -> bool:
        if mode not in {"maintenance", "rebuild"}:
            raise ValueError("mode must be maintenance or rebuild")
        # Reserve the lock before returning 202 so two concurrent HTTP calls
        # cannot both start workers between the check and thread startup.
        if not self._run_lock.acquire(blocking=False):
            return False
        with self._status_lock:
            self._running_mode = mode
            self._last_error = ""

        def worker() -> None:
            try:
                current = self._run_locked(mode)
                with self._status_lock:
                    self._last_success = current["generated_at"]
            except Exception as error:
                LOGGER.exception("background node-health scan failed")
                with self._status_lock:
                    self._last_error = str(error)
            finally:
                with self._status_lock:
                    self._running_mode = ""
                self._run_lock.release()

        try:
            thread = threading.Thread(target=worker, name=f"node-health-{mode}", daemon=True)
            thread.start()
        except Exception as error:
            message = f"failed to start background scan: {error}"
            LOGGER.exception(message)
            with self._status_lock:
                self._running_mode = ""
                self._last_error = message
            self._run_lock.release()
            raise ScanStartError(message) from error
        return True

    def trigger_subscription_audit(self, subscription_url: str, name: str = "") -> str | None:
        if not self.config.audit.enabled:
            raise ValueError("subscription audits are disabled")
        url, origin = validate_subscription_url(subscription_url, self.config)
        audit_name = normalize_audit_name(name)
        if not self._run_lock.acquire(blocking=False):
            return None
        created = self.clock()
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        audit_id = new_audit_id(created)
        created_at = created.astimezone(timezone.utc).isoformat(timespec="seconds")
        status = {
            "schema_version": 1,
            "id": audit_id,
            "name": audit_name,
            "status": "queued",
            "phase": "queued",
            "created_at": created_at,
            "started_at": None,
            "completed_at": None,
            "source": {
                "origin": origin,
                "url_sha256": source_fingerprint(url),
            },
            "node_count": None,
            "summary": None,
            "reports": None,
            "error": None,
        }
        try:
            self.store.create_audit_status(status)
        except Exception:
            self._run_lock.release()
            raise
        with self._status_lock:
            self._running_mode = "subscription-audit"
            self._active_audit_id = audit_id
            self._last_error = ""

        def worker() -> None:
            try:
                self._run_subscription_audit_locked(audit_id, url, audit_name, status)
            except Exception as error:
                LOGGER.exception("background subscription audit failed: %s", audit_id)
                completed_at = self.clock()
                if completed_at.tzinfo is None:
                    completed_at = completed_at.replace(tzinfo=timezone.utc)
                try:
                    self.store.update_audit_status(
                        audit_id,
                        status="failed",
                        phase="failed",
                        completed_at=completed_at.astimezone(timezone.utc).isoformat(timespec="seconds"),
                        error=str(error)[:2000],
                    )
                except Exception:
                    LOGGER.exception("failed to persist audit failure: %s", audit_id)
                with self._status_lock:
                    self._last_error = f"subscription audit {audit_id} failed: {error}"
            finally:
                with self._status_lock:
                    self._running_mode = ""
                    self._active_audit_id = ""
                self._run_lock.release()

        try:
            thread = threading.Thread(
                target=worker,
                name=f"node-health-audit-{audit_id}",
                daemon=True,
            )
            thread.start()
        except Exception as error:
            message = f"failed to start subscription audit worker: {error}"
            try:
                self.store.update_audit_status(
                    audit_id,
                    status="failed",
                    phase="failed",
                    completed_at=created_at,
                    error=message,
                )
            except Exception:
                LOGGER.exception("failed to persist audit worker-start failure: %s", audit_id)
            finally:
                with self._status_lock:
                    self._running_mode = ""
                    self._active_audit_id = ""
                    self._last_error = message
                self._run_lock.release()
            raise ScanStartError(message) from error
        return audit_id

    def _run_subscription_audit_locked(
        self,
        audit_id: str,
        url: str,
        name: str,
        initial_status: dict[str, Any],
    ) -> dict[str, Any]:
        started = self.clock()
        if started.tzinfo is None:
            started = started.replace(tzinfo=timezone.utc)
        started_at = started.astimezone(timezone.utc).isoformat(timespec="seconds")
        self.store.update_audit_status(
            audit_id,
            status="running",
            phase="downloading",
            started_at=started_at,
        )
        payload = self.audit_downloader(
            url,
            self.config.inventory.timeout_seconds,
            self.config.audit.max_subscription_bytes,
        )
        nodes = parse_clash_inventory(payload, self.config.region_patterns)
        if not nodes:
            raise ValueError("subscription contains no proxies")
        if len(nodes) > self.config.audit.max_nodes:
            raise ValueError(
                f"subscription contains {len(nodes)} nodes; audit.max_nodes is {self.config.audit.max_nodes}"
            )
        source_digest = inventory_digest(nodes)
        self.store.update_audit_status(
            audit_id,
            phase="quick-scan",
            node_count=len(nodes),
        )
        with self.environment.open(nodes) as ports:
            quick_raw = run_parallel(
                nodes,
                ports,
                self.quick_probe,
                self.config.probe.concurrency,
                "quick",
            )
            quick_results = {
                key: value for key, value in quick_raw.items() if isinstance(value, QuickResult)
            }
            if len(quick_results) != len(nodes):
                raise RuntimeError("quick audit did not return one result for every node")
            available_nodes = [node for node in nodes if quick_results[node.key].available]
            self.store.update_audit_status(
                audit_id,
                phase="full-scan",
                progress={
                    "quick_completed": len(nodes),
                    "available": len(available_nodes),
                    "full_planned": len(available_nodes),
                },
            )
            full_raw = run_parallel(
                available_nodes,
                ports,
                self.full_auditor,
                self.config.probe.full_concurrency,
                "full",
            )
            full_results = {
                key: value for key, value in full_raw.items() if isinstance(value, FullResult)
            }
            if len(full_results) != len(available_nodes):
                raise RuntimeError("full audit did not return one result for every available node")
            self._validate_full_exit_ips(available_nodes, quick_results, full_results)

        assessments: list[NodeAssessment] = []
        for node in nodes:
            quick = quick_results[node.key]
            full = full_results.get(node.key)
            passes = 1 if full_has_usable_reputation(full, self.config.policy) else 0
            evaluation = evaluate_node(
                node,
                quick,
                full,
                self.config.policy,
                passes,
                was_stable=False,
            )
            if full is not None and not full.completed:
                evaluation.reasons.append("full-audit-incomplete")
            assessments.append(
                NodeAssessment(
                    node=node,
                    quick=quick,
                    full=full,
                    evaluation=evaluation,
                    consecutive_full_passes=passes,
                    fresh_full_completed=bool(full and full.completed),
                    fresh_full_usable=full_has_usable_reputation(full, self.config.policy),
                    fresh_full_attempt=full,
                )
            )

        regions, _ = assign_all_regions(
            "rebuild",
            assessments,
            {},
            self.config.policy.stable_slots,
            self.config.region_order,
            {},
            self.config.policy,
            {},
            started,
        )
        completed = self.clock()
        if completed.tzinfo is None:
            completed = completed.replace(tzinfo=timezone.utc)
        completed_at = completed.astimezone(timezone.utc).isoformat(timespec="seconds")
        current = self._build_current(
            audit_id,
            completed_at,
            "subscription-audit",
            "rebuild",
            source_digest,
            nodes,
            assessments,
            regions,
            {},
        )
        current.update(
            {
                "report_kind": "subscription-audit",
                "name": name,
                "mode": "subscription-audit",
                "started_at": started_at,
                "completed_at": completed_at,
            }
        )
        current["source"].update(initial_status["source"])
        self.store.update_audit_status(audit_id, phase="writing-report")
        reports = self.store.publish_audit(audit_id, current, assessments, completed.astimezone())
        summary = {
            "nodes": len(nodes),
            "available": sum(1 for item in assessments if item.quick.available),
            "unavailable": sum(1 for item in assessments if not item.quick.available),
            "full_completed": sum(
                1 for item in assessments if item.full is not None and item.full.completed
            ),
            "full_incomplete": sum(
                1 for item in assessments if item.full is not None and not item.full.completed
            ),
            "eligible": sum(1 for item in assessments if item.evaluation.eligible),
            "rejected": sum(1 for item in assessments if item.evaluation.redline),
        }
        outcome = (
            "completed"
            if not summary["unavailable"] and not summary["full_incomplete"]
            else "completed_with_warnings"
        )
        return self.store.update_audit_status(
            audit_id,
            status=outcome,
            phase="completed",
            completed_at=completed_at,
            summary=summary,
            reports=reports,
            error=None,
        )

    @staticmethod
    def _validate_full_exit_ips(
        nodes: list[Node],
        quick_results: dict[str, QuickResult],
        full_results: dict[str, FullResult],
    ) -> None:
        for node in nodes:
            result = full_results[node.key]
            if not result.completed:
                continue
            expected_ip = quick_results[node.key].exit_ip
            if not result.audited_exit_ip:
                result.completed = False
                result.error = "full audit did not report its egress IP"
            elif result.audited_exit_ip != expected_ip:
                result.completed = False
                result.error = (
                    "full audit egress changed during scan: "
                    f"{result.audited_exit_ip} != {expected_ip}"
                )

    def _run_locked(self, requested_mode: str) -> dict[str, Any]:
        started_at = self.clock()
        if started_at.tzinfo is None:
            started_at = started_at.replace(tzinfo=timezone.utc)
        previous = self.store.load_state()
        effective_mode = requested_mode if _has_usable_slots(previous) else "rebuild"
        nodes, source_digest = fetch_inventory(self.config, self.downloader)

        with self.environment.open(nodes) as ports:
            quick_raw = run_parallel(
                nodes,
                ports,
                self.quick_probe,
                self.config.probe.concurrency,
                "quick",
            )
            quick_results = {key: value for key, value in quick_raw.items() if isinstance(value, QuickResult)}
            if len(quick_results) != len(nodes):
                raise RuntimeError("quick scan did not return one result for every inventory node")
            available = sum(1 for result in quick_results.values() if result.available)
            ratio = available / len(nodes)
            if available == 0 or ratio < self.config.policy.minimum_publish_available_ratio:
                raise RuntimeError(
                    f"quick scan availability {available}/{len(nodes)} is below publication guard"
                )

            selected = select_full_audit_nodes(
                effective_mode,
                nodes,
                quick_results,
                previous,
                self.config.policy,
                started_at.astimezone(timezone.utc),
            )
            selected_nodes = [node for node in nodes if node.key in selected]
            full_raw = run_parallel(
                selected_nodes,
                ports,
                self.full_auditor,
                self.config.probe.full_concurrency,
                "full",
            )
            scanned_full = {key: value for key, value in full_raw.items() if isinstance(value, FullResult)}
            if len(scanned_full) != len(selected_nodes):
                raise RuntimeError("full scan did not return one result for every selected node")
            for node in selected_nodes:
                result = scanned_full[node.key]
                if not result.completed:
                    continue
                expected_ip = quick_results[node.key].exit_ip
                if not result.audited_exit_ip:
                    result.completed = False
                    result.error = "full audit did not report its egress IP"
                elif result.audited_exit_ip != expected_ip:
                    result.completed = False
                    result.error = (
                        "full audit egress changed during scan: "
                        f"{result.audited_exit_ip} != {expected_ip}"
                    )
            if effective_mode == "rebuild":
                completed = sum(
                    1 for node in selected_nodes if scanned_full[node.key].completed
                )
                completion_ratio = completed / len(selected_nodes) if selected_nodes else 0
                if (
                    completed == 0
                    or completion_ratio
                    < self.config.policy.minimum_rebuild_full_completion_ratio
                ):
                    raise RuntimeError(
                        "rebuild full audit completion "
                        f"{completed}/{len(selected_nodes)} is below publication guard"
                    )
                by_region: dict[str, list[Node]] = {}
                for node in selected_nodes:
                    if node.region != "other":
                        by_region.setdefault(node.region, []).append(node)
                for region, region_nodes in by_region.items():
                    region_completed = sum(
                        1 for node in region_nodes if scanned_full[node.key].completed
                    )
                    required = math.ceil(
                        len(region_nodes)
                        * self.config.policy.minimum_rebuild_full_completion_ratio
                    )
                    if region_completed < required:
                        raise RuntimeError(
                            "rebuild full audit completion for region "
                            f"{region} {region_completed}/{len(region_nodes)} "
                            "is below publication guard"
                        )

        assessments = self._assess(
            nodes,
            quick_results,
            scanned_full,
            previous,
        )
        if effective_mode == "rebuild":
            self._guard_rebuild_evidence(assessments)
        regions, changes = assign_all_regions(
            effective_mode,
            assessments,
            previous.get("stable_slots", {}),
            self.config.policy.stable_slots,
            self.config.region_order,
            previous.get("nodes", {}),
            self.config.policy,
            previous.get("slot_changed_at", {}),
            started_at,
        )
        generated_at = self.clock()
        if generated_at.tzinfo is None:
            generated_at = generated_at.replace(tzinfo=timezone.utc)
        iso_time = generated_at.astimezone().isoformat(timespec="seconds")
        version = self._runtime_version(source_digest, regions)

        current = self._build_current(
            version,
            iso_time,
            requested_mode,
            effective_mode,
            source_digest,
            nodes,
            assessments,
            regions,
            previous,
        )
        state = self._build_state(current, previous, assessments, regions, changes)
        self.store.publish(current, state, assessments, changes, generated_at.astimezone())
        return current

    @staticmethod
    def _runtime_version(
        source_digest: str, regions: dict[str, dict[str, object]]
    ) -> str:
        """Return a stable version for the OpenWrt runtime projection.

        Health scores and timestamps may change on every scan, but they do not
        require a local-socks restart when the selected node identities and
        ordering remain unchanged.
        """
        projection = {
            "source_digest": source_digest,
            "regions": {
                region: {
                    "stable_slots": payload.get("stable_slots", {}),
                    "ranked": payload.get("ranked", []),
                    "rejected": payload.get("rejected", {}),
                }
                for region, payload in sorted(regions.items())
            },
        }
        encoded = json.dumps(projection, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return "r-" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:16]

    def _assess(
        self,
        nodes: list[Node],
        quick_results: dict[str, QuickResult],
        scanned_full: dict[str, FullResult],
        previous: dict[str, Any],
    ) -> list[NodeAssessment]:
        prior_nodes = previous.get("nodes", {})
        stable_keys = _all_stable_keys(previous)
        stable_regions = _stable_region_by_key(previous)
        assessments: list[NodeAssessment] = []
        for node in nodes:
            if node.key in stable_regions and node.region != stable_regions[node.key]:
                node = Node(
                    key=node.key,
                    name=node.name,
                    region=stable_regions[node.key],
                    proxy=node.proxy,
                )
            quick = quick_results[node.key]
            prior = prior_nodes.get(node.key, {})
            prior_full = _full_from_dict(prior.get("last_full"))
            prior_full_exit_ip = str(
                prior.get("last_full_exit_ip")
                or (prior_full.audited_exit_ip if prior_full else "")
                or prior.get("last_exit_ip")
                or ""
            )
            safe_prior_full = (
                prior_full
                if prior_full
                and (not quick.available or prior_full_exit_ip == quick.exit_ip)
                else None
            )
            fresh_full = scanned_full.get(node.key)
            # A transient third-party failure never destroys the last trusted
            # reputation result in maintenance mode. A confirmed redline for
            # the same egress IP is also latched for the current decision: an
            # ambiguous completed response (for example ChatGPT=Failed or
            # empty risk sources) cannot wash it away. Only a new trustworthy
            # clean result, or another confirmed redline, supersedes it.
            fresh_is_trustworthy = bool(
                fresh_full
                and fresh_full.completed
                and (
                    full_has_usable_reputation(fresh_full, self.config.policy)
                    or full_has_confirmed_redline(fresh_full, self.config.policy)
                )
            )
            prior_redline_latched = bool(
                safe_prior_full
                and full_has_confirmed_redline(safe_prior_full, self.config.policy)
            )
            if fresh_full and fresh_full.completed:
                full = (
                    safe_prior_full
                    if prior_redline_latched and not fresh_is_trustworthy
                    else fresh_full
                )
            else:
                full = safe_prior_full
            if full is None and fresh_full is not None:
                full = fresh_full

            passes = int(prior.get("consecutive_full_passes", 0) or 0)
            if full_has_usable_reputation(fresh_full, self.config.policy):
                if prior_full_exit_ip == quick.exit_ip and passes > 0:
                    passes += 1
                else:
                    passes = 1
            elif fresh_full is not None:
                passes = 0

            unavailable_runs = 0
            if not quick.available and node.key in stable_keys:
                unavailable_runs = int(
                    prior.get("consecutive_unavailable_runs", 0) or 0
                ) + 1

            evaluation = evaluate_node(
                node,
                quick,
                full,
                self.config.policy,
                passes,
                previous_exit_ip=str(prior.get("last_exit_ip") or ""),
                was_stable=node.key in stable_keys,
            )
            if fresh_full is not None and not fresh_full.completed:
                evaluation.reasons.append("full-audit-incomplete")
            if fresh_full is not None and evaluation.confidence == "low":
                passes = 0
            if evaluation.redline or (
                evaluation.decision == "unavailable" and node.key not in stable_keys
            ):
                passes = 0
                evaluation = Evaluation(
                    decision=evaluation.decision,
                    score=evaluation.score,
                    confidence=evaluation.confidence,
                    reasons=evaluation.reasons,
                )
            assessments.append(
                NodeAssessment(
                    node=node,
                    quick=quick,
                    full=full,
                    evaluation=evaluation,
                    consecutive_full_passes=passes,
                    consecutive_unavailable_runs=unavailable_runs,
                    fresh_full_completed=bool(fresh_full and fresh_full.completed),
                    fresh_full_usable=full_has_usable_reputation(
                        fresh_full, self.config.policy
                    ),
                    fresh_full_attempt=fresh_full,
                )
            )
        return assessments

    def _guard_rebuild_evidence(self, assessments: list[NodeAssessment]) -> None:
        grouped: dict[str, list[NodeAssessment]] = {}
        for item in assessments:
            if item.quick.available:
                grouped.setdefault(item.node.region, []).append(item)

        def has_current_evidence(item: NodeAssessment) -> bool:
            fresh = item.fresh_full_attempt
            confirmed_full_redline = bool(
                fresh
                and fresh.completed
                and full_has_confirmed_redline(fresh, self.config.policy)
            )
            quick_redline = any(
                reason == "missing-public-egress-ip"
                or reason == "egress-ip-unstable"
                or reason.startswith("country-mismatch:")
                for reason in item.evaluation.reasons
            )
            clean_reputation = (
                item.fresh_full_usable
                and item.evaluation.confidence in {"provisional", "high"}
            )
            return confirmed_full_redline or quick_redline or clean_reputation

        ratio = self.config.policy.minimum_rebuild_full_completion_ratio
        for region, items in grouped.items():
            evidence = sum(1 for item in items if has_current_evidence(item))
            required = math.ceil(len(items) * ratio)
            if evidence < required:
                raise RuntimeError(
                    "rebuild decision evidence for region "
                    f"{region} {evidence}/{len(items)} is below publication guard"
                )

    def _build_current(
        self,
        version: str,
        generated_at: str,
        requested_mode: str,
        effective_mode: str,
        source_digest: str,
        nodes: list[Node],
        assessments: list[NodeAssessment],
        regions: dict[str, dict[str, object]],
        previous: dict[str, Any],
    ) -> dict[str, Any]:
        node_payload = {
            item.node.key: {
                "name": item.node.name,
                "region": item.node.region,
                "score": item.evaluation.score,
                "confidence": item.evaluation.confidence,
                "decision": item.evaluation.decision,
                "reasons": item.evaluation.reasons,
                "consecutive_unavailable_runs": item.consecutive_unavailable_runs,
            }
            for item in assessments
        }
        prior_nodes = previous.get("nodes", {})
        for region, payload in regions.items():
            for key in payload.get("stable_slots", {}).values():
                if key in node_payload:
                    continue
                prior = prior_nodes.get(key, {})
                node_payload[key] = {
                    "name": str(prior.get("name") or "unknown"),
                    "region": region,
                    "score": float(prior.get("last_score") or 0),
                    "confidence": "unknown",
                    "decision": "absent",
                    "reasons": ["missing-from-inventory"],
                }
        return {
            "schema_version": 1,
            "version": version,
            "generated_at": generated_at,
            "requested_mode": requested_mode,
            "mode": effective_mode,
            "source": {"digest": source_digest, "node_count": len(nodes)},
            "region_order": self.config.region_order,
            "regions": regions,
            "nodes": node_payload,
        }

    def _build_state(
        self,
        current: dict[str, Any],
        previous: dict[str, Any],
        assessments: list[NodeAssessment],
        regions: dict[str, dict[str, object]],
        changes: list[dict[str, str]],
    ) -> dict[str, Any]:
        prior_nodes = previous.get("nodes", {})
        assigned_keys = {
            str(key)
            for payload in regions.values()
            for key in payload.get("stable_slots", {}).values()
            if key
        }
        node_state: dict[str, Any] = {}
        for item in assessments:
            prior = prior_nodes.get(item.node.key, {})
            fresh_cacheworthy = bool(
                item.fresh_full_attempt
                and item.fresh_full_attempt.completed
                and (
                    item.fresh_full_usable
                    or full_has_confirmed_redline(
                        item.fresh_full_attempt, self.config.policy
                    )
                )
            )
            prior_full = _full_from_dict(prior.get("last_full"))
            prior_full_exit_ip = str(
                prior.get("last_full_exit_ip")
                or (prior_full.audited_exit_ip if prior_full else "")
                or prior.get("last_exit_ip")
                or ""
            )
            trusted_full = item.fresh_full_attempt if fresh_cacheworthy else prior_full
            node_state[item.node.key] = {
                "name": item.node.name,
                "region": item.node.region,
                "last_exit_ip": item.quick.exit_ip or prior.get("last_exit_ip", ""),
                "last_quick_checked_at": item.quick.checked_at,
                "last_full_checked_at": (
                    trusted_full.checked_at
                    if trusted_full and trusted_full.completed
                    else prior.get("last_full_checked_at", "")
                ),
                "last_full_exit_ip": (
                    trusted_full.audited_exit_ip
                    if trusted_full
                    and trusted_full.completed
                    and trusted_full.audited_exit_ip
                    else prior_full_exit_ip
                ),
                "last_full": (
                    trusted_full.to_dict()
                    if trusted_full and trusted_full.completed
                    else prior.get("last_full")
                ),
                "last_full_attempt_at": (
                    item.fresh_full_attempt.checked_at
                    if item.fresh_full_attempt
                    else prior.get("last_full_attempt_at", "")
                ),
                "last_full_attempt_error": (
                    item.fresh_full_attempt.error
                    if item.fresh_full_attempt
                    else prior.get("last_full_attempt_error", "")
                ),
                "consecutive_full_passes": item.consecutive_full_passes,
                "consecutive_unavailable_runs": item.consecutive_unavailable_runs,
                "last_score": (
                    prior.get("last_score", item.evaluation.score)
                    if item.node.key in assigned_keys
                    and item.evaluation.decision == "unavailable"
                    else item.evaluation.score
                ),
                "last_decision": item.evaluation.decision,
                "current_status": item.evaluation.decision,
            }
        for key in assigned_keys - set(node_state):
            prior = prior_nodes.get(key, {})
            node_state[key] = {
                **prior,
                "name": str(prior.get("name") or "unknown"),
                "current_status": "absent",
            }
        # Keep confirmed danger history even for non-stable nodes that
        # temporarily disappear from the inventory. If the same identity
        # returns, an ambiguous audit must not make it eligible again; a
        # trustworthy clean result is required to clear the latch.
        for key, prior in prior_nodes.items():
            if key in node_state:
                continue
            prior_full = _full_from_dict(prior.get("last_full"))
            if not full_has_confirmed_redline(prior_full, self.config.policy):
                continue
            node_state[key] = {
                **prior,
                "name": str(prior.get("name") or "unknown"),
                "current_status": "absent",
            }
        prior_changed = previous.get("slot_changed_at", {})
        slot_changed_at = {
            region: {
                str(slot): str(prior_changed.get(region, {}).get(str(slot), ""))
                for slot in payload.get("stable_slots", {})
                if prior_changed.get(region, {}).get(str(slot))
            }
            for region, payload in regions.items()
        }
        if current["mode"] == "rebuild":
            slot_changed_at = {
                region: {
                    str(slot): current["generated_at"]
                    for slot in payload.get("stable_slots", {})
                }
                for region, payload in regions.items()
            }
        for change in changes:
            slot_changed_at.setdefault(change["region"], {})[change["slot"]] = current[
                "generated_at"
            ]
        return {
            "schema_version": 1,
            "version": current["version"],
            "updated_at": current["generated_at"],
            "source": current["source"],
            "stable_slots": {
                region: payload["stable_slots"] for region, payload in regions.items()
            },
            "slot_changed_at": slot_changed_at,
            "nodes": node_state,
        }
