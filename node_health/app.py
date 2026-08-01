from __future__ import annotations

import json
import hmac
import logging
import os
import re
import signal
import threading
from datetime import datetime
from datetime import timedelta
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit
from zoneinfo import ZoneInfo

from .config import AppConfig, load_config
from .service import NodeHealthService, ScanStartError

SOFTWARE_VERSION = "0.2.0"
MAX_API_BODY_BYTES = 16 * 1024
LOGGER = logging.getLogger("node_health")


def public_ranking_document(current: dict[str, Any]) -> dict[str, Any]:
    regions: dict[str, dict[str, Any]] = {}
    for region, payload in current.get("regions", {}).items():
        if not isinstance(payload, dict):
            continue
        regions[str(region)] = {
            "stable_slots": payload.get("stable_slots", {}),
            "ranked": payload.get("ranked", []),
            "rejected": payload.get("rejected", {}),
        }
    return {
        key: current[key]
        for key in (
            "schema_version",
            "version",
            "generated_at",
            "requested_mode",
            "mode",
            "source",
            "region_order",
        )
        if key in current
    } | {"regions": regions}


class DailyScheduler:
    def __init__(self, service: NodeHealthService, config: AppConfig):
        self.service = service
        self.config = config
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._loop, name="node-health-scheduler", daemon=True)
        self.last_date = self._last_published_date()
        self.pending_date = ""
        self.attempt_date = ""
        self.attempts = 0
        self.retry_after: datetime | None = None

    def _last_published_date(self) -> str:
        state = self.service.store.load_state()
        value = state.get("updated_at")
        if not value:
            return ""
        try:
            timestamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            return timestamp.astimezone(ZoneInfo(self.config.schedule.timezone)).date().isoformat()
        except (ValueError, KeyError):
            return ""

    def start(self) -> None:
        if self.config.schedule.enabled:
            self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread.is_alive():
            self.thread.join(timeout=5)

    def _trigger_due_scan(self, today: str, now: datetime) -> None:
        try:
            accepted = self.service.trigger(self.config.schedule.default_mode)
        except ScanStartError as error:
            self.attempts += 1
            if self.attempts < 3:
                self.retry_after = now + timedelta(hours=1)
                LOGGER.error(
                    "daily scan worker failed to start for %s; retrying in one hour: %s",
                    today,
                    error,
                )
            else:
                self.last_date = today
                self.retry_after = None
                LOGGER.error(
                    "daily scan worker failed to start after 3 attempts for %s: %s",
                    today,
                    error,
                )
            return
        if accepted:
            self.pending_date = today
            self.attempts += 1

    def _loop(self) -> None:
        timezone = ZoneInfo(self.config.schedule.timezone)
        try:
            hour, minute = (int(value) for value in self.config.schedule.time.split(":", 1))
        except (TypeError, ValueError) as error:
            LOGGER.error("invalid schedule.time: %s", error)
            return
        if not (0 <= hour <= 23 and 0 <= minute <= 59):
            LOGGER.error("schedule.time must be HH:MM")
            return
        while not self.stop_event.wait(20):
            now = datetime.now(timezone)
            today = now.date().isoformat()
            if self.attempt_date != today:
                self.attempt_date = today
                self.attempts = 0
                self.retry_after = None

            # A manual run after today's due time satisfies the daily job. Do
            # not immediately launch a duplicate maintenance scan.
            observed_success = self.service.status().get("last_success")
            if observed_success:
                try:
                    observed_date = datetime.fromisoformat(
                        str(observed_success).replace("Z", "+00:00")
                    ).astimezone(timezone).date().isoformat()
                    if observed_date == today:
                        self.last_date = today
                except ValueError:
                    pass

            if self.pending_date and not self.service.status()["running"]:
                last_success = self.service.status().get("last_success")
                success_date = ""
                if last_success:
                    try:
                        success_date = datetime.fromisoformat(
                            str(last_success).replace("Z", "+00:00")
                        ).astimezone(timezone).date().isoformat()
                    except ValueError:
                        pass
                if success_date == self.pending_date:
                    self.last_date = self.pending_date
                    self.retry_after = None
                elif self.attempts < 3:
                    self.retry_after = now + timedelta(hours=1)
                else:
                    LOGGER.error("daily scan failed after 3 attempts for %s", self.pending_date)
                    self.last_date = self.pending_date
                self.pending_date = ""

            due = (now.hour, now.minute) >= (hour, minute)
            retry_due = self.retry_after is None or now >= self.retry_after
            if due and retry_due and not self.pending_date and self.last_date != today:
                self._trigger_due_scan(today, now)


class ApiServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], service: NodeHealthService, config: AppConfig):
        self.service = service
        self.config = config
        super().__init__(address, ApiHandler)


class ApiHandler(BaseHTTPRequestHandler):
    server: ApiServer

    def log_message(self, format: str, *args: Any) -> None:
        if urlsplit(self.path).path == "/healthz":
            return
        LOGGER.info("http %s - %s", self.client_address[0], format % args)

    def _json(self, status: int, value: Any) -> None:
        body = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _file(self, path: Path, content_type: str) -> None:
        try:
            body = path.read_bytes()
        except FileNotFoundError:
            self._json(HTTPStatus.NOT_FOUND, {"error": "report not found"})
            return
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "private, no-store")
        self.send_header("Content-Disposition", f'inline; filename="{path.name}"')
        self.end_headers()
        self.wfile.write(body)

    def _request_json(self) -> dict[str, Any]:
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise TypeError("Content-Type must be application/json")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as error:
            raise ValueError("invalid Content-Length") from error
        if length < 1:
            raise ValueError("JSON request body is required")
        if length > MAX_API_BODY_BYTES:
            raise OverflowError("request body is too large")
        body = self.rfile.read(length)
        try:
            value = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("request body is not valid JSON") from error
        if not isinstance(value, dict):
            raise ValueError("request body must be a JSON object")
        return value

    def _authorized(self) -> bool:
        expected = self.server.config.http.api_token
        provided = self.headers.get("Authorization", "")
        return not expected or hmac.compare_digest(provided, f"Bearer {expected}")

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        path = urlsplit(self.path).path
        if path == "/healthz":
            self._json(HTTPStatus.OK, self.server.service.status())
            return
        if path == "/version":
            current = self.server.service.store.load_current()
            self._json(
                HTTPStatus.OK,
                {"service_version": SOFTWARE_VERSION, "ranking_version": current.get("version")},
            )
            return
        if path == "/current.json":
            current = self.server.service.store.load_current()
            if not current:
                self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "no published ranking"})
            else:
                self._json(HTTPStatus.OK, public_ranking_document(current))
            return
        match = re.fullmatch(
            r"/api(?:/v1)?/audits/([^/]+)(?:/report\.(json|md))?",
            path,
        )
        if match:
            if not self._authorized():
                self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
                return
            audit_id, extension = match.groups()
            try:
                status = self.server.service.store.load_audit_status(audit_id)
            except ValueError:
                self._json(HTTPStatus.NOT_FOUND, {"error": "audit not found"})
                return
            if not status:
                self._json(HTTPStatus.NOT_FOUND, {"error": "audit not found"})
                return
            if extension:
                report_path = self.server.service.store.audit_report_path(audit_id, extension)
                content_type = (
                    "application/json; charset=utf-8"
                    if extension == "json"
                    else "text/markdown; charset=utf-8"
                )
                self._file(report_path, content_type)
                return
            status = dict(status)
            status["status_url"] = f"/api/v1/audits/{audit_id}"
            if status.get("reports"):
                status["report_urls"] = {
                    "json": f"/api/v1/audits/{audit_id}/report.json",
                    "markdown": f"/api/v1/audits/{audit_id}/report.md",
                }
            self._json(HTTPStatus.OK, status)
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        parsed = urlsplit(self.path)
        if parsed.path in {"/api/audits", "/api/v1/audits"}:
            if not self._authorized():
                self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
                return
            try:
                value = self._request_json()
                subscription_url = value.get("subscription_url", value.get("url", ""))
                audit_id = self.server.service.trigger_subscription_audit(
                    str(subscription_url or ""),
                    str(value.get("name") or ""),
                )
            except TypeError as error:
                self._json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": str(error)})
                return
            except OverflowError as error:
                self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": str(error)})
                return
            except ValueError as error:
                self._json(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            except ScanStartError as error:
                self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": str(error)})
                return
            if audit_id is None:
                self._json(
                    HTTPStatus.CONFLICT,
                    {
                        "error": "another scan or audit is already running",
                        "running_mode": self.server.service.status().get("running_mode"),
                        "active_audit_id": self.server.service.status().get("active_audit_id"),
                    },
                )
                return
            self._json(
                HTTPStatus.ACCEPTED,
                {
                    "accepted": True,
                    "id": audit_id,
                    "status": "queued",
                    "status_url": f"/api/v1/audits/{audit_id}",
                },
            )
            return
        if parsed.path not in {"/api/run", "/api/v1/run"}:
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        if not self._authorized():
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return
        mode = parse_qs(parsed.query).get("mode", ["maintenance"])[0]
        try:
            accepted = self.server.service.trigger(mode)
        except ValueError as error:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(error)})
            return
        except ScanStartError as error:
            self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": str(error)})
            return
        if not accepted:
            self._json(HTTPStatus.CONFLICT, {"error": "scan already running"})
            return
        self._json(HTTPStatus.ACCEPTED, {"accepted": True, "requested_mode": mode})


def create_server(config: AppConfig, service: NodeHealthService | None = None) -> ApiServer:
    service = service or NodeHealthService(config)
    return ApiServer((config.http.host, config.http.port), service, config)


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    config_path = Path(os.environ.get("NODE_HEALTH_CONFIG", "/app/config/config.yaml"))
    config = load_config(config_path)
    service = NodeHealthService(config)
    scheduler = DailyScheduler(service, config)
    server = create_server(config, service)

    def stop(_signum: int, _frame: object) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    scheduler.start()
    LOGGER.info("node-health listening on %s:%s", config.http.host, config.http.port)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        scheduler.stop()
        server.server_close()


if __name__ == "__main__":
    main()
