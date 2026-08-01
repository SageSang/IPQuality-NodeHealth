import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from node_health.audit import download_subscription, validate_subscription_url
from node_health.config import AppConfig, AuditConfig, InventoryConfig


def config(tmp_path, *, allowed=None):
    return AppConfig(
        inventory=InventoryConfig("http://192.0.2.2:3001/inventory"),
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        audit=AuditConfig(allowed_origins=allowed or []),
    )


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "gopher://192.0.2.2:3001/data",
        "http://user:password@192.0.2.2:3001/data",
        "http://192.0.2.2:3001/data#fragment",
        "http://192.0.2.4:3001/data",
    ],
)
def test_audit_url_rejects_unsafe_or_unapproved_sources(tmp_path, url):
    with pytest.raises(ValueError):
        validate_subscription_url(url, config(tmp_path))


def test_audit_url_defaults_to_inventory_origin(tmp_path):
    url, origin = validate_subscription_url(
        "http://192.0.2.2:3001/download/collection/provider?token=secret",
        config(tmp_path),
    )
    assert "token=secret" in url
    assert origin == "http://192.0.2.2:3001"


class DownloadHandler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):  # noqa: N802
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/payload")
            self.end_headers()
            return
        payload = b"x" * 64
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def test_audit_download_refuses_redirect_and_size_overflow():
    server = ThreadingHTTPServer(("127.0.0.1", 0), DownloadHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        with pytest.raises(RuntimeError, match="redirect was refused"):
            download_subscription(base + "/redirect", 2, 1024)
        with pytest.raises(ValueError, match="max_subscription_bytes"):
            download_subscription(base + "/payload", 2, 32)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)

