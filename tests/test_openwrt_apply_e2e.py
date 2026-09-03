import json
import os
import shutil
import signal
import socket
import subprocess
import textwrap
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
APPLY_SCRIPT = ROOT / "integrations" / "openwrt" / "apply-ranking.sh"


def _shell_path(path: Path) -> str:
    resolved = path.resolve()
    if os.name != "nt":
        return resolved.as_posix()
    drive = resolved.drive.rstrip(":").lower()
    relative = resolved.relative_to(resolved.anchor).as_posix()
    return f"/{drive}/{relative}"


def _node_path(path: Path) -> str:
    return path.resolve().as_posix()


def _write(path: Path, content: str, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content).lstrip(), encoding="utf-8", newline="\n")
    if executable:
        path.chmod(0o755)


def _tool(name: str) -> str | None:
    value = shutil.which(name)
    return str(Path(value).resolve()) if value else None


@pytest.mark.parametrize(
    ("mode", "expected_success"),
    [("listening", True), ("zero", True), ("missing", False)],
)
def test_apply_ranking_validates_listeners_and_rolls_back(tmp_path, mode, expected_success):
    bash = _tool("bash")
    node = _tool("node")
    if not bash or not node:
        pytest.skip("bash and node are required for the OpenWrt apply E2E")

    work = tmp_path / "work"
    cache = work / "cache" / "node-health"
    export = tmp_path / "exports"
    work.mkdir(parents=True)
    cache.mkdir(parents=True)
    export.mkdir()
    (export / "sentinel.txt").write_text("old-export\n", encoding="utf-8")

    source = tmp_path / "inventory.yaml"
    current = tmp_path / "current.json"
    config = work / "config.yaml"
    converter = tmp_path / "convert.mjs"
    stable_converter = tmp_path / "stable.js"
    yaml_module = tmp_path / "mock-yaml.cjs"
    mihomo = tmp_path / "mihomo"
    service = tmp_path / "local-socks"
    server = tmp_path / "listener.mjs"
    pid_file = tmp_path / "listener.pid"
    env_file = tmp_path / "node-health.env"
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        listener_port = reservation.getsockname()[1]

    source.write_text("proxies: []\n", encoding="utf-8")
    current.write_text(
        json.dumps({"schema_version": 2, "version": "e2e-v1", "regions": {}}),
        encoding="utf-8",
    )
    config.write_text("old-config\n", encoding="utf-8")
    stable_converter.write_text("module.exports = {};\n", encoding="utf-8")

    _write(
        yaml_module,
        r"""
        exports.load = function load(source) {
          if (/listeners:\s*\[\s*\]/.test(source)) return { listeners: [] };
          const listeners = [];
          for (const match of source.matchAll(/^\s+port:\s*(\d+)\s*$/gm)) {
            listeners.push({ port: Number(match[1]) });
          }
          return { listeners };
        };
        """,
    )
    _write(
        converter,
        r"""
        import fs from 'node:fs';
        import path from 'node:path';

        const [, , outputPath, , , exportDirectory] = process.argv.slice(2);
        const zero = process.env.MOCK_APPLY_MODE === 'zero';
        const port = Number(process.env.MOCK_LISTENER_PORT);
        const yaml = zero
          ? 'listeners: []\nproxies: []\n'
          : `listeners:\n  - name: listener-one\n    type: mixed\n    port: ${port}\nproxies: []\n`;
        fs.writeFileSync(outputPath, yaml);
        fs.mkdirSync(exportDirectory, { recursive: true });
        fs.writeFileSync(
          path.join(exportDirectory, 'united-states.txt'),
          zero ? '' : `socks5://192.0.2.4:${port}{test}\n`,
        );
        fs.writeFileSync(
          path.join(exportDirectory, 'all.txt'),
          zero ? '' : `socks5://192.0.2.4:${port}{test}\n`,
        );
        fs.writeFileSync(
          path.join(exportDirectory, 'all-plain.txt'),
          zero ? '' : `socks5://192.0.2.4:${port}\n`,
        );
        fs.writeFileSync(path.join(exportDirectory, 'README.txt'), 'ranking e2e-v1\n');
        """,
    )
    _write(
        server,
        """
        import fs from 'node:fs';
        import net from 'node:net';

        const server = net.createServer((socket) => socket.end());
        server.listen(Number(process.argv[2]), '127.0.0.1', () => {
          fs.writeFileSync(process.argv[3], String(process.pid));
        });
        """,
    )
    _write(mihomo, "#!/bin/sh\nexit 0\n", executable=True)
    _write(
        service,
        """
        #!/bin/sh
        case "$1" in
          restart)
            if [ -s "$MOCK_PID_FILE" ]; then
              kill "$(cat "$MOCK_PID_FILE")" 2>/dev/null || true
              rm -f "$MOCK_PID_FILE"
            fi
            if [ "${MOCK_APPLY_MODE:-}" = 'listening' ]; then
              "$MOCK_NODE_BIN" "$MOCK_SERVER" "$MOCK_LISTENER_PORT" "$MOCK_PID_FILE" \
                >"$MOCK_SERVER_LOG" 2>&1 &
            fi
            exit 0
            ;;
          status)
            if [ "${MOCK_APPLY_MODE:-}" != 'listening' ]; then
              exit 0
            fi
            [ -s "$MOCK_PID_FILE" ]
            ;;
          stop)
            if [ -s "$MOCK_PID_FILE" ]; then
              kill "$(cat "$MOCK_PID_FILE")" 2>/dev/null || true
            fi
            ;;
          *) exit 2 ;;
        esac
        """,
        executable=True,
    )

    if os.name == "nt":
        ids = subprocess.run(
            [bash, "-lc", "printf '%s:%s' \"$(id -u)\" \"$(id -g)\""],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    else:
        ids = f"{os.getuid()}:{os.getgid()}"

    env_file.write_text(
        "\n".join(
            [
                f"WORK_DIR='{_shell_path(work)}'",
                f"CACHE_DIR='{_shell_path(cache)}'",
                f"CONVERT_RUNNER='{_shell_path(converter)}'",
                f"STABLE_CONVERTER='{_shell_path(stable_converter)}'",
                f"NODE_BIN='{_shell_path(Path(node))}'",
                "NODE_PATH=''",
                f"JS_YAML_PATH='{_node_path(yaml_module)}'",
                f"MIHOMO_BIN='{_shell_path(mihomo)}'",
                f"SERVICE_SCRIPT='{_shell_path(service)}'",
                f"CONFIG_PATH='{_shell_path(config)}'",
                "START_PORT='62000'",
                f"CONFIG_OWNER='{ids}'",
                "CONFIG_MODE='0600'",
                f"EXPORT_DIR='{_shell_path(export)}'",
                "ADVERTISE_HOST='192.0.2.4'",
                "READINESS_ATTEMPTS='3'",
                # The mock listener is spawned in the background. Give it a
                # deterministic scheduling window before readiness polling.
                "READINESS_DELAY_SECONDS='0.05'",
                "LISTENER_CONNECT_TIMEOUT_MS='250'",
                "LISTENER_CHECK_CONCURRENCY='4'",
                "",
            ]
        ),
        encoding="utf-8",
        newline="\n",
    )

    environment = os.environ.copy()
    environment.update(
        {
            "NODE_HEALTH_ENV_FILE": _shell_path(env_file),
            "MOCK_APPLY_MODE": mode,
            "MOCK_NODE_BIN": _shell_path(Path(node)),
            "MOCK_SERVER": _shell_path(server),
            "MOCK_PID_FILE": _shell_path(pid_file),
            "MOCK_SERVER_LOG": _shell_path(tmp_path / "listener.log"),
            "MOCK_LISTENER_PORT": str(listener_port),
        }
    )
    try:
        result = subprocess.run(
            [
                bash,
                _shell_path(APPLY_SCRIPT),
                _shell_path(source),
                _shell_path(current),
                "e2e-v1",
            ],
            env=environment,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    finally:
        subprocess.run(
            [bash, _shell_path(service), "stop"],
            env=environment,
            capture_output=True,
            timeout=5,
            check=False,
        )
        if pid_file.exists():
            try:
                os.kill(int(pid_file.read_text(encoding="utf-8")), signal.SIGTERM)
            except (OSError, ValueError):
                pass

    assert (result.returncode == 0) is expected_success, result.stderr
    if expected_success:
        assert config.read_text(encoding="utf-8").startswith("listeners:")
        assert (export / "README.txt").read_text(encoding="utf-8") == "ranking e2e-v1\n"
        expected_all = "" if mode == "zero" else (
            f"socks5://192.0.2.4:{listener_port}{{test}}\n"
        )
        assert (export / "all.txt").read_text(encoding="utf-8") == expected_all
        expected_all_plain = "" if mode == "zero" else (
            f"socks5://192.0.2.4:{listener_port}\n"
        )
        assert (export / "all-plain.txt").read_text(encoding="utf-8") == expected_all_plain
    else:
        assert config.read_text(encoding="utf-8") == "old-config\n"
        assert (export / "sentinel.txt").read_text(encoding="utf-8") == "old-export\n"
        assert "previous config restored and ready" in result.stderr
