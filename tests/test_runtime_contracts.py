import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def test_compose_has_no_probe_volume_and_rotates_container_logs():
    compose = yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))
    services = compose["services"]

    assert "/probe" not in json.dumps(compose, ensure_ascii=False)
    for name in ("mihomo-probe", "node-health"):
        logging = services[name]["logging"]
        assert logging["driver"] == "json-file"
        assert str(logging["options"]["max-size"]) == "10m"
        assert str(logging["options"]["max-file"]) == "3"


def test_ipquality_script_has_explicit_success_exit_after_ip_checks():
    lines = [
        line.strip()
        for line in (ROOT / "ip.sh").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]

    assert lines[-1] == "exit 0"
    ipv4_check = next(
        index
        for index, line in enumerate(lines)
        if line.endswith('&&check_IP "$IPV4" 4')
    )
    ipv6_check = next(
        index
        for index, line in enumerate(lines)
        if line.endswith('&&check_IP "$IPV6" 6')
    )
    assert ipv4_check < ipv6_check < len(lines) - 1


def test_deployment_env_example_covers_required_compose_inputs():
    example = (ROOT / "deploy" / ".env.example").read_text(encoding="utf-8")

    for name in (
        "NODE_HEALTH_STORAGE_ROOT",
        "NODE_HEALTH_API_TOKEN",
        "SUB_STORE_INVENTORY_URL",
    ):
        assert f"{name}=" in example
    values = {
        key: value
        for line in example.splitlines()
        if line and not line.startswith("#") and "=" in line
        for key, value in [line.split("=", 1)]
    }
    assert values["NODE_HEALTH_API_TOKEN"] == ""
    assert "target=ClashMeta&noCache=true" in example
