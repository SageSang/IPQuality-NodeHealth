import json
import os
import shutil
import subprocess
from pathlib import Path

import yaml
import pytest


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


@pytest.mark.parametrize("fail4,fail6,check6,expected", [(0,0,1,0),(1,0,1,1),(0,1,1,1),(1,1,1,1),(0,1,0,0)])
def test_ipquality_exit_code_reflects_enabled_checks(fail4,fail6,check6,expected):
    if not shutil.which("bash"):
        pytest.skip("bash required")
    source=(ROOT / "ip.sh").read_text()
    tail=source[source.rindex('\nresult_code=0\n'):]
    setup='''check_IP(){ printf '%s\\n' "$2"; if [[ "$2" == 4 ]];then return "$FAIL4";else return "$FAIL6";fi; }
IPV4work=1; IPV6work=1; IPV4check=1
IPV4=8.8.8.8; IPV6=2606:4700::1111
'''
    result=subprocess.run(["bash","-c",setup+tail],env=dict(os.environ,FAIL4=str(fail4),FAIL6=str(fail6),IPV6check=str(check6)),capture_output=True,text=True)
    assert result.returncode==expected
    assert result.stdout.splitlines()==(["4","6"] if check6 else ["4"])


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
