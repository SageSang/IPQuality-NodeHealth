import copy
import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from node_health.config import AppConfig, InventoryConfig
from node_health.inventory import parse_clash_inventory
from node_health.port_mapping import MapError, build_port_mapping, digest, mapping_digest, port_plan

ROOT = Path(__file__).resolve().parents[1]
CONVERTER = ROOT / "integrations/local-socks/convert-any-proxy-to-local-socks-stable.js"


def proxy(name, server="a.example", **extra):
    return {"name": name, "type": "trojan", "server": server, "port": 443, "password": "synthetic", **extra}


def mapping_case(proxies=None, slots=None, ranked=None):
    config = AppConfig(InventoryConfig(url="http://inventory.invalid"))
    config.local_socks_namespace = "test-production"
    config.local_socks_server_instance_id = "test-server"
    proxies = proxies or [proxy("Hong Kong A")]
    nodes = parse_clash_inventory(yaml.safe_dump({"proxies": proxies}), config.region_patterns)
    keys = [node.key for node in nodes]
    current = {"version": "ranking-test", "generated_at": datetime.now(timezone.utc).isoformat(),
               "regions": {"hong-kong": {"stable_slots": slots if slots is not None else {"1": keys[0]},
                                         "ranked": ranked if ranked is not None else keys[1:], "rejected": {}}}}
    return config, nodes, current, build_port_mapping(current, nodes, config)


def render(map_, proxies, *, profile=None, previous=None, mutate_options=None):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node required")
    profile = profile or {"ipv6": False, "allow-lan": True, "mode": "global",
                          "dns": {"enable": False}, "listeners": [], "proxies": []}
    script = """
      const fs=require('fs'), c=require(process.argv[1]);
      const data=JSON.parse(fs.readFileSync(0,'utf8'));
      const options={namespace:data.map.namespace,serverInstanceId:data.map.server_instance_id,
        portPlanVersion:data.map.port_plan_version,runtimeProfile:data.profile,
        runtimeProfileHash:c.runtimeProfileHash(data.profile),previousConfig:data.previous,...data.options};
      try {console.log(JSON.stringify({ok:true,...c.convertConfig({proxies:data.proxies},data.map,options)}));}
      catch(e){console.log(JSON.stringify({ok:false,error:e.message}));}
    """
    result = subprocess.run([node, "-e", script, str(CONVERTER)], input=json.dumps({"map": map_, "proxies": proxies,
        "profile": profile, "previous": previous, "options": mutate_options or {}}), text=True, capture_output=True, check=True)
    return json.loads(result.stdout)


def test_port_map_and_renderer_preserve_holes():
    proxies = [proxy("Hong Kong B", "b.example"), proxy("Hong Kong C", "c.example")]
    config, nodes, current, _ = mapping_case(proxies)
    current["regions"]["hong-kong"] = {"stable_slots": {"2": nodes[0].key, "3": nodes[1].key}, "ranked": [], "rejected": {}}
    map_ = build_port_mapping(current, nodes, config)
    output = render(map_, list(reversed(proxies)))
    assert output["ok"], output
    assert [listener["port"] for listener in output["config"]["listeners"]] == [62001, 62002]
    assert output["config"]["dns"] == {"enable": False}
    assert output["config"]["ipv6"] is False


def test_dynamic_nodes_do_not_fill_empty_slots_and_aliases_are_complete():
    proxies = [proxy("Hong Kong A"), proxy("Hong Kong alias"), proxy("Hong Kong B", "b.example")]
    _, _, _, map_ = mapping_case(proxies)
    output = render(map_, proxies)
    assert output["ok"], output
    assert [listener["port"] for listener in output["config"]["listeners"]] == [62000, 62003, 62004]
    assert len(output["manifest"]) == 3
    assert len(output["config"]["proxies"]) == 2
    assert len({entry["entry_id"] for entry in output["manifest"]}) == 3


def test_duplicate_occurrences_and_inventory_fingerprint_are_cross_language():
    proxies = [proxy("Hong Kong repeated"), proxy("Hong Kong repeated"), proxy("Hong Kong B", "b.example")]
    _, _, _, map_ = mapping_case(proxies)
    assert render(map_, list(reversed(proxies)))["ok"]
    assert not render(map_, proxies[:-1])["ok"]
    assert not render(map_, proxies + [proxy("Hong Kong new", "new.example")])["ok"]


@pytest.mark.parametrize("field,value", [("purpose", "audit-proposal"), ("schema_version", 2),
    ("namespace", "wrong"), ("server_instance_id", "wrong")])
def test_renderer_rejects_wrong_source_and_contract(field, value):
    proxies = [proxy("Hong Kong A")]
    _, _, _, map_ = mapping_case(proxies)
    approvals = {"namespace": map_["namespace"], "serverInstanceId": map_["server_instance_id"]}
    map_[field] = value
    map_["mapping_version"] = mapping_digest(map_)
    assert not render(map_, proxies, mutate_options=approvals)["ok"]


def test_renderer_rejects_wrong_bindings_even_with_valid_hash():
    proxies = [proxy("Hong Kong A"), proxy("Hong Kong B", "b.example")]
    _, _, _, map_ = mapping_case(proxies)
    bound = [entry for entry in map_["bindings"] if entry["entry_id"]]
    bound[1]["port"] = bound[0]["port"]
    map_["mapping_version"] = mapping_digest(map_)
    assert not render(map_, proxies)["ok"]


def test_labels_update_manifest_without_changing_runtime_hash():
    proxies = [proxy("Hong Kong A")]
    _, _, _, map_a = mapping_case(proxies)
    output_a = render(map_a, proxies)
    renamed = [{**proxies[0], "name": "Hong Kong renamed"}]
    _, _, _, map_b = mapping_case(renamed)
    output_b = render(map_b, renamed, previous=output_a["config"])
    assert output_a["ok"] and output_b["ok"]
    assert output_a["runtime_config_hash"] == output_b["runtime_config_hash"]
    assert output_a["manifest_hash"] != output_b["manifest_hash"]


def test_hopping_port_reuses_valid_old_value_but_range_change_changes_runtime():
    proxies = [proxy("Hong Kong A", type="hysteria2", ports="440-450", port=443)]
    _, _, _, map_a = mapping_case(proxies)
    output_a = render(map_a, proxies)
    rotated = [{**proxies[0], "port": 449}]
    output_b = render(map_a, rotated, previous=output_a["config"])
    assert output_a["ok"] and output_b["ok"]
    assert output_a["runtime_config_hash"] == output_b["runtime_config_hash"]
    changed = [{**proxies[0], "ports": "500-510", "port": 505}]
    _, _, _, map_c = mapping_case(changed)
    output_c = render(map_c, changed, previous=output_a["config"])
    assert output_c["ok"]
    assert output_a["runtime_config_hash"] != output_c["runtime_config_hash"]


def test_missing_instance_identity_and_capacity_fail_explicitly():
    config, nodes, current, map_ = mapping_case()
    config.local_socks_server_instance_id = ""
    with pytest.raises(MapError, match="identity_required"):
        build_port_mapping(current, nodes, config)
    config.local_socks_server_instance_id = "test-server"
    proxies = [proxy(f"Hong Kong {i}", f"{i}.example") for i in range(198)]
    nodes = parse_clash_inventory(yaml.safe_dump({"proxies": proxies}), config.region_patterns)
    current["regions"]["hong-kong"] = {"stable_slots": {}, "ranked": [node.key for node in nodes]}
    with pytest.raises(MapError, match="capacity"):
        build_port_mapping(current, nodes, config)


def test_unresolvable_stable_identity_is_not_replaced_by_consumer():
    config, nodes, current, _ = mapping_case()
    current["regions"]["hong-kong"]["stable_slots"]["2"] = "a" * 64
    with pytest.raises(MapError, match="unresolvable"):
        build_port_mapping(current, nodes, config)


def test_standalone_runner_exports_real_newlines_and_nonsecret_manifest(tmp_path):
    proxies=[proxy("Hong Kong north\nA")]
    _,_,_,map_=mapping_case(proxies)
    profile={"mode":"rule","dns":{"enable":False},"proxies":[],"listeners":[]}
    source=tmp_path/"inventory.json"; source.write_text(json.dumps({"proxies":proxies}))
    mapping=tmp_path/"mapping.json"; mapping.write_text(json.dumps(map_))
    profile_path=tmp_path/"profile.json"; profile_path.write_text(json.dumps(profile))
    yaml_module=tmp_path/"yaml.cjs"
    yaml_module.write_text("exports.load=JSON.parse;exports.dump=x=>JSON.stringify(x);\n")
    expected_hash=subprocess.run(["node","-e","const c=require(process.argv[1]); console.log(c.runtimeProfileHash(JSON.parse(process.argv[2])));",
                                  str(CONVERTER),json.dumps(profile)],check=True,text=True,capture_output=True).stdout.strip()
    output=tmp_path/"candidate.json"; exports=tmp_path/"exports-stage"
    env=dict(os.environ,NODE_PATH="",JS_YAML_PATH=str(yaml_module),RUNTIME_PROFILE_PATH=str(profile_path),
             APPROVED_RUNTIME_PROFILE_HASH=expected_hash,APPROVED_NAMESPACE=map_["namespace"],
             APPROVED_SERVER_INSTANCE_ID=map_["server_instance_id"],APPROVED_PORT_PLAN_VERSION=map_["port_plan_version"],
             EXPORT_DIR=str(tmp_path/"final-exports"))
    result=subprocess.run(["node",str(ROOT/"integrations/openwrt/convert-ranking.mjs"),str(source),str(mapping),str(output),"62000",str(CONVERTER),str(exports),"192.0.2.4"],
                          env=env,text=True,capture_output=True)
    assert result.returncode==0,result.stderr
    assert (exports/"all.txt").read_text()=="socks5://192.0.2.4:62000{Hong Kong north A}\n"
    manifest=json.loads(Path(str(output)+".manifest.json").read_text())
    assert manifest["entries"][0]["name"]=="Hong Kong north\nA"
    assert "config" not in manifest
    assert "password" not in json.dumps(manifest)
