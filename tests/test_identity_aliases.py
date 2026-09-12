import json
import subprocess
import sys
from pathlib import Path

import pytest

from node_health.identity import alias_entry_id, node_identity, node_key
from node_health.inventory import classify_region, inventory_digest, parse_clash_inventory
from node_health.reconcile import reconcile_previous_state, resolve_effective_regions
from node_health.regions import DEFAULT_REGION_PATTERNS


ROOT = Path(__file__).resolve().parents[1]
OPERATOR = ROOT / "integrations/sub-store/health-ranking-operator.js"


def proxy(name, server="one.example", source=""):
    return {"name": name, "type": "ss", "server": server, "port": 443,
            "password": "synthetic-only", "_nh_source_id": source}


def inventory(*proxies):
    return parse_clash_inventory(json.dumps({"proxies": proxies}), DEFAULT_REGION_PATTERNS)


def state(nodes, slots=None):
    return {"schema_version": 2, "nodes": {n.key: {"name": n.name, **node_identity(n)} for n in nodes},
            "stable_slots": slots or {}, "frozen_order": {}}


def js(script, payload):
    process = subprocess.run(["node", "-e", "const op = require(process.argv[1]); " + script, str(OPERATOR)],
                             input=json.dumps(payload), text=True, capture_output=True, check=True)
    return json.loads(process.stdout)


def test_every_input_instance_survives_connection_deduplication_and_reordering():
    a, b = proxy("US A"), proxy("US B")
    first = inventory(a, b, a)
    reordered = inventory(a, a, b)
    assert len(first) == 1
    assert len(first[0].aliases) == 3
    assert len({a.entry_id for a in first[0].aliases}) == 3
    assert sorted(a.duplicate_ordinal for a in first[0].aliases) == [1, 1, 2]
    assert inventory_digest(first) == inventory_digest(reordered)
    assert first[0].representative_alias_id == reordered[0].representative_alias_id


def test_legacy_representative_and_existing_region_survive_added_alias_and_rename():
    old = inventory(proxy("US Z"))[0]
    previous = state([old], {"united-states": {"1": old.key}})
    previous["nodes"][old.key].pop("aliases")
    previous["nodes"][old.key].pop("representative_alias_id")
    current = inventory(proxy("JP A"), proxy("US Z"))
    resolved = resolve_effective_regions(current, previous)
    assert resolved[0].name == "US Z"
    assert resolved[0].region == "united-states"
    assert resolved[0].region_conflict
    renamed = resolve_effective_regions(inventory(proxy("JP new")), state(resolved, previous["stable_slots"]))
    assert renamed[0].region == "united-states"


def test_representative_disappears_and_source_metadata_can_be_temporarily_absent():
    old = inventory(proxy("US A", source="airport"), proxy("US B", source="airport"))[0]
    previous = state([old], {"united-states": {"1": old.key}})
    surviving = resolve_effective_regions(inventory(proxy("US B")), previous)[0]
    assert surviving.name == "US B"
    assert surviving.source_id == ""
    assert surviving.region == "united-states"
    assert surviving.representative_alias_id == surviving.aliases[0].entry_id


def test_new_cross_region_aliases_use_other_and_existing_other_stays_frozen():
    mixed = resolve_effective_regions(inventory(proxy("US A"), proxy("JP B")), {})[0]
    assert mixed.region == "other" and mixed.region_conflict
    old = inventory(proxy("Unknown"))[0]
    previous = state([old])
    previous["frozen_order"] = {"other": [old.key]}
    assert resolve_effective_regions(inventory(proxy("US A")), previous)[0].region == "other"


def test_alias_rotation_matches_connections_one_to_one_without_source_metadata():
    old = inventory(proxy("US A"), proxy("US B"))[0]
    previous = state([old], {"united-states": {"1": old.key}})
    new = inventory(proxy("US B", "new.example"), proxy("US A", "new.example"))
    resolved, migrated, events = reconcile_previous_state(new, previous)
    assert len(events) == 1
    assert migrated["stable_slots"]["united-states"]["1"] == resolved[0].key
    assert resolved[0].name == old.name
    assert len(resolved[0].aliases) == 2


def test_aliases_split_between_two_new_connections_are_not_guessed():
    old = inventory(proxy("US A"), proxy("US B"))[0]
    previous = state([old], {"united-states": {"1": old.key}})
    new = inventory(proxy("US A", "new-a.example"), proxy("US B", "new-b.example"))
    _, migrated, events = reconcile_previous_state(new, previous)
    assert events == []
    assert migrated["stable_slots"] == previous["stable_slots"]


def test_aliases_from_known_different_sources_do_not_inherit_by_name():
    old = inventory(proxy("US A", source="source-one"), proxy("US B", source="source-two"))[0]
    previous = state([old], {"united-states": {"1": old.key}})
    _, migrated, events = reconcile_previous_state(inventory(proxy("US B", "new.example", "third-source")), previous)
    assert events == []
    assert migrated["stable_slots"] == previous["stable_slots"]


@pytest.mark.parametrize("name,expected", [
    ("高雄 01", "taiwan"), ("台南 02", "taiwan"), ("洛杉矶", "united-states"),
    ("東京", "japan"), ("US 01", "united-states"), ("us 01", "other"),
    ("ca", "other"), ("CA", "canada"), ("香港HK", "hong-kong"),
    ("漢US漢", "other"), ("LosAngeles 01", "united-states"),
])
def test_default_region_rules_agree_between_python_and_javascript(name, expected):
    assert classify_region(name, DEFAULT_REGION_PATTERNS) == expected
    result = js("const value=JSON.parse(require('fs').readFileSync(0,'utf8')); process.stdout.write(JSON.stringify(op.identityRegion({},value)));", name)
    assert result == expected


def test_region_generated_data_is_current():
    subprocess.run([sys.executable, str(ROOT / "tools/generate_region_rules.py"), "--check"], check=True)


def test_alias_entry_ids_agree_across_languages_for_duplicate_unicode_entries():
    node = inventory(proxy("US 节点", source="  Ａｉｒｐｏｒｔ  "), proxy("US 节点", source="  Ａｉｒｐｏｒｔ  "))[0]
    payload = [[node.key, alias.source_id, alias.original_name, alias.name, alias.duplicate_ordinal] for alias in node.aliases]
    expected = [alias.entry_id for alias in node.aliases]
    assert [alias_entry_id(*row) for row in payload] == expected
    assert js("const rows=JSON.parse(require('fs').readFileSync(0,'utf8')); process.stdout.write(JSON.stringify(rows.map(row=>op.aliasEntryId(...row))));", payload) == expected


def test_operator_preserves_instances_and_moves_extra_stable_aliases_to_dynamic_tail():
    proxies = [proxy("US B"), proxy("US second", "two.example"), proxy("US A"), proxy("US A"), proxy("US third", "three.example")]
    nodes = resolve_effective_regions(inventory(*proxies), {})
    keys = [node_key(p) for p in proxies]
    ranking = {"schema_version": 2, "version": "test", "region_order": ["united-states"],
               "regions": {"united-states": {"stable_slots": {"1": keys[0], "2": keys[1], "3": keys[4]}, "ranked": [], "rejected": {}}},
               "identity_index": {n.key: node_identity(n) for n in nodes}}
    result = js("const p=JSON.parse(require('fs').readFileSync(0,'utf8')); op.operator(p.proxies,null,{options:{rankingUrl:'https://synthetic.invalid/ranking'},ProxyUtils:{produce:rows=>rows,download:async()=>JSON.stringify(p.state)}}).then(rows=>process.stdout.write(JSON.stringify(rows.map(x=>x.name))));", {"proxies":proxies,"state":ranking})
    assert result == ["US A", "US second", "US third", "US B", "US A"]


def test_operator_alias_rotation_maps_all_instances_to_one_legacy_connection():
    old = inventory(proxy("US A"), proxy("US B"))[0]
    new = [proxy("US A", "new.example"), proxy("US B", "new.example")]
    ranking = {"schema_version":2,"version":"test","regions":{"united-states":{"stable_slots":{"1":old.key},"ranked":[],"rejected":{}}},"identity_index":{old.key:node_identity(old)}}
    script = "const p=JSON.parse(require('fs').readFileSync(0,'utf8')); const selected=p.proxies.map(proxy=>({proxy,key:op.nodeKey(proxy),identity:op.selectedIdentity(proxy)})); process.stdout.write(JSON.stringify([...op.resolveIdentityKeys(p.state,selected)].map(([index,key])=>[index,key===p.expected])));"
    assert js(script,{"proxies":new,"state":ranking,"expected":old.key}) == [[0,True],[1,True]]


def test_operator_legacy_index_keeps_authoritative_region_for_exact_keys():
    proxies = [proxy("Custom last", "two.example"), proxy("Custom first")]
    keys = [node_key(p) for p in proxies]
    identities = {key: {"source_id":"", "original_name":p["name"], "normalized_name":p["name"].lower(),
                        "logical_id":"", "region":"united-states"} for key,p in zip(keys,proxies)}
    ranking = {"schema_version":2,"version":"legacy","regions":{"united-states":{"stable_slots":{"1":keys[1],"2":keys[0]},"ranked":[],"rejected":{}}},"identity_index":identities}
    script = "const p=JSON.parse(require('fs').readFileSync(0,'utf8')); op.operator(p.proxies,null,{options:{rankingUrl:'https://synthetic.invalid/ranking'},ProxyUtils:{produce:rows=>rows,download:async()=>JSON.stringify(p.state)}}).then(rows=>process.stdout.write(JSON.stringify(rows.map(x=>x.name))));"
    assert js(script,{"proxies":proxies,"state":ranking}) == ["Custom first","Custom last"]


def test_operator_ambiguous_rotation_preserves_all_unmatched_instances():
    old = inventory(proxy("US A"),proxy("US B"))[0]
    new = [proxy("US A","new-one.example"),proxy("US B","new-two.example")]
    ranking = {"schema_version":2,"version":"test","regions":{"united-states":{"stable_slots":{"1":old.key},"ranked":[],"rejected":{}}},"identity_index":{old.key:node_identity(old)}}
    script = "const p=JSON.parse(require('fs').readFileSync(0,'utf8')); const rows=p.proxies.map(proxy=>({key:op.nodeKey(proxy),identity:op.selectedIdentity(proxy)})); process.stdout.write(JSON.stringify([...op.resolveIdentityKeys(p.state,rows)]));"
    assert js(script,{"proxies":new,"state":ranking}) == []
