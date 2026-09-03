import json

from node_health.inventory import parse_clash_inventory
from node_health.reconcile import reconcile_previous_state


PATTERNS = {
    "hong-kong": [r"Hong Kong"],
    "japan": [r"Japan"],
}


def nodes(*proxies):
    return parse_clash_inventory(
        json.dumps({"proxies": list(proxies)}),
        PATTERNS,
    )


def proxy(name, server, source=""):
    payload = {
        "name": name,
        "type": "ss",
        "server": server,
        "port": 443,
        "cipher": "aes-128-gcm",
        "password": f"secret-{server}",
    }
    if source:
        payload["_nh_source_id"] = source
        payload["_nh_original_name"] = name
    return payload


def prior_state(old_node):
    return {
        "schema_version": 2,
        "stable_slots": {old_node.region: {"1": old_node.key}},
        "slot_changed_at": {old_node.region: {"1": "2026-07-20T00:00:00+00:00"}},
        "promotion_cooldown_at": {
            old_node.region: "2026-07-23T00:00:00+00:00"
        },
        "nodes": {
            old_node.key: {
                "name": old_node.name,
                "region": old_node.region,
                "source_id": old_node.source_id,
                "original_name": old_node.original_name,
                "normalized_name": old_node.normalized_name,
                "logical_id": old_node.logical_id,
                "last_score": 88,
                "last_exit_ip": "198.51.100.8",
                "last_full_exit_ip": "198.51.100.8",
                "last_full": {"completed": True, "tor": False},
                "consecutive_full_passes": 9,
                "consecutive_unavailable_runs": 2,
                "last_decision": "eligible",
            }
        },
    }


def test_source_and_name_rotation_inherits_slot_but_not_connection_reputation():
    old = nodes(proxy("Hong Kong 01", "old.example", "E-IX"))[0]
    new = nodes(proxy("Hong Kong 01", "new.example", "E-IX"))[0]

    resolved, migrated, events = reconcile_previous_state([new], prior_state(old))

    assert resolved == [new]
    assert migrated["stable_slots"]["hong-kong"]["1"] == new.key
    inherited = migrated["nodes"][new.key]
    assert inherited["last_score"] == 88
    assert inherited["last_exit_ip"] == ""
    assert inherited["last_full"] is None
    assert inherited["consecutive_full_passes"] == 0
    assert inherited["consecutive_unavailable_runs"] == 0
    assert migrated["slot_changed_at"] == {
        "hong-kong": {"1": "2026-07-20T00:00:00+00:00"}
    }
    assert migrated["promotion_cooldown_at"] == {
        "hong-kong": "2026-07-23T00:00:00+00:00"
    }
    assert events == [
        {
            "event": "identity-rotated-name-match",
            "method": "source-logical-id",
            "source_id": "e-ix",
            "name": "Hong Kong 01",
            "region": "hong-kong",
            "before": old.key,
            "after": new.key,
        }
    ]


def test_unique_name_rotation_migrates_frozen_other_order():
    old = nodes(proxy("Brazil 01", "old.example"))[0]
    new = nodes(proxy("Brazil 01", "new.example"))[0]
    previous = prior_state(old)
    previous["frozen_order"] = {
        "other": ["before", old.key, "after", old.key]
    }
    previous["ranked_order"] = {
        "other": ["before", old.key, "after", old.key]
    }
    previous["availability_baselines"] = {
        "other": {"available_ratio": 1.0, "node_keys": [old.key, "after"]}
    }

    resolved, migrated, events = reconcile_previous_state([new], previous)

    assert resolved == [new]
    assert migrated["frozen_order"]["other"] == [
        "before",
        new.key,
        "after",
    ]
    assert migrated["ranked_order"]["other"] == [
        "before",
        new.key,
        "after",
    ]
    assert migrated["availability_baselines"]["other"]["node_keys"] == [
        new.key,
        "after",
    ]
    assert events[0]["method"] == "region-original-name"


def test_region_unique_name_rotation_works_without_source_metadata():
    old = nodes(proxy("Japan 01", "old.example"))[0]
    new = nodes(proxy("Japan 01", "new.example"))[0]

    _, migrated, events = reconcile_previous_state([new], prior_state(old))

    assert migrated["stable_slots"]["japan"]["1"] == new.key
    assert events[0]["method"] == "region-original-name"


def test_ambiguous_duplicate_names_are_not_automatically_inherited():
    old_nodes = nodes(
        proxy("Hong Kong 01", "old-a.example"),
        proxy("Hong Kong 01", "old-b.example"),
    )
    new_nodes = nodes(
        proxy("Hong Kong 01", "new-a.example"),
        proxy("Hong Kong 01", "new-b.example"),
    )
    previous = {
        "schema_version": 2,
        "stable_slots": {"hong-kong": {"1": old_nodes[0].key}},
        "nodes": {},
    }
    for item in old_nodes:
        previous["nodes"][item.key] = prior_state(item)["nodes"][item.key]

    _, migrated, events = reconcile_previous_state(new_nodes, previous)

    assert migrated["stable_slots"]["hong-kong"]["1"] == old_nodes[0].key
    assert events == []


def test_known_different_sources_never_inherit_by_name_fallback():
    old = nodes(proxy("Hong Kong 01", "old.example", "airport-a"))[0]
    new = nodes(proxy("Hong Kong 01", "new.example", "airport-b"))[0]

    _, migrated, events = reconcile_previous_state([new], prior_state(old))

    assert migrated["stable_slots"]["hong-kong"]["1"] == old.key
    assert new.key not in migrated["nodes"]
    assert events == []


def test_normalized_unique_name_matches_case_and_whitespace_change():
    old = nodes(proxy("Hong Kong  01", "old.example"))[0]
    new = nodes(proxy("hong kong 01", "new.example"))[0]

    _, migrated, events = reconcile_previous_state([new], prior_state(old))

    assert migrated["stable_slots"]["hong-kong"]["1"] == new.key
    assert events[0]["method"] == "region-normalized-name"


def test_multiple_source_tagged_rotations_reconcile_one_to_one():
    old_nodes = nodes(
        proxy("Hong Kong 01", "old-1.example", "E-IX"),
        proxy("Hong Kong 02", "old-2.example", "E-IX"),
    )
    new_nodes = nodes(
        proxy("Hong Kong 01", "new-1.example", "E-IX"),
        proxy("Hong Kong 02", "new-2.example", "E-IX"),
    )
    previous = {
        "schema_version": 2,
        "stable_slots": {
            "hong-kong": {"1": old_nodes[0].key, "2": old_nodes[1].key}
        },
        "slot_changed_at": {
            "hong-kong": {
                "1": "2026-07-20T00:00:00+00:00",
                "2": "2026-07-21T00:00:00+00:00",
            }
        },
        "promotion_cooldown_at": {
            "hong-kong": "2026-07-23T00:00:00+00:00"
        },
        "nodes": {},
    }
    for item in old_nodes:
        previous["nodes"][item.key] = prior_state(item)["nodes"][item.key]

    _, migrated, events = reconcile_previous_state(new_nodes, previous)

    assert migrated["stable_slots"]["hong-kong"] == {
        "1": new_nodes[0].key,
        "2": new_nodes[1].key,
    }
    assert {event["after"] for event in events} == {
        new_nodes[0].key,
        new_nodes[1].key,
    }
    assert migrated["slot_changed_at"] == previous["slot_changed_at"]
    assert migrated["promotion_cooldown_at"] == previous["promotion_cooldown_at"]


def test_reconciled_slot_keeps_previous_region_when_new_classification_disagrees():
    old = nodes(proxy("Hong Kong 01", "old.example", "E-IX"))[0]
    changed = proxy("Hong Kong 01", "new.example", "E-IX")
    changed["_region"] = "japan"
    new = nodes(changed)[0]

    resolved, migrated, events = reconcile_previous_state([new], prior_state(old))

    assert resolved[0].region == "hong-kong"
    assert migrated["nodes"][new.key]["region"] == "hong-kong"
    assert events[0]["region"] == "hong-kong"


def test_schema_v1_state_is_intentionally_not_reconciled():
    old = nodes(proxy("Hong Kong 01", "old.example", "E-IX"))[0]
    new = nodes(proxy("Hong Kong 01", "new.example", "E-IX"))[0]
    previous = prior_state(old)
    previous["schema_version"] = 1

    resolved, untouched, events = reconcile_previous_state([new], previous)

    assert resolved == [new]
    assert untouched == previous
    assert events == []


def test_exact_connection_key_wins_without_rotation_event():
    old = nodes(proxy("Hong Kong old display", "same.example", "airport-a"))[0]
    changed = proxy("Hong Kong new display", "same.example", "airport-b")
    # Keep connection credentials identical; only logical/display metadata changes.
    changed["password"] = "secret-same.example"
    current = nodes(changed)[0]
    assert current.key == old.key

    resolved, migrated, events = reconcile_previous_state([current], prior_state(old))

    assert resolved == [current]
    assert old.key in migrated["nodes"]
    assert events == []


def test_one_old_name_does_not_guess_between_two_new_connections():
    old = nodes(proxy("Hong Kong 01", "old.example"))[0]
    new_nodes = nodes(
        proxy("Hong Kong 01", "new-a.example"),
        proxy("Hong Kong 01", "new-b.example"),
    )

    _, migrated, events = reconcile_previous_state(new_nodes, prior_state(old))

    assert migrated["stable_slots"]["hong-kong"]["1"] == old.key
    assert all(item.key not in migrated["nodes"] for item in new_nodes)
    assert events == []
