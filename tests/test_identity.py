from node_health.identity import canonical_proxy_json, node_key
from node_health.inventory import parse_clash_inventory


def test_node_key_fixed_cross_language_vector():
    proxy = {
        "name": "US 001",
        "type": "trojan",
        "server": "example.com",
        "port": 443,
        "password": "秘密",
        "tls": True,
        "_region": "united-states",
    }
    assert canonical_proxy_json(proxy) == (
        '{"password":"秘密","port":443,"server":"example.com","tls":true,"type":"trojan"}'
    )
    assert node_key(proxy) == "a16d516fa632e0ee8033bef0fb3fef91f2ce4483db5d4ac19a9885d4f622994e"


def test_node_key_ignores_only_top_level_name_and_runtime_metadata():
    original = {
        "name": "old",
        "server": "a.example",
        "port": 443,
        "ws-opts": {"headers": {"name": "nested-is-identity"}},
        "_region": "us",
    }
    renamed = {**original, "name": "new", "_region": "united-states", "_scan": 1}
    assert node_key(original) == node_key(renamed)

    changed_nested = {**renamed, "ws-opts": {"headers": {"name": "changed"}}}
    assert node_key(original) != node_key(changed_nested)


def test_node_key_treats_connection_or_credential_change_as_new_node():
    proxy = {"name": "A", "type": "ss", "server": "one", "port": 443, "password": "a"}
    assert node_key(proxy) != node_key({**proxy, "password": "b"})
    assert node_key(proxy) != node_key({**proxy, "port": 8443})


def test_port_hopping_identity_ignores_only_the_random_concrete_port():
    first = {
        "name": "hy2-a",
        "type": "hysteria2",
        "server": "edge.example",
        "port": 20001,
        "ports": "20000-20100",
        "password": "secret",
    }
    second = {**first, "name": "hy2-b", "port": 20099}
    assert node_key(first) == node_key(second)
    assert node_key(first) != node_key({**second, "ports": "30000-30100"})


def test_inventory_fails_closed_on_same_connection_with_two_alias_names():
    payload = """
proxies:
  - {name: alias-a, type: ss, server: one.example, port: 443, password: secret}
  - {name: alias-b, type: ss, server: one.example, port: 443, password: secret}
"""
    try:
        parse_clash_inventory(payload, {})
    except ValueError as error:
        assert "connection-identical proxies" in str(error)
    else:
        raise AssertionError("alias collision must fail before generating an invalid dialer graph")


def test_inventory_rejects_explicit_region_outside_fixed_port_contract():
    payload = """
proxies:
  - {name: node-a, type: ss, server: one.example, port: 443, password: secret, _region: mars}
"""
    try:
        parse_clash_inventory(payload, {"united-states": [r"US"]})
    except ValueError as error:
        assert "unsupported _region 'mars'" in str(error)
    else:
        raise AssertionError("unknown explicit regions must fail before slot assignment")
