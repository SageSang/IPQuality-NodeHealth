"""Regression cases from the 2026-10 independent review; synthetic/local only."""
import json
import os
import socket
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml

from node_health.config import AppConfig, InventoryConfig, PolicyConfig, load_config
from node_health.dnsbl import normalize_dnsbl
from node_health.errors import sanitize_error_fields
from node_health.identity import original_name, source_id
from node_health.inventory import parse_clash_inventory
from node_health.models import FullResult, Node
from node_health.policy import _RISK_LABELS, _is_high_risk, _risk_severity, normalize_risk_value, evaluate_node
from node_health.probe import CurlQuickProbe, IPQualityAuditor, generate_mihomo_probe_config, normalize_ipquality
from node_health.service import _full_from_dict
from node_health.slots import assign_all_regions
from test_port_mapping import CONVERTER, ROOT, mapping_case, proxy, render
from test_service import make_service
from test_slots import assessment
from test_probe_policy import node, quick, full_result


def run_node(script, value):
    result = subprocess.run(['node', '-e', script, str(CONVERTER)], input=json.dumps(value),
                            text=True, capture_output=True, check=True)
    return json.loads(result.stdout)


def profile_hash(profile, legacy=False):
    expression = ('c.digest({shell:c.runtimeShell(p),listeners:p.listeners.map(l=>({port:l.port,options:{type:l.type}}))})'
                  if legacy else 'c.runtimeProfileHash(p)')
    return run_node("const c=require(process.argv[1]),p=JSON.parse(require('fs').readFileSync(0,'utf8'));"
                    f'console.log(JSON.stringify({expression}));', profile)


def test_deleted_incumbent_during_outage_still_publishes_resolvable_bundle(tmp_path):
    service, checker, _, source = make_service(tmp_path, count=4)
    first = service.run_once('rebuild')
    old = first['regions']['united-states']['stable_slots']
    removed = old['1']
    source.remove_name(first['nodes'][removed]['name'])
    checker.unavailable_names = {p['name'] for p in source.proxies}
    second = service.run_once('maintenance')
    assert second['regions']['united-states']['stable_slots'] == {'2': old['2'], '3': old['3']}
    assert second['runtime_target_status'] == 'ready'
    persisted = service.store.load_current()
    assert persisted['runtime_bundle']
    bundle = json.loads(service.store.read_runtime_bundle())
    binding = next(b for b in bundle['mapping']['bindings'] if b['port'] == 62800)
    assert binding['node_key'] is None
    inventory_keys = {n.key for n in parse_clash_inventory(source.download(), service.config.region_patterns)}
    assert all(b['node_key'] in inventory_keys for b in bundle['mapping']['bindings'] if b['entry_id'])


def test_frozen_region_does_not_retain_an_identity_from_another_region():
    items = [assessment('moved', 80, region='japan'), assessment('remaining', 50, available=False)]
    regions, _ = assign_all_regions('maintenance', items, {'united-states': {'2': 'moved'}}, 3,
                                    frozen_regions={'united-states': 'all-nodes-unavailable'})
    assert regions['united-states']['stable_slots'] == {}


@pytest.mark.parametrize('environment', [{'NO_PROXY': '*'}, {'no_proxy': '*'}, {'NO_PROXY': '127.0.0.1'}, {'NO_PROXY': '*', 'no_proxy': '*'}])
def test_required_proxy_never_hits_direct_target(monkeypatch, environment):
    hits = []
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path); self.send_response(200); self.end_headers(); self.wfile.write(b'direct')
        def log_message(self, *_): pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        for key in list(os.environ):
            if key.lower().endswith('_proxy'): monkeypatch.delenv(key)
        for key, value in environment.items(): monkeypatch.setenv(key, value)
        checker = CurlQuickProbe(AppConfig(InventoryConfig('https://inventory.invalid')))
        with socket.socket() as dead:
            dead.bind(('127.0.0.1', 0))
            result = checker._http_get(dead.getsockname()[1], f'http://127.0.0.1:{server.server_port}', 1)
        assert result.transport_code != 0
        assert hits == []
        # An explicitly diagnostic request remains usable.
        assert checker._http_get(None, f'http://127.0.0.1:{server.server_port}', 1).http_status == 200
    finally:
        server.shutdown(); server.server_close(); thread.join()


def test_full_auditor_removes_bypass_only_in_child_environment(tmp_path, monkeypatch):
    script = tmp_path / 'audit.sh'
    script.write_text('test -z "${NO_PROXY:-}${no_proxy:-}" || exit 1\nprintf \'%s\\n\' \'{"Head":{"IP":"8.8.8.8"},"Score":{},"Factor":{}}\'\n')
    monkeypatch.setenv('NO_PROXY', '*'); monkeypatch.setenv('no_proxy', '*')
    config = AppConfig(InventoryConfig('x')); config.probe.ipquality_script = str(script)
    assert IPQualityAuditor(config).check(Node('a', 'a', 'other', {}), 20000).completed
    assert os.environ['NO_PROXY'] == os.environ['no_proxy'] == '*'


@pytest.mark.parametrize('field', ['_nh_source_id', '_nh_original_name'])
@pytest.mark.parametrize('blank', [' \n ', '\u00a0\u3000'])
def test_mapping_identity_fallback_agrees_across_consumers(field, blank):
    p = proxy('Hong Kong Fallback', _source_id='BACKUP', _original_name='Hong Kong Original', **{field: blank})
    _, _, _, mapping = mapping_case([p])
    assert render(mapping, [p])['ok']
    actual = run_node("const c=require(process.argv[1]),p=JSON.parse(require('fs').readFileSync(0,'utf8'));console.log(JSON.stringify([c.sourceId(p),c.originalName(p)]));", p)
    assert actual == [source_id(p), original_name(p)]


def probe_config(proxies):
    nodes = parse_clash_inventory(json.dumps({'proxies': proxies}), AppConfig(InventoryConfig('x')).region_patterns)
    return generate_mihomo_probe_config(nodes)[0]


def test_dependency_to_deduplicated_alias_and_two_level_chain():
    proxies = [proxy('Hong Kong A'), proxy('Hong Kong B'),
               proxy('Hong Kong C', 'c.example', **{'dialer-proxy': 'Hong Kong B'}),
               proxy('Hong Kong D', 'd.example', **{'dialer-proxy': 'Hong Kong C'})]
    result = probe_config(proxies)
    by_name = {p['name']: p for p in result['proxies']}
    assert by_name['Hong Kong C']['dialer-proxy'] == 'Hong Kong A'
    assert by_name['Hong Kong D']['dialer-proxy'] == 'Hong Kong C'
    assert all(p['dialer-proxy'] in by_name for p in result['proxies'] if 'dialer-proxy' in p)


def test_explicit_builtin_direct_dialer_remains_supported():
    result = probe_config([proxy('A', **{'dialer-proxy': 'DIRECT'})])
    assert result['proxies'][0]['dialer-proxy'] == 'DIRECT'


@pytest.mark.parametrize('proxies, message', [
    ([proxy('A', **{'dialer-proxy': 'missing'})], 'missing'),
    ([proxy('A', **{'dialer-proxy': 'A'})], 'cyclic'),
    ([proxy('A', **{'dialer-proxy': 'B'}), proxy('B', 'b.example', **{'dialer-proxy': 'A'})], 'cyclic'),
    ([proxy('A'), proxy('A', 'b.example'), proxy('C', 'c.example', **{'dialer-proxy': 'A'})], 'ambiguous'),
])
def test_invalid_dependencies_fail_before_starting_probe_environment(proxies, message):
    with pytest.raises(ValueError, match=message): probe_config(proxies)


@pytest.mark.parametrize('label', sorted(_RISK_LABELS))
def test_every_accepted_risk_label_uses_consistent_severity_and_redline(label):
    value = normalize_risk_value(label.upper().replace(' ', ' _ '))
    assert value
    assert _is_high_risk(value) == (_risk_severity(value) >= .75)
    evaluation = evaluate_node(node('risk'), quick(), full_result(completed=True,
        risk_sources={'one': label, 'two': label}), PolicyConfig(), 2)
    assert any(r.startswith('multiple-high-risk-sources:') for r in evaluation.reasons) == _is_high_risk(value)


@pytest.mark.parametrize('label', ['high', '高', '高风险', 'very high risk', '极高', '极高风险'])
def test_high_semantics_are_never_medium_or_non_redline(label):
    assert _risk_severity(label) >= .8 and _is_high_risk(label)


def test_unknown_label_has_no_default_medium_severity():
    assert normalize_risk_value('new-provider-label') == ''
    with pytest.raises(ValueError): _risk_severity('new-provider-label')


@pytest.mark.parametrize('kind', ['rule', 'group'])
def test_profile_approval_covers_used_alias_binding(kind):
    proxies = [proxy('Hong Kong A'), proxy('Hong Kong B', 'b.example')]
    _, _, _, mapping = mapping_case(proxies)
    profile = {'mode': 'rule', 'listeners': [], 'proxies': [{**proxies[0], 'name': 'alias'}]}
    if kind == 'rule': profile['rules'] = ['MATCH,alias']
    else: profile['proxy-groups'] = [{'name': 'selection', 'type': 'select', 'proxies': ['alias']}]
    approved = profile_hash(profile)
    assert render(mapping, proxies, profile=profile, mutate_options={'runtimeProfileHash': approved})['ok']
    profile['proxies'] = [{**proxies[1], 'name': 'alias'}]
    assert not render(mapping, proxies, profile=profile, mutate_options={'runtimeProfileHash': approved})['ok']


def test_profile_without_alias_references_keeps_existing_approval():
    profile = {'mode': 'rule', 'rules': ['MATCH,DIRECT'], 'listeners': [], 'proxies': [proxy('unused')]}
    approved = profile_hash(profile, legacy=True)
    assert profile_hash(profile) == approved
    profile['proxies'] = [proxy('unused', 'rotated.example')]
    assert profile_hash(profile) == approved


def test_profile_conflicting_duplicate_names_are_rejected():
    profile = {'rules': ['MATCH,alias'], 'listeners': [], 'proxies': [proxy('alias'), proxy('alias', 'b.example')]}
    _, _, _, mapping = mapping_case()
    with pytest.raises(subprocess.CalledProcessError):
        profile_hash(profile)


def dns_result(total=5, clean=5, listed=0, unknown=0, errors=0):
    return {'QueryStatusVersion': 1, 'Total': total, 'Clean': clean, 'Blacklisted': listed,
            'Marked': unknown, 'ErrorCount': errors}


@pytest.mark.parametrize('body, code, counts', [
    ('', 9, [1, 0, 0, 0, 1]), ('', 0, [1, 0, 1, 0, 0]),
    (';; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 1', 0, [1, 0, 0, 0, 1]),
    (';; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 1', 0, [1, 1, 0, 0, 0]),
    (';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1', 0, [1, 1, 0, 0, 0]),
    (';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\nx. 30 IN A 127.0.0.2\nx. 30 IN A 127.0.0.3', 0, [1, 0, 0, 1, 0]),
    (';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\nx. 30 IN A 127.255.255.254', 0, [1, 0, 1, 0, 0]),
])
def test_dnsbl_checks_exit_and_dns_status(body, code, counts):
    source = (ROOT / 'ip.sh').read_text()
    function = source[source.index('check_dnsbl_parallel(){'):source.index('\ncheck_dnsbl(){')]
    shell = '''declare -A smail
read_dnsbl_zones(){ printf 'test.invalid\n'; }
filter_dnsbl_zones(){ cat; }
dig(){ printf '%s\n' "$DNS_BODY"; return "$DNS_EXIT"; }
export -f dig
'''+function+'\ncheck_dnsbl_parallel 8.8.8.8 1\n'
    result = subprocess.run(['bash', '-c', shell], env=dict(os.environ, DNS_BODY=body, DNS_EXIT=str(code)),
                            text=True, capture_output=True, check=True)
    assert list(map(int, result.stdout.split())) == counts


@pytest.mark.parametrize('dns, expected', [
    (dns_result(), 'A'), (dns_result(clean=4, errors=1), 'A'),
    (dns_result(clean=3, errors=2), 'B'), (dns_result(clean=0, errors=5), 'B'),
    ({'Total': 5, 'Clean': 5, 'Blacklisted': 0}, 'B'),
    (dns_result(clean=0, listed=3, errors=2), 'C'),
])
def test_dnsbl_coverage_survives_normalization_cache_and_controls_clean_grade(dns, expected):
    full = normalize_ipquality({'Head': {'IP': '8.8.8.8'}, 'Score': {'a': 'low', 'b': 'low', 'c': 'low'},
                               'Factor': {}, 'Mail': {'DNSBlacklist': dns}})
    saved = _full_from_dict(sanitize_error_fields(full.to_dict()))
    assert saved.dnsbl_coverage == normalize_dnsbl(dns)
    assert saved.details['Mail']['DNSBlacklist'] == dns
    result = evaluate_node(node('dns'), quick(), saved, PolicyConfig(), 2)
    assert result.risk_grade == expected


@pytest.mark.parametrize('value', [0, -1, 1.1, True, '80%', float('nan')])
def test_invalid_dnsbl_coverage_setting_is_rejected(tmp_path, value):
    config = tmp_path / 'config.yaml'
    config.write_text(yaml.safe_dump({'inventory': {'url': 'https://inventory.invalid'},
                                    'policy': {'dnsbl_min_checked_ratio': value}}))
    with pytest.raises(ValueError, match='dnsbl_min_checked_ratio'): load_config(config)


def test_compose_templates_explicitly_pass_optional_provider_credentials():
    for path in ['compose.yaml', 'deploy/compose.synology.yaml']:
        compose = yaml.safe_load((ROOT / path).read_text())
        environment = compose['services']['node-health']['environment']
        assert environment['IPINFO_TOKEN'] == '${IPINFO_TOKEN:-}'
        assert environment['IPAPI_KEY'] == '${IPAPI_KEY:-}'
