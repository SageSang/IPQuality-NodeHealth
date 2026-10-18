"""Boundary regressions for initial baselines and cross-language input parsing."""
import json
import math
import subprocess
import unicodedata

import pytest

from node_health.config import PolicyConfig
from node_health.identity import IDENTITY_WHITESPACE, normalize_source_id, original_name, source_id
from node_health.policy import evaluate_node, full_has_confirmed_redline, normalize_risk_value, valid_risk_sources, _risk_severity
from node_health.probe import normalize_ipquality
from test_port_mapping import ROOT, CONVERTER, mapping_case, proxy, render
from test_probe_policy import node, quick
from test_review_regressions import dns_result

VECTORS = json.loads((ROOT / 'tests/fixtures/identity-whitespace.json').read_text())
POINTS = [(code, True) for code in VECTORS['whitespace_codepoints']] + [(code, False) for code in VECTORS['non_whitespace_codepoints']]
OPERATOR = ROOT / 'integrations/sub-store/health-ranking-operator.js'


def test_frozen_whitespace_preserves_existing_python_identity_semantics():
    assert {ord(char) for char in IDENTITY_WHITESPACE} == {int(code, 16) for code in VECTORS['whitespace_codepoints']}
    for code, _ in POINTS:
        char = chr(int(code, 16))
        for text in [char, f'{char}Ａ{char}{char}Ｂ{char}', f'{char}\ufeff{char}']:
            assert normalize_source_id(text) == ' '.join(unicodedata.normalize('NFKC', text).split()).lower()
            assert original_name({'name': text}) == ' '.join(text.split())


@pytest.mark.parametrize('code,is_space', POINTS)
@pytest.mark.parametrize('field', ['_nh_source_id', '_nh_original_name'])
def test_metadata_whitespace_round_trips_python_mapping_and_both_js(code, is_space, field):
    char = chr(int(code, 16))
    p = proxy('Hong Kong Fallback', _source_id='BACKUP', _original_name='Hong Kong Original', _region='hong-kong', **{field: char})
    expected = ['backup', 'Hong Kong Original']
    if not is_space: expected[0 if field == '_nh_source_id' else 1] = char
    assert [source_id(p), original_name(p)] == expected
    script = """
const c=require(process.argv[1]),o=require(process.argv[2]),p=JSON.parse(require('fs').readFileSync(0,'utf8'));
console.log(JSON.stringify([[c.sourceId(p),c.originalName(p)],[o.sourceId(p),o.originalName(p)]]));
"""
    result = subprocess.run(['node', '-e', script, str(CONVERTER), str(OPERATOR)], input=json.dumps(p), text=True, capture_output=True, check=True)
    assert json.loads(result.stdout) == [expected, expected]
    _, _, _, mapping = mapping_case([p])
    rendered = render(mapping, [p])
    assert rendered['ok'], rendered
    assert rendered['config']['listeners'][0]['port'] == 62000


@pytest.mark.parametrize('code,is_space', [('0085', True), ('001C', True), ('FEFF', False), ('00A0', True)])
def test_display_name_edges_use_the_same_mapping_identity(code, is_space):
    char = chr(int(code, 16))
    p = proxy(f'{char}Hong Kong Name{char}', _region='hong-kong')
    _, nodes, _, mapping = mapping_case([p])
    assert nodes[0].name == ('Hong Kong Name' if is_space else p['name'])
    result = render(mapping, [p])
    assert result['ok'], result


INVALID_RISKS = [-1, -80, -.01, '-1', '-80', '-0.01', '-1%', '- 1', '--1', '1_0',
                 '-1e-1000', '100.0000000000000000001', '1e309', 'nan', 'inf',
                 float('nan'), float('inf'), -float('inf'), 101, '101']


@pytest.mark.parametrize('value', INVALID_RISKS)
def test_invalid_risk_never_becomes_positive_evidence_or_a_redline(value):
    assert normalize_risk_value(value) == ''
    full = normalize_ipquality({'Head': {'IP': '8.8.8.8'}, 'Score': {'one': value, 'two': value, 'three': value},
                               'Factor': {}, 'Mail': {'DNSBlacklist': dns_result()}})
    assert valid_risk_sources(full) == {}
    assert not full_has_confirmed_redline(full)
    evaluation = evaluate_node(node('risk'), quick(), full, PolicyConfig(), 2)
    assert evaluation.risk_grade == 'B'
    assert not evaluation.redline


@pytest.mark.parametrize('number,text', [(0, '0'), (1, '+1'), (.01, '1e-2'), (.01, '1E-2'),
                                        (75, '75%'), (100, '1e2'), (.5, '.5'), (1, '1.')])
def test_numeric_and_string_risk_inputs_have_identical_severity(number, text):
    normalized_number = normalize_risk_value(number)
    normalized_text = normalize_risk_value(text)
    assert normalized_number and normalized_text
    assert math.isclose(_risk_severity(normalized_number), _risk_severity(normalized_text))


@pytest.mark.parametrize('value', ['high-risk', 'HIGH_RISK', 'very-high-risk'])
def test_label_punctuation_is_still_supported(value):
    assert normalize_risk_value(value) in {'high risk', 'very high risk'}
    assert _risk_severity(value) >= .8
