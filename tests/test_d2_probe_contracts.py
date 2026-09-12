import json
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from node_health.config import AppConfig, InventoryConfig, ProbeConfig
from node_health.probe import CurlQuickProbe, HTTPResult, ProbeFailure, _retry_after_seconds, normalize_ipquality
from node_health.policy import valid_risk_sources

ROOT=Path(__file__).resolve().parents[1]


def probe():
    return CurlQuickProbe(AppConfig(InventoryConfig("https://inventory.invalid")))


@pytest.mark.parametrize("value", [None,"","unknown","false",0,[],{}])
def test_unknown_flags_never_form_two_low_risk_sources(value):
    checker=probe()
    ipinfo={"privacy":{"proxy":value,"vpn":value,"tor":value,"hosting":value}}
    ipapi={key:value for key in ("is_proxy","is_vpn","is_tor","is_datacenter","is_abuser")}
    checker._http_get=lambda port,url,timeout=None: HTTPResult(0,200,1,json.dumps(ipinfo if "ipinfo" in url else ipapi))
    result=checker._claude_risk_intelligence(20000,"8.8.8.8")
    assert result["complete"] is False
    assert result["risk_sources"]=={}
    assert result["factors"]=={}


def test_empty_raw_scores_cannot_promote_normalized_legacy_fallback():
    result=normalize_ipquality({"Head":{"IP":"8.8.8.8"},"Score":{},"Factor":{},
                               "risk_sources":{"one":"low","two":"low","three":"low"}})
    assert valid_risk_sources(result)=={}


@pytest.mark.parametrize("body,status,host,expected", [
    ("ip=8.8.8.8\nloc=US\nh=chatgpt.com\n",200,"chatgpt.com","available"),
    ("ip=8.8.8.8\nloc=CN\nh=chatgpt.com\n",200,"chatgpt.com","restricted"),
    ("<html>503 Service Unavailable</html>",503,"chatgpt.com","unknown"),
    ("<html>challenge</html>",200,"chatgpt.com","unknown"),
    ("",200,"chatgpt.com","unknown"),
    ("ip=8.8.8.8\nloc=US\nloc=CN\nh=chatgpt.com",200,"chatgpt.com","unknown"),
    ("ip=127.0.0.1\nloc=US\nh=chatgpt.com",200,"chatgpt.com","unknown"),
    ("ip=8.8.8.8\nloc=US\nh=chatgpt.com",200,"other.invalid","unknown"),
])
def test_site_contract_uses_http_body_and_approved_host(body,status,host,expected):
    checker=probe()
    checker._http_get=lambda *_: HTTPResult(0,status,1,body,host)
    observation=checker._check_site(20000,"https://chatgpt.com/cdn-cgi/trace",{"US"})
    assert observation.result_class==expected
    assert observation.probe_scope=="site-region"


def test_one_denied_route_does_not_block_a_successful_route():
    checker=probe(); calls=[]
    def get(port,url,timeout=None):
        calls.append(port)
        return HTTPResult(0,403,1) if port==20000 else HTTPResult(0,200,1,'{"country":"US"}')
    checker._http_get=get
    with pytest.raises(ProbeFailure):checker._provider_get(20000,"https://provider.invalid/a")
    assert checker._provider_get(20001,"https://provider.invalid/b")[0]=='{"country":"US"}'
    assert calls==[20000,20001]


def test_two_uncertain_routes_have_bounded_global_cooldown_and_half_open(monkeypatch):
    checker=probe(); clock=[0.0]; calls=[]
    monkeypatch.setattr("node_health.probe.time.monotonic",lambda:clock[0])
    checker._http_get=lambda port,*_: (calls.append(port) or HTTPResult(0,403,1))
    for port in (20000,20001,20002):
        with pytest.raises(ProbeFailure):checker._provider_get(port,"https://provider.invalid/a")
    assert calls==[20000,20001]
    clock[0]=61
    with pytest.raises(ProbeFailure):checker._provider_get(20002,"https://provider.invalid/a")
    assert calls==[20000,20001,20002]
    assert checker.diagnostics()["provider.invalid"]["half_open_requests"]==1


def test_retry_after_longer_than_a_day_is_never_shortened(monkeypatch):
    checker=probe(); clock=[0.0]; calls=[]
    monkeypatch.setattr("node_health.probe.time.monotonic",lambda:clock[0])
    def denied(port,*_):
        calls.append(port)
        return HTTPResult(0,429,1,'{"error":{"code":"quota_exceeded"}}',retry_after=172800)
    checker._http_get=denied
    for now,port in ((0,20000),(86401,20001),(172799,20002)):
        clock[0]=now
        with pytest.raises(ProbeFailure):checker._provider_get(port,"https://provider.invalid/a?token=synthetic")
    assert calls==[20000]
    future=datetime(2026,9,14,tzinfo=timezone.utc)
    assert _retry_after_seconds(future.strftime('%a, %d %b %Y %H:%M:%S GMT'),future-timedelta(days=2))==172800


def test_budget_counts_each_configured_resource_and_does_not_reset_on_retries():
    config=AppConfig(InventoryConfig("https://inventory.invalid"),probe=ProbeConfig(
        geo_url_template="https://provider.invalid/geo/{ip}",
        claude_ipinfo_url_template="https://provider.invalid/ipinfo/{ip}",
        claude_ipapi_url_template="https://provider.invalid/ipapi/{ip}",
    ))
    checker=CurlQuickProbe(config); checker.begin_scan([20000]); calls=[]
    checker._http_get=lambda port,url,*_: (calls.append(url) or HTTPResult(0,200,1,'{"country":"US"}'))
    for index in range(3):checker._provider_get(20000,f"https://provider.invalid/{index}")
    with pytest.raises(ProbeFailure,match="provider_budget_exhausted"):
        checker._provider_get(20000,"https://provider.invalid/fourth")
    assert len(calls)==3
    with pytest.raises(ProbeFailure):checker._provider_get(20001,"https://provider.invalid/unplanned-route")
    with pytest.raises(ProbeFailure):checker._provider_get(20000,"https://other.invalid/unplanned-source")
    assert len(calls)==3


def definitions():
    source=(ROOT / "ip.sh").read_text()
    return source[:source.rindex('\ngenerate_random_user_agent\nadapt_locale')]


@pytest.mark.parametrize("ip", ["8.8.8.8","2606:4700::1111"])
def test_real_save_json_preserves_external_strings_and_failed_candidate(ip,tmp_path):
    if not shutil.which("bash") or not shutil.which("jq"):pytest.skip("bash and jq required")
    text='ACME "Networks" \\ path\n台南'
    runner=tmp_path / "save.sh"
    runner.write_text(definitions()+r'''
IP="$1"; fullIP=1; mode_lite=0; ipjson='{"retained":true}'
maxmind[org]="$2"; maxmind[city]="$2"
maxmind[countrycode]=US; maxmind[regcountrycode]=US
save_json || exit 10
printf '%s\n' "$ipjson"
before="$ipjson"
chatgpt_probe_json='invalid-json'
if save_json; then exit 11;fi
[[ $ipjson == "$before" ]] || exit 12
''')
    result=subprocess.run(["bash",str(runner),ip,text],capture_output=True,text=True,timeout=10)
    assert result.returncode==0,result.stderr
    output=json.loads(result.stdout)
    assert output["Info"]["Organization"]==text
    assert output["Info"]["City"]["Name"]==text
    assert output["Head"]["IP"]==ip
    assert output["retained"] is True


@pytest.mark.parametrize("http,body,expected", [
    (200,"ip=8.8.8.8\nloc=US\nh=chatgpt.com\n","available"),
    (503,"<html>Service Unavailable</html>","unknown"),
    (200,"<html>challenge</html>","unknown"),
    (200,"ip=8.8.8.8\nloc=CN\nh=chatgpt.com\n","restricted"),
])
def test_real_openai_shell_probe_uses_site_contract(tmp_path,http,body,expected):
    if not shutil.which("bash") or not shutil.which("jq"):pytest.skip("bash and jq required")
    runner=tmp_path / "site.sh"
    runner.write_text(definitions()+r'''
mock_http="$1"; mock_body="$2"
curl(){
  while [[ $# -gt 0 ]];do
    if [[ $1 == --output ]];then shift;printf '%s' "$mock_body" >"$1";fi
    shift
  done
  printf '%s\n%s' "$mock_http" 'https://chatgpt.com/cdn-cgi/trace'
}
OpenAITest 4 || exit 1
printf '%s\n' "$chatgpt_probe_json"
''')
    result=subprocess.run(["bash",str(runner),str(http),body],capture_output=True,text=True,timeout=5)
    assert result.returncode==0,result.stderr
    observation=json.loads(result.stdout)
    assert observation["result_class"]==expected
    assert observation["probe_scope"]=="site-region"
