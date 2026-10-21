import json
import os
from pathlib import Path
import subprocess
from urllib.parse import parse_qs, urlsplit

import pytest

from node_health.config import AppConfig, InventoryConfig, ProbeConfig, load_config
from node_health.models import ClaudeResult, Node
from node_health.probe import CurlQuickProbe, HTTPResult, IPQualityAuditor


ROOT = Path(__file__).resolve().parents[1]
HEADER = ";; ->>HEADER<<- opcode: QUERY, status: {}, id: 1"
NEGATIVE = HEADER.format("NXDOMAIN")
POSITIVE = HEADER.format("NOERROR") + "\nx. 60 IN A 127.0.0.2"


def config(**kwargs):
    return AppConfig(InventoryConfig("https://inventory.invalid"),
                     probe=ProbeConfig(**kwargs))


def node():
    return Node("a" * 64, "sample", "other", {"name": "sample"})


def definitions():
    source = (ROOT / "ip.sh").read_text()
    return source[:source.rindex("\ngenerate_random_user_agent\nadapt_locale")]


def test_disabled_risk_capabilities_never_request_or_backoff_working_lite():
    probe = CurlQuickProbe(config(
        ipinfo_risk_enabled=False, ipapi_risk_enabled=False,
        geo_url_template="https://api.ipinfo.io/lite/{ip}",
    ))
    probe.begin_scan([20000])
    calls = []
    probe._http_get = lambda port, url, *_: (
        calls.append(url) or HTTPResult(0, 200, 1, '{"country_code":"US","asn":"AS15169"}'))
    for _ in range(2):
        risk = probe._claude_risk_intelligence(20000, "8.8.8.8")
        assert not risk["complete"]
        assert risk["risk_sources"] == risk["factors"] == {}
        assert all(error.startswith("provider_disabled ") for error in risk["errors"])
        probe._provider_get(20000, "https://api.ipinfo.io/lite/8.8.8.8",
                            resource_kind="geo", target_ip="8.8.8.8")
    assert calls == ["https://api.ipinfo.io/lite/8.8.8.8"]
    diagnostics = probe.diagnostics()
    assert diagnostics["ipinfo-risk"]["disabled_skips"] == 2
    assert diagnostics["ipapi-risk"]["disabled_skips"] == 2
    assert diagnostics["api.ipinfo.io"]["complete_responses"] == 1
    assert diagnostics["api.ipinfo.io"]["cache_hits"] == 1
    assert not probe._provider_backoff


def test_lite_geo_token_is_encoded_and_never_becomes_risk_evidence():
    probe = CurlQuickProbe(config(
        geo_url_template="https://api.ipinfo.io/lite/{ip}",
        geo_token="synthetic token&x=1", samples=1,
        ipinfo_risk_enabled=False, ipapi_risk_enabled=False,
    ))
    calls = []
    def get(port, url, *_):
        calls.append(url)
        if "api.ipify.org" in url:
            body = '{"ip":"8.8.8.8"}'
        elif "api.ipinfo.io" in url:
            body = '{"country_code":"US","asn":"AS15169"}'
        elif "chatgpt.com" in url:
            body = "ip=8.8.8.8\nloc=US\nh=chatgpt.com\n"
        else:
            body = ""
        return HTTPResult(0, 200, 10, body, urlsplit(url).hostname or "")
    probe._http_get = get
    probe._check_claude = lambda *_: ClaudeResult()
    result = probe.check(node(), 20000)
    assert result.available and result.country == "US" and result.asn == "AS15169"
    url = next(url for url in calls if "api.ipinfo.io" in url)
    assert urlsplit(url).path == "/lite/8.8.8.8"
    assert parse_qs(urlsplit(url).query) == {"token": ["synthetic token&x=1"]}
    assert "synthetic" not in json.dumps(probe.diagnostics())
    assert not result.claude.risk_sources


@pytest.mark.parametrize("field,value", [
    ("ipinfo_risk_enabled", '"false"'), ("ipapi_risk_enabled", "0"),
    ("geo_token", "42"), ("dnsbl_server", "53"),
    ("dnsbl_server", '"resolver.invalid"'), ("dnsbl_server", '"@1.1.1.1 -p 0"'),
    ("dnsbl_port", "0"), ("dnsbl_port", "65536"), ("dnsbl_port", "true"),
    ("dnsbl_port", '"53"'), ("dnsbl_concurrency", "0"),
    ("dnsbl_concurrency", "51"), ("dnsbl_concurrency", "1.5"),
    ("ipapi_proxy_url", "false"), ("ipapi_proxy_url", "null"),
    ("ipapi_proxy_url", '"file:///tmp/proxy"'),
    ("ipapi_proxy_url", '"socks5h://proxy.invalid"'),
    ("ipapi_proxy_url", '"socks5h://proxy.invalid:0"'),
    ("ipapi_proxy_url", '"http://proxy.invalid:70000"'),
    ("ipapi_proxy_url", '"http://proxy.invalid:8080/path"'),
    ("ipapi_proxy_url", '"http://proxy.invalid:8080?key=bad"'),
])
def test_provider_config_rejects_invalid_values(tmp_path, field, value):
    path = tmp_path / "config.yaml"
    path.write_text(f"inventory:\n  url: https://inventory.invalid\nprobe:\n  {field}: {value}\n")
    with pytest.raises(ValueError, match=field):
        load_config(path)


def test_dnsbl_custom_port_requires_explicit_resolver(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("inventory:\n  url: https://inventory.invalid\nprobe:\n  dnsbl_port: 1053\n")
    with pytest.raises(ValueError, match="dnsbl_server"):
        load_config(path)


def test_full_worker_receives_same_capability_flags_credentials_and_dns(monkeypatch):
    captured = {}
    def run(*args, **kwargs):
        captured.update(kwargs["env"])
        return subprocess.CompletedProcess(args, 0, '{"Head":{"IP":"8.8.8.8"},"Score":{}}', "")
    monkeypatch.setattr("node_health.probe.subprocess.run", run)
    auditor = IPQualityAuditor(config(
        ipinfo_risk_enabled=False, ipapi_risk_enabled=False,
        claude_ipapi_key="synthetic key&x", dnsbl_server="2001:db8::53",
        dnsbl_port=1053, dnsbl_concurrency=7,
        ipapi_proxy_url="socks5h://lookup.invalid:1080",
    ))
    auditor.check(node(), 20000)
    assert captured["IPQUALITY_IPINFO_ENABLED"] == captured["IPQUALITY_IPAPI_ENABLED"] == "0"
    assert captured["IPAPI_KEY"] == "synthetic key&x"
    assert captured["IPQUALITY_DNSBL_SERVER"] == "2001:db8::53"
    assert captured["IPQUALITY_DNSBL_PORT"] == "1053"
    assert captured["IPQUALITY_DNSBL_CONCURRENCY"] == "7"
    assert captured["IPQUALITY_IPAPI_PROXY_URL"] == "socks5h://lookup.invalid:1080"


@pytest.mark.parametrize("response_ip", ["9.9.9.9", "", None, "not-an-ip"])
def test_configured_query_transport_rejects_wrong_or_missing_target_ip(response_ip):
    probe = CurlQuickProbe(config(ipinfo_risk_enabled=False,
                                 ipapi_proxy_url="socks5h://lookup.invalid:1080"))
    probe._http_get = lambda *args, **kwargs: HTTPResult(
        0, 200, 1, json.dumps({"ip": response_ip, "company": {"abuser_score": "0 (Very Low)"}}))
    result = probe._claude_risk_intelligence(20000, "8.8.8.8")
    assert not result["risk_sources"]
    assert not probe._provider_cache
    assert any(error.startswith("provider_invalid_response ") for error in result["errors"])


def test_configured_query_transport_is_only_used_for_ipapi_metadata():
    proxy = "socks5h://lookup.invalid:1080"
    probe = CurlQuickProbe(config(ipinfo_risk_enabled=False, ipapi_proxy_url=proxy))
    calls = []
    def http(port, url, timeout=None, **kwargs):
        calls.append((port, url, kwargs))
        return HTTPResult(0, 200, 1, json.dumps({
            "ip": "8.8.8.8", "company": {"abuser_score": "0 (Very Low)"},
            "location": {"country_code": "US"},
        }))
    probe._http_get = http
    result = probe._claude_risk_intelligence(20000, "8.8.8.8")
    assert result["risk_sources"] == {"ipapi": "very low"}
    probe._get(20000, "https://site.invalid")
    assert calls[0][2] == {"proxy_url": proxy}
    assert calls[1][2] == {}
    diagnostics = probe.diagnostics()
    assert diagnostics["api.ipapi.is"]["query_transport"] == "configured-proxy"
    assert "lookup.invalid" not in json.dumps(diagnostics)


def test_one_configured_transport_uses_one_route_cooldown_across_nodes_and_scans():
    probe = CurlQuickProbe(config(ipinfo_risk_enabled=False,
                                 ipapi_proxy_url="socks5h://lookup.invalid:1080"))
    calls = []
    probe._http_get = lambda *args, **kwargs: (calls.append(args) or HTTPResult(35, 0, 1))
    probe.begin_scan([20000, 20001])
    probe._claude_risk_intelligence(20000, "8.8.8.8")
    probe._claude_risk_intelligence(20001, "1.1.1.1")
    probe.begin_scan([20002])
    probe._claude_risk_intelligence(20002, "9.9.9.9")
    assert len(calls) == 1


def test_configured_transport_cannot_be_bypassed_by_no_proxy(monkeypatch):
    probe = CurlQuickProbe(config())
    captured = []
    def run(command, **kwargs):
        captured.append(command)
        return subprocess.CompletedProcess(command, 0, "200\nhttps://api.ipapi.is/", "")
    monkeypatch.setenv("NO_PROXY", "*")
    monkeypatch.setattr("node_health.probe.subprocess.run", run)
    probe._http_get(20000, "https://api.ipapi.is/", proxy_url="socks5h://lookup.invalid:1080")
    command = captured[0]
    assert command[command.index("--proxy") + 1] == "socks5h://lookup.invalid:1080"
    assert command[command.index("--noproxy") + 1] == ""


def test_disabled_real_shell_sources_clear_prior_facts_without_network(tmp_path):
    calls = tmp_path / "calls"
    shell = definitions() + r'''
curl(){ printf 'unexpected\n' >>"$CALLS"; return 1; }
ipinfo[proxy]=true
ipapi[score]=0
db_ipinfo
db_ipapi
[[ ${#ipinfo[@]} == 0 && ${#ipapi[@]} == 0 ]] || exit 9
'''
    result = subprocess.run(["bash", "-c", shell], capture_output=True, text=True, timeout=10,
                            env=dict(os.environ, CALLS=str(calls), IPQUALITY_IPINFO_ENABLED="0",
                                     IPQUALITY_IPAPI_ENABLED="0"))
    assert result.returncode == 0, result.stderr
    assert not calls.exists()


def test_enabled_shell_ipapi_uses_encoded_configured_key(tmp_path):
    calls = tmp_path / "calls"
    shell = definitions() + r'''
IP=8.8.8.8
CurlARG=""
show_progress_bar(){ :; }
kill_progress_bar(){ :; }
curl(){ printf '%s\n' "$@" >"$CALLS"; printf '{"error":true}'; }
db_ipapi || :
'''
    result = subprocess.run(["bash", "-c", shell], capture_output=True, text=True, timeout=10,
                            env=dict(os.environ, CALLS=str(calls), IPAPI_KEY="synthetic & key",
                                     IPQUALITY_IPAPI_ENABLED="1"))
    assert result.returncode == 0, result.stderr
    url = calls.read_text().splitlines()[-1]
    assert parse_qs(urlsplit(url).query) == {"q": ["8.8.8.8"], "key": ["synthetic & key"]}


@pytest.mark.parametrize("response_ip,accepted", [("8.8.8.8", True), ("9.9.9.9", False), ("", False)])
def test_real_shell_configured_lookup_is_bound_to_requested_ip(tmp_path, response_ip, accepted):
    calls = tmp_path / "calls"
    shell = definitions() + r'''
IP=8.8.8.8
CurlARG="-x socks5h://measured.invalid:20000"
show_progress_bar(){ :; }
kill_progress_bar(){ :; }
curl(){ printf '%s\n' "$@" >"$CALLS"; printf '%s' "$RESPONSE"; }
db_ipapi || :
[[ $CurlARG == "-x socks5h://measured.invalid:20000" ]] || exit 8
printf '%s\n' "${ipapi[scorenum]:-missing}"
'''
    result = subprocess.run(["bash", "-c", shell], capture_output=True, text=True, timeout=10,
                            env=dict(os.environ, CALLS=str(calls), RESPONSE=json.dumps({
                                "ip": response_ip, "company": {"abuser_score": "0 (Very Low)"}}),
                                IPQUALITY_IPAPI_PROXY_URL="socks5h://lookup.invalid:1080",
                                IPQUALITY_IPAPI_ENABLED="1"))
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == ("0" if accepted else "missing")
    args = calls.read_text().splitlines()
    assert args[args.index("--proxy") + 1] == "socks5h://lookup.invalid:1080"
    assert args[args.index("--noproxy") + 1] == ""


def dnsbl(tmp_path, target, *, positive=POSITIVE, negative=NEGATIVE,
          zone="test.invalid", target_exit=0, server="192.0.2.53", port="1053"):
    source = (ROOT / "ip.sh").read_text()
    function = source[source.index("check_dnsbl_parallel(){"):source.index("\ncheck_dnsbl(){")]
    calls = tmp_path / "dns-calls"
    shell = r'''
declare -A smail
read_dnsbl_zones(){ printf '%s\n' "$ZONE"; }
filter_dnsbl_zones(){ cat; }
dig(){
printf '%s\n' "$*" >>"$CALLS"
case "${@: -2:1}" in
2.0.0.127.*)printf '%s\n' "$POSITIVE";;
1.0.0.127.*)printf '%s\n' "$NEGATIVE";;
*)printf '%s\n' "$TARGET"; return "$TARGET_EXIT";;
esac
}
export -f dig
''' + function + "\ncheck_dnsbl_parallel 8.8.8.8 1\n"
    result = subprocess.run(["bash", "-c", shell], capture_output=True, text=True, timeout=5,
                            env=dict(os.environ, ZONE=zone, CALLS=str(calls), POSITIVE=positive,
                                     NEGATIVE=negative, TARGET=target, TARGET_EXIT=str(target_exit),
                                     IPQUALITY_DNSBL_SERVER=server, IPQUALITY_DNSBL_PORT=port))
    assert result.returncode == 0, result.stderr
    return list(map(int, result.stdout.split())), calls.read_text().splitlines() if calls.exists() else []


@pytest.mark.parametrize("target,expected", [
    (NEGATIVE, [1, 1, 0, 0, 0]),
    (POSITIVE, [1, 0, 0, 1, 0]),
    (HEADER.format("NOERROR") + "\nx. 60 IN A 198.18.0.8", [1, 0, 1, 0, 0]),
    (HEADER.format("NOERROR") + "\nx. 60 IN A 127.255.255.254", [1, 0, 0, 0, 1]),
    (HEADER.format("NOERROR") + "\nx. 60 IN A 127.255.255.255", [1, 0, 0, 0, 1]),
    (HEADER.format("REFUSED"), [1, 0, 0, 0, 1]),
    (HEADER.format("SERVFAIL"), [1, 0, 0, 0, 1]),
    (POSITIVE + "\nx. 60 IN A 198.18.0.8", [1, 0, 1, 0, 0]),
    (POSITIVE + "\nx. 60 IN A 127.255.255.254", [1, 0, 0, 0, 1]),
])
def test_dnsbl_real_shell_uses_explicit_resolver_and_classifies_target(tmp_path, target, expected):
    counts, calls = dnsbl(tmp_path, target)
    assert counts == expected
    assert len(calls) == 3
    assert all("@192.0.2.53 -p 1053" in call for call in calls)


@pytest.mark.parametrize("positive,negative", [
    (NEGATIVE, NEGATIVE),  # retired zone
    (POSITIVE, POSITIVE),  # wildcard
    (HEADER.format("NOERROR") + "\nx. 60 IN A 198.18.0.8", NEGATIVE),
])
def test_unverified_dnsbl_zones_cannot_claim_clean_or_blacklisted(tmp_path, positive, negative):
    counts, calls = dnsbl(tmp_path, POSITIVE, positive=positive, negative=negative)
    assert counts == [1, 0, 1, 0, 0]
    assert not any("8.8.8.8." in call for call in calls)


def test_dnsbl_refused_control_stops_without_querying_target(tmp_path):
    counts, calls = dnsbl(tmp_path, NEGATIVE,
                         positive=HEADER.format("NOERROR") + "\nx. 60 IN A 127.255.255.254")
    assert counts == [1, 0, 0, 0, 1] and len(calls) == 1


@pytest.mark.parametrize("address,expected", [
    ("127.0.0.3", [1, 0, 0, 1, 0]),
    ("127.0.0.4", [1, 0, 0, 1, 0]),
    ("127.0.0.9", [1, 0, 0, 1, 0]),
    ("127.0.0.10", [1, 0, 1, 0, 0]),  # non-mail-sender policy, not abuse
    ("127.0.0.11", [1, 0, 1, 0, 0]),
])
def test_spamhaus_security_and_policy_codes_are_not_conflated(tmp_path, address, expected):
    counts, _ = dnsbl(tmp_path, HEADER.format("NOERROR") + "\nx. 60 IN A " + address,
                      zone="zen.spamhaus.org")
    assert counts == expected


def test_dnsbl_target_transport_failure_is_not_clean(tmp_path):
    counts, _ = dnsbl(tmp_path, "", target_exit=9)
    assert counts == [1, 0, 0, 0, 1]


def test_bad_dnsbl_settings_do_not_silently_fall_back_to_system_dns(tmp_path):
    counts, calls = dnsbl(tmp_path, NEGATIVE, server="", port="1053")
    assert counts == [1, 0, 0, 0, 1] and not calls
