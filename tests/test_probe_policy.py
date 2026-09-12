import json
import shutil
import subprocess
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from node_health.config import AppConfig, InventoryConfig, PolicyConfig, ProbeConfig
from node_health.models import ClaudeResult, FullResult, Node, QuickResult, SiteProbeResult
from node_health.policy import (
    chatgpt_explicitly_allowed,
    evaluate_node,
    full_has_confirmed_redline,
    residential_profile,
    score_node,
    select_full_audit_nodes,
    attach_quick_ai_evidence,
    sample_qualified,
)
from node_health.probe import (
    BUNDLED_DNSBL_FILE,
    CurlQuickProbe,
    IPQualityAuditor,
    MihomoProbeEnvironment,
    generate_mihomo_probe_config,
    normalize_ipquality,
    preserve_sidecar_controller,
    HTTPResult,
    _retry_after_seconds,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
REAL_HTTP_GET = CurlQuickProbe._http_get


@pytest.fixture(autouse=True)
def prohibit_live_probe_http(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("live probe HTTP is forbidden in unit tests")
    monkeypatch.setattr(CurlQuickProbe, "_http_get", blocked)


def site(host="chatgpt.com", ip="8.8.8.8", country="US", result="available"):
    return SiteProbeResult(attempted=True, result_class=result, probe_contract_version=1,
                           observation_id=f"fixture-{host}-{ip}-{country}-{result}",
                           exit_ip=ip, country=country, host=host, http_status=200,
                           checked_at="2026-07-24T00:00:00+00:00")


def full_result(*args, **kwargs):
    kwargs.setdefault("risk_evidence_version", 1)
    return FullResult(*args, **kwargs)


def mock_http(probe, get):
    def response(port, url, timeout=None):
        try:
            body, elapsed = get(port, url, timeout)
        except Exception:
            return HTTPResult(1, 0, 1.0)
        host = urllib.parse.urlsplit(url).hostname or ""
        if body.startswith("ip=") and "\nh=" not in body:
            body += f"h={host}\n"
        return HTTPResult(0, 200, elapsed, body, host)
    probe._http_get = response


def test_json_output_preserves_escapes_and_rejects_an_internal_head():
    from node_health.probe import _extract_json
    script = (PROJECT_ROOT / "ip.sh").read_text()
    emit = next(line for line in script.splitlines() if line.startswith('[[ mode_json -eq 1 ]]'))
    original = {"Head": {"IP": "8.8.8.8"}, "Score": {}, "Info": {"Organization": "line one\nline two"}}
    result = subprocess.run(["bash", "-c", 'mode_json=1; ipjson="$1"\n' + emit, "_", json.dumps(original)], capture_output=True, text=True, check=True)
    assert json.loads(result.stdout) == original
    malformed = json.dumps(original).replace('line one\\nline two', 'line one\nline two')
    assert _extract_json(malformed) is None


@pytest.mark.parametrize("response", [
    {"error": "rate limit exceeded"}, {}, {"company": {"abuser_score": None}},
    {"company": {"abuser_score": "invalid"}}, {"company": {"abuser_score": "2.0 (High)"}},
])
def test_bash_ipapi_errors_never_create_zero_risk(response):
    if not shutil.which("bash") or not shutil.which("jq"):
        pytest.skip("bash and jq required")
    script = (PROJECT_ROOT / "ip.sh").read_text()
    function = script[script.index('db_ipapi(){'):script.index('\ndb_abuseipdb(){')]
    setup = '''declare -A sinfo stype sscore ipapi
IP=8.8.8.8
payload="$1"
show_progress_bar(){ return 0; }
kill_progress_bar(){ return 0; }
curl(){ printf '%s\\n' "$payload"; }
'''
    result = subprocess.run(["bash", "-c", setup + function + '\ndb_ipapi 4\nprintf "%s" "${ipapi[score]}"', "_", json.dumps(response)], capture_output=True, text=True, check=True)
    assert result.stdout == ""


def test_full_timeout_keeps_partial_diagnostics_without_claiming_completion():
    config = AppConfig(inventory=InventoryConfig("https://inventory.invalid"))
    def timeout(command, **kwargs):
        checkpoint = Path(kwargs["env"]["IPQUALITY_CHECKPOINT_FILE"])
        checkpoint.write_text(json.dumps({"Head": {"IP": "8.8.8.8"}, "Score": {"a": "low"}, "Automation": {"stage": "risk"}}))
        raise subprocess.TimeoutExpired(command, 300)
    with patch("node_health.probe.subprocess.run", side_effect=timeout):
        result = IPQualityAuditor(config).check(node("a"), 20000)
    assert not result.completed
    assert result.details["Automation"]["stage"] == "risk"
    assert result.audited_exit_ip == "8.8.8.8"


def test_automation_shell_emits_complete_json_and_phase_checkpoints(tmp_path):
    if not shutil.which("bash") or not shutil.which("jq"):
        pytest.skip("bash and jq required")
    script = (PROJECT_ROOT / "ip.sh").read_text()
    definitions = script[:script.rindex('\ngenerate_random_user_agent\nadapt_locale')]
    runner = tmp_path / "automation.sh"
    runner.write_text(definitions + r'''
IPQUALITY_AUTOMATION=1
IPQUALITY_CHECKPOINT_FILE="$1"
IPQUALITY_SKIP_MAIL=1
mode_json=1
mode_privacy=1
mode_lite=0
fullIP=1
for function in hide_ipv4 countRunTimes db_maxmind db_ipinfo db_scamalytics db_ipregistry db_ipapi db_abuseipdb db_ip2location db_dbip db_ipdata db_ipqs skip_mail check_dnsbl show_head show_basic show_type show_score show_factor show_media show_mail show_tail; do
  eval "$function(){ :; }"
done
OpenAITest(){ chatgpt[status]=Yes; }
for function in MediaUnlockTest_TikTok MediaUnlockTest_DisneyPlus MediaUnlockTest_Netflix MediaUnlockTest_YouTube_Premium MediaUnlockTest_PrimeVideo_Region MediaUnlockTest_Reddit; do
  eval "$function(){ echo unexpected-media-call >&2; }"
done
check_IP 8.8.8.8 4
''')
    checkpoint = tmp_path / "partial.json"
    result = subprocess.run(["bash", str(runner), str(checkpoint)], capture_output=True, text=True, timeout=15, check=True)
    completed = json.loads(result.stdout)
    partial = json.loads(checkpoint.read_text())
    assert completed["Head"]["IP"] == "8.8.8.8"
    assert completed["Automation"]["complete"] is True
    assert set(completed["Automation"]["stage_elapsed_seconds"]) == {"risk", "ai", "dnsbl"}
    assert partial["Automation"]["complete"] is False
    assert partial["Automation"]["stage"] == "dnsbl"
    assert "unexpected-media-call" not in result.stderr


def test_provider_cache_is_target_specific_and_fresh_for_each_scan():
    probe = CurlQuickProbe(AppConfig(inventory=InventoryConfig("https://inventory.invalid")))
    calls = []
    def get(port, url, timeout=None):
        calls.append(url)
        return '{"country_code":"US"}', 1.0
    mock_http(probe, get)
    probe._provider_get(20000, "https://geo.invalid/8.8.8.8")
    probe._provider_get(20001, "https://geo.invalid/8.8.8.8")
    probe._provider_get(20001, "https://geo.invalid/1.1.1.1")
    assert len(calls) == 2
    assert probe.diagnostics()["geo.invalid"]["cache_hits"] == 1
    probe.begin_scan()
    probe._provider_get(20000, "https://geo.invalid/8.8.8.8")
    assert len(calls) == 3


def test_provider_quota_backoff_is_bounded_and_does_not_expose_credentials(monkeypatch):
    probe = CurlQuickProbe(AppConfig(inventory=InventoryConfig("https://inventory.invalid")))
    clock = [0.0]
    monkeypatch.setattr("node_health.probe.time.monotonic", lambda: clock[0])
    calls = []
    def fail(port, url, timeout=None):
        calls.append(url)
        return HTTPResult(0, 429, 1.0, "secret-token")
    probe._http_get = fail
    for url in ["https://geo.invalid/8.8.8.8", "https://geo.invalid/1.1.1.1"]:
        with pytest.raises(RuntimeError) as error:
            probe._provider_get(20000, url)
        assert "secret-token" not in str(error.value)
    assert len(calls) == 1
    clock[0] = 301
    with pytest.raises(RuntimeError):
        probe._provider_get(20000, "https://geo.invalid/1.1.1.1")
    assert len(calls) == 2


def test_failed_full_audits_do_not_starve_other_rotation_candidates():
    nodes = [Node(str(i), str(i), "us", {}) for i in range(10)]
    results = {n.key: QuickResult(True, exit_ip="8.8.8.8", claude=ClaudeResult(exit_ip="8.8.8.8")) for n in nodes}
    previous = {"stable_slots": {"us": {"1": "0", "2": "1", "3": "2"}}, "nodes": {
        n.key: {"last_exit_ip": "8.8.8.8", "last_claude": {"exit_ip": "8.8.8.8"},
                "last_risk_source_count": 3, "overall_grade": "A", "last_score": 100-int(n.key),
                "last_decision": "eligible", "last_full_checked_at": "2026-07-01T00:00:00+00:00",
                "last_full_attempt_at": "2026-07-23T00:00:00+00:00"} for n in nodes}}
    covered = set()
    for day in (24, 25):
        selected = select_full_audit_nodes("maintenance", nodes, results, previous, PolicyConfig(), datetime(2026, 7, day, tzinfo=timezone.utc))
        covered.update(selected)
        for key in selected:
            previous["nodes"][key]["last_full_attempt_at"] = f"2026-07-{day}T00:00:00+00:00"
    assert covered == set(results)


def node(key: str, name: str = "US") -> Node:
    return Node(
        key=key,
        name=name,
        region="united-states",
        proxy={"name": name, "type": "ss", "server": f"{key}.example", "port": 443},
    )


def quick(**overrides) -> QuickResult:
    values = {
        "available": True,
        "exit_ip": "8.8.8.8",
        "country": "US",
        "latency_ms": 100,
        "success_rate": 1,
        "success_count": 3,
        "sample_count": 3,
        "chatgpt": site(),
        "exit_ip_stable": True,
        "google_ok": True,
        "chatgpt_ok": True,
        "claude": ClaudeResult(
            status="available",
            trace_ok=True,
            anthropic_ok=True,
            exit_ip="8.8.8.8",
            country="US",
            supported=True,
            route_stable=True,
        ),
        "checked_at": "2026-07-24T00:00:00+00:00",
    }
    values.update(overrides)
    if "success_rate" in overrides and "success_count" not in overrides:
        values["success_count"] = round(float(overrides["success_rate"]) * 3)
    claude = values["claude"]
    claude.risk_evidence_version = 1
    if claude.status in {"available", "restricted"}:
        claude.site_probe = site("claude.ai", claude.exit_ip or values["exit_ip"], claude.country or "US", "restricted" if claude.status == "restricted" else "available")
        claude.anthropic_probe = site("www.anthropic.com", claude.exit_ip or values["exit_ip"])
    return QuickResult(**values)


def test_claude_split_route_collects_two_source_risk_intelligence():
    config = AppConfig(inventory=InventoryConfig("http://inventory.invalid"))
    probe = CurlQuickProbe(config)
    responses = {
        config.probe.claude_trace_url: "ip=1.1.1.1\nloc=US\n",
        config.probe.anthropic_trace_url: "ip=1.1.1.1\nloc=US\n",
        config.probe.claude_ipinfo_url_template.format(ip="1.1.1.1"): json.dumps(
            {
                "data": {
                    "asn": {"asn": "AS13335", "name": "Cloudflare", "type": "isp"},
                    "company": {"name": "Cloudflare", "type": "isp"},
                    "privacy": {"proxy": False, "vpn": False, "tor": False, "hosting": False},
                }
            }
        ),
        config.probe.claude_ipapi_url_template.format(ip="1.1.1.1"): json.dumps(
            {
                "asn": {"asn": "AS13335", "type": "isp"},
                "company": {"name": "Cloudflare", "type": "isp", "abuser_score": "0.1016 (High)"},
                "location": {"country_code": "US"},
                "is_proxy": False,
                "is_vpn": False,
                "is_tor": False,
                "is_datacenter": False,
                "is_abuser": False,
                "is_crawler": False,
            }
        ),
    }

    mock_http(probe, lambda _port, url, _timeout=None: (responses[url], 1.0))
    result = probe._check_claude(20000, "8.8.8.8")

    assert result.status == "available"
    assert result.exit_ip == "1.1.1.1"
    assert result.country == "US"
    assert result.supported is True
    assert result.intelligence_complete is True
    assert result.asn == "AS13335"
    assert result.residential == "confirmed"
    assert set(result.risk_sources) == {"IPinfo-privacy", "ipapi"}
    assert result.risk_sources["ipapi"] == "high"


def test_claude_trace_country_is_not_overwritten_by_risk_provider_country():
    config = AppConfig(inventory=InventoryConfig("http://inventory.invalid"))
    probe = CurlQuickProbe(config)
    responses = {
        config.probe.claude_trace_url: "ip=1.1.1.1\nloc=US\n",
        config.probe.anthropic_trace_url: "ip=1.1.1.1\nloc=US\n",
        config.probe.claude_ipinfo_url_template.format(ip="1.1.1.1"): json.dumps(
            {
                "country_code": "CN",
                "is_anonymous": False,
                "is_hosting": False,
            }
        ),
        config.probe.claude_ipapi_url_template.format(ip="1.1.1.1"): json.dumps(
            {"cc": "CN", "is_proxy": False, "is_vpn": False}
        ),
    }
    mock_http(probe, lambda _port, url, _timeout=None: (responses[url], 1.0))

    result = probe._check_claude(20000, "8.8.8.8")

    assert result.status == "available"
    assert result.country == "US"
    assert result.supported is True
    assert result.intelligence_country == "CN"


def test_claude_ipapi_anonymous_response_shape_is_usable_without_an_api_key():
    config = AppConfig(inventory=InventoryConfig("http://inventory.invalid"))
    probe = CurlQuickProbe(config)

    def fake_get(_port, url, _timeout=None):
        if "ipinfo.io" in url:
            raise RuntimeError("rate limited")
        return (
            json.dumps(
                {
                    "ip": "82.66.115.249",
                    "is_datacenter": False,
                    "is_tor": False,
                    "is_proxy": False,
                    "is_vpn": False,
                    "is_abuser": False,
                    "company_name": "Proxad / Free SAS",
                    "asn_num": 12322,
                    "asn_org": "Free SAS",
                    "cc": "FR",
                }
            ),
            1.0,
        )

    mock_http(probe, fake_get)
    result = probe._claude_risk_intelligence(20000, "82.66.115.249")

    assert result["complete"] is False
    assert result["asn"] == "AS12322"
    assert result["organization"] == "Proxad / Free SAS"
    assert result["country"] == "FR"
    assert result["risk_sources"] == {"ipapi-flags": "low"}


def test_claude_provider_response_without_risk_fields_does_not_invent_low_risk():
    config = AppConfig(inventory=InventoryConfig("http://inventory.invalid"))
    probe = CurlQuickProbe(config)

    def fake_get(_port, url, _timeout=None):
        if "ipinfo.io" in url:
            return json.dumps({"asn": "AS12322", "as_name": "Free SAS", "country_code": "FR"}), 1.0
        return json.dumps({"company": {"name": "Free SAS"}, "asn": {"asn": "AS12322"}, "cc": "FR"}), 1.0

    mock_http(probe, fake_get)
    result = probe._claude_risk_intelligence(20000, "82.66.115.249")

    assert result["complete"] is False
    assert result["risk_sources"] == {}


def test_claude_risk_provider_credentials_are_appended_without_entering_templates():
    config = AppConfig(
        inventory=InventoryConfig("http://inventory.invalid"),
        probe=ProbeConfig(claude_ipinfo_token="info secret", claude_ipapi_key="api secret"),
    )
    probe = CurlQuickProbe(config)
    urls = []

    def fake_get(_port, url, _timeout=None):
        urls.append(url)
        if "ipinfo.io" in url:
            return json.dumps({"is_anonymous": False, "is_hosting": False}), 1.0
        return json.dumps({"is_proxy": False}), 1.0

    mock_http(probe, fake_get)
    probe._claude_risk_intelligence(20000, "8.8.8.8")

    assert any("token=info+secret" in url for url in urls)
    assert any("key=api+secret" in url for url in urls)


@pytest.mark.parametrize(
    ("claude_body", "anthropic_error", "expected"),
    [
        ("ip=8.8.8.8\nloc=CN\n", None, "restricted"),
        ("ip=8.8.8.8\nloc=US\n", RuntimeError("connection refused"), "degraded"),
        (RuntimeError("connection refused"), RuntimeError("connection refused"), "unknown"),
        (RuntimeError("curl exited 28"), RuntimeError("curl exited 28"), "unknown"),
        (RuntimeError("HTTP 503"), RuntimeError("HTTP 503"), "unknown"),
        (RuntimeError("HTTP 429"), RuntimeError("HTTP 429"), "unknown"),
    ],
)
def test_claude_status_classification(claude_body, anthropic_error, expected):
    config = AppConfig(inventory=InventoryConfig("http://inventory.invalid"))
    probe = CurlQuickProbe(config)

    def fake_get(_port, url, _timeout=None):
        if url == config.probe.claude_trace_url:
            if isinstance(claude_body, Exception):
                raise claude_body
            return claude_body, 1.0
        if url == config.probe.anthropic_trace_url:
            if anthropic_error is not None:
                raise anthropic_error
            return "ok=1\n", 1.0
        raise AssertionError(f"unexpected URL: {url}")

    mock_http(probe, fake_get)
    assert probe._check_claude(20000, "8.8.8.8").status == expected


def test_probe_config_preserves_names_and_dialer_references():
    base = node("a", "base")
    chained = Node(
        key="b",
        name="chain",
        region="united-states",
        proxy={
            "name": "chain",
            "type": "ss",
            "server": "chain.example",
            "port": 443,
            "dialer-proxy": "base",
        },
    )
    config, ports = generate_mihomo_probe_config([base, chained], 20000)
    assert [item["name"] for item in config["proxies"]] == ["base", "chain"]
    assert config["proxies"][1]["dialer-proxy"] == "base"
    assert ports == {"a": 20000, "b": 20001}


def test_probe_config_disambiguates_names_but_rejects_ambiguous_dependencies():
    first = node("a", "duplicate")
    second = Node("b", "duplicate", "united-states", {"name": "duplicate", "type": "ss"})
    config, ports = generate_mihomo_probe_config([first, second])
    assert len(config["proxies"]) == len(ports) == 2
    assert len({item["name"] for item in config["proxies"]}) == 2
    chained = Node("c", "chain", "united-states", {"name":"chain", "dialer-proxy":"duplicate"})
    with pytest.raises(ValueError, match="ambiguous proxy dependency"):
        generate_mihomo_probe_config([first, second, chained])


def test_sidecar_reload_keeps_controller_available_for_next_day():
    config, _ = generate_mihomo_probe_config([node("a")], listener_host="0.0.0.0")
    preserve_sidecar_controller(config, "0.0.0.0:9090", "controller-secret")
    assert config["external-controller"] == "0.0.0.0:9090"
    assert config["secret"] == "controller-secret"
    assert config["allow-lan"] is True


def test_sidecar_sends_credentials_only_in_controller_payload(tmp_path):
    config = AppConfig(
        inventory=InventoryConfig("http://inventory.invalid"),
        probe=ProbeConfig(controller_url="http://mihomo-probe:9090"),
    )
    environment = MihomoProbeEnvironment(config)
    session = environment._open_sidecar({"proxies": [{"password": "secret"}]}, {"a": 20000})
    captured = {}

    def reject(request, **_kwargs):
        captured.update(json.loads(request.data.decode("utf-8")))
        raise RuntimeError("controller offline")

    with patch("urllib.request.urlopen", side_effect=reject):
        with pytest.raises(RuntimeError, match="controller offline"):
            next(session)
    assert "path" not in captured
    assert "password: secret" in captured["payload"]
    assert not (tmp_path / ".probe.yaml.tmp").exists()
    assert not (tmp_path / "probe.yaml").exists()


def test_full_auditor_uses_bundled_dnsbl_file():
    config = AppConfig(
        inventory=InventoryConfig("http://inventory.invalid"),
        probe=ProbeConfig(proxy_host="mihomo-probe"),
    )
    completed = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout='{"Head":{"IP":"8.8.8.8"},"Score":{},"Factor":{},"Mail":{"DNSBlacklist":{"Blacklisted":0}}}',
        stderr="",
    )
    with patch("node_health.probe.subprocess.run", return_value=completed) as run:
        assert IPQualityAuditor(config).check(node("a"), 20000).completed

    environment = run.call_args.kwargs["env"]
    assert environment["IPQUALITY_AUTOMATION"] == "1"
    assert environment["IPQUALITY_SKIP_MAIL"] == "1"
    assert environment["IPQUALITY_DNSBL_FILE"] == BUNDLED_DNSBL_FILE
    assert BUNDLED_DNSBL_FILE == "/app/ref/dnsbl.list"


def test_quick_http_get_rejects_http_error_responses(monkeypatch):
    config = AppConfig(inventory=InventoryConfig("http://inventory.invalid"))
    failed = subprocess.CompletedProcess(
        args=[], returncode=22, stdout="error page", stderr="curl: (22) HTTP 503"
    )
    monkeypatch.setattr(CurlQuickProbe, "_http_get", REAL_HTTP_GET)
    with patch("node_health.probe.subprocess.run", return_value=failed) as run:
        with pytest.raises(RuntimeError, match="probe_failed"):
            CurlQuickProbe(config)._get(20000, "https://claude.ai/cdn-cgi/trace")

    assert "--max-filesize" in run.call_args.args[0]


def test_full_auditor_keeps_valid_json_as_partial_on_exit_one():
    config = AppConfig(
        inventory=InventoryConfig("http://inventory.invalid"),
        probe=ProbeConfig(proxy_host="mihomo-probe"),
    )
    completed = subprocess.CompletedProcess(
        args=[],
        returncode=1,
        stdout=(
            'progress before JSON\n'
            '{"Head":{"IP":"8.8.8.8"},"Score":{},"Factor":{},'
            '"Mail":{"DNSBlacklist":{"Blacklisted":0}}}'
        ),
        stderr="legacy ip.sh exits one after valid IPv4 output",
    )

    with patch("node_health.probe.subprocess.run", return_value=completed) as run:
        result = IPQualityAuditor(config).check(node("a"), 20000)

    assert not result.completed
    assert result.audited_exit_ip == "8.8.8.8"
    assert "-E" in run.call_args.args[0]


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash is required for shell filter test")
def test_dnsbl_zone_filter_rejects_shell_text_and_normalizes_valid_zones():
    script = (PROJECT_ROOT / "ip.sh").read_text(encoding="utf-8")
    start = script.index("filter_dnsbl_zones(){")
    end = script.index("\n}\ncheck_dnsbl_parallel(){", start) + 2
    function = script[start:end]
    zones = "\n".join(
        [
            "zen.spamhaus.org",
            " DNSBL.EXAMPLE. ",
            "fresh.sa_slip.rbl.arix.com",
            "evil.$(touch injected)",
            "zone;id",
            "-bad.example",
            "bad-.example",
            "hostkarma.junkemailfilter.com[brl]",
            "a" * 64 + ".example",
        ]
    )
    result = subprocess.run(
        ["bash", "-c", f"{function}\nfilter_dnsbl_zones"],
        input=zones,
        capture_output=True,
        text=True,
        check=True,
    )

    assert result.stdout.splitlines() == [
        "zen.spamhaus.org",
        "dnsbl.example",
        "fresh.sa_slip.rbl.arix.com",
    ]
    assert "reversed_ip.{}" not in script


def test_docker_build_includes_only_the_bundled_dnsbl_reference():
    dockerignore = (PROJECT_ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    dockerfile = (PROJECT_ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "ref/*" in dockerignore
    assert "!ref/dnsbl.list" in dockerignore
    assert "ref/" not in dockerignore
    assert "COPY ref/dnsbl.list /app/ref/dnsbl.list" in dockerfile


def test_normalize_real_ipquality_shape():
    result = normalize_ipquality(
        {
            "Score": {"scamalytics": "85%", "ipapi": "high"},
            "Factor": {
                "Tor": {"one": False, "two": True},
                "Proxy": True,
                "VPN": False,
                "Server": True,
            },
            "Mail": {"DNSBlacklist": {"Blacklisted": 2}},
        }
    )
    assert result.tor is True
    assert result.dnsbl_blacklisted is True
    assert result.dnsbl_listed_count == 2
    assert result.risk_sources == {"scamalytics": "85%", "ipapi": "high"}
    assert {"proxy", "server"}.issubset(result.labels)

    clean = normalize_ipquality(
        {"Mail": {"DNSBlacklist": {"Blacklisted": "false"}}}
    )
    assert clean.dnsbl_blacklisted is False
    assert clean.dnsbl_listed_count == 0


def test_dnsbl_requires_multiple_listings_for_a_confirmed_redline():
    policy = PolicyConfig(
        expected_country={"united-states": "US"},
        dnsbl_redline_threshold=3,
    )
    common = {
        "completed": True,
        "risk_sources": {"one": "low", "two": "low", "three": "low"},
        "details": {"Media": {"ChatGPT": {"Status": "Yes"}}},
    }
    single = full_result(
        **common,
        dnsbl_blacklisted=True,
        dnsbl_listed_count=1,
    )
    confirmed = full_result(
        **common,
        dnsbl_blacklisted=True,
        dnsbl_listed_count=3,
    )

    single_evaluation = evaluate_node(node("a"), quick(), single, policy, 2)
    confirmed_evaluation = evaluate_node(node("a"), quick(), confirmed, policy, 2)

    assert single_evaluation.eligible
    assert "dnsbl-listed:1" in single_evaluation.reasons
    assert not full_has_confirmed_redline(single, policy)
    assert confirmed_evaluation.redline
    assert "dnsbl-redline:3>=3" in confirmed_evaluation.reasons
    assert full_has_confirmed_redline(confirmed, policy)

    relaxed = PolicyConfig(
        expected_country={"united-states": "US"},
        dnsbl_redline_threshold=4,
    )
    relaxed_evaluation = evaluate_node(node("a"), quick(), confirmed, relaxed, 2)
    assert relaxed_evaluation.eligible
    assert "dnsbl-listed:3" in relaxed_evaluation.reasons
    assert not full_has_confirmed_redline(confirmed, relaxed)


def test_legacy_dnsbl_boolean_is_treated_as_one_listing():
    policy = PolicyConfig(expected_country={"united-states": "US"})
    full = full_result(
        completed=True,
        dnsbl_blacklisted=True,
        risk_sources={"one": "low", "two": "low", "three": "low"},
        details={"Media": {"ChatGPT": {"Status": "Yes"}}},
    )

    evaluation = evaluate_node(node("a"), quick(), full, policy, 2)

    assert evaluation.eligible
    assert "dnsbl-listed:1" in evaluation.reasons


def test_numeric_risk_scores_apply_a_continuous_penalty():
    policy = PolicyConfig(expected_country={"united-states": "US"})

    def scored(risk: int) -> float:
        return score_node(
            node("a"),
            quick(),
            full_result(
                completed=True,
                risk_sources={"one": str(risk), "two": f"{risk}%", "three": str(risk)},
            ),
            policy,
        )

    assert scored(5) > scored(70) > scored(74)
    assert scored(5) - scored(70) >= 10


@pytest.mark.parametrize(
    ("type_data", "expected_grade", "expected_points"),
    [
        (
            {
                "Usage": {"one": "Fixed Line ISP", "two": "Broadband"},
                "Company": {"one": "ISP"},
            },
            "confirmed",
            10,
        ),
        ({"Usage": {"one": "ISP", "two": "ISP"}}, "probable", 5),
        ({"Usage": {"one": "Residential"}}, "probable", 5),
        ({"Company": {"one": "ISP"}}, "unknown", 0),
        (
            {
                "Usage": {"one": "Residential", "two": "Broadband"},
                "Company": {"three": "Hosting"},
            },
            "unknown",
            0,
        ),
    ],
)
def test_residential_evidence_levels(type_data, expected_grade, expected_points):
    grade, points, _ = residential_profile(
        full_result(completed=True, details={"Type": type_data})
    )
    assert grade == expected_grade
    assert points == expected_points


def test_geo_multi_source_country_consensus_receives_consistency_point():
    policy = PolicyConfig(expected_country={"united-states": "US"})
    evaluation = evaluate_node(
        node("a"),
        quick(),
        full_result(
            completed=True,
            risk_sources={"one": "low", "two": "low", "three": "low"},
            details={
                "Factor": {"CountryCode": {"one": "US", "two": "US", "three": "JP"}},
                "Info": {
                    "Region": {"Code": "US"},
                    "RegisteredRegion": {"Code": "US"},
                    "ASN": "AS15169",
                    "Organization": "Example ISP",
                },
                "Media": {"ChatGPT": {"Status": "Yes", "Region": "US"}},
            },
        ),
        policy,
        1,
    )
    assert evaluation.components["geo"] == 10


def test_chatgpt_split_route_needs_independent_same_exit_geography():
    evaluation = evaluate_node(
        node("a"),
        quick(country="US", chatgpt=site(ip="1.1.1.1", country="JP")),
        full_result(
            completed=True,
            risk_sources={"one": "low", "two": "low", "three": "low"},
            details={
                "Media": {
                    "ChatGPT": {"Status": "Yes", "Region": "JP", "Type": "Native"}
                }
            },
        ),
        PolicyConfig(),
        1,
    )

    assert evaluation.components["ai"] == 22


def test_crawler_only_is_a_small_penalty_but_not_a_risk_downgrade():
    policy = PolicyConfig(expected_country={"united-states": "US"})
    evaluation = evaluate_node(
        node("a"),
        quick(),
        full_result(
            completed=True,
            risk_sources={"one": "0", "two": "0", "three": "0"},
            details={
                "Factor": {"Robot": {"one": True}},
                "Media": {"ChatGPT": {"Status": "Yes", "Region": "US"}},
            },
        ),
        policy,
        2,
    )
    assert evaluation.risk_grade == "A"
    assert evaluation.components["risk"] == 24


def test_three_source_proxy_consensus_is_risk_c():
    policy = PolicyConfig(expected_country={"united-states": "US"})
    full = full_result(
        completed=True,
        risk_sources={"one": "low", "two": "low", "three": "low"},
        details={
            "Factor": {"Proxy": {"one": True, "two": True, "three": True}},
            "Media": {"ChatGPT": {"Status": "Yes"}},
        },
    )
    evaluation = evaluate_node(node("a"), quick(), full, policy, 2)
    assert evaluation.risk_grade == "C"
    assert evaluation.redline
    assert "risk-consensus-severe" in evaluation.reasons


def test_claude_route_evidence_does_not_fill_generic_risk_coverage():
    split = quick(
        claude=ClaudeResult(
            status="available",
            trace_ok=True,
            anthropic_ok=True,
            exit_ip="1.1.1.1",
            country="US",
            supported=True,
            intelligence_complete=True,
            risk_sources={"claude-one": "low", "claude-two": "low"},
        )
    )
    evaluation = evaluate_node(
        node("a"),
        split,
        full_result(completed=True, risk_sources={"generic-one": "low"}),
        PolicyConfig(expected_country={"united-states": "US"}),
        2,
    )

    assert evaluation.risk_grade == "B"
    assert evaluation.components["risk_source_count"] == 1
    assert "insufficient-risk-coverage:1/3" in evaluation.reasons
    assert "claude-insufficient-risk-coverage:2/2" not in evaluation.reasons


def test_clean_generic_and_claude_routes_are_independently_risk_a():
    split = quick(
        claude=ClaudeResult(
            status="available",
            trace_ok=True,
            anthropic_ok=True,
            exit_ip="1.1.1.1",
            country="US",
            supported=True,
            intelligence_complete=True,
            risk_sources={"claude-one": "low", "claude-two": "low"},
        )
    )
    evaluation = evaluate_node(
        node("a"),
        split,
        full_result(
            completed=True,
            risk_sources={"generic-one": "low", "generic-two": "low", "generic-three": "low"},
        ),
        PolicyConfig(expected_country={"united-states": "US"}),
        2,
    )

    assert evaluation.risk_grade == "A"


def test_high_risk_and_factor_consensus_do_not_cross_egress_routes():
    split = quick(
        claude=ClaudeResult(
            status="available",
            trace_ok=True,
            anthropic_ok=True,
            exit_ip="1.1.1.1",
            country="US",
            supported=True,
            intelligence_complete=True,
            risk_sources={"claude-high": "high", "claude-low": "low"},
            factors={"proxy": {"claude": True}},
        )
    )
    evaluation = evaluate_node(
        node("a"),
        split,
        full_result(
            completed=True,
            risk_sources={"generic-high": "high", "generic-low": "low", "generic-low-2": "low"},
            details={"Factor": {"Proxy": {"generic": True}}},
        ),
        PolicyConfig(expected_country={"united-states": "US"}),
        2,
    )

    assert evaluation.risk_grade == "B"
    assert not evaluation.redline
    assert not any("multiple-high-risk-sources" in reason for reason in evaluation.reasons)
    assert "risk-consensus-severe" not in evaluation.reasons


def test_two_high_risk_sources_on_claude_route_are_risk_c():
    split = quick(
        claude=ClaudeResult(
            status="available",
            trace_ok=True,
            anthropic_ok=True,
            exit_ip="1.1.1.1",
            country="US",
            supported=True,
            intelligence_complete=True,
            risk_sources={"claude-one": "high", "claude-two": "85"},
        )
    )
    evaluation = evaluate_node(
        node("a"),
        split,
        full_result(
            completed=True,
            risk_sources={"one": "low", "two": "low", "three": "low"},
        ),
        PolicyConfig(expected_country={"united-states": "US"}),
        2,
    )

    assert evaluation.risk_grade == "C"
    assert evaluation.redline
    assert any(
        reason.startswith("claude-multiple-high-risk-sources:")
        for reason in evaluation.reasons
    )


def test_danger_policy_and_stable_ip_change():
    policy = PolicyConfig(expected_country={"united-states": "US"})
    full = full_result(
        completed=True,
        risk_sources={"one": "85%", "two": "high"},
        checked_at="2026-07-24T00:00:00+00:00",
    )
    evaluation = evaluate_node(node("a"), quick(), full, policy, 1)
    assert evaluation.decision == "rejected"
    assert any(reason.startswith("multiple-high-risk-sources") for reason in evaluation.reasons)

    changed = evaluate_node(
        node("a"),
        quick(exit_ip="1.1.1.1"),
        full_result(completed=True),
        policy,
        2,
        previous_exit_ip="8.8.8.8",
        was_stable=True,
    )
    assert "stable-egress-ip-changed" in changed.reasons
    assert changed.eligible


def test_real_ipquality_high_risk_labels_are_redlines():
    policy = PolicyConfig(expected_country={"united-states": "US"})
    for values in (
        {"one": "VeryHigh", "two": "HighRisk"},
        {"one": "极高风险", "two": "高风险"},
    ):
        evaluation = evaluate_node(
            node("a"),
            quick(),
            full_result(completed=True, risk_sources=values),
            policy,
            2,
        )
        assert evaluation.redline
        assert any(reason.startswith("multiple-high-risk-sources") for reason in evaluation.reasons)


def test_chatgpt_explicit_block_is_ai_b_when_claude_is_available():
    policy = PolicyConfig(expected_country={"united-states": "US"})
    blocked = full_result(
        completed=True,
        chatgpt=site(result="restricted", country="CN"),
        chatgpt_evidence_version=1,
        details={"Media": {"ChatGPT": {"Status": "Block"}}},
    )
    evaluation = evaluate_node(node("a"), quick(), blocked, policy, 2)
    assert evaluation.eligible
    assert evaluation.ai_grade == "B"
    assert "chatgpt-unavailable" in evaluation.reasons

    unknown = full_result(
        completed=True,
        details={"Media": {"ChatGPT": {"Status": "Unknown"}}},
    )
    evaluation = evaluate_node(node("a"), quick(), unknown, policy, 2)
    assert evaluation.eligible


@pytest.mark.parametrize("status", ["Yes", "解锁"])
def test_legacy_chatgpt_allow_strings_do_not_grant_evidence(status):
    full = full_result(
        completed=True,
        details={"Media": {"ChatGPT": {"Status": status}}},
    )
    assert not chatgpt_explicitly_allowed(full)
    attach_quick_ai_evidence(full, quick())
    assert chatgpt_explicitly_allowed(full)


@pytest.mark.parametrize(
    "status",
    ["Block", "屏蔽", "WebOnly", "APPOnly", "仅网页", "仅APP"],
)
def test_legacy_chatgpt_strings_do_not_override_current_site_evidence(status):
    evaluation = evaluate_node(
        node("a"),
        quick(),
        full_result(
            completed=True,
            details={"Media": {"ChatGPT": {"Status": status}}},
        ),
        PolicyConfig(expected_country={"united-states": "US"}),
        2,
    )
    assert evaluation.eligible
    assert evaluation.ai_grade == "A"
    assert "chatgpt-unavailable" not in evaluation.reasons


@pytest.mark.parametrize("status", ["Failed", "失败"])
def test_chatgpt_transient_probe_failures_are_degraded_not_redlines(status):
    evaluation = evaluate_node(
        node("a"),
        quick(chatgpt=SiteProbeResult(attempted=True)),
        full_result(
            completed=True,
            risk_sources={"one": "low", "two": "low", "three": "low"},
            details={"Media": {"ChatGPT": {"Status": status}}},
        ),
        PolicyConfig(expected_country={"united-states": "US"}),
        2,
    )
    assert evaluation.eligible
    assert evaluation.confidence == "provisional"
    assert "chatgpt-unknown" in evaluation.reasons


def test_chatgpt_negated_available_words_are_never_allowed():
    for status in ("Not Available", "Not Supported", "Not Working", "Region Restricted"):
        full = full_result(
            completed=True,
            details={"Media": {"ChatGPT": {"Status": status}}},
        )
        assert not chatgpt_explicitly_allowed(full)
        evaluation = evaluate_node(
            node("a"),
            quick(),
            full,
            PolicyConfig(expected_country={"united-states": "US"}),
            2,
        )
        assert evaluation.eligible
        assert evaluation.ai_grade == "A"


def test_both_ai_sites_confirmed_restricted_are_grade_c():
    unavailable = quick(
        chatgpt_ok=False,
        chatgpt=site(result="restricted", country="CN"),
        claude=ClaudeResult(
            status="restricted",
            trace_ok=True,
            anthropic_ok=True,
            country="CN",
            supported=False,
        ),
    )
    evaluation = evaluate_node(
        node("a"),
        unavailable,
        full_result(
            completed=True,
            risk_sources={"one": "low", "two": "low", "three": "low"},
            details={"Media": {"ChatGPT": {"Status": "Block"}}},
        ),
        PolicyConfig(expected_country={"united-states": "US"}),
        2,
    )
    assert evaluation.redline
    assert evaluation.ai_grade == "C"
    assert "ai-services-unavailable" in evaluation.reasons


def test_unknown_risk_values_do_not_count_as_coverage_or_full_score():
    policy = PolicyConfig(expected_country={"united-states": "US"})
    unknown = full_result(
        completed=True,
        risk_sources={"one": "null", "two": "none", "three": "unknown"},
        details={"Media": {"ChatGPT": {"Status": "Yes"}}},
    )
    clean = full_result(
        completed=True,
        risk_sources={"one": "low", "two": "low", "three": "low"},
        details={"Media": {"ChatGPT": {"Status": "Yes"}}},
    )

    unknown_evaluation = evaluate_node(node("a"), quick(), unknown, policy, 2)
    clean_evaluation = evaluate_node(node("a"), quick(), clean, policy, 2)

    assert unknown_evaluation.eligible
    assert unknown_evaluation.confidence == "low"
    assert "insufficient-risk-coverage:0/3" in unknown_evaluation.reasons
    assert unknown_evaluation.score < clean_evaluation.score


def test_two_of_three_quick_successes_meet_the_default_candidate_threshold():
    evaluation = evaluate_node(
        node("a"),
        quick(success_rate=0.6667),
        full_result(
            completed=True,
            risk_sources={"one": "low", "two": "low", "three": "low"},
            details={"Media": {"ChatGPT": {"Status": "Yes"}}},
        ),
        PolicyConfig(expected_country={"united-states": "US"}),
        2,
    )
    assert evaluation.eligible
    assert evaluation.confidence == "high"
    assert not any(
        reason.startswith("insufficient-quick-success-rate:")
        for reason in evaluation.reasons
    )


def test_missing_country_is_eligible_but_low_confidence():
    evaluation = evaluate_node(
        node("a"),
        quick(country=""),
        full_result(
            completed=True,
            risk_sources={"one": "low", "two": "low", "three": "low"},
            details={"Media": {"ChatGPT": {"Status": "Yes"}}},
        ),
        PolicyConfig(expected_country={"united-states": "US"}),
        2,
    )
    assert evaluation.eligible
    assert evaluation.confidence == "low"
    assert "country-unconfirmed" in evaluation.reasons


def test_full_country_majority_overrides_a_lone_quick_geo_result():
    policy = PolicyConfig(expected_country={"united-states": "US"})
    full = full_result(
        completed=True,
        details={
            "Factor": {"CountryCode": {"one": "JP", "two": "JP", "three": "US"}},
            "Media": {"ChatGPT": {"Status": "Yes"}},
        },
    )
    mismatch = evaluate_node(node("a"), quick(country=""), full, policy, 2)
    assert "country-mismatch:JP!=US" in mismatch.reasons

    quick_disagrees = full_result(
        completed=True,
        risk_sources={"one": "low", "two": "low", "three": "low"},
        details={
            "Factor": {"CountryCode": {"one": "US", "two": "US", "three": "JP"}},
            "Media": {"ChatGPT": {"Status": "Yes"}},
        },
    )
    preferred = evaluate_node(node("a"), quick(country="JP"), quick_disagrees, policy, 2)
    assert preferred.eligible
    assert preferred.confidence == "high"
    assert "quick-country-disagrees-with-full:JP!=US" in preferred.reasons
    assert not any(reason.startswith("country-mismatch:") for reason in preferred.reasons)

    lone_quick = evaluate_node(
        node("a"),
        quick(country="JP"),
        full_result(
            completed=True,
            risk_sources={"one": "low", "two": "low", "three": "low"},
            details={"Media": {"ChatGPT": {"Status": "Yes"}}},
        ),
        policy,
        2,
    )
    assert lone_quick.redline
    assert lone_quick.overall_grade == "C"
    assert "quick-country-mismatch:JP!=US" in lone_quick.reasons

    conflict = full_result(
        completed=True,
        details={"Factor": {"CountryCode": {"one": "JP", "two": "US"}}},
    )
    assert evaluate_node(node("a"), quick(country=""), conflict, policy, 2).eligible

    unavailable = evaluate_node(
        node("a"),
        quick(available=False, country="", exit_ip=""),
        full,
        policy,
        2,
        was_stable=True,
    )
    assert unavailable.decision == "unavailable"
    assert unavailable.overall_grade == "C"
    assert "country-mismatch:JP!=US" in unavailable.reasons


def test_full_audit_selection_modes_and_stale_history():
    nodes = [node("a"), node("b")]
    results = {"a": quick(), "b": quick(exit_ip="1.1.1.1")}
    prior = {
        "stable_slots": {"united-states": {"1": "a"}},
        "nodes": {
            "a": {
                "last_exit_ip": "8.8.8.8",
                "last_full_checked_at": "2026-07-24T00:00:00+00:00",
            },
            "b": {
                "last_exit_ip": "9.9.9.9",
                "last_full_checked_at": "2026-07-24T00:00:00+00:00",
            },
        },
    }
    policy = PolicyConfig(full_audit_top_candidates=0, full_audit_max_age_hours=48)
    now = datetime(2026, 7, 24, 12, tzinfo=timezone.utc)
    assert select_full_audit_nodes("rebuild", nodes, results, prior, policy, now) == {"a", "b"}
    assert select_full_audit_nodes("maintenance", nodes, results, prior, policy, now) == {"a", "b"}


def test_newly_observed_claude_route_forces_a_full_audit():
    target = node("a")
    results = {"a": quick()}
    prior = {
        "stable_slots": {},
        "nodes": {
            "a": {
                "last_exit_ip": "8.8.8.8",
                "last_claude": {"exit_ip": ""},
                "last_risk_source_count": 3,
                "last_decision": "eligible",
            }
        },
    }

    selected = select_full_audit_nodes(
        "maintenance",
        [target],
        results,
        prior,
        PolicyConfig(full_audit_daily_fraction=0, promotion_challengers_per_region=0),
        datetime(2026, 7, 24, tzinfo=timezone.utc),
    )

    assert selected == {"a"}


def test_maintenance_samples_oldest_quarter_across_dynamic_ranking():
    nodes = [node(key) for key in "abcdefghi"]
    results = {item.key: quick() for item in nodes}
    prior_nodes = {
        item.key: {
            "last_exit_ip": "8.8.8.8",
            "last_score": 100 - index,
            "last_full_checked_at": f"2026-07-{20 + (index % 4):02d}T00:00:00+00:00",
            "last_risk_source_count": 3,
            "last_claude": {"exit_ip": "8.8.8.8"},
        }
        for index, item in enumerate(nodes)
    }
    prior = {
        "stable_slots": {"united-states": {"1": "a"}},
        "nodes": prior_nodes,
    }
    policy = PolicyConfig(
        full_audit_daily_fraction=0.25,
        promotion_challengers_per_region=1,
    )

    selected = select_full_audit_nodes(
        "maintenance",
        nodes,
        results,
        prior,
        policy,
        datetime(2026, 7, 24, 12, tzinfo=timezone.utc),
    )

    # a is stable, b is the configured strongest challenger, and e/i are the
    # oldest rotation members after that challenger is removed.
    assert selected == {"a", "b", "e", "i"}


def test_maintenance_always_audits_new_and_changed_egress_nodes():
    nodes = [node(key) for key in "abcde"]
    results = {item.key: quick() for item in nodes}
    results["d"] = quick(exit_ip="1.1.1.1")
    prior = {
        "stable_slots": {"united-states": {"1": "a"}},
        "nodes": {
            key: {
                "last_exit_ip": "8.8.8.8",
                "last_score": 90 - index,
                "last_full_checked_at": "2026-07-24T00:00:00+00:00",
            }
            for index, key in enumerate("abcd")
        },
    }
    policy = PolicyConfig(
        full_audit_daily_fraction=0.25,
        promotion_challengers_per_region=0,
    )

    selected = select_full_audit_nodes(
        "maintenance",
        nodes,
        results,
        prior,
        policy,
        datetime(2026, 7, 24, 12, tzinfo=timezone.utc),
    )

    assert {"a", "d", "e"}.issubset(selected)


def test_default_audit_plan_checks_three_challengers_daily_and_covers_pool_in_two_days():
    nodes = [node(key) for key in "abcdefghi"]
    results = {item.key: quick() for item in nodes}
    prior_nodes = {
        item.key: {
            "last_exit_ip": "8.8.8.8",
            "last_score": 100 - index,
            "last_full_checked_at": "2026-07-20T00:00:00+00:00",
            "last_risk_source_count": 3,
            "last_decision": "eligible",
        }
        for index, item in enumerate(nodes)
    }
    prior = {
        "stable_slots": {"united-states": {"1": "a"}},
        "nodes": prior_nodes,
    }
    policy = PolicyConfig()
    first = select_full_audit_nodes(
        "maintenance",
        nodes,
        results,
        prior,
        policy,
        datetime(2026, 7, 24, tzinfo=timezone.utc),
    )
    assert {"a", "b", "c", "d"}.issubset(first)

    second_prior = json.loads(json.dumps(prior))
    for key in first:
        second_prior["nodes"][key]["last_full_checked_at"] = "2026-07-24T00:00:00+00:00"
    second = select_full_audit_nodes(
        "maintenance",
        nodes,
        results,
        second_prior,
        policy,
        datetime(2026, 7, 25, tzinfo=timezone.utc),
    )

    assert {"a", "b", "c", "d"}.issubset(second)
    assert first | second == {item.key for item in nodes}


def test_risk_conflict_forces_full_audit_outside_rotation():
    nodes = [node(key) for key in "abc"]
    results = {item.key: quick() for item in nodes}
    prior = {
        "stable_slots": {"united-states": {"1": "a"}},
        "nodes": {
            key: {
                "last_exit_ip": "8.8.8.8",
                "last_score": 100 - index,
                "last_full_checked_at": "2026-07-24T00:00:00+00:00",
                "last_risk_source_count": 3,
                "last_decision": "eligible",
                "risk_data_conflict": key == "c",
                "last_claude": {"exit_ip": "8.8.8.8"},
            }
            for index, key in enumerate("abc")
        },
    }
    selected = select_full_audit_nodes(
        "maintenance",
        nodes,
        results,
        prior,
        PolicyConfig(full_audit_daily_fraction=0, promotion_challengers_per_region=0),
        datetime(2026, 7, 25, tzinfo=timezone.utc),
    )
    assert selected == {"a", "c"}
