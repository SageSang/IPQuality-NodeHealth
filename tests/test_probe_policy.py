import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from node_health.config import AppConfig, InventoryConfig, PolicyConfig, ProbeConfig
from node_health.models import FullResult, Node, QuickResult
from node_health.policy import (
    chatgpt_explicitly_allowed,
    evaluate_node,
    full_has_confirmed_redline,
    score_node,
    select_full_audit_nodes,
)
from node_health.probe import (
    BUNDLED_DNSBL_FILE,
    IPQualityAuditor,
    MihomoProbeEnvironment,
    generate_mihomo_probe_config,
    normalize_ipquality,
    preserve_sidecar_controller,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]


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
        "exit_ip_stable": True,
        "google_ok": True,
        "chatgpt_ok": True,
        "checked_at": "2026-07-24T00:00:00+00:00",
    }
    values.update(overrides)
    return QuickResult(**values)


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


def test_probe_config_fails_closed_on_duplicate_names():
    first = node("a", "duplicate")
    second = Node("b", "duplicate", "united-states", {"name": "duplicate", "type": "ss"})
    try:
        generate_mihomo_probe_config([first, second])
    except ValueError as error:
        assert "duplicate proxy names" in str(error)
    else:
        raise AssertionError("duplicate names must fail before mihomo reload")


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
        stdout='{"Score":{},"Factor":{},"Mail":{"DNSBlacklist":{"Blacklisted":0}}}',
        stderr="",
    )
    with patch("node_health.probe.subprocess.run", return_value=completed) as run:
        assert IPQualityAuditor(config).check(node("a"), 20000).completed

    environment = run.call_args.kwargs["env"]
    assert environment["IPQUALITY_AUTOMATION"] == "1"
    assert environment["IPQUALITY_SKIP_MAIL"] == "1"
    assert environment["IPQUALITY_DNSBL_FILE"] == BUNDLED_DNSBL_FILE
    assert BUNDLED_DNSBL_FILE == "/app/ref/dnsbl.list"


def test_full_auditor_accepts_valid_json_on_exit_one_and_binds_audited_ip():
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

    assert result.completed
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
        "risk_sources": {"one": "low", "two": "low"},
        "details": {"Media": {"ChatGPT": {"Status": "Yes"}}},
    }
    single = FullResult(
        **common,
        dnsbl_blacklisted=True,
        dnsbl_listed_count=1,
    )
    confirmed = FullResult(
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
    full = FullResult(
        completed=True,
        dnsbl_blacklisted=True,
        risk_sources={"one": "low", "two": "low"},
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
            FullResult(
                completed=True,
                risk_sources={"one": str(risk), "two": f"{risk}%"},
            ),
            policy,
        )

    assert scored(5) > scored(70) > scored(74)
    assert scored(5) - scored(70) >= 10


def test_danger_policy_and_stable_ip_change():
    policy = PolicyConfig(expected_country={"united-states": "US"})
    full = FullResult(
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
        FullResult(completed=True),
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
            FullResult(completed=True, risk_sources=values),
            policy,
            2,
        )
        assert evaluation.redline
        assert any(reason.startswith("multiple-high-risk-sources") for reason in evaluation.reasons)


def test_chatgpt_explicit_block_is_redline_but_unknown_is_not():
    policy = PolicyConfig(expected_country={"united-states": "US"})
    blocked = FullResult(
        completed=True,
        details={"Media": {"ChatGPT": {"Status": "Block"}}},
    )
    evaluation = evaluate_node(node("a"), quick(), blocked, policy, 2)
    assert evaluation.redline
    assert "chatgpt-redline:Block" in evaluation.reasons

    unknown = FullResult(
        completed=True,
        details={"Media": {"ChatGPT": {"Status": "Unknown"}}},
    )
    evaluation = evaluate_node(node("a"), quick(), unknown, policy, 2)
    assert evaluation.eligible


@pytest.mark.parametrize("status", ["Yes", "解锁"])
def test_chatgpt_explicit_allow_statuses_are_usable(status):
    full = FullResult(
        completed=True,
        details={"Media": {"ChatGPT": {"Status": status}}},
    )
    assert chatgpt_explicitly_allowed(full)


@pytest.mark.parametrize(
    "status",
    ["Block", "屏蔽", "WebOnly", "APPOnly", "仅网页", "仅APP"],
)
def test_chatgpt_explicit_restrictions_are_redlines(status):
    evaluation = evaluate_node(
        node("a"),
        quick(),
        FullResult(
            completed=True,
            details={"Media": {"ChatGPT": {"Status": status}}},
        ),
        PolicyConfig(expected_country={"united-states": "US"}),
        2,
    )
    assert evaluation.redline
    assert f"chatgpt-redline:{status}" in evaluation.reasons


@pytest.mark.parametrize("status", ["Failed", "失败"])
def test_chatgpt_transient_probe_failures_are_degraded_not_redlines(status):
    evaluation = evaluate_node(
        node("a"),
        quick(),
        FullResult(
            completed=True,
            risk_sources={"one": "low", "two": "low"},
            details={"Media": {"ChatGPT": {"Status": status}}},
        ),
        PolicyConfig(expected_country={"united-states": "US"}),
        2,
    )
    assert evaluation.eligible
    assert evaluation.confidence == "low"
    assert f"chatgpt-unconfirmed:{status}" in evaluation.reasons


def test_chatgpt_negated_available_words_are_never_allowed():
    for status in ("Not Available", "Not Supported", "Not Working", "Region Restricted"):
        full = FullResult(
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
        assert evaluation.redline


def test_unknown_risk_values_do_not_count_as_coverage_or_full_score():
    policy = PolicyConfig(expected_country={"united-states": "US"})
    unknown = FullResult(
        completed=True,
        risk_sources={"one": "null", "two": "none", "three": "unknown"},
        details={"Media": {"ChatGPT": {"Status": "Yes"}}},
    )
    clean = FullResult(
        completed=True,
        risk_sources={"one": "low", "two": "low"},
        details={"Media": {"ChatGPT": {"Status": "Yes"}}},
    )

    unknown_evaluation = evaluate_node(node("a"), quick(), unknown, policy, 2)
    clean_evaluation = evaluate_node(node("a"), quick(), clean, policy, 2)

    assert unknown_evaluation.eligible
    assert unknown_evaluation.confidence == "low"
    assert "insufficient-risk-coverage:0/2" in unknown_evaluation.reasons
    assert unknown_evaluation.score < clean_evaluation.score


def test_two_of_three_quick_successes_meet_the_default_candidate_threshold():
    evaluation = evaluate_node(
        node("a"),
        quick(success_rate=0.6667),
        FullResult(
            completed=True,
            risk_sources={"one": "low", "two": "low"},
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
        FullResult(
            completed=True,
            risk_sources={"one": "low", "two": "low"},
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
    full = FullResult(
        completed=True,
        details={
            "Factor": {"CountryCode": {"one": "JP", "two": "JP", "three": "US"}},
            "Media": {"ChatGPT": {"Status": "Yes"}},
        },
    )
    mismatch = evaluate_node(node("a"), quick(country=""), full, policy, 2)
    assert "country-mismatch:JP!=US" in mismatch.reasons

    quick_disagrees = FullResult(
        completed=True,
        risk_sources={"one": "low", "two": "low"},
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
        FullResult(
            completed=True,
            risk_sources={"one": "low", "two": "low"},
            details={"Media": {"ChatGPT": {"Status": "Yes"}}},
        ),
        policy,
        2,
    )
    assert lone_quick.eligible
    assert lone_quick.confidence == "low"
    assert "quick-country-mismatch:JP!=US" in lone_quick.reasons

    conflict = FullResult(
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
    assert unavailable.redline
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
