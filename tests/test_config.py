from pathlib import Path

import pytest

from node_health.config import DEFAULT_REGION_PATTERNS, load_config
from node_health.inventory import classify_region


def write_config(path: Path, extra: str = "") -> Path:
    path.write_text(
        "inventory:\n"
        "  url: http://inventory.invalid/collection.yaml\n"
        "http:\n"
        "  host: 127.0.0.1\n"
        "  port: 8080\n"
        f"{extra}",
        encoding="utf-8",
    )
    return path


def test_config_rejects_cross_component_slot_mismatch(tmp_path):
    path = write_config(
        tmp_path / "config.yaml",
        "policy:\n  stable_slots: 5\n",
    )
    with pytest.raises(ValueError, match="stable_slots must be 3"):
        load_config(path)


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        (
            "local_socks:\n  stable_slots: 5\n  dynamic_offset: 3\n",
            "local_socks.stable_slots must be 3",
        ),
        (
            "local_socks:\n  stable_slots: 3\n  dynamic_offset: 5\n",
            "local_socks.dynamic_offset must be 3",
        ),
    ],
)
def test_config_rejects_legacy_local_socks_slot_contract(tmp_path, extra, message):
    with pytest.raises(ValueError, match=message):
        load_config(write_config(tmp_path / "config.yaml", extra))


def test_config_requires_token_for_lan_listener(tmp_path):
    path = write_config(
        tmp_path / "config.yaml",
        "http:\n  host: 0.0.0.0\n  port: 8080\n",
    )
    with pytest.raises(ValueError, match="api_token is required"):
        load_config(path)


def test_minimal_loopback_config_is_valid(tmp_path):
    config = load_config(write_config(tmp_path / "config.yaml"))
    assert config.http.host == "127.0.0.1"
    assert config.policy.stable_slots == 3
    assert config.policy.stable_unavailable_replace_after_runs == 3
    assert config.policy.dnsbl_redline_threshold == 3
    assert config.policy.claude_min_valid_risk_sources == 2
    assert config.policy.ai_service_outage_min_egresses == 5
    assert config.report.retention_days == 30


def test_ignored_legacy_unavailable_threshold_accepts_old_values(tmp_path, caplog):
    path = write_config(
        tmp_path / "config.yaml",
        "policy:\n  stable_unavailable_replace_after_runs: 0\n",
    )
    config = load_config(path)
    assert config.policy.stable_unavailable_replace_after_runs == 0
    assert "deprecated and ignored" in caplog.text


def test_legacy_unavailable_run_setting_loads_with_deprecation_warning(tmp_path, caplog):
    path = write_config(
        tmp_path / "config.yaml",
        "policy:\n  stable_unavailable_replace_after_runs: 9\n",
    )
    config = load_config(path)
    assert config.policy.stable_unavailable_replace_after_runs == 9
    assert "deprecated and ignored" in caplog.text


def test_legacy_ai_outage_node_count_maps_to_unique_egresses(tmp_path, caplog):
    config = load_config(
        write_config(
            tmp_path / "config.yaml",
            "policy:\n  ai_service_outage_min_nodes: 7\n",
        )
    )

    assert config.policy.ai_service_outage_min_egresses == 7
    assert "ai_service_outage_min_nodes is deprecated" in caplog.text


def test_ai_service_failure_ratio_must_be_positive(tmp_path):
    path = write_config(
        tmp_path / "config.yaml",
        "policy:\n  claude_service_failure_ratio: 0\n",
    )

    with pytest.raises(ValueError, match=r"must be in \(0, 1\]"):
        load_config(path)


@pytest.mark.parametrize(
    "key",
    [
        "full_audit_top_candidates",
        "full_audit_max_age_hours",
        "min_full_passes_high_confidence",
        "promotion_min_full_passes",
    ],
)
def test_unused_legacy_policy_settings_load_with_warning(tmp_path, caplog, key):
    config = load_config(
        write_config(tmp_path / "config.yaml", f"policy:\n  {key}: 0\n")
    )

    assert getattr(config.policy, key) == 0
    assert f"policy.{key} is deprecated and ignored" in caplog.text


def test_config_rejects_single_dnsbl_listing_as_redline_threshold(tmp_path):
    path = write_config(
        tmp_path / "config.yaml",
        "policy:\n  dnsbl_redline_threshold: 1\n",
    )
    with pytest.raises(ValueError, match="dnsbl_redline_threshold must be at least 2"):
        load_config(path)


@pytest.mark.parametrize(
    ("field", "message"),
    [
        (
            "claude_min_valid_risk_sources",
            "claude_min_valid_risk_sources must be positive",
        ),
        (
            "ai_service_outage_min_egresses",
            "ai_service_outage_min_egresses must be positive",
        ),
    ],
)
def test_config_rejects_nonpositive_new_evidence_thresholds(
    tmp_path, field, message
):
    path = write_config(tmp_path / "config.yaml", f"policy:\n  {field}: 0\n")
    with pytest.raises(ValueError, match=message):
        load_config(path)


@pytest.mark.parametrize("name", ["台北 01", "臺北 01", "Taipei IEPL"])
def test_taipei_names_are_classified_as_taiwan(name):
    assert classify_region(name, DEFAULT_REGION_PATTERNS) == "taiwan"


@pytest.mark.parametrize(
    ("name", "region"),
    [
        ("🇺🇸 Seattle premium", "united-states"),
        ("🇺🇸 Los Angeles 01", "united-states"),
        ("🇯🇵 Tokyo IEPL", "japan"),
        ("🇸🇬 Singapore 01", "singapore"),
        ("🇰🇷 Seoul 01", "south-korea"),
        ("🇨🇦 Vancouver 01", "canada"),
        ("🇬🇧 Manchester 01", "united-kingdom"),
        ("🇩🇪 Berlin 01", "germany"),
        ("🇫🇷 Paris 01", "france"),
        ("🇦🇺 Melbourne 01", "australia"),
        ("🇹🇼 Hinet 01", "taiwan"),
    ],
)
def test_meta_ini_country_aliases_match_fixed_regions(name, region):
    assert classify_region(name, DEFAULT_REGION_PATTERNS) == region


def test_deployment_config_classifies_chinese_taipei_names(monkeypatch):
    monkeypatch.setenv("SUB_STORE_INVENTORY_URL", "http://inventory.invalid/clash.yaml")
    monkeypatch.setenv("NODE_HEALTH_API_TOKEN", "test-token")
    path = Path(__file__).resolve().parents[1] / "deploy" / "config" / "config.example.yaml"
    config = load_config(path)

    assert classify_region("台北 01", config.region_patterns) == "taiwan"
    assert classify_region("臺北 01", config.region_patterns) == "taiwan"
    assert config.probe.full_concurrency == 3
    assert config.schedule.time == "03:30"
    assert config.policy.full_audit_daily_fraction == 0.5
    assert config.policy.promotion_challengers_per_region == 3
    assert config.policy.promotion_min_full_passes == 2
    assert config.policy.promotion_min_healthy_days == 6
    assert config.policy.promotion_evidence_days == 3
    assert config.policy.promotion_score_margin == 15
    assert config.policy.promotion_cooldown_days == 7
    assert config.policy.stable_protection_min_healthy_days == 6
    assert config.policy.mass_outage_drop_ratio == 0.6
    assert config.policy.claude_min_valid_risk_sources == 2
    assert config.policy.ai_service_outage_min_egresses == 5
    assert config.probe.unavailable_retry_delays_seconds == [120, 300]
    assert config.probe.claude_ipinfo_url_template == "https://api.ipinfo.io/lookup/{ip}"
    assert config.probe.claude_ipinfo_token == ""
    assert config.probe.claude_ipapi_key == ""
    assert "US" in config.probe.chatgpt_supported_countries
    assert "TW" in config.probe.chatgpt_supported_countries
    assert "CN" not in config.probe.chatgpt_supported_countries
    assert config.report.retention_days == 30


def test_config_rejects_region_without_fixed_openwrt_port_block(tmp_path):
    path = write_config(
        tmp_path / "config.yaml",
        "regions:\n  mars:\n    - Mars\n",
    )
    with pytest.raises(ValueError, match="outside the fixed local-socks port plan: mars"):
        load_config(path)


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        ("schedule:\n  time: '25:00'\n", "schedule.time must be HH:MM"),
        ("schedule:\n  default_mode: unsafe\n", "schedule.default_mode"),
        ("schedule:\n  timezone: Invalid/Nowhere\n", "schedule.timezone is invalid"),
    ],
)
def test_config_rejects_scheduler_values_that_would_stop_the_worker(tmp_path, extra, message):
    with pytest.raises(ValueError, match=message):
        load_config(write_config(tmp_path / "config.yaml", extra))
