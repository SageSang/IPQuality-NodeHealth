#!/usr/bin/env python3
"""Validate reviewed real-calibration evidence before publishing the D2 image."""
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from node_health.config import AppConfig, InventoryConfig
from node_health.policy import PROBE_CONTRACT_VERSION
from node_health.probe import CurlQuickProbe, HTTPResult


def check_gate(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if (value.get("calibration_kind") != "real" or value.get("reviewed") is not True
            or value.get("original_result_class") != "available"
            or not isinstance(value.get("environment_class"), str) or not value["environment_class"].strip()
            or value.get("probe_contract_version") != PROBE_CONTRACT_VERSION):
        raise ValueError("reviewed real calibration required")
    captured = datetime.fromisoformat(value["captured_at"].replace("Z", "+00:00"))
    if captured.tzinfo is None or captured > datetime.now(timezone.utc):
        raise ValueError("invalid capture time")
    config = AppConfig(InventoryConfig("https://inventory.invalid"))
    endpoints = {
        "chatgpt": (config.probe.chatgpt_url, set(config.probe.chatgpt_supported_countries)),
        "claude": (config.probe.claude_trace_url, set(config.probe.claude_supported_countries)),
    }
    url, supported = endpoints[value["site"]]
    response = value["response"]
    checker = CurlQuickProbe(config)
    checker._http_get = lambda *_: HTTPResult(
        response["transport_code"], response["http_status"], 0, response["sanitized_body"], response["host"],
    )
    observation = checker._check_site(0, url, supported)
    if observation.result_class != "available":
        raise ValueError("positive trace calibration failed")
    return {"status":"passed", "site":value["site"], "probe_contract_version":PROBE_CONTRACT_VERSION,
            "scope":"site-region", "network_executed":False}


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file",type=Path,default=Path("deploy/calibration/site-region.json"))
    args=parser.parse_args()
    try:
        result=check_gate(args.file)
    except Exception:
        print(json.dumps({"status":"blocked","code":"reviewed_real_positive_calibration_required"}))
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
