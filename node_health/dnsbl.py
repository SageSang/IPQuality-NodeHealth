"""DNSBL coverage is evidence only when query outcomes were recorded."""
from typing import Any


def normalize_dnsbl(value: Any) -> dict[str, Any]:
    unknown = {"version": 0, "status": "unknown", "total": 0, "checked": 0,
               "clean": 0, "listed": 0, "unknown": 0, "error_count": 0}
    if not isinstance(value, dict) or type(value.get("QueryStatusVersion")) is not int or value["QueryStatusVersion"] != 1:
        return unknown
    fields = {"total": "Total", "clean": "Clean", "listed": "Blacklisted",
              "unknown": "Marked", "error_count": "ErrorCount"}
    counts = {key: value.get(source) for key, source in fields.items()}
    if any(type(number) is not int or number < 0 for number in counts.values()):
        return unknown
    if counts["total"] != sum(counts[key] for key in ("clean", "listed", "unknown", "error_count")):
        return unknown
    checked = counts["clean"] + counts["listed"]
    status = ("listed" if counts["listed"] else
              "clean" if checked and checked == counts["total"] else
              "partial" if checked else "unknown")
    return {"version": 1, "status": status, **counts, "checked": checked}


def clean_coverage(coverage: Any, minimum_ratio: float) -> bool:
    if not isinstance(coverage, dict):
        return False
    # Revalidate cached normalized data rather than trust its status label.
    normalized = normalize_dnsbl({
        "QueryStatusVersion": coverage.get("version"), "Total": coverage.get("total"),
        "Clean": coverage.get("clean"), "Blacklisted": coverage.get("listed"),
        "Marked": coverage.get("unknown"), "ErrorCount": coverage.get("error_count"),
    })
    return bool(normalized["checked"] and not normalized["listed"] and
                normalized["checked"] / normalized["total"] >= minimum_ratio)
