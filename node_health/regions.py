from __future__ import annotations

import json
import re
from pathlib import Path


REGION_RULES = json.loads(Path(__file__).with_name("region_rules.json").read_text(encoding="utf-8"))


def _pattern(rule: dict[str, object]) -> str:
    terms = [r"\s*".join(re.escape(part) for part in str(term).split())
             for term in rule.get("terms", [])]
    terms.extend(re.escape(str(term)) + r"(?:[^A-Za-z]|$)"
                 for term in rule.get("suffix_terms", []))
    terms.extend(r"(?-i:\b" + re.escape(str(code)) + r"\b)"
                 for code in rule.get("codes", []))
    return "|".join(terms)


DEFAULT_REGION_PATTERNS = {rule["region"]: [_pattern(rule)] for rule in REGION_RULES}
