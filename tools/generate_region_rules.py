"""Keep the standalone Sub-Store operator's data aligned with Python defaults."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
START = "// BEGIN GENERATED REGION RULES"
END = "// END GENERATED REGION RULES"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rules = json.loads((ROOT / "node_health/region_rules.json").read_text(encoding="utf-8"))
    path = ROOT / "integrations/sub-store/health-ranking-operator.js"
    text = path.read_text(encoding="utf-8")
    start, end = text.index(START), text.index(END) + len(END)
    block = START + "\nconst REGION_RULES = " + json.dumps(rules, ensure_ascii=False, indent=2) + ";\n" + END
    updated = text[:start] + block + text[end:]
    if args.check:
        if updated != text:
            raise SystemExit("generated region rules differ; run tools/generate_region_rules.py")
    else:
        path.write_text(updated, encoding="utf-8")


if __name__ == "__main__":
    main()
