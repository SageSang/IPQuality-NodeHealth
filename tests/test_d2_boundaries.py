from datetime import datetime, timezone

import pytest

from node_health.config import AppConfig, InventoryConfig, PolicyConfig
from node_health.slots import _apply_promotions
from node_health.storage import StateStore, atomic_write_json
from test_slots import assessment


@pytest.mark.parametrize("kind", ["legacy-history", "boolean-history-version", "old-assessment", "boolean-assessment-version", "low-success"])
def test_promotion_defensively_rejects_unqualified_evidence(kind):
    incumbent=assessment("incumbent",70)
    candidate=assessment("candidate",95)
    policy=PolicyConfig()
    now=datetime(2026,7,24,tzinfo=timezone.utc)
    assert _apply_promotions({"1":"incumbent"},[incumbent,candidate],"",policy,now)[0]=={"1":"candidate"}
    if kind=="legacy-history":
        for entry in candidate.daily_quality_history:entry["qualification_version"]=0
    elif kind=="boolean-history-version":
        for entry in candidate.daily_quality_history:entry["qualification_version"]=True
    elif kind=="old-assessment":candidate.qualification_version=0
    elif kind=="boolean-assessment-version":candidate.qualification_version=True
    else:candidate.quick.success_count=1
    slots,promoted=_apply_promotions({"1":"incumbent"},[incumbent,candidate],"",policy,now)
    assert slots=={"1":"incumbent"}
    assert not promoted


@pytest.mark.parametrize("document", [[],{"schema_version":3,"version":"future"},{"schema_version":True}])
def test_invalid_or_future_layout_never_becomes_an_empty_rebuild(tmp_path,document):
    import json
    data=tmp_path/"data";data.mkdir()
    current=data/"current.json";current.write_text(json.dumps(document))
    audit=data/"audit-jobs/20260912T000000Z-1234abcd.json"
    atomic_write_json(audit,{"status":"running"})
    before=current.read_bytes(),audit.read_bytes()
    with pytest.raises(ValueError):
        StateStore(AppConfig(InventoryConfig("https://inventory.invalid"),data_dir=data,reports_dir=tmp_path/"reports"))
    assert (current.read_bytes(),audit.read_bytes())==before
    assert not (tmp_path/"reports").exists()
