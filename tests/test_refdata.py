import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import refdata  # noqa: E402
import sysmongen  # noqa: E402

RULE = """title: Test Rule
id: 0f06a3a5-6a09-413f-8743-e6cf35561297
status: test
tags:
    - attack.execution
    - attack.t1047
logsource:
    category: {category}
    product: windows
detection:
    selection:
        EventID: 1
    condition: selection
level: medium
"""


def test_build_sigma_keeps_only_sysmon_categories(tmp_path):
    d = tmp_path / "rules" / "windows"
    d.mkdir(parents=True)
    (d / "wmi.yml").write_text(RULE.format(category="wmi_event"))
    (d / "ps.yml").write_text(RULE.format(category="ps_script").replace("0f06a3a5", "aaaaaaaa"))
    data = refdata.build_sigma(tmp_path, "r1")
    assert list(data["rules"]) == ["0f06a3a5-6a09-413f-8743-e6cf35561297"]
    rule = data["rules"]["0f06a3a5-6a09-413f-8743-e6cf35561297"]
    assert rule["category"] == "wmi_event" and rule["techniques"] == ["T1047"]
    assert rule["path"] == "rules/windows/wmi.yml"


def test_build_attack_records_revocations(tmp_path):
    def tech(stix, ext, name, **kw):
        return {"type": "attack-pattern", "id": stix, "name": name,
                "external_references": [{"source_name": "mitre-attack", "external_id": ext}],
                "kill_chain_phases": [{"phase_name": "stealth"}], **kw}
    bundle = {"objects": [
        tech("ap--1", "T1562.001", "Old", revoked=True),
        tech("ap--2", "T1685", "Disable or Modify Tools"),
        {"type": "relationship", "relationship_type": "revoked-by",
         "source_ref": "ap--1", "target_ref": "ap--2"},
    ]}
    (tmp_path / "enterprise-attack").mkdir()
    (tmp_path / "enterprise-attack" / "enterprise-attack.json").write_text(json.dumps(bundle))
    data = refdata.build_attack(tmp_path, "v1")
    assert data["techniques"]["T1562.001"]["revoked_by"] == "T1685"
    assert data["techniques"]["T1685"] == {"name": "Disable or Modify Tools", "tactics": ["stealth"]}


def test_category_maps_agree():
    assert refdata.SIGMA_CATEGORY_EVENTS == sysmongen.SIGMA_CATEGORY_EVENTS


def test_committed_reference_data_is_consistent():
    ref = sysmongen.load_refdata()
    assert ref.attack_version == json.loads((ROOT / "data" / "versions.json").read_text())["attack"]
    assert all(r["category"] in refdata.SIGMA_CATEGORY_EVENTS for r in ref.sigma.values())
