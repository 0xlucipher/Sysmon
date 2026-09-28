import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import sysmongen  # noqa: E402


def write_module(base: Path, mid: str, event: str, onmatch: str, body: str,
                 meta: str = "title: test") -> None:
    path = base / "modules" / f"{mid}.xml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f'<Sysmon schemaversion="4.90"><!--\n{meta}\n--><EventFiltering>'
        f'<RuleGroup name="{mid}" groupRelation="or"><{event} onmatch="{onmatch}">{body}</{event}>'
        f'</RuleGroup></EventFiltering></Sysmon>')


def write_profile(base: Path, name: str, text: str) -> None:
    (base / "profiles").mkdir(exist_ok=True)
    (base / "profiles" / f"{name}.toml").write_text(text)


@pytest.fixture
def repo(tmp_path):
    write_module(tmp_path, "process_create/noise", "ProcessCreate", "exclude",
                 '<Image condition="is">C:\\a.exe</Image>')
    write_module(tmp_path, "process_create/tech", "ProcessCreate", "include",
                 '<Image condition="end with">\\mshta.exe</Image>',
                 meta="title: t\ntechniques: T1218.005")
    write_module(tmp_path, "process_access/lsass", "ProcessAccess", "include",
                 '<TargetImage condition="end with">\\lsass.exe</TargetImage>',
                 meta="title: l\ntechniques: T1003.001")
    return tmp_path


def build(repo, name):
    modules = sysmongen.load_modules(repo / "modules")
    profile, xml = sysmongen.build_profile(name, repo / "profiles", modules)
    return profile, ET.fromstring(xml)


def filters(root, event):
    return {f.get("onmatch"): f for f in root.iter(event)}


def test_modes_all_skips_includes_and_off_is_empty_include(repo):
    write_profile(repo, "p", 'modules = ["process_create/noise", "process_create/tech", '
                             '"process_access/lsass"]\n'
                             '[events]\nProcessCreate = "all"\nProcessAccess = "off"\n')
    profile, root = build(repo, "p")
    pc = filters(root, "ProcessCreate")
    assert set(pc) == {"exclude"}
    assert [c.text for c in pc["exclude"] if isinstance(c.tag, str)] == ["C:\\a.exe"]
    pa = filters(root, "ProcessAccess")
    assert set(pa) == {"include"} and len(pa["include"]) == 0
    assert any("tech is redundant" in n for n in profile.notes)
    assert any("lsass" in n for n in profile.notes)


def test_every_filterable_event_is_emitted_explicitly(repo):
    write_profile(repo, "p", "modules = []\n")
    _, root = build(repo, "p")
    for event in sysmongen.EVENT_IDS:
        assert set(filters(root, event)) == {"include"}


def test_selective_merges_and_stamps_rule_names(repo):
    write_profile(repo, "p", 'modules = ["process_create/noise", "process_create/tech"]\n'
                             '[events]\nProcessCreate = "selective"\n')
    _, root = build(repo, "p")
    pc = filters(root, "ProcessCreate")
    inc = [c for c in pc["include"] if isinstance(c.tag, str)]
    assert inc[0].get("name") == "technique_id=T1218.005,module=process_create/tech"
    exc = [c for c in pc["exclude"] if isinstance(c.tag, str)]
    assert exc[0].get("name") is None  # exclude rules never produce events


def test_selective_without_includes_is_an_error(repo):
    write_profile(repo, "p", 'modules = ["process_create/noise"]\n'
                             '[events]\nProcessCreate = "selective"\n')
    with pytest.raises(sysmongen.BuildError, match="no include modules"):
        build(repo, "p")


def test_blocking_event_cannot_be_enabled(repo):
    write_profile(repo, "p", 'modules = []\n[events]\nFileBlockExecutable = "all"\n')
    with pytest.raises(sysmongen.BuildError, match="blocks files"):
        build(repo, "p")


def test_unknown_module_event_and_mode_are_errors(repo):
    write_profile(repo, "a", 'modules = ["nope/x"]\n')
    with pytest.raises(sysmongen.BuildError, match="unknown module"):
        build(repo, "a")
    write_profile(repo, "b", 'modules = []\n[events]\nSysmonStatus = "all"\n')
    with pytest.raises(sysmongen.BuildError, match="unknown event"):
        build(repo, "b")
    write_profile(repo, "c", 'modules = []\n[events]\nDnsQuery = "most"\n')
    with pytest.raises(sysmongen.BuildError, match="mode"):
        build(repo, "c")


def test_extends_overrides_events_and_appends_modules(repo):
    write_profile(repo, "base", 'modules = ["process_create/noise"]\n'
                                '[settings]\nhash_algorithms = ["SHA256"]\n'
                                '[events]\nProcessCreate = "all"\n')
    write_profile(repo, "child", 'extends = "base"\nmodules = ["process_access/lsass"]\n'
                                 '[events]\nProcessAccess = "selective"\n')
    profile, root = build(repo, "child")
    assert profile.modules == ["process_create/noise", "process_access/lsass"]
    assert profile.events["ProcessCreate"] == "all"
    assert root.findtext("HashAlgorithms") == "SHA256"
    assert "include" in filters(root, "ProcessAccess")


def test_inheritance_cycle_is_an_error(repo):
    write_profile(repo, "a", 'extends = "b"\n')
    write_profile(repo, "b", 'extends = "a"\n')
    with pytest.raises(sysmongen.BuildError, match="cycle"):
        build(repo, "a")


def test_module_must_hold_one_filter_and_metadata(repo):
    bad = repo / "modules" / "x" / "two.xml"
    bad.parent.mkdir(parents=True)
    bad.write_text('<Sysmon schemaversion="4.90"><!-- title: t --><EventFiltering>'
                   '<RuleGroup name="x" groupRelation="or"><DnsQuery onmatch="include">'
                   '<QueryName condition="is">a</QueryName></DnsQuery><PipeEvent onmatch="include">'
                   '<PipeName condition="is">b</PipeName></PipeEvent></RuleGroup>'
                   '</EventFiltering></Sysmon>')
    with pytest.raises(sysmongen.BuildError, match="exactly one"):
        sysmongen.load_modules(repo / "modules")


def test_output_is_deterministic(repo):
    write_profile(repo, "p", 'modules = ["process_create/noise"]\n[events]\nProcessCreate = "all"\n')
    a = sysmongen.build_all(repo / "modules", repo / "profiles")
    b = sysmongen.build_all(repo / "modules", repo / "profiles")
    assert a == b
    catalog = json.loads(a["catalog.json"])
    assert {m["id"] for m in catalog["modules"]} == {
        "process_create/noise", "process_create/tech", "process_access/lsass"}


def test_repository_dist_is_up_to_date():
    assert sysmongen.main(["build", "--check"]) == 0
