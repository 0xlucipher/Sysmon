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


# ---------------------------------------------------------------- reference data

def ref(**over):
    base = dict(attack_version="v0", sigma_release="r0",
                techniques={"T1218.005": {"name": "Mshta", "tactics": ["stealth"]},
                            "T1562.001": {"name": "Old", "tactics": [], "revoked_by": "T1685"},
                            "T1685": {"name": "Disable or Modify Tools", "tactics": []}},
                sigma={"11111111-1111-1111-1111-111111111111":
                       {"title": "proc rule", "category": "process_creation", "path": "a.yml",
                        "level": "high"},
                       "22222222-2222-2222-2222-222222222222":
                       {"title": "dns rule", "category": "dns_query", "path": "b.yml",
                        "level": "high"}})
    base.update(over)
    return sysmongen.RefData(**base)


def test_references_accept_valid_ids(repo):
    write_module(repo, "process_create/ok", "ProcessCreate", "include",
                 '<Image condition="end with">\\x.exe</Image>',
                 meta="title: t\ntechniques: T1218.005\nsigma: 11111111-1111-1111-1111-111111111111")
    sysmongen.validate_references(
        {k: v for k, v in sysmongen.load_modules(repo / "modules").items() if k.endswith("ok")},
        ref())


@pytest.mark.parametrize("meta, message", [
    ("techniques: T9999", "unknown ATT&CK technique T9999"),
    ("techniques: T1562.001", "use T1685"),
    ("sigma: 33333333-3333-3333-3333-333333333333", "not in SigmaHQ"),
    ("sigma: 22222222-2222-2222-2222-222222222222", "reads 'dns_query'"),
])
def test_references_reject_bad_ids(repo, meta, message):
    write_module(repo, "process_create/bad", "ProcessCreate", "include",
                 '<Image condition="end with">\\x.exe</Image>', meta=f"title: t\n{meta}")
    mods = {k: v for k, v in sysmongen.load_modules(repo / "modules").items() if k.endswith("bad")}
    with pytest.raises(sysmongen.BuildError, match=message):
        sysmongen.validate_references(mods, ref())


def test_coverage_reports_all_and_rules_per_profile(repo):
    write_module(repo, "dns_query/mshta", "DnsQuery", "include",
                 '<Image condition="end with">\\mshta.exe</Image>',
                 meta="title: t\ntechniques: T1218.005")
    write_profile(repo, "p", 'modules = ["process_create/tech", "dns_query/mshta"]\n'
                             '[events]\nProcessCreate = "all"\nDnsQuery = "selective"\n')
    write_profile(repo, "q", 'modules = []\n[events]\nDnsQuery = "all"\n')
    modules = sysmongen.load_modules(repo / "modules")
    profiles = [sysmongen.load_profile(n, repo / "profiles") for n in ("p", "q")]
    cov = sysmongen.coverage(modules, profiles)
    entry = cov["T1218.005"]
    assert entry["events"] == ["DnsQuery", "ProcessCreate"]
    assert entry["profiles"] == {"p": ["all", "rules"], "q": ["all"]}
    assert "T1003.001" in cov and cov["T1003.001"]["profiles"]["p"] == []


# ---------------------------------------------------------------- shadowed includes

@pytest.mark.parametrize("exclude, include, shadowed", [
    ('<QueryName condition="end with">cloudflare.com</QueryName>',
     '<QueryName condition="end with">trycloudflare.com</QueryName>', True),
    ('<QueryName condition="end with">.cloudflare.com</QueryName>',
     '<QueryName condition="end with">trycloudflare.com</QueryName>', False),
    ('<QueryName condition="contains">xmrig</QueryName>',
     '<QueryName condition="contains any">coinminer;xmrig.pool</QueryName>', True),
    ('<QueryName condition="begin with">wpad</QueryName>',
     '<QueryName condition="is">wpad.corp</QueryName>', True),
    ('<Image condition="end with">\\x.exe</Image>',
     '<QueryName condition="end with">\\x.exe</QueryName>', False),  # different field
    ('<Rule groupRelation="and"><QueryName condition="contains">a</QueryName>'
     '<Image condition="is">b</Image></Rule>',
     '<QueryName condition="is">a.com</QueryName>', False),  # exclude rule is narrower
    ('<QueryName condition="end with">.onion</QueryName>',
     '<Rule groupRelation="and"><QueryName condition="end with">x.onion</QueryName>'
     '<Image condition="is">c</Image></Rule>', True),  # AND include shadowed via one field
])
def test_find_shadowed(repo, exclude, include, shadowed):
    write_module(repo, "dns_query/inc", "DnsQuery", "include", include)
    write_module(repo, "dns_query/exc", "DnsQuery", "exclude", exclude)
    mods = sysmongen.load_modules(repo / "modules")
    found = sysmongen.find_shadowed([mods["dns_query/inc"]], [mods["dns_query/exc"]])
    assert bool(found) is shadowed


def test_build_fails_when_exclude_hides_include(repo):
    write_module(repo, "dns_query/inc", "DnsQuery", "include",
                 '<QueryName condition="end with">trycloudflare.com</QueryName>')
    write_module(repo, "dns_query/exc", "DnsQuery", "exclude",
                 '<QueryName condition="end with">cloudflare.com</QueryName>')
    write_profile(repo, "p", 'modules = ["dns_query/inc", "dns_query/exc"]\n'
                             '[events]\nDnsQuery = "selective"\n')
    with pytest.raises(sysmongen.BuildError, match="exclusions hide include rules"):
        build(repo, "p")
