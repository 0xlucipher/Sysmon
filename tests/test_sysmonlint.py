import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import sysmonlint  # noqa: E402


def lint(filtering: str, schema: str = "4.90", top: str = ""):
    xml = f'<Sysmon schemaversion="{schema}">{top}<EventFiltering>{filtering}</EventFiltering></Sysmon>'
    return sysmonlint.lint_tree(ET.fromstring(xml), Path("t.xml"))


def messages(findings, level):
    return [f.message for f in findings if f.level == level]


def group(body: str, name: str = "g") -> str:
    return f'<RuleGroup name="{name}" groupRelation="or">{body}</RuleGroup>'


def test_valid_config_is_clean():
    f = lint(group('<ProcessCreate onmatch="include">'
                   '<Image condition="end with">\\cmd.exe</Image>'
                   '<Rule groupRelation="and">'
                   '<ParentImage condition="end with">\\winword.exe</ParentImage>'
                   '<CommandLine condition="contains any">-enc;-e </CommandLine>'
                   '</Rule></ProcessCreate>'))
    assert f == []


@pytest.mark.parametrize("tag", ["SysmonStatus", "SysmonConfigurationChange"])
def test_non_filterable_events_are_errors(tag):
    errs = messages(lint(group(f'<{tag} onmatch="include"/>')), "error")
    assert len(errs) == 1 and "not a filterable event" in errs[0]


def test_unknown_event_is_error():
    errs = messages(lint(group('<FileBlockRansomware onmatch="include"/>')), "error")
    assert errs and "unknown event type" in errs[0]


def test_field_not_on_event_is_error():
    errs = messages(lint(group('<ProcessCreate onmatch="include">'
                               '<Signed condition="is">false</Signed></ProcessCreate>')), "error")
    assert errs and "<Signed> does not exist" in errs[0]


def test_invalid_condition_is_error():
    errs = messages(lint(group('<ProcessAccess onmatch="include">'
                               '<TargetImage condition="does not contain">x</TargetImage>'
                               '</ProcessAccess>')), "error")
    assert errs and "invalid condition" in errs[0]


def test_bad_onmatch_and_group_relation():
    errs = messages(lint('<RuleGroup name="g" groupRelation="xor">'
                         '<DnsQuery onmatch="both"/></RuleGroup>'), "error")
    assert len(errs) == 2


def test_empty_include_warns():
    warns = messages(lint(group('<WmiEvent onmatch="include"/>')), "warning")
    assert warns and "logs NOTHING" in warns[0]


def test_empty_exclude_is_fine():
    assert lint(group('<WmiEvent onmatch="exclude"/>')) == []


def test_blocking_event_empty_include_is_safe_default():
    assert lint(group('<FileBlockExecutable onmatch="include"/>')) == []


def test_blocking_event_empty_exclude_is_error():
    errs = messages(lint(group('<FileBlockShredding onmatch="exclude"/>')), "error")
    assert errs and "BLOCKS every" in errs[0]


def test_duplicate_event_onmatch_across_groups_warns():
    body = '<DnsQuery onmatch="exclude"><QueryName condition="is">a</QueryName></DnsQuery>'
    warns = messages(lint(group(body, "a") + group(body, "b")), "warning")
    assert any("appears in 2 RuleGroups" in w for w in warns)


def test_unsupported_schema_is_error():
    errs = messages(lint("", schema="4.50"), "error")
    assert errs and "schemaversion" in errs[0]


def test_bad_hash_algorithm_is_error():
    errs = messages(lint("", top="<HashAlgorithms>SHA256,CRC32</HashAlgorithms>"), "error")
    assert errs and "CRC32" in errs[0]


def test_repository_configs_have_no_errors():
    files = sysmonlint.collect([str(ROOT / "modules"), str(ROOT / "dist")])
    assert files
    errors = [str(f) for p in files for f in sysmonlint.lint_file(p) if f.level == "error"]
    assert errors == []


def test_standalone_parent_image_exclude_warns():
    warns = messages(lint(group('<ProcessCreate onmatch="exclude">'
                                '<ParentImage condition="contains">\\Office\\</ParentImage>'
                                '</ProcessCreate>')), "warning")
    assert warns and "EVERY child" in warns[0]


def test_unanchored_image_exclude_warns():
    warns = messages(lint(group('<ProcessAccess onmatch="exclude">'
                                '<SourceImage condition="end with">procexp.exe</SourceImage>'
                                '</ProcessAccess>')), "warning")
    assert warns and "not anchored" in warns[0]


def test_anchored_or_rule_scoped_exclude_is_fine():
    f = lint(group('<ProcessCreate onmatch="exclude">'
                   '<Image condition="begin with">C:\\Program Files\\Mozilla Firefox\\</Image>'
                   '<Image condition="end with">C:\\Program Files\\App\\x.exe</Image>'
                   '<Rule groupRelation="and">'
                   '<ParentImage condition="is">C:\\Windows\\System32\\services.exe</ParentImage>'
                   '<Image condition="end with">\\svc.exe</Image>'
                   '</Rule></ProcessCreate>'))
    assert f == []


def test_comments_are_ignored():
    root = ET.fromstring('<Sysmon schemaversion="4.90"><!-- c --><EventFiltering><!-- c -->'
                         '<RuleGroup name="g" groupRelation="or"><!-- c -->'
                         '<DnsQuery onmatch="exclude"><!-- c --></DnsQuery>'
                         '</RuleGroup></EventFiltering></Sysmon>',
                         parser=ET.XMLParser(target=ET.TreeBuilder(insert_comments=True)))
    assert sysmonlint.lint_tree(root, Path("t.xml")) == []


def test_standalone_command_line_exclude_warns():
    warns = messages(lint(group('<ProcessCreate onmatch="exclude">'
                                '<CommandLine condition="contains">--type=</CommandLine>'
                                '</ProcessCreate>')), "warning")
    assert warns and "attacker-controlled" in warns[0]


def test_empty_include_in_off_group_is_intentional():
    assert lint(group('<ProcessTerminate onmatch="include"/>', "ProcessTerminate off")) == []
