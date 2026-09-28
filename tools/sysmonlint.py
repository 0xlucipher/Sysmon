#!/usr/bin/env python3
"""Static validator for Sysmon configuration files.

Checks what Sysmon itself would reject or silently misinterpret, without
needing Windows: unknown event types, fields that do not exist on an event,
invalid conditions, bad onmatch/groupRelation values, and empty "include"
filters (which log nothing, a common mistake when "log everything" was meant).

Usage:
    python tools/sysmonlint.py [--strict] FILE_OR_DIR [...]

Exit status is 1 if any error was found (or any warning with --strict).
Standard library only.
"""

from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

SUPPORTED_SCHEMAS = {"4.90", "4.91"}

# Filterable event types and their fields, per Sysmon 15.x (schema 4.90).
# Event IDs 4 (service state change), 16 (config change) and 255 (error)
# are always logged and cannot appear in EventFiltering.
_COMMON = "RuleName UtcTime ProcessGuid ProcessId Image User"
EVENT_FIELDS: dict[str, set[str]] = {
    name: set(fields.split())
    for name, fields in {
        # 1
        "ProcessCreate": _COMMON + " FileVersion Description Product Company"
        " OriginalFileName CommandLine CurrentDirectory LogonGuid LogonId"
        " TerminalSessionId IntegrityLevel Hashes ParentProcessGuid"
        " ParentProcessId ParentImage ParentCommandLine ParentUser",
        # 2
        "FileCreateTime": _COMMON + " TargetFilename CreationUtcTime PreviousCreationUtcTime",
        # 3
        "NetworkConnect": _COMMON + " Protocol Initiated SourceIsIpv6 SourceIp"
        " SourceHostname SourcePort SourcePortName DestinationIsIpv6"
        " DestinationIp DestinationHostname DestinationPort DestinationPortName",
        # 5
        "ProcessTerminate": _COMMON,
        # 6
        "DriverLoad": "RuleName UtcTime ImageLoaded Hashes Signed Signature SignatureStatus",
        # 7
        "ImageLoad": _COMMON + " ImageLoaded FileVersion Description Product"
        " Company OriginalFileName Hashes Signed Signature SignatureStatus",
        # 8
        "CreateRemoteThread": "RuleName UtcTime SourceProcessGuid SourceProcessId"
        " SourceImage TargetProcessGuid TargetProcessId TargetImage NewThreadId"
        " StartAddress StartModule StartFunction SourceUser TargetUser",
        # 9
        "RawAccessRead": _COMMON + " Device",
        # 10
        "ProcessAccess": "RuleName UtcTime SourceProcessGUID SourceProcessGuid"
        " SourceProcessId SourceThreadId SourceImage TargetProcessGUID"
        " TargetProcessGuid TargetProcessId TargetImage GrantedAccess CallTrace"
        " SourceUser TargetUser",
        # 11
        "FileCreate": _COMMON + " TargetFilename CreationUtcTime",
        # 12, 13, 14
        "RegistryEvent": _COMMON + " EventType TargetObject Details NewName",
        # 15
        "FileCreateStreamHash": _COMMON + " TargetFilename CreationUtcTime Hash Contents",
        # 17, 18
        "PipeEvent": _COMMON + " EventType PipeName",
        # 19, 20, 21
        "WmiEvent": "RuleName EventType UtcTime Operation User EventNamespace"
        " Name Query Type Destination Consumer Filter",
        # 22
        "DnsQuery": _COMMON + " QueryName QueryStatus QueryResults",
        # 23
        "FileDelete": _COMMON + " TargetFilename Hashes IsExecutable Archived",
        # 24
        "ClipboardChange": _COMMON + " Session ClientInfo Hashes Archived",
        # 25
        "ProcessTampering": _COMMON + " Type",
        # 26
        "FileDeleteDetected": _COMMON + " TargetFilename Hashes IsExecutable",
        # 27
        "FileBlockExecutable": _COMMON + " TargetFilename Hashes",
        # 28
        "FileBlockShredding": _COMMON + " TargetFilename Hashes IsExecutable",
        # 29
        "FileExecutableDetected": _COMMON + " TargetFilename Hashes",
    }.items()
}

# Event types that are frequently used by mistake but are not filterable.
NOT_FILTERABLE = {
    "SysmonStatus": "event 4 (service state change) is always logged and cannot be filtered",
    "SysmonConfigurationChange": "event 16 (config change) is always logged and cannot be filtered",
    "SysmonError": "event 255 is always logged and cannot be filtered",
}

CONDITIONS = {
    "is", "is not", "is any",
    "contains", "contains any", "contains all",
    "excludes", "excludes any", "excludes all",
    "begin with", "not begin with",
    "end with", "not end with",
    "less than", "more than",
    "image",
}

TOP_LEVEL = {
    "HashAlgorithms", "CheckRevocation", "DnsLookup", "ArchiveDirectory",
    "CopyOnDeletePE", "CopyOnDeleteSIDs", "CopyOnDeleteExtensions",
    "CopyOnDeleteProcesses", "CaptureClipboard", "DriverName", "FieldSizes",
    "EventFiltering",
}

# For these events the rules decide what Sysmon BLOCKS, not what it logs.
# An empty include (block nothing) is the safe default; an empty exclude
# would block every matching file operation on the host.
BLOCKING_EVENTS = {"FileBlockExecutable", "FileBlockShredding"}

HASH_ALGORITHMS = {"MD5", "SHA1", "SHA256", "IMPHASH", "*"}
GROUP_RELATIONS = {"and", "or"}


@dataclass
class Finding:
    path: Path
    level: str  # "error" | "warning"
    message: str

    def __str__(self) -> str:
        return f"{self.path}: {self.level}: {self.message}"


def lint_tree(root: ET.Element, path: Path) -> list[Finding]:
    out: list[Finding] = []

    def err(msg: str) -> None:
        out.append(Finding(path, "error", msg))

    def warn(msg: str) -> None:
        out.append(Finding(path, "warning", msg))

    if root.tag != "Sysmon":
        err(f"root element is <{root.tag}>, expected <Sysmon>")
        return out

    schema = root.get("schemaversion")
    if schema not in SUPPORTED_SCHEMAS:
        err(f"schemaversion {schema!r} not in supported {sorted(SUPPORTED_SCHEMAS)}")

    for child in root:
        if child.tag not in TOP_LEVEL:
            err(f"unknown top-level element <{child.tag}>")

    hashes = root.findtext("HashAlgorithms")
    if hashes is not None:
        for algo in (h.strip() for h in hashes.split(",")):
            if algo.upper() not in HASH_ALGORITHMS:
                err(f"unknown hash algorithm {algo!r}")

    filtering = root.find("EventFiltering")
    if filtering is None:
        return out

    seen: dict[tuple[str, str], list[str]] = {}
    for group in filtering:
        if group.tag != "RuleGroup":
            # Bare event elements directly under EventFiltering are legal.
            events, gname = [group], "(no RuleGroup)"
        else:
            gname = group.get("name") or "(unnamed)"
            rel = group.get("groupRelation")
            if rel not in GROUP_RELATIONS:
                err(f"RuleGroup {gname!r}: groupRelation={rel!r}, expected 'and' or 'or'")
            events = list(group)
            if len(events) > 1:
                tags = ", ".join(e.tag for e in events)
                warn(f"RuleGroup {gname!r} holds {len(events)} event filters ({tags}); "
                     "use one event filter per RuleGroup")
        for ev in events:
            _lint_event(ev, gname, err, warn)
            if ev.tag in EVENT_FIELDS:
                seen.setdefault((ev.tag, ev.get("onmatch", "")), []).append(gname)

    for (tag, onmatch), groups in seen.items():
        if len(groups) > 1:
            warn(f"{tag} onmatch={onmatch!r} appears in {len(groups)} RuleGroups "
                 f"({', '.join(groups)}); merge them into one")
    return out


def _lint_event(ev: ET.Element, gname: str, err, warn) -> None:
    where = f"RuleGroup {gname!r}: <{ev.tag}>"
    if ev.tag in NOT_FILTERABLE:
        err(f"{where}: not a filterable event type ({NOT_FILTERABLE[ev.tag]})")
        return
    if ev.tag not in EVENT_FIELDS:
        err(f"{where}: unknown event type")
        return

    onmatch = ev.get("onmatch")
    if onmatch not in ("include", "exclude"):
        err(f"{where}: onmatch={onmatch!r}, expected 'include' or 'exclude'")
        return

    fields = EVENT_FIELDS[ev.tag]
    children = list(ev)
    if ev.tag in BLOCKING_EVENTS:
        if onmatch == "exclude" and not children:
            err(f"{where}: empty onmatch='exclude' BLOCKS every matching file operation")
        elif onmatch == "exclude":
            warn(f"{where}: onmatch='exclude' blocks everything not excluded; "
                 "prefer narrow include rules")
    elif not children and onmatch == "include":
        warn(f"{where}: empty onmatch='include' logs NOTHING for this event; "
             "use an empty onmatch='exclude' to log everything")

    for child in children:
        if child.tag == "Rule":
            rel = child.get("groupRelation")
            if rel not in GROUP_RELATIONS:
                err(f"{where}: <Rule name={child.get('name')!r}> groupRelation={rel!r}")
            if not list(child):
                err(f"{where}: <Rule name={child.get('name')!r}> has no conditions")
            for leaf in child:
                _lint_field(leaf, fields, where, err)
        else:
            _lint_field(child, fields, where, err)


def _lint_field(leaf: ET.Element, fields: set[str], where: str, err) -> None:
    if leaf.tag not in fields:
        err(f"{where}: field <{leaf.tag}> does not exist on this event")
    cond = leaf.get("condition")
    if cond is not None and cond not in CONDITIONS:
        err(f"{where}: <{leaf.tag}> has invalid condition {cond!r}")
    if not (leaf.text or "").strip():
        err(f"{where}: <{leaf.tag}> has an empty value")


def lint_file(path: Path) -> list[Finding]:
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as exc:
        return [Finding(path, "error", f"XML parse error: {exc}")]
    return lint_tree(root, path)


def collect(paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for p in map(Path, paths):
        files.extend(sorted(p.rglob("*.xml")) if p.is_dir() else [p])
    return files


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("paths", nargs="+", help="XML files or directories")
    ap.add_argument("--strict", action="store_true", help="treat warnings as errors")
    args = ap.parse_args(argv)

    findings: list[Finding] = []
    files = collect(args.paths)
    for f in files:
        findings.extend(lint_file(f))

    for f in findings:
        print(f)
    errors = sum(f.level == "error" for f in findings)
    warnings = len(findings) - errors
    print(f"\n{len(files)} file(s): {errors} error(s), {warnings} warning(s)")
    return 1 if errors or (args.strict and warnings) else 0


if __name__ == "__main__":
    sys.exit(main())
