#!/usr/bin/env python3
"""Build Sysmon configurations from modules and profiles.

Modules (modules/<event>/<name>.xml) each hold ONE event filter plus a
metadata comment. Profiles (profiles/<name>.toml) choose a mode per event
and list the modules to merge. The generator merges all modules of the
same event and onmatch into one filter, stamps RuleNames on include rules,
validates the result with sysmonlint, and writes dist/sysmon-<profile>.xml
and dist/catalog.json.

Event modes:
    off        log nothing (empty include). Modules for the event are skipped.
    all        log everything except exclude modules. Include modules are
               skipped, because including rules would turn "log all" into
               "log only matches".
    selective  log include-module matches minus exclude-module matches.

Usage:
    python tools/sysmongen.py build [--check]

Standard library only (Python 3.11+).
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
import tomllib
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sysmonlint  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"

# Filterable events in Sysmon event-ID order.
EVENT_IDS = {
    "ProcessCreate": "1", "FileCreateTime": "2", "NetworkConnect": "3",
    "ProcessTerminate": "5", "DriverLoad": "6", "ImageLoad": "7",
    "CreateRemoteThread": "8", "RawAccessRead": "9", "ProcessAccess": "10",
    "FileCreate": "11", "RegistryEvent": "12-14", "FileCreateStreamHash": "15",
    "PipeEvent": "17-18", "WmiEvent": "19-21", "DnsQuery": "22",
    "FileDelete": "23", "ClipboardChange": "24", "ProcessTampering": "25",
    "FileDeleteDetected": "26", "FileBlockExecutable": "27",
    "FileBlockShredding": "28", "FileExecutableDetected": "29",
}
assert set(EVENT_IDS) == set(sysmonlint.EVENT_FIELDS)

MODES = ("off", "all", "selective")
META_LIST_KEYS = {"techniques", "sigma", "atomics"}
SCHEMAS = ("4.90", "4.91")


class BuildError(Exception):
    pass


@dataclass
class Module:
    id: str
    path: Path
    event: str
    onmatch: str
    filter: ET.Element
    meta: dict

    @property
    def techniques(self) -> list[str]:
        return self.meta.get("techniques", [])

    @property
    def rule_count(self) -> int:
        return sum(1 for c in self.filter if not callable(c.tag))


@dataclass
class Profile:
    name: str
    description: str
    schema: str
    settings: dict
    events: dict[str, str]
    modules: list[str]
    extends: str | None = None
    notes: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# Loading

def _parser() -> ET.XMLParser:
    return ET.XMLParser(target=ET.TreeBuilder(insert_comments=True))


def parse_meta(text: str) -> dict:
    meta: dict = {}
    for line in text.strip().splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if not key or " " in key:
            continue
        if key in META_LIST_KEYS:
            meta[key] = [v.strip() for v in value.split(",") if v.strip()]
        else:
            meta[key] = value
    return meta


def load_module(path: Path, modules_dir: Path) -> Module:
    mid = path.relative_to(modules_dir).with_suffix("").as_posix()
    root = ET.parse(path, parser=_parser()).getroot()
    if root.tag != "Sysmon":
        raise BuildError(f"{mid}: root must be <Sysmon>")
    meta_comment = next((c for c in root if c.tag is ET.Comment), None)
    if meta_comment is None:
        raise BuildError(f"{mid}: missing metadata comment inside <Sysmon>")
    meta = parse_meta(meta_comment.text or "")
    if "title" not in meta:
        raise BuildError(f"{mid}: metadata needs a 'title'")

    groups = [g for g in root.iter("RuleGroup")]
    filters = [e for g in groups for e in g if not callable(e.tag)]
    if len(groups) != 1 or len(filters) != 1:
        raise BuildError(f"{mid}: must contain exactly one RuleGroup with one event filter")
    flt = filters[0]
    if flt.tag not in EVENT_IDS:
        raise BuildError(f"{mid}: unknown or non-filterable event <{flt.tag}>")
    onmatch = flt.get("onmatch")
    if onmatch not in ("include", "exclude"):
        raise BuildError(f"{mid}: onmatch must be include or exclude")
    if meta.get("min_schema") and meta["min_schema"] not in SCHEMAS:
        raise BuildError(f"{mid}: min_schema {meta['min_schema']!r} not in {SCHEMAS}")
    return Module(mid, path, flt.tag, onmatch, flt, meta)


def load_modules(modules_dir: Path) -> dict[str, Module]:
    mods = {}
    for p in sorted(modules_dir.rglob("*.xml")):
        m = load_module(p, modules_dir)
        mods[m.id] = m
    return mods


def load_profile(name: str, profiles_dir: Path, _seen: tuple = ()) -> Profile:
    if name in _seen:
        raise BuildError(f"profile inheritance cycle: {' -> '.join(_seen + (name,))}")
    path = profiles_dir / f"{name}.toml"
    if not path.exists():
        raise BuildError(f"profile {name!r} not found at {path}")
    data = tomllib.loads(path.read_text(encoding="utf-8"))

    parent = None
    if data.get("extends"):
        parent = load_profile(data["extends"], profiles_dir, _seen + (name,))

    events = dict(parent.events) if parent else {}
    for ev, mode in data.get("events", {}).items():
        if ev not in EVENT_IDS:
            raise BuildError(f"profile {name}: unknown event {ev!r}")
        if mode not in MODES:
            raise BuildError(f"profile {name}: {ev} mode {mode!r} not in {MODES}")
        events[ev] = mode

    modules = list(parent.modules) if parent else []
    for m in data.get("modules", []):
        if m not in modules:
            modules.append(m)

    settings = dict(parent.settings) if parent else {}
    settings.update(data.get("settings", {}))

    return Profile(
        name=name,
        description=data.get("description", ""),
        schema=data.get("schema", parent.schema if parent else "4.90"),
        settings=settings,
        events=events,
        modules=modules,
        extends=data.get("extends"),
    )


def profile_names(profiles_dir: Path) -> list[str]:
    return sorted(p.stem for p in profiles_dir.glob("*.toml"))


# --------------------------------------------------------------------------
# Reference data (data/attack.json, data/sigma.json; see tools/refdata.py)

# Sigma logsource category -> Sysmon events. Kept in sync with tools/refdata.py.
SIGMA_CATEGORY_EVENTS = {
    "process_creation": ["ProcessCreate"], "file_change": ["FileCreateTime"],
    "network_connection": ["NetworkConnect"], "driver_load": ["DriverLoad"],
    "image_load": ["ImageLoad"], "create_remote_thread": ["CreateRemoteThread"],
    "raw_access_thread": ["RawAccessRead"], "process_access": ["ProcessAccess"],
    "file_event": ["FileCreate"], "registry_add": ["RegistryEvent"],
    "registry_delete": ["RegistryEvent"], "registry_set": ["RegistryEvent"],
    "registry_rename": ["RegistryEvent"], "registry_event": ["RegistryEvent"],
    "create_stream_hash": ["FileCreateStreamHash"], "pipe_created": ["PipeEvent"],
    "wmi_event": ["WmiEvent"], "dns_query": ["DnsQuery"],
    "file_delete": ["FileDelete", "FileDeleteDetected"],
    "clipboard_change": ["ClipboardChange"], "process_tampering": ["ProcessTampering"],
    "file_block_executable": ["FileBlockExecutable"],
    "file_block_shredding": ["FileBlockShredding"],
    "file_executable_detected": ["FileExecutableDetected"],
}


@dataclass
class RefData:
    attack_version: str
    techniques: dict
    sigma_release: str
    sigma: dict

    def technique_name(self, tid: str) -> str:
        return self.techniques.get(tid, {}).get("name", "?")

    def sigma_url(self, rid: str) -> str:
        return (f"https://github.com/SigmaHQ/sigma/blob/{self.sigma_release}/"
                f"{self.sigma[rid]['path']}")


def load_refdata(data_dir: Path = DATA) -> RefData:
    attack = json.loads((data_dir / "attack.json").read_text(encoding="utf-8"))
    sigma = json.loads((data_dir / "sigma.json").read_text(encoding="utf-8"))
    return RefData(attack["version"], attack["techniques"], sigma["release"], sigma["rules"])


def validate_references(modules: dict[str, Module], ref: RefData) -> None:
    """Fail on unknown/revoked ATT&CK IDs and on Sigma rules that cannot match the module's event."""
    problems = []
    for m in modules.values():
        for tid in m.techniques:
            t = ref.techniques.get(tid)
            if t is None:
                problems.append(f"{m.id}: unknown ATT&CK technique {tid} (ATT&CK {ref.attack_version})")
            elif "revoked_by" in t:
                problems.append(f"{m.id}: {tid} was revoked in ATT&CK {ref.attack_version}; "
                                f"use {t['revoked_by']} ({ref.technique_name(t['revoked_by'])})")
            elif t.get("deprecated"):
                problems.append(f"{m.id}: {tid} is deprecated in ATT&CK {ref.attack_version}")
        for rid in m.meta.get("sigma", []):
            rule = ref.sigma.get(rid)
            if rule is None:
                problems.append(f"{m.id}: Sigma rule {rid} not in SigmaHQ {ref.sigma_release} "
                                "(Windows, Sysmon log sources)")
            elif m.event not in SIGMA_CATEGORY_EVENTS.get(rule["category"], []):
                problems.append(f"{m.id}: Sigma rule {rid} ({rule['title']}) reads "
                                f"'{rule['category']}', which {m.event} does not produce")
        if m.meta.get("sigma") and m.onmatch != "include":
            problems.append(f"{m.id}: only include modules may list Sigma rules")
    if problems:
        raise BuildError("module metadata:\n  " + "\n  ".join(problems))


# --------------------------------------------------------------------------
# Building

def _rule_name(mod: Module) -> str:
    parts = []
    if len(mod.techniques) == 1:
        parts.append(f"technique_id={mod.techniques[0]}")
    parts.append(f"module={mod.id}")
    return ",".join(parts)


def _append_module(target: ET.Element, mod: Module, stamp: bool) -> None:
    target.append(ET.Comment(f" module: {mod.id} "))
    for child in mod.filter:
        c = copy.deepcopy(child)
        if stamp and not callable(c.tag) and "name" not in c.attrib:
            c.set("name", _rule_name(mod))
        target.append(c)


def build_tree(profile: Profile, modules: dict[str, Module]) -> ET.Element:
    for mid in profile.modules:
        if mid not in modules:
            raise BuildError(f"profile {profile.name}: unknown module {mid!r}")
        needs = modules[mid].meta.get("min_schema")
        if needs and SCHEMAS.index(needs) > SCHEMAS.index(profile.schema):
            raise BuildError(f"profile {profile.name}: module {mid} needs schema {needs}, "
                             f"profile targets {profile.schema}")

    root = ET.Element("Sysmon", schemaversion=profile.schema)
    root.append(ET.Comment(_header(profile)))
    s = profile.settings
    if s.get("hash_algorithms"):
        ET.SubElement(root, "HashAlgorithms").text = ",".join(s["hash_algorithms"])
    if s.get("check_revocation"):
        ET.SubElement(root, "CheckRevocation")
    ET.SubElement(root, "DnsLookup").text = "True" if s.get("dns_lookup") else "False"
    if s.get("archive_directory"):
        ET.SubElement(root, "ArchiveDirectory").text = s["archive_directory"]
    filtering = ET.SubElement(root, "EventFiltering")

    notes: list[str] = []
    for event in EVENT_IDS:
        mode = profile.events.get(event, "off")
        if event in sysmonlint.BLOCKING_EVENTS and mode != "off":
            raise BuildError(f"profile {profile.name}: {event} blocks files; only mode 'off' is allowed")
        mods = [modules[m] for m in profile.modules if modules[m].event == event]
        includes = [m for m in mods if m.onmatch == "include"]
        excludes = [m for m in mods if m.onmatch == "exclude"]

        filtering.append(ET.Comment(f" Event {EVENT_IDS[event]}: {event} ({mode}) "))
        if mode == "off":
            notes += [f"{event} is off: skipped module {m.id}" for m in mods]
            group = ET.SubElement(filtering, "RuleGroup", name=f"{event} off", groupRelation="or")
            ET.SubElement(group, event, onmatch="include")
            continue

        if mode == "all":
            notes += [f"{event} logs all: include module {m.id} is redundant, skipped"
                      for m in includes]
            includes = []
        elif not includes:
            raise BuildError(f"profile {profile.name}: {event} is 'selective' but has no include modules")

        if includes:
            group = ET.SubElement(filtering, "RuleGroup", name=f"{event} include", groupRelation="or")
            flt = ET.SubElement(group, event, onmatch="include")
            for m in includes:
                _append_module(flt, m, stamp=True)
        if mode == "all" or excludes:
            group = ET.SubElement(filtering, "RuleGroup", name=f"{event} exclude", groupRelation="or")
            flt = ET.SubElement(group, event, onmatch="exclude")
            for m in excludes:
                _append_module(flt, m, stamp=False)

    profile.notes = notes
    ET.indent(root, space="  ")
    return root


def _header(profile: Profile) -> str:
    lines = [
        "",
        f"  GENERATED by tools/sysmongen.py from profiles/{profile.name}.toml. Do not edit.",
        "",
        f"  Profile: {profile.name}" + (f" (extends {profile.extends})" if profile.extends else ""),
    ]
    if profile.description:
        lines.append(f"  {profile.description}")
    lines += ["", "  Event modes:"]
    for event in EVENT_IDS:
        lines.append(f"    {event:<24} {profile.events.get(event, 'off')}")
    lines += ["", "  Modules:"] + [f"    {m}" for m in profile.modules] + [""]
    return "\n".join(lines)


def render(root: ET.Element) -> str:
    return ET.tostring(root, encoding="unicode") + "\n"


def build_profile(name: str, profiles_dir: Path, modules: dict[str, Module]) -> tuple[Profile, str]:
    profile = load_profile(name, profiles_dir)
    root = build_tree(profile, modules)
    errors = [f for f in sysmonlint.lint_tree(root, Path(f"{name}.xml")) if f.level == "error"]
    if errors:
        raise BuildError("generated config failed validation:\n  " + "\n  ".join(map(str, errors)))
    return profile, render(root)


def coverage(modules: dict[str, Module], profiles: list[Profile]) -> dict[str, dict]:
    """Per technique: which modules declare it, and how each profile collects its events.

    For each profile, the states that apply across the technique's modules:
      "all"    an event a module watches is logged in full (mode all);
      "rules"  the module is in the profile and its include rules are active.
    An empty list means the profile collects none of the technique's events.
    """
    out: dict[str, dict] = {}
    for m in sorted(modules.values(), key=lambda m: m.id):
        if m.onmatch != "include":
            continue
        for tid in m.techniques:
            entry = out.setdefault(tid, {"modules": [], "events": [], "sigma": [],
                                         "profiles": {p.name: [] for p in profiles}})
            entry["modules"].append(m.id)
            if m.event not in entry["events"]:
                entry["events"].append(m.event)
            entry["sigma"] += [r for r in m.meta.get("sigma", []) if r not in entry["sigma"]]
            for p in profiles:
                mode = p.events.get(m.event, "off")
                state = "all" if mode == "all" else (
                    "rules" if mode == "selective" and m.id in p.modules else None)
                if state and state not in entry["profiles"][p.name]:
                    entry["profiles"][p.name].append(state)
    for entry in out.values():
        entry["events"].sort()
        for states in entry["profiles"].values():
            states.sort()
    return dict(sorted(out.items()))


def coverage_markdown(cov: dict[str, dict], profiles: list[Profile], ref: RefData) -> str:
    label = {"all": "all events", "rules": "rules"}
    names = [p.name for p in profiles]

    def cell(states: list[str]) -> str:
        return " + ".join(label[s] for s in states) or "–"

    lines = [
        "# ATT&CK coverage",
        "",
        "GENERATED by `tools/sysmongen.py` from module metadata. Do not edit.",
        "",
        f"ATT&CK {ref.attack_version} · SigmaHQ {ref.sigma_release}. Per profile: **all events** = an",
        "event type the technique's modules watch is logged in full; **rules** = the modules'",
        "include rules are active on a selectively logged event; **–** = not collected.",
        "Sigma = SigmaHQ detections that read this telemetry.",
        "Replay = an Atomic Red Team test proved the events appear (phase 4).",
        "",
        "| Technique | Tactics | " + " | ".join(names) + " | Sysmon events | Sigma | Replay |",
        "|---|---|" + "---|" * len(names) + "---|---|---|",
    ]
    for tid, e in cov.items():
        t = ref.techniques.get(tid, {})
        lines.append(
            f"| {tid} {t.get('name', '?')} | {', '.join(t.get('tactics', []))} | "
            + " | ".join(cell(e["profiles"][n]) for n in names)
            + f" | {', '.join(e['events'])} | {len(e['sigma'])} | not yet |")
    lines += ["", "## Modules and Sigma rules per technique", ""]
    for tid, e in cov.items():
        lines += [f"### {tid} {ref.technique_name(tid)}", ""]
        lines += [f"- module `{mid}`" for mid in e["modules"]]
        lines += [f"- Sigma [{ref.sigma[r]['title']}]({ref.sigma_url(r)}) ({ref.sigma[r]['level']})"
                  for r in e["sigma"]]
        lines.append("")
    return "\n".join(lines)


def catalog(modules: dict[str, Module], profiles: list[Profile], ref: RefData,
            cov: dict[str, dict]) -> str:
    data = {
        "format": 1,
        "references": {"attack": ref.attack_version, "sigma": ref.sigma_release},
        "schemas": list(SCHEMAS),
        "events": {e: {"id": i, "blocking": e in sysmonlint.BLOCKING_EVENTS}
                   for e, i in EVENT_IDS.items()},
        "modules": [
            {
                "id": m.id,
                "path": m.path.relative_to(ROOT).as_posix() if m.path.is_relative_to(ROOT) else str(m.path),
                "event": m.event,
                "onmatch": m.onmatch,
                "rules": m.rule_count,
                **{k: m.meta[k] for k in sorted(m.meta)},
            }
            for m in sorted(modules.values(), key=lambda m: m.id)
        ],
        "profiles": [
            {
                "name": p.name,
                "description": p.description,
                "extends": p.extends,
                "schema": p.schema,
                "settings": p.settings,
                "events": {e: p.events.get(e, "off") for e in EVENT_IDS},
                "modules": p.modules,
                "output": f"sysmon-{p.name}.xml",
            }
            for p in profiles
        ],
        "coverage": {
            tid: {"name": ref.technique_name(tid),
                  "tactics": ref.techniques.get(tid, {}).get("tactics", []), **e}
            for tid, e in cov.items()
        },
    }
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def build_all(modules_dir: Path, profiles_dir: Path, verbose: bool = False,
              data_dir: Path = DATA) -> dict[str, str]:
    """Return {output filename: content}: every profile, the catalog and the coverage matrix."""
    modules = load_modules(modules_dir)
    ref = load_refdata(data_dir)
    validate_references(modules, ref)
    outputs: dict[str, str] = {}
    profiles = []
    for name in profile_names(profiles_dir):
        profile, xml = build_profile(name, profiles_dir, modules)
        outputs[f"sysmon-{name}.xml"] = xml
        profiles.append(profile)
        if verbose:
            for note in profile.notes:
                print(f"  note [{name}]: {note}")
        elif profile.notes:
            print(f"  {name}: {len(profile.notes)} module filter(s) skipped by event mode "
                  "(--verbose for details)")
    unused = sorted(set(modules) - {m for p in profiles for m in p.modules})
    if unused:
        print(f"  {len(unused)} module(s) not used by any profile: {', '.join(unused)}")
    cov = coverage(modules, profiles)
    outputs["catalog.json"] = catalog(modules, profiles, ref, cov)
    outputs["coverage.md"] = coverage_markdown(cov, profiles, ref)
    return outputs


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="build every profile into dist/")
    b.add_argument("--modules", type=Path, default=ROOT / "modules")
    b.add_argument("--profiles", type=Path, default=ROOT / "profiles")
    b.add_argument("--out", type=Path, default=ROOT / "dist")
    b.add_argument("--check", action="store_true",
                   help="fail if dist/ is not up to date instead of writing it")
    b.add_argument("--verbose", action="store_true", help="list every skipped module filter")
    args = ap.parse_args(argv)

    try:
        outputs = build_all(args.modules, args.profiles, args.verbose)
    except BuildError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.check:
        existing = {p.name for p in args.out.glob("*")} if args.out.exists() else set()
        stale = [n for n, c in outputs.items()
                 if not (args.out / n).exists() or (args.out / n).read_text(encoding="utf-8") != c]
        stale += sorted(existing - set(outputs))
        if stale:
            print("dist/ is out of date; run `python tools/sysmongen.py build`:\n  "
                  + "\n  ".join(stale), file=sys.stderr)
            return 1
        print(f"dist/ is up to date ({len(outputs)} files)")
        return 0

    args.out.mkdir(parents=True, exist_ok=True)
    for old in args.out.glob("*"):
        if old.name not in outputs:
            old.unlink()
    for name, content in outputs.items():
        (args.out / name).write_text(content, encoding="utf-8")
    print(f"wrote {len(outputs)} files to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
