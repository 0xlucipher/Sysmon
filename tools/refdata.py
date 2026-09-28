#!/usr/bin/env python3
"""Build or check the pinned reference data in data/.

data/attack.json   ATT&CK Enterprise techniques (id -> name, tactics, revoked_by)
data/sigma.json    SigmaHQ Windows rules for Sysmon log sources (id -> title, category, ...)

The generator validates module metadata against these files, so a typo, a
revoked ATT&CK ID or a Sigma rule for the wrong event type fails the build.

Usage:
    python tools/refdata.py --attack <attack-stix-data checkout> --sigma <sigma checkout> [--check]

The pinned versions live in data/versions.json; CI clones exactly those tags
and runs this with --check.

Standard library only.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"

# Sigma logsource category -> Sysmon events that produce it.
SIGMA_CATEGORY_EVENTS = {
    "process_creation": ["ProcessCreate"],
    "file_change": ["FileCreateTime"],
    "network_connection": ["NetworkConnect"],
    "driver_load": ["DriverLoad"],
    "image_load": ["ImageLoad"],
    "create_remote_thread": ["CreateRemoteThread"],
    "raw_access_thread": ["RawAccessRead"],
    "process_access": ["ProcessAccess"],
    "file_event": ["FileCreate"],
    "registry_add": ["RegistryEvent"],
    "registry_delete": ["RegistryEvent"],
    "registry_set": ["RegistryEvent"],
    "registry_rename": ["RegistryEvent"],
    "registry_event": ["RegistryEvent"],
    "create_stream_hash": ["FileCreateStreamHash"],
    "pipe_created": ["PipeEvent"],
    "wmi_event": ["WmiEvent"],
    "dns_query": ["DnsQuery"],
    "file_delete": ["FileDelete", "FileDeleteDetected"],
    "clipboard_change": ["ClipboardChange"],
    "process_tampering": ["ProcessTampering"],
    "file_block_executable": ["FileBlockExecutable"],
    "file_block_shredding": ["FileBlockShredding"],
    "file_executable_detected": ["FileExecutableDetected"],
}

_TAG = re.compile(r"^\s+-\s*attack\.(t\d{4}(?:\.\d{3})?)\s*$", re.M)


def _top(text: str, key: str) -> str | None:
    m = re.search(rf"^{key}:\s*(.+?)\s*$", text, re.M)
    return m.group(1).strip("'\"") if m else None


def build_sigma(checkout: Path, release: str) -> dict:
    rules = {}
    for path in sorted((checkout / "rules" / "windows").rglob("*.yml")):
        text = path.read_text(encoding="utf-8", errors="replace")
        block = re.search(r"^logsource:\n((?:[ \t]+.*\n?)+)", text, re.M)
        logsource = dict(re.findall(r"^\s+(\w+):\s*(\S+)", block.group(1), re.M)) if block else {}
        category = logsource.get("category")
        if category not in SIGMA_CATEGORY_EVENTS:
            continue
        rid = _top(text, "id")
        if not rid:
            continue
        rules[rid] = {
            "title": _top(text, "title"),
            "category": category,
            "status": _top(text, "status"),
            "level": _top(text, "level"),
            "techniques": sorted({t.upper() for t in _TAG.findall(text)}),
            "path": path.relative_to(checkout).as_posix(),
        }
    return {"release": release, "source": "https://github.com/SigmaHQ/sigma",
            "license": "Detection Rule License (DRL) 1.1", "rules": rules}


def build_attack(checkout: Path, version: str) -> dict:
    bundle = json.loads((checkout / "enterprise-attack" / "enterprise-attack.json")
                        .read_text(encoding="utf-8"))
    by_stix, revoked_by = {}, {}
    for o in bundle["objects"]:
        if o.get("type") != "attack-pattern":
            continue
        ext = next((r["external_id"] for r in o.get("external_references", [])
                    if r.get("source_name") == "mitre-attack"), None)
        if ext:
            by_stix[o["id"]] = (ext, o)
    for o in bundle["objects"]:
        if o.get("type") == "relationship" and o.get("relationship_type") == "revoked-by":
            src, dst = by_stix.get(o["source_ref"]), by_stix.get(o["target_ref"])
            if src and dst:
                revoked_by[src[0]] = dst[0]
    techniques = {}
    for ext, o in sorted(by_stix.values(), key=lambda x: x[0]):
        entry = {"name": o["name"],
                 "tactics": [p["phase_name"] for p in o.get("kill_chain_phases", [])]}
        if o.get("revoked"):
            entry["revoked_by"] = revoked_by.get(ext)
        if o.get("x_mitre_deprecated"):
            entry["deprecated"] = True
        techniques[ext] = entry
    return {"version": version, "source": "https://github.com/mitre-attack/attack-stix-data",
            "techniques": techniques}


def dump(data: dict) -> str:
    return json.dumps(data, indent=1, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--attack", type=Path, required=True, help="attack-stix-data checkout")
    ap.add_argument("--sigma", type=Path, required=True, help="SigmaHQ sigma checkout")
    ap.add_argument("--check", action="store_true", help="fail if data/ differs")
    args = ap.parse_args(argv)

    versions = json.loads((DATA / "versions.json").read_text())
    outputs = {
        "attack.json": dump(build_attack(args.attack, versions["attack"])),
        "sigma.json": dump(build_sigma(args.sigma, versions["sigma"])),
    }
    if args.check:
        stale = [n for n, c in outputs.items()
                 if not (DATA / n).exists() or (DATA / n).read_text(encoding="utf-8") != c]
        if stale:
            print(f"data/ does not match the pinned sources: {', '.join(stale)}", file=sys.stderr)
            return 1
        print("data/ matches the pinned sources")
        return 0
    for name, content in outputs.items():
        (DATA / name).write_text(content, encoding="utf-8")
    print(f"wrote {', '.join(outputs)} to {DATA}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
