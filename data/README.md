# Reference data

Pinned indexes the generator validates module metadata against. Do not edit by
hand: regenerate with `tools/refdata.py` after bumping `versions.json`. CI
(`reference-data` job) rebuilds them from the pinned tags and fails on any
difference.

| File | Source | Pinned | Contents |
|---|---|---|---|
| `attack.json` | [mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data) | `versions.json` → `attack` | Enterprise technique IDs, names, tactics; revoked IDs with their replacement |
| `sigma.json` | [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) | `versions.json` → `sigma` | Windows rules for Sysmon log sources: ID, title, category, level, status, ATT&CK tags, path |

## Updating

```bash
git clone --depth 1 --branch <attack tag> https://github.com/mitre-attack/attack-stix-data /tmp/attack
git clone --depth 1 --branch <sigma tag>  https://github.com/SigmaHQ/sigma /tmp/sigma
# edit data/versions.json to the new tags, then:
python tools/refdata.py --attack /tmp/attack --sigma /tmp/sigma
python tools/sysmongen.py build   # fails if a module now uses a revoked ID or a removed rule
```

## Attribution

- MITRE ATT&CK® is a registered trademark of The MITRE Corporation. Technique
  names and IDs are © The MITRE Corporation, reproduced and distributed with
  permission under the [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).
- Sigma rule titles and metadata come from SigmaHQ, whose rules are licensed under the
  [Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/Detection-Rule-License).
  This repository references rules by ID and links to them. It does not copy
  their detection logic. Credit for each rule belongs to its authors, listed in
  the linked rule files.
