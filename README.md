# sysmon-config

Sysmon configurations built from small, ATT&CK-tagged modules, where every
config is validated and loaded into real Sysmon in CI before it ships.

[![Validate](https://github.com/0xlucipher/Sysmon/actions/workflows/validate.yml/badge.svg)](https://github.com/0xlucipher/Sysmon/actions/workflows/validate.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Sysmon](https://img.shields.io/badge/Sysmon-15.0%2B-blue.svg)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
[![ATT&CK](https://img.shields.io/badge/ATT%26CK-v19.2-red.svg)](https://attack.mitre.org/)

## What makes it different

- **Nothing ships unverified.** Every module and generated config passes a
  static validator and is loaded with `sysmon -c` on a Windows runner.
  Deliberately broken probe configs prove the check can fail.
- **One source of truth.** Each rule lives in exactly one module. Profiles only
  choose modules and set an explicit mode per event (`off`, `all`,
  `selective`). A generator merges them, so rules are never copied between files.
- **Exclusions can't quietly blind you.** The validator warns about exclusions
  an attacker can use to hide: standalone `CommandLine` or `ParentImage`
  matches, and image names not anchored to a protected directory. Several such
  holes in the original configs are documented in
  [documentation/AUDIT.md](documentation/AUDIT.md).
- **Coverage is generated, not claimed.** The ATT&CK matrix is built from
  module metadata, linked to [SigmaHQ](https://github.com/SigmaHQ/sigma)
  detections. ATT&CK and Sigma are pinned, and the build rejects revoked
  technique IDs.

## Quick start

Requirements: Windows 10/11 or Server 2016+ (64-bit), administrator rights,
PowerShell 5.1+.

```powershell
git clone https://github.com/0xlucipher/Sysmon.git
cd Sysmon
.\deployment\Install-Sysmon.ps1                       # balanced profile
.\deployment\Install-Sysmon.ps1 -ConfigProfile dc     # domain controllers
.\deployment\Test-SysmonDrift.ps1 -ConfigProfile balanced
```

`Install-Sysmon.ps1 -Source Auto` (the default) uses **built-in Windows Sysmon**
where the OS offers it (Windows 11 / Server 2025 optional feature) and no
standalone Sysmon is installed. Otherwise it downloads Sysinternals Sysmon and
refuses to run it unless it is validly signed by Microsoft. Use
`-Source BuiltIn` or `-Source Standalone` to choose.

Manual install with a release file:

```powershell
Sysmon64.exe -accepteula -i sysmon-balanced.xml   # verify it against SHA256SUMS first
```

## Profiles

| Profile | File | Use |
|---|---|---|
| `balanced` | `dist/sysmon-balanced.xml` | Default for workstations and member servers |
| `verbose` | `dist/sysmon-verbose.xml` | Investigating a single host: every event type except clipboard, minus known noise. Archives deleted executables. |
| `dc` | `dist/sysmon-dc.xml` | Domain controllers: `balanced` plus DC-specific rules |

Clipboard capture is never enabled, and file blocking (events 27/28) stays off.
[Releases](https://github.com/0xlucipher/Sysmon/releases) carry these files
with a `SHA256SUMS`.

**Volume.** The `Volume baseline` workflow measures events per profile on a
GitHub runner: 60 s settle, 300 s idle, then 60 iterations of a scripted benign
workload. It is a **synthetic baseline** for comparing profiles and catching
regressions. A runner has no real user, browser or business software, so don't
size a SIEM with it. Measure your own hosts with
`performance\Measure-LogVolume.ps1`.

| Profile | Events/hour (synthetic) | Largest sources |
|---|---|---|
| `balanced` | ~16,700 | registry value set (13), process access (10), network (3), process create (1) |
| `dc` | ~16,100 | same as balanced on a non-DC runner |
| `verbose` | ~441,000 | registry value set (13) ~62%, process access (10) ~20%, registry key create/delete (12) ~16% |

*Sysmon 15.22 on Windows Server 2025 (GitHub-hosted runner), 2026-09-28.*

## How it's built

```
modules/<event>/<name>.xml   one event filter per file + metadata (title, techniques, sigma)
profiles/<name>.toml         event modes and module list; a profile can `extends` another
tools/sysmongen.py           modules + profiles -> dist/ (configs, catalog.json, coverage.md)
tools/sysmonlint.py          static validator
tools/refdata.py             builds the pinned ATT&CK / Sigma indexes in data/
testing/                     Sysmon load test, rejection probes, deployment and volume tests
deployment/                  install, update, drift check, remove
```

```bash
python tools/sysmongen.py build          # regenerate dist/
python tools/sysmonlint.py modules dist  # validate
python -m pytest tests                   # unit tests
```

Python 3.11+, standard library only. See [modules/README.md](modules/README.md)
for the module format and [documentation/DESIGN.md](documentation/DESIGN.md) for
the design decisions.

### CI

| Job | Checks |
|---|---|
| Static validation | unit tests; validator over `modules/` and `dist/`; `dist/` matches a fresh build |
| Reference data | `data/` matches the pinned ATT&CK and SigmaHQ releases |
| Load configs into Sysmon | every module and profile loads with `sysmon -c`; broken probes are rejected |
| Deployment | install → no drift → switch profile → drift detected → remove, using the real scripts |
| PowerShell analysis | PSScriptAnalyzer, error severity |

## ATT&CK coverage

See **[dist/coverage.md](dist/coverage.md)**. For each technique it lists:

- the Sysmon events that carry it;
- how each profile collects them (logged in full, or through include rules);
- the SigmaHQ rules that read that telemetry.

The current focus is about 20 of the most prevalent Windows endpoint techniques
(Red Canary Threat Detection Report). Techniques use ATT&CK v19 IDs, for
example `T1685` (formerly `T1562.001`).

Sysmon only sees the endpoint. Cloud and identity techniques, encrypted C2
content and off-host activity need other log sources.

## Customizing

Add your own exclusions or detections as modules in a profile of your own:

```toml
# profiles/mycompany.toml
extends = "balanced"
modules = ["process_create/noise_mycompany"]
```

Keep exclusions narrow:

- Anchor paths with `begin with` a directory users can't write to.
- Scope any `ParentImage` or `CommandLine` condition inside
  `<Rule groupRelation="and">`.

Excludes apply before includes, so a broad exclusion hides detections from
every module for that event. [modules/README.md](modules/README.md) has a
worked example.

## Troubleshooting

- **Sysmon rejects a config:** run `python tools/sysmonlint.py <file>`. It
  reports unknown or non-filterable events, fields that don't exist on an
  event, invalid conditions and malformed XML.
- **An event type is missing:** check its mode in the generated file's header.
  An empty `onmatch="include"` logs *nothing*.
- **Too many events:** find the sources with
  `.\performance\Measure-LogVolume.ps1 -GroupBy Image`, then add a narrow noise
  module.
- **Is the host still on the expected config?** Run
  `.\deployment\Test-SysmonDrift.ps1`. It exits 0 on a match and 1 on drift.

## Contributing

Change modules or profiles, never `dist/` by hand. Run the three commands under
[How it's built](#how-its-built) and commit the regenerated `dist/`. CI does the
rest.

## License and attribution

MIT, see [LICENSE](LICENSE). MITRE ATT&CK® is a registered trademark of The
MITRE Corporation. SigmaHQ rules are referenced by ID and link under the
[DRL 1.1](https://github.com/SigmaHQ/Detection-Rule-License); see
[data/README.md](data/README.md). Built-in Sysmon is documented by
[Microsoft](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/how-to-enable-sysmon).
