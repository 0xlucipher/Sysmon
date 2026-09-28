# Design

This is the target design for the repository, agreed before the rework started.
[AUDIT.md](AUDIT.md) maps the current repository against it.

## Goal

A portfolio-grade Sysmon configuration held to community standards. It
competes on **proof, not size**: every detection rule is tied to an ATT&CK
technique and to a replayed attack that shows it fires. SwiftOnSecurity and
sysmon-modular already cover breadth. Neither proves detection.

## Principles

1. **Single source of truth.** Rules live in small modules. Profiles are
   lists of modules. Generated XML is never edited by hand.
2. **Nothing ships unverified.** Every config is statically validated, loaded
   into real Sysmon, and, for detection modules, replayed against Atomic Red
   Team tests.
3. **Numbers come from measurements.** Volume and coverage claims are
   generated from test runs, not written by hand.

## Decisions

| # | Topic | Decision |
|---|---|---|
| 1 | Audience | Portfolio project, community-grade rigour. Narrow and proven beats broad. |
| 2 | Repo | Restructure in place and keep history. Delete hand-copied profiles and examples. |
| 3 | Sysmon targets | Standalone Sysmon 15.0+ (schema 4.90 / 4.91) and built-in Windows Sysmon (Windows 11 / Server 2025, since Feb 2026). Per-schema builds. Nothing older than 15. |
| 4 | Tooling language | Python (stdlib-first) for the generator and validator. PowerShell only for on-host scripts. |
| 5 | Profiles | `balanced` (default), `verbose` (IR/research), `dc-overlay` (added on top of balanced). |
| 6 | Borrowing | Detection rules written here. Noise exclusions may be borrowed with attribution in the module header, after a licence check. |
| 7 | Detection proof | PRs: static checks on Linux plus `sysmon -c` on a Windows runner. Atomic Red Team replays on GitHub-hosted Windows runners. |
| 8 | ATT&CK scope | About 20 most-prevalent techniques (Red Canary Threat Detection Report), weighted to credential access, persistence, execution and lateral movement. |
| 9 | SIEM | Sigma. Each module lists the Sigma rules that depend on it. |
| 10 | Deployment | One installer (built-in and standalone), Authenticode check, drift check. GPO / Intune / SCCM as docs only. |
| 11 | Volume | Events/hour per event ID per profile: idle baseline plus scripted workload. |
| 12 | Docs | Remove the hand-written validation report and fix log. README rewritten, short and honest. |
| 13 | Defaults | SHA256 + IMPHASH, no clipboard capture, no DNS reverse lookup. FileDelete logged without archiving in balanced; executables archived in verbose. |
| 14 | Lab | None available (macOS only). All Windows testing runs on GitHub-hosted runners. |
| 15 | Delivery | Four phases, one PR each (see below). |
| 16 | Replays | On `windows-latest`: Defender real-time off, install Sysmon, run atomics, assert expected event IDs. Runners are Server SKU without a domain, so `dc-overlay` is load-tested only. |
| 17 | Replay cadence | Weekly schedule, manual dispatch, and on PRs touching a module. |
| 18 | Volume labelling | Published as a "synthetic baseline", with that limitation stated. |
| 19–22 | GUI | Separate repo, static web app on GitHub Pages, runs this repo's Python generator in-browser via Pyodide. v1: profile + module toggles, exclusion editing, ATT&CK heatmap, volume estimate, validated export. Starts after phase 2. |
| 23 | Name | Drop "Ultimate". New project name to be chosen. The GitHub repo stays `Sysmon`. |
| 24 | Releases | SemVer GitHub Releases carrying generated XML per profile × schema, `catalog.json`, SHA256 checksums, coverage and volume reports. |
| 25 | Workflow | One PR per phase, merged before the next starts. |
| 26 | Licence | MIT, copyright updated to the owner. SwiftOnSecurity licence checked before borrowing. |

## Target layout

```
modules/<event>/<id>_<name>.xml   rule fragments with metadata header
profiles/<name>.yml               ordered module lists + global settings
tools/                            generator, validator (Python)
tests/                            unit tests for tools
atomics/<technique>.yml           which Atomic tests prove which module
deployment/                       on-host PowerShell (install/update/drift)
dist/ (release asset only)        generated XML, catalog.json, reports
```

### Module metadata (header comment, machine-read)

```
technique: T1003.001
event: ProcessAccess (10)
onmatch: include
volume: low | medium | high
sigma: [<rule ids>]
atomics: [T1003.001-1, T1003.001-2]
source: original | <attribution>
```

## Phases

1. **Correctness + CI.** Fix configs Sysmon rejects or misreads. Add a static
   validator, a Windows `sysmon -c` load test, and a signature check in the installer.
2. **Modules + generator.** Build the new layout and a generator that merges by
   event type and `onmatch`, with per-schema builds. Rebuild the three profiles
   and publish `catalog.json`.
3. **Coverage.** Add ATT&CK-tagged modules for the top techniques, with Sigma
   links and a generated coverage matrix.
4. **Proof + docs.** Atomic Red Team replay workflow, synthetic volume report,
   release pipeline, README rewrite.
