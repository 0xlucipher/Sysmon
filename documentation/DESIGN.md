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
| 23 | Name | **sysmon-config**. The GitHub repo stays `Sysmon`. |
| 24 | Releases | SemVer GitHub Releases carrying generated XML per profile × schema, `catalog.json`, SHA256 checksums, coverage and volume reports. |
| 25 | Workflow | One PR per phase, merged before the next starts. |
| 26 | Licence | MIT, copyright updated to the owner. SwiftOnSecurity licence checked before borrowing. |

## Layout

```
modules/<event>/<name>.xml   one event filter + metadata (see modules/README.md)
profiles/<name>.toml         event modes, module list, settings; may `extends` another
tools/sysmongen.py           generator: modules + profile -> dist/
tools/sysmonlint.py          static validator
tests/                       unit tests for tools
testing/                     Windows load test and rejection probes
dist/                        generated configs, catalog.json, coverage.md (committed; CI checks it is current)
data/                        pinned ATT&CK and SigmaHQ indexes the build validates against
deployment/                  on-host PowerShell (install/update)
atomics/<technique>.yml      (phase 4) which Atomic tests prove which module
```

Profiles are TOML rather than YAML so the generator needs only the Python
standard library (`tomllib`), which also runs unchanged under Pyodide for the GUI.

### Event modes

Every filterable event gets an explicit mode in each profile: `off`, `all`
(exclude modules only) or `selective` (include modules minus exclude modules).
The generator refuses combinations that would silently change meaning. For
example, include rules added to an `all` event would turn "log everything" into
"log only matches"; the generator skips them and reports it. See
[modules/README.md](../modules/README.md).

### ATT&CK and Sigma references

Module metadata names ATT&CK techniques and SigmaHQ rules. Both are validated
at build time against pinned indexes in `data/` (ATT&CK v19.2, SigmaHQ
r2026-07-01), which CI rebuilds from those tags. ATT&CK v19 (April 2026) split
Defense Evasion into Stealth and Defense
Impairment (TA0112), revoking and renumbering several techniques. The build
rejects revoked IDs and names the replacement.

Coverage (`dist/coverage.md`) is derived, never hand-written. In `balanced`,
ProcessCreate and NetworkConnect are logged in full, so technique modules for
them contribute Sigma links and ready-made rules for selective profiles rather
than filters (DESIGN #27).

### Schemas

Every module targets schema 4.90 unless it declares `min_schema: 4.91`. A
profile targets one schema, and the build fails if a module needs a newer one.
CI confirms 4.90 output loads on Sysmon 15.22 (schema 4.91). A second per-schema
output is added only when a module needs a 4.91-only feature. Built-in Windows
Sysmon reads the same configuration format.

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
