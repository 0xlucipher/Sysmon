# Repository audit against the design

This audit compares the repository to [DESIGN.md](DESIGN.md), as of the start
of phase 1. **Verdicts:** keep · fix · rebuild · delete.
Items marked ✅ are fixed in phase 1.

## Summary

The repository has a good amount of raw material: modules, exclusion lists,
deployment scripts and a MITRE mapping. But the configurations had never been
loaded into Sysmon. Several were likely to be rejected outright, including the
default `balanced` profile used by the installer (`sysmon-base.xml`). Others
silently logged nothing where they claimed to log everything. The biggest
structural gap is that detection logic is copied across nine hand-maintained
files, with no generator that can reliably rebuild them.

## Configurations

| Item | Finding | Verdict |
|---|---|---|
| Non-filterable events | `SysmonStatus` (7 files) and `SysmonConfigurationChange` (2) used as filters. Events 4 and 16 are always logged and cannot be filtered. | ✅ fixed (removed) |
| Non-existent event | `FileBlockRansomware` in `sysmon-base.xml`. No such Sysmon event. | ✅ fixed (removed) |
| Empty `include` = log nothing | WmiEvent, ProcessTampering and CreateRemoteThread were meant to "log all" but logged nothing in every profile (16 places). | ✅ fixed (empty `exclude`) |
| Blocking events | `FileBlockExecutable` / `FileBlockShredding` comments said "log all", but rules there decide what is **blocked**. Kept as empty include (block nothing) and comments corrected. Wrong version notes fixed. | ✅ fixed |
| Invalid fields | `Signed` used on ProcessCreate and NetworkConnect. It exists only on ImageLoad and DriverLoad. | ✅ fixed (removed, with note) |
| Invalid condition | `does not contain` in `10_process_access.xml`. The correct condition is `excludes`. | ✅ fixed |
| BYOVD blind spot | Server/DC examples excluded driver loads on `Signed=true` **OR** `Signature=Microsoft Windows`, hiding every signed driver including vulnerable ones. | ✅ fixed (AND rule) |
| Multiple event types per RuleGroup | Common in modules and examples (e.g. `AlwaysLog`, `T1003.001_LSASS_Memory`). The validator warns; the Windows load test will show whether Sysmon accepts it. | rebuild (phase 2) |
| Same event and `onmatch` in several RuleGroups | Modules repeat e.g. `ProcessCreate include` 3×. Unclear semantics once merged. | rebuild (phase 2) |
| Profiles (`minimal`, `base`, `comprehensive`, `forensics`, `modular`) | Five overlapping hand-written files. Design calls for three generated profiles. | delete → generated in phase 2 |
| `examples/*` (workstation, server, DC) | Copies of profile content. Hand-maintained. | delete; DC logic → `dc-overlay` |
| Technique modules (T1003, T1021, T1047, T1053, T1055, T1059) | Useful rule content, but mixed event types per group and no test IDs. | keep content, rebuild format |
| Category modules (01, 03, 10, 13) | Overlap with technique modules. | fold into per-event modules |
| Exclusion modules | Reasonable noise lists. `environment_specific_template.xml` duplicates `common_software.xml` structure. | keep, reformat, add attribution |
| `forensics` profile | Uses `begin with C:\` as "log all" (misses other drives and UNC paths); captures clipboard. | superseded by `verbose` (empty exclude, no clipboard) |
| Schema | All files target 4.90. No 4.91 build. Nothing covers built-in Windows Sysmon. | rebuild (phase 2) |

## Tooling

| Item | Finding | Verdict |
|---|---|---|
| `tools/Generate-ModularConfig.ps1` | Concatenates `EventFiltering` inner XML. No merging by event type and `onmatch`, no conflict handling. References a `compliance/` folder that does not exist. | delete → Python generator (phase 2) |
| `testing/Validate-Configuration.ps1` | Treats `SysmonStatus` as valid. No field, condition or empty-include checks. Its include/exclude regex flags nearly every file. | delete → `tools/sysmonlint.py` ✅ |
| Static validator | Did not exist. | ✅ `tools/sysmonlint.py` plus 15 unit tests |
| Real Sysmon load test | Did not exist. | ✅ `testing/Test-SysmonLoad.ps1` on a Windows runner |
| CI | No `.github/`. | ✅ `validate.yml` (lint + Windows load) |
| PowerShell linting | No PSScriptAnalyzer. | add (phase 2) |
| Atomic Red Team replays | Missing. | add (phase 4) |

## Deployment and performance scripts

| Item | Finding | Verdict |
|---|---|---|
| `Install-Sysmon.ps1` download | Ran the downloaded binary without verifying its signature. | ✅ Authenticode check added |
| `Install-Sysmon.ps1` built-in Sysmon | Only knows the Sysinternals zip. No path for the Windows optional feature. | fix (phase 2) |
| Install/Update profile names | Map to the old five profiles. `balanced` → `sysmon-base.xml`. | fix when profiles are generated |
| Drift detection | Missing (loaded config hash vs release). | add (phase 2) |
| `Remove-Sysmon.ps1` | Fine in scope. | keep |
| `Benchmark-Sysmon.ps1`, `Measure-LogVolume.ps1` | Useful on real hosts. The README's performance numbers are not produced by them. | keep; feed the volume report (phase 4) |

## Documentation

| Item | Finding | Verdict |
|---|---|---|
| `VALIDATION-REPORT.md`, `FIXES.md` | Claim validation that never covered loading into Sysmon. | delete (phase 4) |
| `README.md` | Very long. "Ultimate" / "production-ready" claims. Advertises compliance modules that don't exist. | rewrite (phase 4) |
| `documentation/mitre-mapping-matrix.csv` | Hand-written. 67 of 119 technique rows have no module behind them. | delete → generated from module metadata (phase 3) |
| `documentation/detection-logic-explained.md` | Good explanatory content. | keep, link from modules |
| Placeholder URLs | `yourusername/sysmon-ultimate` in installer and CHANGELOG. | fix (phase 4 with rename) |
| `LICENSE` | MIT, copyright "Sysmon Ultimate … Contributors". | fix copyright holder |

## Coverage gap (vs. design Q8)

Six technique modules exist (T1003, T1021, T1047, T1053, T1055, T1059). The
phase-3 target list will be taken from the current Red Canary Threat Detection
Report. Likely additions: T1547 (Run keys / startup), T1218 (signed binary
proxy execution), T1105 (ingress tool transfer), T1562 (impair defenses),
T1036 (masquerading), T1543.003 (services), T1071 / T1572 (C2 over
DNS/HTTP/tunnels), T1490 / T1486 (ransomware impact), T1027 (obfuscation),
T1566 child processes of Office.
