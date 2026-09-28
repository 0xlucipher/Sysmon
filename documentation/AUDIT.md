# Repository audit against the design

This audit compares the repository to [DESIGN.md](DESIGN.md), as of the start
of phase 1. **Verdicts:** keep · fix · rebuild · delete.
✅ = fixed in phase 1. ✅² = phase 2. ✅³ = phase 3. ✅⁴ = phase 4.

## Summary

The repository has a good amount of raw material: modules, exclusion lists,
deployment scripts and a MITRE mapping. But the configurations had never been
loaded into Sysmon. CI now confirms (Sysmon 15.22, `testing/probes`) that every
class of mistake below makes Sysmon **reject the whole file**. That included the
default `balanced` profile used by the installer (`sysmon-base.xml`), so a
default install could not apply its configuration. Others silently logged
nothing where they claimed to log everything.

**Verified in CI:** Sysmon 15.22 rejects non-filterable events, unknown events,
fields that don't exist on an event, invalid conditions and malformed XML. It
accepts several event types in one RuleGroup and the same event in several
RuleGroups. The validator reports those two as style warnings only.

The biggest structural gap was that detection logic was copied across nine
hand-maintained files, with no generator that could reliably rebuild them.
Phase 2 replaced them with modules, profiles and a generator.

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
| Multiple event types per RuleGroup | Common in modules and examples (e.g. `AlwaysLog`, `T1003.001_LSASS_Memory`). Sysmon accepts it (verified), but it makes merging and review harder. | ✅² one filter per module |
| Same event and `onmatch` in several RuleGroups | Modules repeat e.g. `ProcessCreate include` 3×. Unclear semantics once merged. | ✅² generator merges per event and onmatch |
| Profiles (`minimal`, `base`, `comprehensive`, `forensics`, `modular`) | Five overlapping hand-written files. Design calls for three generated profiles. | ✅² deleted → `dist/sysmon-{balanced,verbose,dc}.xml` |
| `examples/*` (workstation, server, DC) | Copies of profile content. Hand-maintained. | ✅² deleted; DC rules → `dc_*` modules and the `dc` profile. Workstation/server copies dropped. |
| Technique modules (T1003, T1021, T1047, T1053, T1055, T1059) | Useful rule content, but mixed event types per group and no test IDs. | ✅² split into `t<id>_*` modules (test IDs in phase 4) |
| Category modules (01, 03, 10, 13) | Overlap with technique modules. | ✅² kept as optional `extended_*` modules, not in any profile |
| Exclusion modules | Reasonable noise lists, but several exclusions hid attacks (see phase 2 findings). `environment_specific_template.xml` was placeholders only. | ✅² fixed, became `noise_*` modules for `verbose`. Template dropped. |
| `forensics` profile | Uses `begin with C:\` as "log all" (misses other drives and UNC paths); captures clipboard. | superseded by `verbose` (empty exclude, no clipboard) |
| Schema | All files target 4.90. No 4.91 build. Nothing covers built-in Windows Sysmon. | ✅² `min_schema` mechanism. 4.90 output verified on 15.22. See DESIGN "Schemas". |

## Tooling

| Item | Finding | Verdict |
|---|---|---|
| `tools/Generate-ModularConfig.ps1` | Concatenates `EventFiltering` inner XML. No merging by event type and `onmatch`, no conflict handling. References a `compliance/` folder that does not exist. | ✅² deleted → `tools/sysmongen.py` |
| `testing/Validate-Configuration.ps1` | Treats `SysmonStatus` as valid. No field, condition or empty-include checks. Its include/exclude regex flags nearly every file. | ✅² deleted → `tools/sysmonlint.py` |
| Static validator | Did not exist. | ✅ `tools/sysmonlint.py` plus 15 unit tests |
| Real Sysmon load test | Did not exist. | ✅ `testing/Test-SysmonLoad.ps1` on a Windows runner |
| CI | No `.github/`. | ✅ `validate.yml` (lint + Windows load) |
| PowerShell linting | No PSScriptAnalyzer. | ✅² CI job (error severity) |
| Atomic Red Team replays | Missing. | add (phase 4) |

## Deployment and performance scripts

| Item | Finding | Verdict |
|---|---|---|
| `Install-Sysmon.ps1` download | Ran the downloaded binary without verifying its signature. | ✅ Authenticode check added |
| `Install-Sysmon.ps1` built-in Sysmon | Only knows the Sysinternals zip. No path for the Windows optional feature. | ✅⁴ `-Source Auto\|BuiltIn\|Standalone` |
| Install/Update profile names | Mapped to the old five profiles. | ✅² `balanced` / `verbose` / `dc` from `dist/`. Unmeasured CPU and log figures removed. |
| Drift detection | Missing (loaded config hash vs release). | ✅⁴ `Test-SysmonDrift.ps1`, tested end to end in CI |
| `Remove-Sysmon.ps1` | Fine in scope. | keep |
| `Benchmark-Sysmon.ps1`, `Measure-LogVolume.ps1` | Useful on real hosts. The README's performance numbers were not produced by them. | kept; ✅⁴ unmeasured numbers removed, synthetic baseline workflow added |

## Documentation

| Item | Finding | Verdict |
|---|---|---|
| `VALIDATION-REPORT.md`, `FIXES.md` | Claim validation that never covered loading into Sysmon. | ✅⁴ deleted |
| `README.md` | Very long. "Ultimate" / "production-ready" claims. Advertises compliance modules that don't exist. | ✅⁴ rewritten |
| `documentation/mitre-mapping-matrix.csv` | Hand-written. 67 of 119 technique rows have no module behind them. | ✅³ deleted → generated `dist/coverage.md` |
| `documentation/detection-logic-explained.md` | Good explanatory content. | keep, link from modules |
| Placeholder URLs | `yourusername/sysmon-ultimate` in installer and CHANGELOG. | ✅⁴ fixed |
| `LICENSE` | MIT, copyright "Sysmon Ultimate … Contributors". | ✅⁴ 0xlucipher |

## Phase 2 findings

Splitting the files into single-filter modules exposed rules that did the
opposite of their comments. The new validator checks now flag each pattern.

| Module | Problem | Fix |
|---|---|---|
| `process_create/noise_microsoft` | Protected View exclusion was two standalone conditions, so `ParentImage contains \Microsoft Office\root\Office` hid **every** child of Word/Excel/Outlook (macro → PowerShell, T1566/T1204). | AND rule |
| `process_create/noise_microsoft` | Standalone `CommandLine contains --type=` hid any process that added that string. | Scoped to Edge's install path |
| `process_create/noise_microsoft` | Name-only excludes of `MSBuild.exe`, `csc.exe`, `vbc.exe` (LOLBins, T1127.001 / T1027.004) and of updaters in user-writable paths. | Removed |
| `process_create/noise_common_software` | Standalone `ParentImage contains \Mozilla Firefox\` hid browser-exploit child processes. `updater.exe` and other name-only excludes matched any file with that name. | Removed or anchored to install paths |
| `process_access/noise_global`, `extended_exclude` | `SourceImage end with procexp.exe` / `procmon.exe`: rename a credential dumper and LSASS access goes unlogged. | Removed |
| `image_load/t1055_process_injection` | Included every load of `kernel32.dll`, `ntdll.dll`, `user32.dll`, i.e. every process. | Only when loaded from outside `C:\Windows\` |
| `registry_event/t1003_credential_dumping` | `TargetObject contains \Cache\` matched countless keys. | `\SECURITY\Cache` (cached domain credentials) |
| `create_remote_thread/baseline_exclude`, `file_create_time/baseline_exclude` | A directory used with `end with` never matched. `explorer.exe` was matched by name, not path. | Removed / anchored |

**Behaviour of `balanced` vs. the old `sysmon-base.xml`:** same event modes and
rules, except the two anchored/removed rules above, plus 50 include rules from the
technique modules. File deletions moved from FileDelete (archives) to
FileDeleteDetected (no archive), per DESIGN #13. Include rules for events that
already log everything (ProcessCreate, NetworkConnect, CreateRemoteThread,
RawAccessRead, WmiEvent) are skipped, so those events carry no technique tags yet.
That is a phase 3 topic.

## Phase 3 findings

| Area | Finding | Fix |
|---|---|---|
| ATT&CK IDs | ATT&CK v19 (April 2026) revoked `T1562.001` (→ `T1685`), `T1562.004` (→ `T1686`) and `T1070.001` (→ `T1685.005`); modules used the old IDs. | ✅³ modules retagged; build rejects revoked IDs |
| Named-pipe rules | `begin with \\PSEXESVC`, `\\PSHost`, `\\WMIC` used a double backslash. Sysmon logs `\PSEXESVC`, so these never matched. | ✅³ single backslash |
| `baseline_include` modules | One module per event mixing unrelated techniques; no Sigma links. | ✅³ split into 41 technique and `general_*` modules; rule-by-rule diff shows no include rule lost |
| `extended_*` modules | Unreviewed, unused. | ✅³ deleted |
| README coverage claims | "200/224 techniques = 89.3%", plus a non-existent `Update-MitreMapping.ps1`. | ✅³ replaced by the generated matrix |

## Phase 4 findings

| Area | Finding | Fix |
|---|---|---|
| DNS exclusions | `QueryName end with microsoft.com` (and 20 similar) also matched lookalikes such as `notmicrosoft.com`. | ✅⁴ anchored: `is` the domain, `end with .<domain>` for subdomains. The validator warns on unanchored domain excludes. |
| DNS exclusions | Whole cloud platforms excluded (`amazonaws.com`, `azure.com`, `cloudflare.com`, `googleusercontent.com`). Attackers host C2 there, and the `cloudflare.com` exclusion silently cancelled this config's own `trycloudflare.com` tunnel detection. | ✅⁴ removed. The generator now fails the build when an exclusion hides an include rule. |
| DNS telemetry | First volume run logged zero DNS events (ID 22) in every profile, including `verbose`. | ✅⁴ resolved: not a config problem. Unique names looked up via `Resolve-DnsName`, .NET and `ping` are all logged. The workload looked up the same name repeatedly, and answers served from the DNS client cache were not logged (60+ lookups produced 2 events). Keep this in mind when hunting: a name is logged when it is resolved, not on every use. |

## Coverage gap (vs. design Q8)

Six technique modules exist (T1003, T1021, T1047, T1053, T1055, T1059). The
phase-3 target list will be taken from the current Red Canary Threat Detection
Report. Likely additions: T1547 (Run keys / startup), T1218 (signed binary
proxy execution), T1105 (ingress tool transfer), T1562 (impair defenses),
T1036 (masquerading), T1543.003 (services), T1071 / T1572 (C2 over
DNS/HTTP/tunnels), T1490 / T1486 (ransomware impact), T1027 (obfuscation),
T1566 child processes of Office.
