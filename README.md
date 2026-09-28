# Sysmon Ultimate Configuration Repository

> The definitive, production-ready Sysmon configuration for Windows security monitoring - comprehensive, modular, and performance-optimized.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Sysmon Version](https://img.shields.io/badge/Sysmon-15.0+-blue.svg)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20v15-red.svg)](https://attack.mitre.org/)
[![Validate](https://github.com/0xlucipher/Sysmon/actions/workflows/validate.yml/badge.svg)](https://github.com/0xlucipher/Sysmon/actions/workflows/validate.yml)

> **Rework in progress.** See [documentation/DESIGN.md](documentation/DESIGN.md) for the plan and
> [documentation/AUDIT.md](documentation/AUDIT.md) for what was found and fixed. The quick start,
> architecture and profile sections below are current. The performance, coverage and
> customization sections further down predate the rework and will be regenerated from
> measurements in later phases.

## Table of Contents

- [Why Logging Matters](#why-logging-matters)
- [Why Sysmon?](#why-sysmon)
- [Quick Start (5-Minute Setup)](#quick-start-5-minute-setup)
- [Repository Architecture](#repository-architecture)
- [Configuration Profiles](#configuration-profiles)
- [Advanced Usage](#advanced-usage)
- [Performance Characteristics](#performance-characteristics)
- [MITRE ATT&CK Coverage](#mitre-attck-coverage)
- [Customization Guide](#customization-guide)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [FAQ](#faq)

---

## Why Logging Matters

**You can't detect what you can't see.**

In modern security operations, visibility is the foundation of defense. Without comprehensive logging:
- **Incident response is blind**: No evidence trail to investigate breaches
- **Threats go undetected**: Advanced attackers operate in silence
- **Compliance fails**: Regulatory requirements demand audit trails (PCI-DSS, HIPAA, GDPR, NIST)
- **Forensics is impossible**: No artifacts to analyze post-compromise

Default Windows logging captures only a fraction of security-relevant events. Sysmon fills the critical gaps.

---

## Why Sysmon?

**System Monitor (Sysmon)** is a Windows system service from Microsoft Sysinternals that provides:

### Key Capabilities

| Feature | Benefit |
|---------|---------|
| **Process Creation Tracking** | Full command-line logging with parent-child relationships |
| **Network Connections** | Every TCP/UDP connection with process context |
| **File & Registry Monitoring** | Detects persistence mechanisms and data exfiltration |
| **Image Loading** | DLL/driver loading for injection detection |
| **Named Pipe Activity** | Lateral movement and C2 communication |
| **DNS Queries** | Malicious domain detection at the endpoint |
| **Process Injection Detection** | CreateRemoteThread, Process Hollowing, APC injection |
| **WMI Event Monitoring** | Persistence and remote execution detection |
| **Clipboard Capture** | Data theft detection (privacy-aware) |
| **Process Tampering** | Anti-evasion and integrity monitoring |

### Advantages Over Native Windows Logging

- **Granular Filtering**: Reduce noise while maintaining visibility
- **Performance Optimized**: Kernel-level driver with minimal overhead
- **Free & Supported**: Official Microsoft tool, no licensing costs
- **SIEM-Friendly**: Writes to standard Windows Event Log
- **Persistent**: Survives reboots, tracks early-boot activity
- **Attack-Resistant**: Protected against common evasion techniques

---

## Quick Start (5-Minute Setup)

### Prerequisites

- Windows 10/11 or Server 2016+ (64-bit), administrator rights
- PowerShell 5.1 or later
- Sysmon 15.0+ (the installer downloads it and verifies Microsoft's signature)

### Automatic Installation

```powershell
git clone https://github.com/0xlucipher/Sysmon.git
cd Sysmon
.\deployment\Install-Sysmon.ps1                     # balanced (default)
.\deployment\Install-Sysmon.ps1 -ConfigProfile dc   # domain controllers
.\deployment\Install-Sysmon.ps1 -ListProfiles
```

### Manual Installation

```powershell
Sysmon64.exe -accepteula -i dist\sysmon-balanced.xml   # install
Sysmon64.exe -c dist\sysmon-balanced.xml               # update an existing install
```

---

## Repository Architecture

### Directory Structure

```
modules/<event>/<name>.xml   one Sysmon event filter per file, with metadata
profiles/<name>.toml         which modules a profile uses, and a mode per event
tools/sysmongen.py           builds dist/ from modules + profiles
tools/sysmonlint.py          static validator (event types, fields, conditions, risky exclusions)
dist/                        generated configs, catalog.json, coverage.md. Do not edit by hand.
data/                        pinned ATT&CK + SigmaHQ indexes the build validates against
testing/                     loads every config into real Sysmon in CI
deployment/                  install / update / remove scripts
documentation/               design, audit, detection notes
```

### Module Organization Philosophy

Every rule lives in exactly one module. Profiles only choose modules, and each
event gets an explicit mode (`off`, `all`, `selective`). The generator merges
them, so no rule is copied between configurations. See
[modules/README.md](modules/README.md) and [documentation/DESIGN.md](documentation/DESIGN.md).

Every change is checked in CI:

1. Unit tests for the generator and validator.
2. The validator run over every module and generated config.
3. A check that `dist/` matches a fresh build.
4. Every generated config and module loaded into real Sysmon on a Windows runner.

---

## Configuration Profiles

| Profile | File | Use |
|---|---|---|
| `balanced` | `dist/sysmon-balanced.xml` | Default for workstations and member servers |
| `verbose` | `dist/sysmon-verbose.xml` | Incident response / research on individual hosts. Logs every event type except clipboard, minus known noise. Archives deleted executables. |
| `dc` | `dist/sysmon-dc.xml` | Domain controllers: `balanced` plus DC-specific rules |

Log volume per profile has not been measured yet. The numbers in older
versions of this README were estimates and have been removed from the tooling.

---

## Advanced Usage

### Building Custom Configurations

```bash
python tools/sysmongen.py build            # regenerate dist/
python tools/sysmongen.py build --check    # CI: fail if dist/ is stale
python tools/sysmonlint.py modules dist    # validate
python -m pytest tests                     # unit tests
```

Python 3.11+, standard library only. To make your own profile, add
`profiles/<name>.toml`. It can `extends = "balanced"` and add modules or
change event modes.

### Updating Configurations

```powershell
.\deployment\Update-Sysmon.ps1 -ConfigProfile verbose   # switch profile in place
```

---

## Performance Characteristics

Performance testing conducted on: **Intel i7-10700K, 32GB RAM, Windows 11 Pro 23H2**

### Baseline Metrics

| Configuration | Idle CPU | Active CPU (Office Work) | Active CPU (Heavy Dev) | Memory | Daily Event Volume |
|---------------|----------|--------------------------|------------------------|--------|-------------------|
| **No Sysmon** | 1-3% | 8-15% | 25-40% | ~2GB | 0 events |
| **Minimal** | 1-3% | 8-16% | 25-42% | ~2.1GB | ~5K events |
| **Balanced** | 1-4% | 9-18% | 26-45% | ~2.3GB | ~20K events |
| **Comprehensive** | 2-5% | 11-22% | 28-50% | ~2.6GB | ~60K events |
| **Forensics** | 3-8% | 15-30% | 35-60% | ~3.1GB | ~150K events |

**Key Findings:**
- **Balanced profile**: Adds only 1-3% CPU overhead in real-world usage
- **Memory footprint**: Minimal (~100-500MB depending on profile)
- **Disk I/O**: Negligible impact with proper log rotation
- **Network**: Zero network overhead (logs locally)

### Performance Tuning

If experiencing performance issues:

1. **Start with `balanced`**: keep `verbose` for individual hosts under investigation
2. **Analyze logs**: Identify high-volume event sources
3. **Apply exclusions**: add a narrow noise module (see the Customization Guide)
4. **Iteratively expand**: Add rules incrementally while monitoring impact

```powershell
# Benchmark your environment
.\performance\Benchmark-Sysmon.ps1 -DurationMinutes 60 -GenerateReport

# Measure log volume before tuning
.\performance\Measure-LogVolume.ps1 -Days 7
```

---

## MITRE ATT&CK Coverage

The coverage matrix is generated from module metadata on every build:
**[dist/coverage.md](dist/coverage.md)** (also in `dist/catalog.json`). For each ATT&CK
technique it shows:

- which Sysmon events carry its telemetry;
- how each profile collects those events (logged in full, or through include rules);
- which [SigmaHQ](https://github.com/SigmaHQ/sigma) detections read that telemetry;
- whether a replayed attack has proven it (phase 4).

Techniques use **ATT&CK v19** IDs. v19 split Defense Evasion into *Stealth* and
*Defense Impairment*, so for example `T1562.001` is now `T1685` and `T1070.001` is
now `T1685.005`. The build rejects revoked IDs and names the replacement. ATT&CK
and Sigma are pinned in `data/versions.json`, and CI checks `data/` against those
exact releases.

Phase 3 focuses on about 20 of the most prevalent Windows endpoint techniques in
Red Canary's Threat Detection Report: PowerShell, cmd, ClickFix (paste-and-run),
WMI, Rundll32/Regsvr32/Mshta, obfuscation, masquerading, disabling security
tools, log clearing, LSASS and NTDS credential theft, scheduled tasks, Run keys,
services, process injection, ingress tool transfer, SMB/WinRM lateral movement
and inhibiting recovery.

Sysmon cannot see everything. Cloud and identity techniques (Red Canary's #1 is
Cloud Accounts), encrypted C2 content and anything that happens off the endpoint
need other log sources.

---

## Customization Guide

### Adding Environment-Specific Exclusions

Put your exclusions in a module of their own, add them to a profile of your
own, and rebuild:

```xml
<!-- modules/process_create/noise_mycompany.xml -->
<Sysmon schemaversion="4.90">
  <!--
    title: Noise: MyCompany backup agent
    source: original
  -->
  <EventFiltering>
    <RuleGroup name="process_create/noise_mycompany" groupRelation="or">
      <ProcessCreate onmatch="exclude">
        <!-- Anchor to a directory users cannot write to -->
        <Image condition="is">C:\Program Files\Veeam\Veeam.Backup.Service.exe</Image>
        <!-- Scope parent/command-line conditions with an AND rule, never standalone -->
        <Rule groupRelation="and">
          <ParentImage condition="is">C:\Windows\CCM\CcmExec.exe</ParentImage>
          <Image condition="is">C:\Windows\System32\msiexec.exe</Image>
        </Rule>
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

```toml
# profiles/mycompany.toml
extends = "balanced"
modules = ["process_create/noise_mycompany"]
```

```bash
python tools/sysmongen.py build      # writes dist/sysmon-mycompany.xml
```

Excludes are applied before includes. A broad exclusion therefore hides
detections from every module for that event. The validator warns about
standalone `ParentImage` / `CommandLine` exclusions and about name-only matches
such as `end with \updater.exe`.

### Creating Custom Technique Modules

Write an include module tagged with its technique (`techniques: T1218.005`),
add it to a profile where that event is `selective`, and rebuild. Matching
events carry `RuleName: technique_id=T1218.005,module=<id>`. The format is in
[modules/README.md](modules/README.md).

---

## Troubleshooting

### Common Issues

#### Issue: "Sysmon rejects the configuration"

Run `python tools/sysmonlint.py <file>`. It reports what Sysmon rejects: unknown
or non-filterable events (for example `SysmonStatus`), fields that don't exist
on an event, invalid conditions, and malformed XML. See `testing/probes/` for
confirmed examples.

#### Issue: "An event type I expected is missing"

Check its mode in the header comment of the generated file. An empty
`onmatch="include"` logs **nothing**. Use mode `all` in the profile to log
everything except exclusions.

#### Issue: "Too many events"

Find the noisy sources with
`.\performance\Measure-LogVolume.ps1 -Days 1 -GroupBy Image`, then add a narrow
noise module as described above. `verbose` is meant for single hosts during an
investigation, not fleet-wide use.

#### Issue: "Events not appearing in Event Viewer"

Sysmon writes to `Applications and Services Logs/Microsoft/Windows/Sysmon/Operational`.
Check that the service is running (`Get-Service Sysmon64`) and print the loaded
configuration with `Sysmon64.exe -c`.

---

## Contributing

1. Change or add modules or profiles. Never edit `dist/` by hand.
2. Run `python -m pytest tests`, `python tools/sysmonlint.py modules dist` and
   `python tools/sysmongen.py build`.
3. Commit the regenerated `dist/`. CI loads every config into real Sysmon.

---

## FAQ

**Q: Which Sysmon version is required?**
A: 15.0 or later (schema 4.90). CI tests against the current Sysinternals
release. Built-in Windows Sysmon (Windows 11 / Server 2025) uses the same
configuration format.

**Q: Can I use include and exclude rules together?**
A: Yes. For one event, Sysmon logs what matches an include rule and no exclude
rule. The generator makes this explicit with the `selective` mode.

**Q: How do I enable only specific MITRE techniques?**
A: Create a profile that lists only the technique modules you want, with those
events set to `selective`.

**Q: Can I merge this with my existing Sysmon config?**
A: Split your config into modules (one event filter each), then add them to a
profile. The generator merges filters per event and flags conflicts.

**Q: Does this support Linux Sysmon?**
A: No. Sysmon for Linux uses a different event set.

---

## Resources

### Official Documentation
- [Sysmon Download & Docs](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Windows Event Log Documentation](https://learn.microsoft.com/en-us/windows/win32/wes/windows-event-log)

### Community Resources
- [TrustedSec Sysmon Community Guide](https://github.com/trustedsec/SysmonCommunityGuide)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [Olaf Hartong Sysmon Modular](https://github.com/olafhartong/sysmon-modular)
- [JPCERT Tool Analysis](https://jpcertcc.github.io/ToolAnalysisResultSheet/)

### Learning & Training
- [Sysmon Configuration Masterclass](https://www.youtube.com/results?search_query=sysmon+configuration+tutorial)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) - Test your detections
- [Malware Archaeology Logging Cheat Sheets](https://www.malwarearchaeology.com/logging/)

---

## Project Status

- **Version**: 1.0.0
- **Status**: Production Ready
- **Last Updated**: 2025-10-30
- **Maintainers**: Community-driven (see [CONTRIBUTORS.md](CONTRIBUTORS.md))

### Roadmap

- [ ] Web-based configuration builder (GUI for custom configs)
- [ ] Cloud integration (Azure Sentinel, AWS Security Hub)
- [ ] Linux Sysmon for Windows compatibility
- [ ] Automated threat intelligence feed integration
- [ ] Machine learning-based exclusion suggestions

---

## License

This project is licensed under the **MIT License** - see [LICENSE](LICENSE) for details.

This configuration incorporates best practices from the Sysmon community. We gratefully acknowledge the pioneering work of SwiftOnSecurity, Olaf Hartong, Florian Roth, Michael Haag, JPCERT/CC, and countless other contributors.

---

## Acknowledgments

Special thanks to:
- **Microsoft Sysinternals Team** - For creating and maintaining Sysmon
- **SwiftOnSecurity** - For the foundational sysmon-config that started it all
- **Olaf Hartong** - For pioneering modular architecture and MITRE mapping
- **Florian Roth (Neo23x0)** - For threat intelligence-driven rules
- **Michael Haag** - For DFIR-focused detection logic
- **JPCERT/CC** - For comprehensive attack tool analysis
- **TrustedSec** - For community education and documentation
- **The entire InfoSec community** - For continuous improvement through collaboration

---

**Built by the community, for the community. Contributions welcome.**

[Report Issue](../../issues) | [Request Feature](../../issues) | [Contribute](CONTRIBUTING.md)
