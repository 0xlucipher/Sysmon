# Detection Logic Explained

This document explains the rationale and methodology behind key detection rules in the Sysmon Ultimate configuration.

## Table of Contents

- [Credential Dumping Detection](#credential-dumping-detection)
- [Process Injection Detection](#process-injection-detection)
- [Lateral Movement Detection](#lateral-movement-detection)
- [Persistence Mechanism Detection](#persistence-mechanism-detection)
- [Defense Evasion Detection](#defense-evasion-detection)
- [Command and Control Detection](#command-and-control-detection)
- [Ransomware Detection](#ransomware-detection)

---

## Credential Dumping Detection

### T1003.001 - LSASS Memory Dumping

**Attack Scenario:**
Attackers frequently target the Local Security Authority Subsystem Service (LSASS) process to extract credentials from memory. Tools like Mimikatz, ProcDump, and custom malware read LSASS memory to obtain plaintext passwords, NTLM hashes, and Kerberos tickets.

**Detection Method:**

1. **ProcessAccess (Event ID 10):**
   ```xml
   <ProcessAccess onmatch="include">
     <TargetImage condition="end with">\lsass.exe</TargetImage>
     <GrantedAccess condition="is">0x1410</GrantedAccess>
   </ProcessAccess>
   ```
   - Detects any process accessing LSASS with PROCESS_VM_READ rights
   - Excludes legitimate system processes (svchost.exe, csrss.exe)
   - Focuses on dangerous access rights: 0x1410, 0x1438, 0x143A, 0x1FFFFF

2. **ProcessCreate (Event ID 1):**
   ```xml
   <ProcessCreate onmatch="include">
     <CommandLine condition="contains">comsvcs.dll MiniDump</CommandLine>
   </ProcessCreate>
   ```
   - Detects `rundll32.exe comsvcs.dll MiniDump` technique
   - Monitors ProcDump usage: `procdump64.exe -ma lsass.exe`
   - Identifies Mimikatz execution via command-line keywords

3. **FileCreate (Event ID 11):**
   ```xml
   <FileCreate onmatch="include">
     <TargetFilename condition="contains">lsass</TargetFilename>
     <TargetFilename condition="end with">.dmp</TargetFilename>
   </FileCreate>
   ```
   - Detects LSASS dump file creation (e.g., `lsass.dmp`, `lsass_dump.dmp`)

**Expected False Positives:**
- Windows Defender occasionally scans LSASS (excluded via specific GrantedAccess)
- Task Manager creating dumps (excluded if legitimate use)
- Process Explorer/Process Hacker (security tools - configure exclusions)

**Tuning Recommendations:**
- Add your security tools to exclusions
- Monitor for spike in LSASS access attempts (possible attack)
- Correlate with authentication failures and privilege escalation attempts

**Real-World Example:**
```
Attacker runs: rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 652 C:\temp\lsass.dmp full

Sysmon Events Generated:
- Event ID 1: Rundll32 with comsvcs.dll and MiniDump parameters
- Event ID 10: Rundll32 accessing lsass.exe with 0x1FFFFF access
- Event ID 11: lsass.dmp file created in C:\temp\
```

---

## Process Injection Detection

### T1055.001 - DLL Injection

**Attack Scenario:**
Attackers inject malicious DLLs into legitimate processes to evade detection, escalate privileges, or persist. Common targets: explorer.exe, svchost.exe, browser processes.

**Detection Method:**

1. **CreateRemoteThread (Event ID 8):**
   ```xml
   <CreateRemoteThread onmatch="include">
     <TargetImage condition="end with">\lsass.exe</TargetImage>
   </CreateRemoteThread>
   ```
   - Detects thread creation in remote processes
   - Critical indicator of injection
   - Monitors StartModule for null (reflective injection)

2. **ImageLoad (Event ID 7):**
   ```xml
   <ImageLoad onmatch="include">
     <ImageLoaded condition="begin with">C:\Users\</ImageLoaded>
     <Signed condition="is">false</Signed>
   </ImageLoad>
   ```
   - Unsigned DLLs loaded from user directories
   - DLLs loaded from Temp directories
   - Known malicious DLL names (mimicking system DLLs)

3. **ProcessAccess (Event ID 10):**
   ```xml
   <ProcessAccess onmatch="include">
     <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
   </ProcessAccess>
   ```
   - PROCESS_ALL_ACCESS rights often precede injection
   - Detects VirtualAllocEx + WriteProcessMemory pattern

**Expected False Positives:**
- Antivirus/EDR products inject into processes for monitoring
- Browser plugins and extensions (Chrome, Firefox)
- .NET applications loading assemblies

**Tuning Recommendations:**
- Exclude your EDR/AV vendor paths
- Whitelist signed DLLs from Program Files
- Monitor patterns: injection from PowerShell, script hosts

**Real-World Example:**
```
Attacker uses PowerShell Empire to inject into explorer.exe

Sysmon Events Generated:
- Event ID 1: powershell.exe with -EncodedCommand (obfuscated)
- Event ID 8: powershell.exe creating remote thread in explorer.exe
- Event ID 7: Unsigned DLL loaded into explorer.exe from C:\Users\...\AppData\
- Event ID 10: powershell.exe accessing explorer.exe with 0x1FFFFF
```

---

## Lateral Movement Detection

### T1021.002 - PSExec-Style Lateral Movement

**Attack Scenario:**
Attackers use PSExec or alternatives (PaExec, RemCom, CSExec) to execute commands on remote systems via SMB named pipes and remote service creation.

**Detection Method:**

1. **PipeEvent (Event ID 17/18):**
   ```xml
   <PipeEvent onmatch="include">
     <PipeName condition="begin with">\\PSEXESVC</PipeName>
   </PipeEvent>
   ```
   - PSExec creates named pipe: `\\.\pipe\PSEXESVC`
   - Alternative tools use similar patterns

2. **ProcessCreate (Event ID 1):**
   ```xml
   <ProcessCreate onmatch="include">
     <ParentImage condition="end with">\services.exe</ParentImage>
     <Image condition="begin with">C:\Windows\</Image>
   </ProcessCreate>
   ```
   - Remote service execution: parent process is services.exe
   - Monitor for unusual command-lines spawned remotely

3. **NetworkConnect (Event ID 3):**
   ```xml
   <NetworkConnect onmatch="include">
     <DestinationPort condition="is">445</DestinationPort>
   </NetworkConnect>
   ```
   - SMB connections (port 445) to remote hosts
   - Correlate with process and pipe events

**Expected False Positives:**
- Legitimate administrative tools (SCCM, Group Policy)
- IT management software
- Scheduled tasks running across systems

**Tuning Recommendations:**
- Whitelist known admin workstations
- Monitor for PSExec usage from non-admin systems
- Alert on lateral movement outside business hours

**Real-World Example:**
```
Attacker runs: psexec.exe \\targetPC -u admin -p pass cmd.exe

Sysmon Events (on attacker system):
- Event ID 1: psexec.exe with target system and credentials
- Event ID 3: Network connection to targetPC:445

Sysmon Events (on target system):
- Event ID 17: Named pipe created: \\.\pipe\PSEXESVC
- Event ID 1: cmd.exe spawned by services.exe (remote execution)
```

---

## Persistence Mechanism Detection

### T1547.001 - Registry Run Keys

**Attack Scenario:**
Attackers modify registry run keys to achieve persistence. Every system reboot or user login executes the malicious payload.

**Detection Method:**

```xml
<RegistryEvent onmatch="include">
  <TargetObject condition="contains">\Microsoft\Windows\CurrentVersion\Run</TargetObject>
</RegistryEvent>
```

**Monitored Registry Keys:**
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`

**Expected False Positives:**
- Legitimate software auto-start entries (OneDrive, Dropbox, security software)
- Windows Update components
- User-installed applications

**Tuning Recommendations:**
- Baseline normal run key entries in your environment
- Alert on new entries in HKLM (system-wide persistence)
- Monitor for entries pointing to Temp directories or user Downloads

**Real-World Example:**
```
Attacker adds persistence:
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityUpdate" /t REG_SZ /d "C:\Users\victim\AppData\Roaming\malware.exe"

Sysmon Events:
- Event ID 1: reg.exe with "add" and "Run" keywords
- Event ID 13: Registry value set in CurrentVersion\Run
```

---

## Defense Evasion Detection

### T1562.001 - Disable Windows Defender

**Attack Scenario:**
Attackers disable or modify security tools to evade detection. Common targets: Windows Defender, firewall, Sysmon.

**Detection Method:**

```xml
<RegistryEvent onmatch="include">
  <TargetObject condition="contains">\SOFTWARE\Microsoft\Windows Defender\</TargetObject>
</RegistryEvent>

<ProcessCreate onmatch="include">
  <CommandLine condition="contains">Set-MpPreference -DisableRealtimeMonitoring $true</CommandLine>
</ProcessCreate>
```

**Monitored Activities:**
- Registry modification: `DisableAntiSpyware`, `DisableRealtimeMonitoring`
- PowerShell: `Set-MpPreference` cmdlet abuse
- Service stop: `sc stop WinDefend`
- Sysmon service tampering (Event ID 16)

**Expected False Positives:**
- Legitimate system administration
- Testing/QA environments
- Software installations requiring temporary AV disable

**Tuning Recommendations:**
- Alert immediately on production systems
- Whitelist change management processes
- Monitor for defense evasion + other attack techniques (staged attack)

**Real-World Example:**
```
Ransomware disables Defender before encryption:
powershell.exe -Command "Set-MpPreference -DisableRealtimeMonitoring $true"

Sysmon Events:
- Event ID 1: powershell.exe with Set-MpPreference command
- Event ID 13: Registry modification in Windows Defender keys
- Event ID 5: Windows Defender service stopped (if applicable)
```

---

## Command and Control Detection

### T1071.004 - DNS C2 Communication

**Attack Scenario:**
Attackers use DNS queries for command and control or data exfiltration. DNS tunneling tools encode commands/data in DNS queries and responses.

**Detection Method:**

```xml
<DnsQuery onmatch="include">
  <QueryName condition="end with">duckdns.org</QueryName>
  <QueryName condition="end with">no-ip.com</QueryName>
  <QueryName condition="end with">.tk</QueryName>
</DnsQuery>
```

**Detection Indicators:**
- Dynamic DNS services (DuckDNS, No-IP, FreeDNS)
- Suspicious TLDs (.tk, .ml, .ga, .cf, .gq)
- Tunneling services (ngrok, localtunnel)
- High-frequency queries to same domain
- Unusually long subdomain names (DGA or data encoding)

**Expected False Positives:**
- Legitimate use of dynamic DNS for remote access
- Development/testing with tunneling services
- IoT devices using dynamic DNS

**Tuning Recommendations:**
- Baseline normal DNS patterns
- Focus on DNS from unusual processes (not browsers, not system)
- Alert on DGA-like patterns (random-looking domains)
- Correlate with network data transfer volumes

**Real-World Example:**
```
Cobalt Strike beacon using DNS C2:
Random queries: a1b2c3d4.malicious-c2.com, e5f6g7h8.malicious-c2.com

Sysmon Events:
- Event ID 22: Repeated DNS queries to same domain with varying subdomains
- Event ID 3: (if DNS tunneling tool makes direct connections)
```

---

## Ransomware Detection

### T1486 + T1490 - Ransomware Behavior Chain

**Attack Scenario:**
Ransomware typically follows a pattern:
1. Disable system recovery (vssadmin delete shadows)
2. Modify boot configuration (bcdedit)
3. Stop backup services
4. Mass file encryption
5. Drop ransom notes

**Detection Method:**

1. **Inhibit System Recovery:**
   ```xml
   <ProcessCreate onmatch="include">
     <CommandLine condition="contains">vssadmin delete shadows</CommandLine>
     <CommandLine condition="contains">bcdedit /set {default} recoveryenabled No</CommandLine>
   </ProcessCreate>
   ```

2. **Service Manipulation:**
   ```xml
   <ProcessCreate onmatch="include">
     <CommandLine condition="contains">wmic shadowcopy delete</CommandLine>
     <CommandLine condition="contains">net stop vss</CommandLine>
   </ProcessCreate>
   ```

3. **Mass File Modification:**
   ```xml
   <FileCreate onmatch="include">
     <TargetFilename condition="end with">.encrypted</TargetFilename>
     <TargetFilename condition="end with">.locked</TargetFilename>
     <TargetFilename condition="end with">.ransom</TargetFilename>
   </FileCreate>
   ```

4. **Ransom Note Creation:**
   ```xml
   <FileCreate onmatch="include">
     <TargetFilename condition="contains">DECRYPT</TargetFilename>
     <TargetFilename condition="contains">RANSOM</TargetFilename>
     <TargetFilename condition="contains">RESTORE</TargetFilename>
   </FileCreate>
   ```

**Expected False Positives:**
- Legitimate backup operations
- System administrators managing shadow copies
- Disaster recovery testing

**Tuning Recommendations:**
- Alert immediately on vssadmin delete + bcdedit combination
- Monitor for rapid file creation rate spikes
- Baseline normal file extensions created
- Implement emergency response playbook

**Real-World Example:**
```
WannaCry ransomware execution:

Sysmon Events (sequence):
1. Event ID 1: cmd.exe /c vssadmin delete shadows /all /quiet
2. Event ID 1: cmd.exe /c bcdedit /set {default} recoveryenabled No
3. Event ID 1: cmd.exe /c wmic shadowcopy delete
4. Event ID 11: Hundreds of .WNCRY file creations
5. Event ID 11: @WanaDecryptor@.exe dropped in multiple directories
6. Event ID 1: @WanaDecryptor@.exe execution
```

---

## Detection Correlation Examples

### Multi-Stage Attack Detection

**Scenario: APT-style intrusion chain**

1. **Initial Access (Phishing):**
   - Event ID 11: malicious.docm downloaded to Downloads folder
   - Event ID 1: WINWORD.EXE spawns cmd.exe (macro execution)

2. **Execution (PowerShell):**
   - Event ID 1: cmd.exe spawns powershell.exe with -EncodedCommand
   - Event ID 3: PowerShell connects to external IP (payload download)

3. **Persistence:**
   - Event ID 13: Registry Run key modified
   - Event ID 11: Malware dropped to C:\ProgramData\

4. **Defense Evasion:**
   - Event ID 13: Windows Defender DisableRealtimeMonitoring set
   - Event ID 1: PowerShell modifying exclusions

5. **Credential Access:**
   - Event ID 10: Malware accessing lsass.exe
   - Event ID 11: credentials.dmp created

6. **Lateral Movement:**
   - Event ID 3: SMB connection to internal host
   - Event ID 17: PSEXESVC pipe created
   - Event ID 1: cmd.exe spawned by services.exe on target

7. **Collection & Exfiltration:**
   - Event ID 1: 7z.exe archiving documents
   - Event ID 3: Large data transfer to external IP

**Detection Strategy:**
- Individual events may be benign
- Sequence and timing correlation is key
- SIEM rules should chain these events
- Alert on 3+ stages detected within short timeframe

---

## SIEM Correlation Rules

### Example: Credential Dumping Alert

```
Rule: LSASS Access from Unusual Process
Logic: (Event ID 10 AND TargetImage = "*\lsass.exe")
       AND SourceImage NOT IN (whitelist)
       AND GrantedAccess IN (0x1410, 0x1438, 0x143A, 0x1FFFFF)
Severity: High
Action: Alert SOC + Block process + Isolate endpoint
```

### Example: Lateral Movement Detection

```
Rule: PSExec-style Lateral Movement
Logic: (Event ID 17 AND PipeName = "*PSEXESVC*")
       OR (Event ID 1 AND ParentImage = "*services.exe"
           AND CommandLine = "*cmd.exe*"
           AND User != SYSTEM)
Timeframe: Within 60 seconds
Severity: Critical
Action: Alert SOC + Investigate source/target systems
```

---

## Performance Optimization Notes

### High-Volume Events

**Event ID 1 (Process Creation):**
- ~60% of total Sysmon events
- Optimization: Exclude noisy system processes
- Balance: Don't over-exclude or miss attacks

**Event ID 3 (Network):**
- ~25% of total events
- Optimization: Exclude internal private networks (with exceptions for SMB/RDP/SSH)
- Balance: Log external connections + critical internal protocols

**Event ID 7 (Image Load):**
- Potentially highest volume if unfiltered
- Optimization: Exclude signed Microsoft DLLs from system directories
- Balance: Log unsigned DLLs and unusual loading paths

**Event ID 22 (DNS):**
- High volume if all queries logged
- Optimization: Exclude major legitimate domains (Microsoft, Google, CDNs)
- Balance: Log suspicious TLDs, dynamic DNS, tunneling services

### Exclusion Best Practices

1. **Start Conservative:** Begin with minimal exclusions, add based on analysis
2. **Measure Impact:** Use performance benchmarking tools
3. **Document Exclusions:** Maintain list of what's excluded and why
4. **Regular Review:** Quarterly review of exclusions vs. threat landscape
5. **Environment-Specific:** Tailor to your software stack

---

## Additional Resources

- **MITRE ATT&CK Navigator:** Visualize technique coverage
- **Atomic Red Team:** Test detections with atomic tests
- **SIGMA Rules:** Convert Sysmon rules to SIEM queries
- **Sysmon Community Guide:** Extended documentation and examples

---

**Document Version:** 1.0.0
**Last Updated:** 2025-10-30
**Maintained by:** Sysmon Ultimate Configuration Project
