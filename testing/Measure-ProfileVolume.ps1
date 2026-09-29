<#
.SYNOPSIS
    Measure Sysmon event volume per profile on a disposable Windows machine.

.DESCRIPTION
    For each profile in dist/: apply it, clear the Sysmon log, let the machine
    idle, run a scripted benign workload (process starts, file and registry
    activity, DNS lookups and a web request), then count events per event ID.

    This is a SYNTHETIC BASELINE: a CI runner has no real user, browser or
    line-of-business software, so real hosts will differ. Use it to compare
    profiles and spot regressions, not to size a SIEM.

.PARAMETER IdleSeconds
    Idle time per profile before the workload.

.PARAMETER Iterations
    How many times the workload loop runs per profile.

.PARAMETER SettleSeconds
    Wait after applying a profile (and after install) before counting, so
    start-up activity does not land in the first profile's numbers.

.PARAMETER OutputPath
    Markdown report path. A JSON file with the same base name is written too.
#>
[CmdletBinding()]
param(
    [int]$IdleSeconds = 300,
    [int]$Iterations = 60,
    [int]$SettleSeconds = 60,
    [string]$OutputPath = (Join-Path $PWD 'volume-report.md')
)

$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..')
$log = 'Microsoft-Windows-Sysmon/Operational'

function Invoke-Workload {
    param([int]$Iterations)
    $tmp = Join-Path $env:TEMP "volume-$([guid]::NewGuid())"
    New-Item -ItemType Directory -Path $tmp | Out-Null
    for ($i = 0; $i -lt $Iterations; $i++) {
        cmd.exe /c "echo workload $i > `"$tmp\f$i.txt`"" | Out-Null
        Get-ChildItem $env:SystemRoot\System32 -Filter *.dll | Select-Object -First 50 | Out-Null
        Remove-Item "$tmp\f$i.txt"
        Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | Out-Null
        Set-ItemProperty -Path 'HKCU:\Software' -Name 'VolumeTest' -Value $i
        Resolve-DnsName -Name "example.com" -ErrorAction SilentlyContinue | Out-Null
        try { Invoke-WebRequest -Uri 'https://example.com' -UseBasicParsing -TimeoutSec 10 | Out-Null } catch { }
        Start-Process -FilePath "$env:SystemRoot\System32\whoami.exe" -Wait -WindowStyle Hidden
        Start-Process -FilePath "$env:SystemRoot\System32\ipconfig.exe" -Wait -WindowStyle Hidden
    }
    Remove-ItemProperty -Path 'HKCU:\Software' -Name 'VolumeTest' -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $tmp
}

# Install Sysmon once (verified download), then switch profiles with -c.
$work = Join-Path $env:TEMP "sysmon-volume"
New-Item -ItemType Directory -Force -Path $work | Out-Null
Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile "$work\Sysmon.zip" -UseBasicParsing
Expand-Archive "$work\Sysmon.zip" -DestinationPath $work -Force
$sysmon = Join-Path $work 'Sysmon64.exe'
$sig = Get-AuthenticodeSignature $sysmon
if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
    throw "Sysmon signature check failed"
}
& $sysmon -accepteula -i 2>&1 | Out-Null
Start-Sleep -Seconds $SettleSeconds   # warm-up: let install-time activity pass

function Test-DnsTelemetry {
    # Resolve unique names through different APIs and check which ones Sysmon logs
    # as event 22. Sysmon reads DNS from the Windows DNS Client (ETW), so lookups that
    # bypass it (nslookup talks to the server directly) are not expected to appear.
    $probes = [ordered]@{
        'Resolve-DnsName'        = { param($n) Resolve-DnsName -Name $n -ErrorAction SilentlyContinue | Out-Null }
        '.NET GetHostAddresses'  = { param($n) try { [System.Net.Dns]::GetHostAddresses($n) | Out-Null } catch { } }
        'ping (getaddrinfo)'     = { param($n) ping.exe -n 1 -w 500 $n | Out-Null }
    }
    $result = [ordered]@{}
    foreach ($name in $probes.Keys) {
        $host_ = "sysmon-dns-probe-$([guid]::NewGuid().ToString('N').Substring(0, 12)).example.com"
        & $probes[$name] $host_
        Start-Sleep -Seconds 3
        $hit = Get-WinEvent -LogName $log -ErrorAction SilentlyContinue |
            Where-Object { $_.Id -eq 22 -and $_.Message -match [regex]::Escape($host_) }
        $result[$name] = [bool]$hit
    }
    return $result
}

$dnsClient = Get-Service -Name Dnscache -ErrorAction SilentlyContinue
$dnsProvider = [bool](Get-WinEvent -ListProvider 'Microsoft-Windows-DNS-Client' -ErrorAction SilentlyContinue)
$dnsProbe = $null

$results = [ordered]@{}
foreach ($cfg in Get-ChildItem (Join-Path $root 'dist') -Filter 'sysmon-*.xml' | Sort-Object Name) {
    $profileName = $cfg.BaseName -replace '^sysmon-', ''
    Write-Host "=== $profileName"
    & $sysmon -c $cfg.FullName 2>&1 | Out-Null
    Start-Sleep -Seconds $SettleSeconds
    wevtutil.exe cl $log
    $start = Get-Date
    Start-Sleep -Seconds $IdleSeconds
    Invoke-Workload -Iterations $Iterations
    Start-Sleep -Seconds 5
    $minutes = ((Get-Date) - $start).TotalMinutes
    $events = Get-WinEvent -LogName $log -ErrorAction SilentlyContinue
    $counts = [ordered]@{}
    foreach ($g in ($events | Group-Object Id | Sort-Object { [int]$_.Name })) { $counts[$g.Name] = $g.Count }
    if ($profileName -eq 'verbose') {
        # verbose logs DnsQuery in full, so any lookup the DNS Client sees should appear
        $dnsProbe = Test-DnsTelemetry
    }
    $results[$profileName] = [ordered]@{
        minutes = [math]::Round($minutes, 1)
        total = @($events).Count
        per_hour = [math]::Round(@($events).Count / $minutes * 60)
        by_event_id = $counts
    }
}
& $sysmon -u force 2>&1 | Out-Null

$ids = $results.Values | ForEach-Object { $_.by_event_id.Keys } | Sort-Object { [int]$_ } -Unique
$md = @(
    '# Synthetic volume baseline', '',
    "Sysmon $((Get-Item $sysmon).VersionInfo.FileVersion) on $((Get-CimInstance Win32_OperatingSystem).Caption), GitHub-hosted runner.",
    "Each profile: $SettleSeconds s settle after applying it, then $IdleSeconds s idle and $Iterations iterations of a scripted benign workload.",
    'A runner has no real user, browser or business software. Compare profiles with this, do not size a SIEM with it.', '',
    '| Profile | Minutes | Events | Events/hour |', '|---|---|---|---|'
)
foreach ($p in $results.Keys) { $r = $results[$p]; $md += "| $p | $($r.minutes) | $($r.total) | $($r.per_hour) |" }
$md += '', '## Events by ID', '', ('| Event ID | ' + ($results.Keys -join ' | ') + ' |'), ('|---|' + ('---|' * $results.Count))
foreach ($id in $ids) { $md += "| $id | " + (($results.Keys | ForEach-Object { $results[$_].by_event_id[$id] ?? 0 }) -join ' | ') + ' |' }
$md += '', '## DNS telemetry check (verbose profile)', '',
    "- DNS Client service (Dnscache): $(if ($dnsClient) { "$($dnsClient.Status), start type $($dnsClient.StartType)" } else { 'not present' })",
    "- Microsoft-Windows-DNS-Client event provider: $(if ($dnsProvider) { 'present' } else { 'missing' })"
if ($dnsProbe) {
    foreach ($k in $dnsProbe.Keys) { $md += "- Unique-name lookup via ${k}: $(if ($dnsProbe[$k]) { 'logged as event 22' } else { 'NOT logged' })" }
}
$md -join "`n" | Out-File -Encoding utf8 $OutputPath
[ordered]@{ profiles = $results; dns = [ordered]@{
        dnscache = if ($dnsClient) { "$($dnsClient.Status)/$($dnsClient.StartType)" } else { $null }
        provider = $dnsProvider; probes = $dnsProbe } } |
    ConvertTo-Json -Depth 6 | Out-File -Encoding utf8 ([IO.Path]::ChangeExtension($OutputPath, '.json'))
Get-Content $OutputPath | Write-Host
