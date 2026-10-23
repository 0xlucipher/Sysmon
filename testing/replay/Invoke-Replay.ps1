<#
.SYNOPSIS
    Prove that technique modules fire: run Atomic Red Team tests and assert the
    expected Sysmon events appear.

.DESCRIPTION
    For each test in testing/replay/manifest.json:
      1. note the current time,
      2. run the Atomic test BY GUID with Invoke-AtomicTest (get prereqs, execute,
         then clean up),
      3. read the Sysmon Operational log for events written since step 1,
      4. pass the test if every expected event ID for that technique appeared.

    The attack commands are NOT in this repository. Invoke-AtomicTest downloads
    and runs them from the pinned Atomic Red Team checkout. This script only
    orchestrates and checks telemetry.

    Intended for a DISPOSABLE Windows machine (a CI runner). It disables Microsoft
    Defender real-time protection so the atomics are not blocked mid-run, and runs
    real offensive techniques. Do not run it on a machine you care about.

.PARAMETER ConfigProfile
    Which dist/ profile to load before replaying. Defaults to the manifest's profile.

.PARAMETER OutputPath
    Markdown summary path. A JSON file with the same base name is written too.

.PARAMETER SettleSeconds
    Seconds to wait after each atomic for telemetry to flush before counting.
#>
[CmdletBinding()]
param(
    [string]$ConfigProfile,
    [string]$OutputPath = (Join-Path $PWD 'replay-report.md'),
    [int]$SettleSeconds = 5
)

$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path (Join-Path $PSScriptRoot '..') '..')
$manifest = Get-Content (Join-Path $PSScriptRoot 'manifest.json') -Raw | ConvertFrom-Json
if (-not $ConfigProfile) { $ConfigProfile = $manifest.framework.profile }
$log = 'Microsoft-Windows-Sysmon/Operational'

# Sysmon event-name -> numeric Event ID(s). A technique "expects" an event name;
# any ID in its set satisfies it (RegistryEvent is 12/13/14, etc.).
$eventIds = @{
    ProcessCreate = 1; FileCreateTime = 2; NetworkConnect = 3; ProcessTerminate = 5
    DriverLoad = 6; ImageLoad = 7; CreateRemoteThread = 8; RawAccessRead = 9
    ProcessAccess = 10; FileCreate = 11; RegistryEvent = 12, 13, 14; FileCreateStreamHash = 15
    PipeEvent = 17, 18; WmiEvent = 19, 20, 21; DnsQuery = 22; FileDelete = 23
    ClipboardChange = 24; ProcessTampering = 25; FileDeleteDetected = 26
    FileBlockExecutable = 27; FileBlockShredding = 28; FileExecutableDetected = 29
}

function Install-Sysmon {
    param([string]$ConfigFile)
    $work = Join-Path $env:TEMP 'sysmon-replay'
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Sysmon.zip' `
        -OutFile "$work\Sysmon.zip" -UseBasicParsing
    Expand-Archive "$work\Sysmon.zip" -DestinationPath $work -Force
    $sysmon = Join-Path $work 'Sysmon64.exe'
    $sig = Get-AuthenticodeSignature $sysmon
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
        throw "Sysmon signature check failed: $($sig.Status)"
    }
    if (Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue) {
        & $sysmon -accepteula -c $ConfigFile 2>&1 | Out-Null
    } else {
        & $sysmon -accepteula -i $ConfigFile 2>&1 | Out-Null
    }
    Start-Sleep -Seconds $SettleSeconds
}

function Install-AtomicRunner {
    param([string]$AtomicsRef, [string[]]$Techniques)
    # Install the runner and check out only the atomics folders this run needs,
    # pinned to the manifest's commit. A full checkout of atomic-red-team fails on
    # Windows (some unrelated test folders have paths NTFS rejects), so use a
    # sparse checkout limited to the manifest's techniques.
    Install-Module -Name powershell-yaml -Scope CurrentUser -Force -ErrorAction SilentlyContinue
    $iart = Join-Path $env:TEMP 'invoke-atomicredteam'
    if (-not (Test-Path $iart)) {
        git clone -q --depth 1 https://github.com/redcanaryco/invoke-atomicredteam $iart
    }
    Import-Module (Join-Path $iart 'Invoke-AtomicRedTeam.psd1') -Force

    $repo = Join-Path $env:TEMP 'atomic-red-team'
    if (-not (Test-Path (Join-Path $repo 'atomics'))) {
        if (Test-Path $repo) { Remove-Item -Recurse -Force $repo }
        git clone -q --filter=blob:none --no-checkout --sparse `
            https://github.com/redcanaryco/atomic-red-team $repo
        $paths = $Techniques | ForEach-Object { "atomics/$_" }
        git -C $repo sparse-checkout set --cone @paths
        git -C $repo checkout -q $AtomicsRef
    }
    return (Join-Path $repo 'atomics')
}

function Get-EventCounts {
    param([datetime]$Since)
    $counts = @{}
    try {
        Get-WinEvent -FilterHashtable @{ LogName = $log; StartTime = $Since } -ErrorAction Stop |
            ForEach-Object {
                if ($counts.ContainsKey($_.Id)) { $counts[$_.Id]++ } else { $counts[$_.Id] = 1 }
            }
    } catch {
        # "No events were found" throws; treat as empty.
    }
    return $counts
}

Write-Host "Loading profile '$ConfigProfile'"
Install-Sysmon -ConfigFile (Join-Path $root "dist\sysmon-$ConfigProfile.xml")

Write-Host "Disabling Defender real-time protection (disposable host)"
try { Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop } catch {
    Write-Warning "Could not disable Defender real-time monitoring: $_"
}

$techniques = $manifest.tests | ForEach-Object { $_.technique } | Sort-Object -Unique
$atomicsPath = Install-AtomicRunner -AtomicsRef $manifest.framework.atomics_ref -Techniques $techniques

$results = @()
foreach ($test in $manifest.tests) {
    Write-Host "`n=== $($test.technique) $($test.guid) — $($test.name)"
    $start = (Get-Date).AddSeconds(-1)
    $error.Clear()
    $ran = $true
    $reason = ''
    try {
        Invoke-AtomicTest $test.technique -TestGuids $test.guid -PathToAtomicsFolder $atomicsPath `
            -GetPrereqs -TimeoutSeconds 120 2>&1 | Out-Null
        Invoke-AtomicTest $test.technique -TestGuids $test.guid -PathToAtomicsFolder $atomicsPath `
            -TimeoutSeconds 120 2>&1 | Out-Null
    } catch {
        $ran = $false
        $reason = "$_"
    } finally {
        try {
            Invoke-AtomicTest $test.technique -TestGuids $test.guid -PathToAtomicsFolder $atomicsPath `
                -Cleanup -TimeoutSeconds 120 2>&1 | Out-Null
        } catch { }
    }

    Start-Sleep -Seconds $SettleSeconds
    $counts = Get-EventCounts -Since $start

    $seen = @()
    $missing = @()
    foreach ($name in $test.expect) {
        $ids = @($eventIds[$name])
        $hit = $ids | Where-Object { $counts.ContainsKey($_) }
        if ($hit) { $seen += $name } else { $missing += $name }
    }
    $pass = $ran -and $missing.Count -eq 0
    if (-not $ran) { $reason = "atomic did not run: $reason" }
    elseif ($missing.Count) { $reason = "no Sysmon events for: $($missing -join ', ')" }

    $byId = ($counts.Keys | Sort-Object | ForEach-Object { "$_=$($counts[$_])" }) -join ' '
    Write-Host ("  {0}  expected [{1}] seen [{2}]  events: {3}" -f `
        ($(if ($pass) { 'PASS' } else { 'FAIL' })), ($test.expect -join ','), ($seen -join ','), $byId)

    $results += [ordered]@{
        technique = $test.technique
        guid      = $test.guid
        name      = $test.name
        expect    = $test.expect
        seen      = $seen
        pass      = $pass
        reason    = $reason
    }
}

$passed = ($results | Where-Object { $_.pass }).Count
$total = $results.Count

$report = [ordered]@{
    profile       = $ConfigProfile
    atomics_ref   = $manifest.framework.atomics_ref
    generated_utc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    passed        = $passed
    total         = $total
    tests         = $results
}
$jsonPath = [IO.Path]::ChangeExtension($OutputPath, 'json')
$report | ConvertTo-Json -Depth 6 | Set-Content -Path $jsonPath -Encoding utf8

$md = @()
$md += "# Replay results"
$md += ""
$md += "Profile ``$ConfigProfile`` · atomics ``$($manifest.framework.atomics_ref.Substring(0,12))`` · $passed/$total passed · $($report.generated_utc)"
$md += ""
$md += "| Technique | Atomic | Expected events | Seen | Result |"
$md += "|---|---|---|---|---|"
foreach ($r in $results) {
    $res = if ($r.pass) { 'PASS' } else { "FAIL ($($r.reason))" }
    $md += "| $($r.technique) | $($r.name) | $($r.expect -join ', ') | $($r.seen -join ', ') | $res |"
}
$md -join "`n" | Set-Content -Path $OutputPath -Encoding utf8

Write-Host "`n$passed/$total passed. Report: $OutputPath"
if ($passed -ne $total) { exit 1 }
