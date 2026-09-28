<#
.SYNOPSIS
    End-to-end test of the deployment scripts on a disposable Windows machine.

.DESCRIPTION
    Installs the balanced profile with Install-Sysmon.ps1, checks there is no
    drift, switches to verbose with Update-Sysmon.ps1, checks that drift from
    balanced is detected, then removes Sysmon. Also reports whether this
    Windows build offers built-in Sysmon (informational).
#>
$ErrorActionPreference = 'Stop'
$deploy = Join-Path $PSScriptRoot '..\deployment'
$failures = @()

function Invoke-Step {
    param([string]$Name, [scriptblock]$Script, [int]$ExpectExit = 0)
    Write-Host "`n=== $Name"
    $global:LASTEXITCODE = 0
    & $Script
    $code = $LASTEXITCODE
    if ($code -ne $ExpectExit) {
        Write-Host "FAIL: $Name exited $code, expected $ExpectExit"
        $script:failures += $Name
    } else {
        Write-Host "PASS: $Name (exit $code)"
    }
}

$feature = Get-WindowsOptionalFeature -Online -FeatureName 'Sysmon' -ErrorAction SilentlyContinue
Write-Host "Built-in Sysmon feature on this image: $(if ($feature) { $feature.State } else { 'not available' })"

Invoke-Step 'Install balanced (standalone)' {
    & (Join-Path $deploy 'Install-Sysmon.ps1') -Source Standalone -ConfigProfile balanced -Force -NoRestart
}
Invoke-Step 'No drift from balanced' { & (Join-Path $deploy 'Test-SysmonDrift.ps1') -ConfigProfile balanced }
Invoke-Step 'Switch to verbose' { & (Join-Path $deploy 'Update-Sysmon.ps1') -ConfigProfile verbose -Backup:$false }
Invoke-Step 'Drift from balanced is detected' { & (Join-Path $deploy 'Test-SysmonDrift.ps1') -ConfigProfile balanced } -ExpectExit 1
Invoke-Step 'No drift from verbose' { & (Join-Path $deploy 'Test-SysmonDrift.ps1') -ConfigProfile verbose }
Invoke-Step 'Remove Sysmon' { & (Join-Path $deploy 'Remove-Sysmon.ps1') -Force }

if ($failures) {
    Write-Host "::error::Deployment test failed: $($failures -join '; ')"
    exit 1
}
Write-Host "`nAll deployment steps passed."
