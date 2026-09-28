<#
.SYNOPSIS
    Check whether the configuration Sysmon has loaded matches an expected file.

.DESCRIPTION
    Sysmon records the hash of the configuration it loaded in its driver's
    registry parameters (ConfigHash, e.g. "SHA256=<hex>"). This compares it with
    the hash of an expected configuration: a profile from dist/, a file, or a
    hash taken from a release's SHA256SUMS.

    Exit codes: 0 = matches, 1 = drift, 2 = Sysmon or its config hash not found.

.PARAMETER ConfigProfile
    Expected profile from dist/: balanced, verbose or dc.

.PARAMETER ConfigPath
    Expected configuration file.

.PARAMETER ExpectedHash
    Expected SHA256 (hex), e.g. from a release's SHA256SUMS.

.EXAMPLE
    .\deployment\Test-SysmonDrift.ps1 -ConfigProfile balanced
#>
[CmdletBinding(DefaultParameterSetName = 'Profile')]
param(
    [Parameter(ParameterSetName = 'Profile')]
    [ValidateSet('balanced', 'verbose', 'dc')]
    [string]$ConfigProfile = 'balanced',

    [Parameter(ParameterSetName = 'Path', Mandatory)]
    [string]$ConfigPath,

    [Parameter(ParameterSetName = 'Hash', Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedHash
)

function Get-LoadedSysmonConfig {
    # The Sysmon driver service's Parameters key holds ConfigHash and ConfigFile.
    Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction SilentlyContinue |
        ForEach-Object {
            $params = Get-ItemProperty -Path (Join-Path $_.PSPath 'Parameters') -ErrorAction SilentlyContinue
            if ($params -and $params.ConfigHash) {
                [pscustomobject]@{
                    Driver     = $_.PSChildName
                    ConfigHash = [string]$params.ConfigHash
                    ConfigFile = [string]$params.ConfigFile
                }
            }
        } | Select-Object -First 1
}

switch ($PSCmdlet.ParameterSetName) {
    'Hash' { $expected = $ExpectedHash.ToUpperInvariant(); $source = 'expected hash' }
    default {
        if ($PSCmdlet.ParameterSetName -eq 'Profile') {
            $ConfigPath = Join-Path $PSScriptRoot "..\dist\sysmon-$ConfigProfile.xml"
        }
        if (-not (Test-Path $ConfigPath)) {
            Write-Host "Expected configuration not found: $ConfigPath" -ForegroundColor Red
            exit 2
        }
        $expected = (Get-FileHash -Algorithm SHA256 -Path $ConfigPath).Hash.ToUpperInvariant()
        $source = $ConfigPath
    }
}

$loaded = Get-LoadedSysmonConfig
if (-not $loaded) {
    Write-Host "Sysmon is not installed, or has no configuration hash recorded." -ForegroundColor Red
    exit 2
}

$actual = ($loaded.ConfigHash -replace '^.*SHA256=', '' -split ',')[0].Trim().ToUpperInvariant()
Write-Host "Loaded config : $($loaded.ConfigFile) ($($loaded.Driver))"
Write-Host "Loaded hash   : $actual"
Write-Host "Expected hash : $expected ($source)"

if ($actual -eq $expected) {
    Write-Host "OK: loaded configuration matches." -ForegroundColor Green
    exit 0
}
Write-Host "DRIFT: loaded configuration differs from $source." -ForegroundColor Yellow
exit 1
