<#
.SYNOPSIS
    Load every Sysmon configuration into a real Sysmon instance and fail on any rejection.

.DESCRIPTION
    Intended for disposable Windows machines (CI runners, lab VMs). Downloads
    Sysmon from Sysinternals, verifies its Authenticode signature, installs the
    service, then applies each configuration with `Sysmon64.exe -c <file>`.
    A configuration passes only if Sysmon exits 0 and reports "Configuration updated".

    Also writes the Sysmon schema (`-s`) to the output directory so the static
    validator's field table can be checked against the real schema.

.PARAMETER Path
    Files or directories to test. Directories are searched recursively for *.xml.

.PARAMETER OutputDirectory
    Where to write the schema dump and per-config Sysmon output.

.EXAMPLE
    .\testing\Test-SysmonLoad.ps1 -Path configurations, examples
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string[]]$Path,

    [string]$OutputDirectory = (Join-Path $PWD 'sysmon-load-results')
)

$ErrorActionPreference = 'Stop'

function Get-VerifiedSysmon {
    param([string]$WorkDirectory)

    $zip = Join-Path $WorkDirectory 'Sysmon.zip'
    Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile $zip -UseBasicParsing
    Expand-Archive -Path $zip -DestinationPath $WorkDirectory -Force

    $exe = Join-Path $WorkDirectory 'Sysmon64.exe'
    $sig = Get-AuthenticodeSignature -FilePath $exe
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
        throw "Sysmon64.exe signature check failed: status=$($sig.Status) subject=$($sig.SignerCertificate.Subject)"
    }
    Write-Host "Verified signature: $($sig.SignerCertificate.Subject)"
    return $exe
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$work = Join-Path ([IO.Path]::GetTempPath()) "sysmon-load-$([guid]::NewGuid())"
New-Item -ItemType Directory -Force -Path $work | Out-Null

$sysmon = Get-VerifiedSysmon -WorkDirectory $work
$version = (Get-Item $sysmon).VersionInfo.FileVersion
Write-Host "Sysmon version: $version"

& $sysmon -accepteula -i 2>&1 | Out-Host
if ($LASTEXITCODE -ne 0) { throw "Sysmon install failed with exit code $LASTEXITCODE" }

& $sysmon -s 2>&1 | Out-File -Encoding utf8 (Join-Path $OutputDirectory 'sysmon-schema.xml')

$configs = foreach ($p in $Path) {
    if (Test-Path $p -PathType Container) {
        Get-ChildItem -Path $p -Filter *.xml -Recurse -File
    } else {
        Get-Item $p
    }
}

$failed = @()
foreach ($cfg in $configs | Sort-Object FullName) {
    $rel = Resolve-Path -Relative $cfg.FullName
    $output = (& $sysmon -c $cfg.FullName 2>&1 | Out-String)
    $code = $LASTEXITCODE
    $logName = ($rel -replace '^[.\\/]+', '' -replace '[\\/]', '_') + '.log'
    $output | Out-File -Encoding utf8 (Join-Path $OutputDirectory $logName)

    if ($code -eq 0 -and $output -match 'Configuration updated') {
        Write-Host "PASS  $rel"
    } else {
        Write-Host "FAIL  $rel (exit $code)"
        Write-Host ($output.Trim() -replace '(?m)^', '      ')
        $failed += $rel
    }
}

& $sysmon -u force 2>&1 | Out-Null

Write-Host ""
Write-Host "Sysmon ${version}: $($configs.Count - $failed.Count)/$($configs.Count) configurations loaded"
if ($failed.Count -gt 0) {
    Write-Host "::error::$($failed.Count) configuration(s) rejected by Sysmon: $($failed -join ', ')"
    exit 1
}
