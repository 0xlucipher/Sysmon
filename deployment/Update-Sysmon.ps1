<#
.SYNOPSIS
    Update Sysmon configuration without service interruption.

.DESCRIPTION
    Hot-reload Sysmon configuration for tuning and updates. Supports profile
    switching and custom configuration deployment.

.PARAMETER ConfigProfile
    Configuration profile: balanced, verbose, dc

.PARAMETER ConfigPath
    Custom configuration file path

.PARAMETER Validate
    Validate configuration before applying

.PARAMETER Backup
    Create backup of current configuration before update

.PARAMETER Force
    Force update even if configuration appears unchanged

.EXAMPLE
    .\Update-Sysmon.ps1 -ConfigProfile verbose
    Switch to the verbose profile for an investigation

.EXAMPLE
    .\Update-Sysmon.ps1 -ConfigPath "C:\Custom\tuned-config.xml" -Validate
    Update with custom configuration after validation

.NOTES
    Version: 1.0.0
    Requires: PowerShell 5.1+ and Administrator privileges
#>

[CmdletBinding()]
param(
    [ValidateSet('balanced','verbose','dc')]
    [string]$ConfigProfile = 'balanced',

    [string]$ConfigPath,

    [switch]$Validate,

    [switch]$Backup = $true,

    [switch]$Force
)

#Requires -Version 5.1
#Requires -RunAsAdministrator

function Get-InstalledSysmonExe {
    # Standalone Sysmon runs as "Sysmon64" (or "Sysmon" on 32-bit); built-in
    # Windows Sysmon also registers a service. Use whichever is installed.
    foreach ($name in 'Sysmon64', 'Sysmon') {
        $svc = Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction SilentlyContinue
        if ($svc) {
            return ($svc.PathName -replace '^"([^"]+)".*$', '$1' -replace '^(\S+\.exe).*$', '$1')
        }
    }
    return $null
}

function Update-Configuration {
    # Check Sysmon installation
    $sysmonExe = Get-InstalledSysmonExe
    if (-not $sysmonExe) {
        Write-Host "ERROR: no Sysmon service found. Install Sysmon first." -ForegroundColor Red
        exit 1
    }

    # Determine config file
    if (-not $ConfigPath) {
        $ConfigPath = Join-Path $PSScriptRoot "..\dist\sysmon-$ConfigProfile.xml"
    }

    if (-not (Test-Path $ConfigPath)) {
        Write-Host "ERROR: Configuration file not found: $ConfigPath" -ForegroundColor Red
        exit 1
    }

    # Validate if requested
    if ($Validate) {
        Write-Host "Validating configuration..." -ForegroundColor Yellow
        try {
            [xml]$config = Get-Content $ConfigPath
            if (-not $config.Sysmon) {
                throw "Invalid configuration format"
            }
            Write-Host "Configuration valid" -ForegroundColor Green
        } catch {
            Write-Host "ERROR: Configuration validation failed: $_" -ForegroundColor Red
            exit 1
        }
    }

    # Backup current config
    if ($Backup) {
        $backupDir = "C:\Sysmon\Backup"
        New-Item -Path $backupDir -ItemType Directory -Force | Out-Null
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $backupPath = Join-Path $backupDir "config-$timestamp.xml"

        Write-Host "Backing up current configuration to $backupPath" -ForegroundColor Cyan
        & $sysmonExe -c | Out-File $backupPath
    }

    # Update configuration
    Write-Host "Updating Sysmon configuration..." -ForegroundColor Yellow
    $result = & $sysmonExe -c $ConfigPath 2>&1

    if ($LASTEXITCODE -eq 0) {
        Write-Host "Configuration updated successfully!" -ForegroundColor Green
        Write-Host "Sysmon is now using: $ConfigPath" -ForegroundColor Green
    } else {
        Write-Host "ERROR: Failed to update configuration" -ForegroundColor Red
        Write-Host $result -ForegroundColor Red
        exit 1
    }
}

Update-Configuration
