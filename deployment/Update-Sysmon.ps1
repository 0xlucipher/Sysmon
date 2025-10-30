<#
.SYNOPSIS
    Update Sysmon configuration without service interruption.

.DESCRIPTION
    Hot-reload Sysmon configuration for tuning and updates. Supports profile
    switching and custom configuration deployment.

.PARAMETER ConfigProfile
    Configuration profile: minimal, balanced, comprehensive, forensics

.PARAMETER ConfigPath
    Custom configuration file path

.PARAMETER Validate
    Validate configuration before applying

.PARAMETER Backup
    Create backup of current configuration before update

.PARAMETER Force
    Force update even if configuration appears unchanged

.EXAMPLE
    .\Update-Sysmon.ps1 -ConfigProfile comprehensive
    Switch to comprehensive profile

.EXAMPLE
    .\Update-Sysmon.ps1 -ConfigPath "C:\Custom\tuned-config.xml" -Validate
    Update with custom configuration after validation

.NOTES
    Version: 1.0.0
    Requires: PowerShell 5.1+ and Administrator privileges
#>

[CmdletBinding()]
param(
    [ValidateSet('minimal','balanced','comprehensive','forensics')]
    [string]$ConfigProfile = 'balanced',

    [string]$ConfigPath,

    [switch]$Validate,

    [switch]$Backup = $true,

    [switch]$Force
)

#Requires -Version 5.1
#Requires -RunAsAdministrator

function Update-Configuration {
    # Check Sysmon installation
    $sysmon = Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue
    if (-not $sysmon) {
        Write-Host "ERROR: Sysmon64 service not found. Install Sysmon first." -ForegroundColor Red
        exit 1
    }

    # Determine config file
    if (-not $ConfigPath) {
        $profiles = @{
            'minimal' = 'sysmon-minimal.xml'
            'balanced' = 'sysmon-base.xml'
            'comprehensive' = 'sysmon-comprehensive.xml'
            'forensics' = 'sysmon-forensics.xml'
        }

        $ConfigPath = Join-Path $PSScriptRoot "..\configurations\$($profiles[$ConfigProfile])"
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
        & Sysmon64.exe -c | Out-File $backupPath
    }

    # Update configuration
    Write-Host "Updating Sysmon configuration..." -ForegroundColor Yellow
    $result = & Sysmon64.exe -c $ConfigPath 2>&1

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
