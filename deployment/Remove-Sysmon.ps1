<#
.SYNOPSIS
    Remove Sysmon from the system with optional configuration backup.

.DESCRIPTION
    Cleanly uninstalls Sysmon service and driver with backup options.

.PARAMETER BackupConfig
    Backup current configuration before removal

.PARAMETER Force
    Force removal without confirmation

.EXAMPLE
    .\Remove-Sysmon.ps1
    Remove Sysmon with confirmation prompt

.EXAMPLE
    .\Remove-Sysmon.ps1 -Force -BackupConfig
    Force remove with configuration backup

.NOTES
    Version: 1.0.0
    Requires: Administrator privileges
#>

[CmdletBinding()]
param(
    [switch]$BackupConfig,
    [switch]$Force
)

#Requires -RunAsAdministrator

function Remove-SysmonService {
    Write-Host "`n===============================================" -ForegroundColor Cyan
    Write-Host "   SYSMON REMOVAL UTILITY" -ForegroundColor Cyan
    Write-Host "===============================================`n" -ForegroundColor Cyan

    # Check if Sysmon is installed
    $sysmon = Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue
    if (-not $sysmon) {
        $sysmon = Get-Service -Name 'Sysmon' -ErrorAction SilentlyContinue
    }

    if (-not $sysmon) {
        Write-Host "Sysmon is not installed on this system." -ForegroundColor Yellow
        return
    }

    Write-Host "Found Sysmon service: $($sysmon.Name)" -ForegroundColor Cyan
    Write-Host "Status: $($sysmon.Status)" -ForegroundColor Cyan

    # Backup configuration if requested
    if ($BackupConfig) {
        Write-Host "`nBacking up configuration..." -ForegroundColor Yellow
        $backupDir = "C:\Sysmon\Backup"
        New-Item -Path $backupDir -ItemType Directory -Force | Out-Null
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $backupPath = Join-Path $backupDir "config-before-removal-$timestamp.xml"

        $sysmonExe = if ($sysmon.Name -eq 'Sysmon64') { 'Sysmon64.exe' } else { 'Sysmon.exe' }

        try {
            & $sysmonExe -c | Out-File $backupPath -ErrorAction Stop
            Write-Host "Configuration backed up to: $backupPath" -ForegroundColor Green
        } catch {
            Write-Host "Failed to backup configuration: $_" -ForegroundColor Red
        }
    }

    # Confirmation prompt
    if (-not $Force) {
        Write-Host "`nWARNING: This will remove Sysmon and stop all logging." -ForegroundColor Red
        $response = Read-Host "Are you sure you want to continue? (yes/no)"
        if ($response -ne 'yes') {
            Write-Host "Removal cancelled." -ForegroundColor Yellow
            return
        }
    }

    # Determine Sysmon executable path
    $sysmonExe = if ($sysmon.Name -eq 'Sysmon64') { 'Sysmon64.exe' } else { 'Sysmon.exe' }
    $sysmonPath = Join-Path $env:SystemRoot "System32\$sysmonExe"

    if (-not (Test-Path $sysmonPath)) {
        # Try to find it
        $sysmonPath = Get-Command $sysmonExe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
    }

    if (-not $sysmonPath) {
        Write-Host "ERROR: Cannot locate Sysmon executable" -ForegroundColor Red
        return
    }

    # Uninstall Sysmon
    Write-Host "`nRemoving Sysmon..." -ForegroundColor Yellow

    try {
        $process = Start-Process -FilePath $sysmonPath -ArgumentList '-u','force' -Wait -PassThru -NoNewWindow

        if ($process.ExitCode -eq 0) {
            Write-Host "`n✓ Sysmon removed successfully!" -ForegroundColor Green
            Write-Host "  - Service uninstalled" -ForegroundColor Green
            Write-Host "  - Driver removed" -ForegroundColor Green

            # Verify removal
            Start-Sleep -Seconds 2
            $checkService = Get-Service -Name 'Sysmon64','Sysmon' -ErrorAction SilentlyContinue
            if ($checkService) {
                Write-Host "`nWARNING: Service still detected. Reboot may be required." -ForegroundColor Yellow
            } else {
                Write-Host "  - Verification passed" -ForegroundColor Green
            }
        } else {
            Write-Host "`nERROR: Removal failed with exit code: $($process.ExitCode)" -ForegroundColor Red
        }
    } catch {
        Write-Host "`nERROR: Failed to remove Sysmon: $_" -ForegroundColor Red
    }

    Write-Host "`nNote: Event logs will remain in Event Viewer until manually cleared." -ForegroundColor Cyan
}

Remove-SysmonService
