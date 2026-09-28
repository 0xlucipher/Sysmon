<#
.SYNOPSIS
    Automated Sysmon deployment script with configuration profile selection.

.DESCRIPTION
    This script automates the installation and configuration of Sysmon with
    intelligent profile selection and validation. Supports multiple deployment
    scenarios including standalone, SCCM, and Group Policy.

.PARAMETER ConfigProfile
    Configuration profile to use: balanced, verbose, dc
    Default: balanced

.PARAMETER Source
    Where Sysmon comes from: Auto (default), BuiltIn or Standalone.
    BuiltIn enables the Windows optional feature (Windows 11 / Server 2025).
    Standalone downloads Sysinternals Sysmon and verifies its signature.
    Auto uses built-in Sysmon when Windows offers it and no standalone Sysmon
    is installed (the two cannot coexist), otherwise standalone.

.PARAMETER SysmonPath
    Path to Sysmon64.exe. If not specified, script will attempt to download.

.PARAMETER ConfigPath
    Custom configuration file path. Overrides -ConfigProfile if specified.

.PARAMETER SkipDownload
    Skip automatic Sysmon download if not found locally.

.PARAMETER Force
    Force reinstallation even if Sysmon is already installed.

.PARAMETER NoRestart
    Don't restart Sysmon service after configuration (use for hot-reload).

.PARAMETER ListProfiles
    List available configuration profiles and exit.

.PARAMETER Validate
    Validate configuration before deployment.

.PARAMETER LogPath
    Path for installation log. Default: C:\Windows\Temp\Sysmon-Install.log

.EXAMPLE
    .\Install-Sysmon.ps1
    Install Sysmon with default 'balanced' profile

.EXAMPLE
    .\Install-Sysmon.ps1 -ConfigProfile dc
    Install with the domain controller profile

.EXAMPLE
    .\Install-Sysmon.ps1 -ConfigPath "C:\Custom\my-config.xml"
    Install with custom configuration file

.EXAMPLE
    .\Install-Sysmon.ps1 -ListProfiles
    Display available configuration profiles

.NOTES
    Version: 1.0.0
    Project: sysmon-config (https://github.com/0xlucipher/Sysmon)
    Requires: PowerShell 5.1+ and Administrator privileges
    Compatible: Windows 10/11, Server 2016/2019/2022

.LINK
    https://github.com/0xlucipher/Sysmon
    https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
#>

[CmdletBinding(DefaultParameterSetName='Install')]
param(
    [Parameter(ParameterSetName='Install')]
    [ValidateSet('balanced','verbose','dc')]
    [string]$ConfigProfile = 'balanced',

    [Parameter(ParameterSetName='Install')]
    [ValidateSet('Auto','BuiltIn','Standalone')]
    [string]$Source = 'Auto',

    [Parameter(ParameterSetName='Install')]
    [string]$SysmonPath,

    [Parameter(ParameterSetName='Install')]
    [string]$ConfigPath,

    [Parameter(ParameterSetName='Install')]
    [switch]$SkipDownload,

    [Parameter(ParameterSetName='Install')]
    [switch]$Force,

    [Parameter(ParameterSetName='Install')]
    [switch]$NoRestart,

    [Parameter(ParameterSetName='Install')]
    [switch]$Validate,

    [Parameter(ParameterSetName='Install')]
    [string]$LogPath = "$env:TEMP\Sysmon-Install.log",

    [Parameter(ParameterSetName='List')]
    [switch]$ListProfiles
)

#Requires -Version 5.1
#Requires -RunAsAdministrator

# Script configuration
$ErrorActionPreference = 'Stop'
$Script:ScriptVersion = '1.0.0'
$Script:SysmonDownloadUrl = 'https://download.sysinternals.com/files/Sysmon.zip'
$Script:SysmonMinVersion = [Version]'15.0'

# Profile definitions. Configs are generated into dist/ by tools/sysmongen.py.
# Volume is not listed until it has been measured (see documentation/DESIGN.md #11).
$Script:Profiles = @{
    'balanced' = @{
        Name = 'Balanced'
        Description = 'Default for workstations and servers'
        ConfigFile = 'sysmon-balanced.xml'
        UseCase = 'Fleet-wide default'
    }
    'verbose' = @{
        Name = 'Verbose'
        Description = 'Every event type except clipboard and blocking, minus known noise; archives deleted executables'
        ConfigFile = 'sysmon-verbose.xml'
        UseCase = 'Incident response and research on individual hosts'
    }
    'dc' = @{
        Name = 'Domain controller'
        Description = 'Balanced plus domain-controller detections and noise filters'
        ConfigFile = 'sysmon-dc.xml'
        UseCase = 'Domain controllers'
    }
}


#region Helper Functions

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info','Success','Warning','Error')]
        [string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] [$Level] $Message"

    # Console output with colors
    switch ($Level) {
        'Success' { Write-Host $logMessage -ForegroundColor Green }
        'Warning' { Write-Host $logMessage -ForegroundColor Yellow }
        'Error'   { Write-Host $logMessage -ForegroundColor Red }
        default   { Write-Host $logMessage }
    }

    # File logging
    try {
        Add-Content -Path $LogPath -Value $logMessage -ErrorAction SilentlyContinue
    } catch {
        # Ignore logging errors to not disrupt installation
    }
}

function Test-AdministratorPrivileges {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-CompatibleOS {
    $os = Get-CimInstance Win32_OperatingSystem
    $version = [Version]$os.Version

    # Windows 10 (10.0.10240) or later
    if ($version.Major -ge 10) {
        return $true
    }

    # Server 2016 or later
    if ($os.ProductType -ne 1 -and $version.Major -ge 10) {
        return $true
    }

    return $false
}

function Get-SysmonStatus {
    try {
        $service = Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue
        if (-not $service) {
            $service = Get-Service -Name 'Sysmon' -ErrorAction SilentlyContinue
        }

        if ($service) {
            $driverPath = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv' -Name 'ImagePath' -ErrorAction SilentlyContinue).ImagePath

            return @{
                Installed = $true
                ServiceName = $service.Name
                Status = $service.Status
                StartType = $service.StartType
                DriverPath = $driverPath
            }
        }

        return @{ Installed = $false }
    } catch {
        return @{ Installed = $false }
    }
}

function Get-SysmonVersion {
    param([string]$SysmonExePath)

    try {
        $versionInfo = (Get-Item $SysmonExePath).VersionInfo
        return [Version]$versionInfo.FileVersion
    } catch {
        return $null
    }
}

function Download-Sysmon {
    param([string]$DestinationPath)

    Write-Log "Downloading Sysmon from $Script:SysmonDownloadUrl" -Level Info

    try {
        $zipPath = Join-Path $DestinationPath 'Sysmon.zip'

        # Use BITS if available for better performance
        if (Get-Command Start-BitsTransfer -ErrorAction SilentlyContinue) {
            Start-BitsTransfer -Source $Script:SysmonDownloadUrl -Destination $zipPath
        } else {
            Invoke-WebRequest -Uri $Script:SysmonDownloadUrl -OutFile $zipPath -UseBasicParsing
        }

        Write-Log "Extracting Sysmon archive" -Level Info
        Expand-Archive -Path $zipPath -DestinationPath $DestinationPath -Force

        Remove-Item $zipPath -Force

        $sysmonExe = Join-Path $DestinationPath 'Sysmon64.exe'
        if (-not (Test-Path $sysmonExe)) {
            throw "Sysmon64.exe not found in extracted archive"
        }

        # Refuse to run anything that is not validly signed by Microsoft
        $signature = Get-AuthenticodeSignature -FilePath $sysmonExe
        if ($signature.Status -ne 'Valid' -or
            $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
            Remove-Item $sysmonExe -Force -ErrorAction SilentlyContinue
            throw "Sysmon64.exe failed signature verification (status: $($signature.Status))"
        }

        Write-Log "Sysmon downloaded and signature verified" -Level Success
        return $sysmonExe
    } catch {
        Write-Log "Failed to download Sysmon: $_" -Level Error
        throw
    }
}

function Get-BuiltInSysmon {
    <#
    Returns the path to built-in Sysmon (Windows optional feature "Sysmon"),
    enabling the feature first when -Enable is given. Returns $null when the
    feature does not exist on this Windows build.
    #>
    param([switch]$Enable)

    $feature = Get-WindowsOptionalFeature -Online -FeatureName 'Sysmon' -ErrorAction SilentlyContinue
    if (-not $feature) {
        return $null
    }

    if ($feature.State -ne 'Enabled') {
        if (-not $Enable) {
            return $null
        }
        Write-Log "Enabling the built-in Sysmon Windows feature" -Level Info
        Enable-WindowsOptionalFeature -Online -FeatureName 'Sysmon' -NoRestart | Out-Null
    }

    $exe = Get-Command 'sysmon.exe' -ErrorAction SilentlyContinue
    if (-not $exe) {
        $candidate = Join-Path $env:SystemRoot 'System32\Sysmon.exe'
        if (Test-Path $candidate) { return $candidate }
        throw "Built-in Sysmon feature is enabled but sysmon.exe was not found"
    }
    return $exe.Source
}

function Test-ConfigurationValid {
    param([string]$ConfigPath)

    Write-Log "Validating configuration file: $ConfigPath" -Level Info

    if (-not (Test-Path $ConfigPath)) {
        Write-Log "Configuration file not found: $ConfigPath" -Level Error
        return $false
    }

    try {
        # Basic XML validation
        [xml]$config = Get-Content $ConfigPath -Raw

        # Check for Sysmon root element
        if ($config.Sysmon) {
            $schemaVersion = $config.Sysmon.schemaversion
            Write-Log "Configuration valid - Schema version: $schemaVersion" -Level Success
            return $true
        } else {
            Write-Log "Invalid configuration: Missing Sysmon root element" -Level Error
            return $false
        }
    } catch {
        Write-Log "Configuration validation failed: $_" -Level Error
        return $false
    }
}

function Install-SysmonService {
    param(
        [string]$SysmonExe,
        [string]$ConfigFile
    )

    Write-Log "Installing Sysmon service with configuration: $ConfigFile" -Level Info

    try {
        $arguments = @('-accepteula', '-i', $ConfigFile)
        $process = Start-Process -FilePath $SysmonExe -ArgumentList $arguments -Wait -PassThru -NoNewWindow

        if ($process.ExitCode -eq 0) {
            Write-Log "Sysmon installed successfully" -Level Success
            return $true
        } else {
            Write-Log "Sysmon installation failed with exit code: $($process.ExitCode)" -Level Error
            return $false
        }
    } catch {
        Write-Log "Sysmon installation error: $_" -Level Error
        return $false
    }
}

function Update-SysmonConfiguration {
    param(
        [string]$SysmonExe,
        [string]$ConfigFile,
        [bool]$RestartService = $true
    )

    Write-Log "Updating Sysmon configuration: $ConfigFile" -Level Info

    try {
        $arguments = @('-c', $ConfigFile)
        $process = Start-Process -FilePath $SysmonExe -ArgumentList $arguments -Wait -PassThru -NoNewWindow

        if ($process.ExitCode -eq 0) {
            Write-Log "Sysmon configuration updated successfully" -Level Success

            if ($RestartService) {
                Write-Log "Restarting Sysmon service" -Level Info
                Restart-Service -Name 'Sysmon64' -Force
                Start-Sleep -Seconds 2

                $service = Get-Service -Name 'Sysmon64'
                if ($service.Status -eq 'Running') {
                    Write-Log "Sysmon service restarted successfully" -Level Success
                }
            }

            return $true
        } else {
            Write-Log "Sysmon configuration update failed with exit code: $($process.ExitCode)" -Level Error
            return $false
        }
    } catch {
        Write-Log "Sysmon configuration update error: $_" -Level Error
        return $false
    }
}

function Show-Profiles {
    Write-Host "`n===============================================" -ForegroundColor Cyan
    Write-Host "   SYSMON CONFIGURATION PROFILES" -ForegroundColor Cyan
    Write-Host "===============================================`n" -ForegroundColor Cyan

    foreach ($profileKey in $Script:Profiles.Keys | Sort-Object) {
        $profile = $Script:Profiles[$profileKey]

        Write-Host "[$profileKey]".ToUpper() -ForegroundColor Yellow -NoNewline
        Write-Host " - $($profile.Name)"
        Write-Host "  Description: $($profile.Description)"
        Write-Host "  Use Case: $($profile.UseCase)"
        Write-Host ""
    }

    Write-Host "Usage: .\Install-Sysmon.ps1 -ConfigProfile <profile>`n" -ForegroundColor Gray
}

function Backup-ExistingConfiguration {
    try {
        $status = Get-SysmonStatus
        if ($status.Installed) {
            $backupDir = "C:\Sysmon\Backup"
            if (-not (Test-Path $backupDir)) {
                New-Item -Path $backupDir -ItemType Directory -Force | Out-Null
            }

            $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
            $backupPath = Join-Path $backupDir "sysmon-config-backup-$timestamp.xml"

            # Export current configuration
            $sysmonExe = if ($status.ServiceName -eq 'Sysmon64') { 'Sysmon64.exe' } else { 'Sysmon.exe' }
            $sysmonPath = Join-Path $env:SystemRoot "System32\$sysmonExe"

            if (Test-Path $sysmonPath) {
                $process = Start-Process -FilePath $sysmonPath -ArgumentList '-c' -Wait -PassThru -NoNewWindow -RedirectStandardOutput $backupPath

                if (Test-Path $backupPath) {
                    Write-Log "Current configuration backed up to: $backupPath" -Level Success
                    return $backupPath
                }
            }
        }
    } catch {
        Write-Log "Failed to backup configuration: $_" -Level Warning
    }

    return $null
}

#endregion


#region Main Execution

function Main {
    Write-Host "`n===============================================" -ForegroundColor Cyan
    Write-Host "   SYSMON-CONFIG - INSTALLATION SCRIPT" -ForegroundColor Cyan
    Write-Host "   Version: $Script:ScriptVersion" -ForegroundColor Cyan
    Write-Host "===============================================`n" -ForegroundColor Cyan

    # Handle -ListProfiles
    if ($ListProfiles) {
        Show-Profiles
        return
    }

    # Pre-flight checks
    Write-Log "Starting pre-flight checks" -Level Info

    if (-not (Test-AdministratorPrivileges)) {
        Write-Log "ERROR: This script requires Administrator privileges" -Level Error
        Write-Log "Please run PowerShell as Administrator and try again" -Level Error
        exit 1
    }

    if (-not (Test-CompatibleOS)) {
        Write-Log "ERROR: Incompatible OS version" -Level Error
        Write-Log "Requires: Windows 10+ or Server 2016+" -Level Error
        exit 1
    }

    Write-Log "Pre-flight checks passed" -Level Success

    # Check existing installation
    $existingStatus = Get-SysmonStatus

    if ($existingStatus.Installed) {
        Write-Log "Existing Sysmon installation detected" -Level Info
        Write-Log "  Service: $($existingStatus.ServiceName)" -Level Info
        Write-Log "  Status: $($existingStatus.Status)" -Level Info

        if (-not $Force) {
            Write-Host "`nSysmon is already installed. Choose an option:" -ForegroundColor Yellow
            Write-Host "  [U] Update configuration only"
            Write-Host "  [R] Reinstall Sysmon"
            Write-Host "  [C] Cancel"

            $choice = Read-Host "Selection (U/R/C)"

            switch ($choice.ToUpper()) {
                'U' { $updateOnly = $true }
                'R' { $Force = $true }
                'C' { Write-Log "Installation cancelled by user" -Level Info; return }
                default { Write-Log "Invalid selection. Exiting." -Level Warning; return }
            }
        }

        # Backup existing configuration
        Backup-ExistingConfiguration
    }

    # Determine configuration file
    if ($ConfigPath) {
        $configFile = $ConfigPath
        Write-Log "Using custom configuration: $configFile" -Level Info
    } else {
        $profileInfo = $Script:Profiles[$ConfigProfile]
        $configFile = Join-Path $PSScriptRoot "..\dist\$($profileInfo.ConfigFile)"

        Write-Log "Using profile: $($profileInfo.Name)" -Level Info
        Write-Log "  Description: $($profileInfo.Description)" -Level Info
    }

    # Validate configuration
    if ($Validate -or $true) {  # Always validate
        if (-not (Test-ConfigurationValid -ConfigPath $configFile)) {
            Write-Log "Configuration validation failed. Aborting installation." -Level Error
            exit 1
        }
    }

    # Determine Sysmon executable path: built-in Windows Sysmon first, when allowed
    if (-not $SysmonPath -and $Source -ne 'Standalone') {
        $builtInEnabled = (Get-WindowsOptionalFeature -Online -FeatureName 'Sysmon' -ErrorAction SilentlyContinue).State -eq 'Enabled'
        if ($Source -eq 'BuiltIn' -or $builtInEnabled -or -not $existingStatus.Installed) {
            $SysmonPath = Get-BuiltInSysmon -Enable
            if ($SysmonPath) {
                Write-Log "Using built-in Windows Sysmon: $SysmonPath" -Level Info
            } elseif ($Source -eq 'BuiltIn') {
                Write-Log "ERROR: built-in Sysmon is not available on this Windows build" -Level Error
                exit 1
            }
        }
    }

    if (-not $SysmonPath) {
        # Check common locations
        $commonPaths = @(
            "C:\Windows\Sysmon64.exe",
            "C:\Windows\System32\Sysmon64.exe",
            (Join-Path $PSScriptRoot "Sysmon64.exe"),
            (Join-Path $env:TEMP "Sysmon\Sysmon64.exe")
        )

        foreach ($path in $commonPaths) {
            if (Test-Path $path) {
                $SysmonPath = $path
                break
            }
        }

        # Download if not found
        if (-not $SysmonPath -and -not $SkipDownload) {
            $downloadPath = Join-Path $env:TEMP "Sysmon"
            if (-not (Test-Path $downloadPath)) {
                New-Item -Path $downloadPath -ItemType Directory -Force | Out-Null
            }

            $SysmonPath = Download-Sysmon -DestinationPath $downloadPath
        }
    }

    if (-not (Test-Path $SysmonPath)) {
        Write-Log "ERROR: Sysmon executable not found: $SysmonPath" -Level Error
        Write-Log "Please specify -SysmonPath or allow automatic download" -Level Error
        exit 1
    }

    # Check Sysmon version
    $sysmonVersion = Get-SysmonVersion -SysmonExePath $SysmonPath
    if ($sysmonVersion -lt $Script:SysmonMinVersion) {
        Write-Log "WARNING: Sysmon version $sysmonVersion is below recommended minimum $Script:SysmonMinVersion" -Level Warning
        Write-Log "Some features may not be available" -Level Warning
    } else {
        Write-Log "Sysmon version: $sysmonVersion" -Level Success
    }

    # Install or update
    if ($updateOnly) {
        $success = Update-SysmonConfiguration -SysmonExe $SysmonPath -ConfigFile $configFile -RestartService (-not $NoRestart)
    } else {
        if ($existingStatus.Installed -and $Force) {
            Write-Log "Uninstalling existing Sysmon" -Level Info
            $process = Start-Process -FilePath $SysmonPath -ArgumentList '-u','force' -Wait -PassThru -NoNewWindow
        }

        $success = Install-SysmonService -SysmonExe $SysmonPath -ConfigFile $configFile
    }

    if ($success) {
        Write-Host "`n===============================================" -ForegroundColor Green
        Write-Host "   INSTALLATION COMPLETED SUCCESSFULLY" -ForegroundColor Green
        Write-Host "===============================================`n" -ForegroundColor Green

        Write-Log "Sysmon is now monitoring system activity" -Level Success
        Write-Log "Event Log: Applications and Services → Microsoft → Windows → Sysmon → Operational" -Level Info
        Write-Log "" -Level Info
        Write-Log "Next steps:" -Level Info
        Write-Log "  1. Verify events: Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 10" -Level Info
        Write-Log "  2. Forward logs to your SIEM" -Level Info
        Write-Log "  3. Monitor performance: .\performance\Benchmark-Sysmon.ps1" -Level Info
        Write-Log "  4. Tune configuration based on environment" -Level Info

        Write-Log "`nLog file: $LogPath" -Level Info
    } else {
        Write-Host "`n===============================================" -ForegroundColor Red
        Write-Host "   INSTALLATION FAILED" -ForegroundColor Red
        Write-Host "===============================================`n" -ForegroundColor Red

        Write-Log "Installation failed. Check log file for details: $LogPath" -Level Error
        exit 1
    }
}

# Execute main function
try {
    Main
} catch {
    Write-Log "Unexpected error: $_" -Level Error
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level Error
    exit 1
}

#endregion
