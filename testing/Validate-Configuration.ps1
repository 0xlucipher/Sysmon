<#
.SYNOPSIS
    Validate Sysmon configuration files for syntax and schema compliance.

.DESCRIPTION
    Comprehensive validation tool that checks:
    - XML syntax validity
    - Sysmon schema compliance
    - Rule logic consistency
    - Common configuration mistakes
    - Performance impact estimation

.PARAMETER ConfigPath
    Path to Sysmon configuration file to validate

.PARAMETER Detailed
    Show detailed analysis and recommendations

.PARAMETER CheckPerformance
    Estimate performance impact of configuration

.EXAMPLE
    .\Validate-Configuration.ps1 -ConfigPath "..\configurations\sysmon-base.xml"

.EXAMPLE
    .\Validate-Configuration.ps1 -ConfigPath "custom-config.xml" -Detailed -CheckPerformance

.NOTES
    Version: 1.0.0
    Author: Sysmon Ultimate Configuration Project
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$ConfigPath,

    [switch]$Detailed,

    [switch]$CheckPerformance
)

$ErrorActionPreference = 'Stop'

# Validation results
$Script:ValidationResults = @{
    Errors = @()
    Warnings = @()
    Info = @()
    Passed = $true
}

function Write-ValidationResult {
    param(
        [string]$Message,
        [ValidateSet('Error','Warning','Info','Success')]
        [string]$Level = 'Info'
    )

    switch ($Level) {
        'Error' {
            $Script:ValidationResults.Errors += $Message
            $Script:ValidationResults.Passed = $false
            Write-Host "[ERROR] $Message" -ForegroundColor Red
        }
        'Warning' {
            $Script:ValidationResults.Warnings += $Message
            Write-Host "[WARN]  $Message" -ForegroundColor Yellow
        }
        'Info' {
            $Script:ValidationResults.Info += $Message
            Write-Host "[INFO]  $Message" -ForegroundColor Cyan
        }
        'Success' {
            Write-Host "[OK]    $Message" -ForegroundColor Green
        }
    }
}

function Test-XMLSyntax {
    param([string]$FilePath)

    Write-Host "`n=== XML Syntax Validation ===" -ForegroundColor Cyan

    try {
        [xml]$config = Get-Content $FilePath -Raw
        Write-ValidationResult "XML syntax is valid" -Level Success
        return $config
    } catch {
        Write-ValidationResult "XML syntax error: $($_.Exception.Message)" -Level Error
        return $null
    }
}

function Test-SysmonSchema {
    param([xml]$Config)

    Write-Host "`n=== Sysmon Schema Validation ===" -ForegroundColor Cyan

    # Check root element
    if (-not $Config.Sysmon) {
        Write-ValidationResult "Missing Sysmon root element" -Level Error
        return
    }

    # Check schema version
    $schemaVersion = $Config.Sysmon.schemaversion
    if (-not $schemaVersion) {
        Write-ValidationResult "Missing schemaversion attribute" -Level Error
    } else {
        Write-ValidationResult "Schema version: $schemaVersion" -Level Info

        try {
            $version = [decimal]$schemaVersion
            if ($version -lt 4.0) {
                Write-ValidationResult "Schema version $schemaVersion is outdated (recommend 4.90+)" -Level Warning
            } elseif ($version -ge 4.90) {
                Write-ValidationResult "Schema version is current" -Level Success
            }
        } catch {
            Write-ValidationResult "Invalid schema version format: $schemaVersion" -Level Error
        }
    }

    # Check hash algorithms
    if ($Config.Sysmon.HashAlgorithms) {
        $hashAlgos = $Config.Sysmon.HashAlgorithms
        Write-ValidationResult "Hash algorithms: $hashAlgos" -Level Info

        if ($hashAlgos -notmatch 'SHA256') {
            Write-ValidationResult "SHA256 not enabled (recommended for file integrity)" -Level Warning
        }

        if ($hashAlgos -notmatch 'IMPHASH') {
            Write-ValidationResult "IMPHASH not enabled (recommended for malware clustering)" -Level Warning
        }
    } else {
        Write-ValidationResult "No hash algorithms configured" -Level Warning
    }

    # Check EventFiltering section
    if (-not $Config.Sysmon.EventFiltering) {
        Write-ValidationResult "Missing EventFiltering section" -Level Error
        return
    }

    Write-ValidationResult "EventFiltering section present" -Level Success
}

function Test-RuleGroups {
    param([xml]$Config)

    Write-Host "`n=== Rule Group Validation ===" -ForegroundColor Cyan

    $eventFiltering = $Config.Sysmon.EventFiltering
    if (-not $eventFiltering) { return }

    $ruleGroups = $eventFiltering.RuleGroup
    if (-not $ruleGroups) {
        Write-ValidationResult "No RuleGroups found" -Level Warning
        return
    }

    $ruleGroupCount = if ($ruleGroups -is [Array]) { $ruleGroups.Count } else { 1 }
    Write-ValidationResult "Found $ruleGroupCount RuleGroup(s)" -Level Info

    # Check each rule group
    foreach ($ruleGroup in $ruleGroups) {
        $name = $ruleGroup.name
        $relation = $ruleGroup.groupRelation

        if ($name) {
            Write-ValidationResult "RuleGroup '$name' (groupRelation: $relation)" -Level Info
        }

        # Check for empty rule groups
        $hasRules = $false
        foreach ($prop in $ruleGroup.PSObject.Properties) {
            if ($prop.Name -notin @('name','groupRelation')) {
                $hasRules = $true
                break
            }
        }

        if (-not $hasRules) {
            Write-ValidationResult "RuleGroup '$name' appears to be empty" -Level Warning
        }
    }
}

function Test-EventTypes {
    param([xml]$Config)

    Write-Host "`n=== Event Type Coverage ===" -ForegroundColor Cyan

    $eventFiltering = $Config.Sysmon.EventFiltering
    if (-not $eventFiltering) { return }

    $eventTypes = @{
        'ProcessCreate' = 'Event ID 1: Process Creation'
        'FileCreateTime' = 'Event ID 2: File Creation Time Changed'
        'NetworkConnect' = 'Event ID 3: Network Connection'
        'SysmonStatus' = 'Event ID 4: Sysmon Service State Changed'
        'ProcessTerminate' = 'Event ID 5: Process Terminated'
        'DriverLoad' = 'Event ID 6: Driver Loaded'
        'ImageLoad' = 'Event ID 7: Image Loaded (DLL)'
        'CreateRemoteThread' = 'Event ID 8: CreateRemoteThread'
        'RawAccessRead' = 'Event ID 9: RawAccessRead'
        'ProcessAccess' = 'Event ID 10: Process Access'
        'FileCreate' = 'Event ID 11: File Created'
        'RegistryEvent' = 'Event ID 12-14: Registry Events'
        'FileCreateStreamHash' = 'Event ID 15: File Stream Created'
        'SysmonConfigurationChange' = 'Event ID 16: Sysmon Config Changed'
        'PipeEvent' = 'Event ID 17-18: Named Pipe Events'
        'WmiEvent' = 'Event ID 19-21: WMI Events'
        'DnsQuery' = 'Event ID 22: DNS Query'
        'FileDelete' = 'Event ID 23: File Delete'
        'ClipboardChange' = 'Event ID 24: Clipboard Change'
        'ProcessTampering' = 'Event ID 25: Process Tampering'
        'FileDeleteDetected' = 'Event ID 26: File Delete Detected'
    }

    $configuredEvents = @()

    foreach ($eventType in $eventTypes.Keys) {
        $xpath = "//*[local-name()='$eventType']"
        $nodes = $Config.SelectNodes($xpath)

        if ($nodes.Count -gt 0) {
            $configuredEvents += $eventType
            Write-ValidationResult "$($eventTypes[$eventType]): Configured" -Level Success
        } elseif ($Detailed) {
            Write-ValidationResult "$($eventTypes[$eventType]): Not configured" -Level Info
        }
    }

    Write-ValidationResult "Total event types configured: $($configuredEvents.Count)/$($eventTypes.Count)" -Level Info

    # Recommend critical missing events
    $critical = @('ProcessCreate','NetworkConnect','ProcessAccess','FileCreate','RegistryEvent')
    foreach ($event in $critical) {
        if ($event -notin $configuredEvents) {
            Write-ValidationResult "Missing critical event type: $($eventTypes[$event])" -Level Warning
        }
    }
}

function Test-CommonMistakes {
    param([xml]$Config)

    Write-Host "`n=== Common Configuration Mistakes ===" -ForegroundColor Cyan

    $configText = Get-Content $ConfigPath -Raw

    # Check for conflicting include/exclude
    if ($configText -match 'onmatch="include".*onmatch="exclude"' -or
        $configText -match 'onmatch="exclude".*onmatch="include"') {
        Write-ValidationResult "Configuration mixes include and exclude rules (can cause confusion)" -Level Warning
    }

    # Check for overly broad exclusions
    if ($configText -match 'condition="begin with">C:\\<') {
        Write-ValidationResult "Found very broad exclusion (C:\) - may exclude too much" -Level Warning
    }

    # Check for common typos
    if ($configText -match 'condition="equal"') {
        Write-ValidationResult "Found 'equal' condition (should be 'is')" -Level Error
    }

    if ($configText -match 'condition="starts with"') {
        Write-ValidationResult "Found 'starts with' condition (should be 'begin with')" -Level Error
    }

    # Check for unescaped XML characters
    if ($configText -match '[<>]' -and $configText -notmatch '&lt;|&gt;') {
        Write-ValidationResult "Possible unescaped XML characters found" -Level Warning
    }

    Write-ValidationResult "Common mistake check completed" -Level Success
}

function Get-PerformanceEstimate {
    param([xml]$Config)

    Write-Host "`n=== Performance Impact Estimation ===" -ForegroundColor Cyan

    $configText = Get-Content $ConfigPath -Raw

    # Estimate based on event types and filtering
    $score = 0
    $highVolumeEvents = @{
        'ProcessCreate' = 30
        'NetworkConnect' = 25
        'ImageLoad' = 40
        'FileCreate' = 20
        'DnsQuery' = 30
        'RegistryEvent' = 20
    }

    foreach ($eventType in $highVolumeEvents.Keys) {
        if ($configText -match $eventType) {
            # Check if mostly includes (higher impact) vs mostly excludes (lower impact)
            $includeMatches = ([regex]::Matches($configText, "$eventType.*onmatch=`"include`"")).Count
            $excludeMatches = ([regex]::Matches($configText, "$eventType.*onmatch=`"exclude`"")).Count

            if ($includeMatches -gt $excludeMatches) {
                $score += $highVolumeEvents[$eventType]
            } else {
                $score += ($highVolumeEvents[$eventType] * 0.3)  # Exclusions reduce load
            }
        }
    }

    # Performance assessment
    if ($score -lt 40) {
        $profile = "Minimal"
        $impact = "Low (<2% CPU)"
        $color = "Green"
    } elseif ($score -lt 80) {
        $profile = "Balanced"
        $impact = "Medium (<5% CPU)"
        $color = "Yellow"
    } elseif ($score -lt 120) {
        $profile = "Comprehensive"
        $impact = "Medium-High (<10% CPU)"
        $color = "Yellow"
    } else {
        $profile = "Forensics"
        $impact = "High (10-15% CPU)"
        $color = "Red"
    }

    Write-Host "Estimated Profile: $profile" -ForegroundColor $color
    Write-Host "Estimated CPU Impact: $impact" -ForegroundColor $color
    Write-Host "Performance Score: $score/200" -ForegroundColor $color

    if ($score -gt 100) {
        Write-ValidationResult "Consider adding more exclusions to reduce performance impact" -Level Warning
    }
}

function Show-ValidationSummary {
    Write-Host "`n" + ("="*60) -ForegroundColor Cyan
    Write-Host "VALIDATION SUMMARY" -ForegroundColor Cyan
    Write-Host ("="*60) -ForegroundColor Cyan

    Write-Host "`nErrors:   $($Script:ValidationResults.Errors.Count)" -ForegroundColor $(if ($Script:ValidationResults.Errors.Count -gt 0) { "Red" } else { "Green" })
    Write-Host "Warnings: $($Script:ValidationResults.Warnings.Count)" -ForegroundColor $(if ($Script:ValidationResults.Warnings.Count -gt 0) { "Yellow" } else { "Green" })
    Write-Host "Info:     $($Script:ValidationResults.Info.Count)" -ForegroundColor Cyan

    if ($Script:ValidationResults.Passed) {
        Write-Host "`nResult: PASSED" -ForegroundColor Green
        Write-Host "Configuration is valid and ready for deployment" -ForegroundColor Green
    } else {
        Write-Host "`nResult: FAILED" -ForegroundColor Red
        Write-Host "Configuration has errors that must be fixed before deployment" -ForegroundColor Red
        Write-Host "`nErrors:" -ForegroundColor Red
        foreach ($error in $Script:ValidationResults.Errors) {
            Write-Host "  - $error" -ForegroundColor Red
        }
    }

    if ($Script:ValidationResults.Warnings.Count -gt 0) {
        Write-Host "`nWarnings:" -ForegroundColor Yellow
        foreach ($warning in $Script:ValidationResults.Warnings) {
            Write-Host "  - $warning" -ForegroundColor Yellow
        }
    }

    Write-Host ""
}

# Main execution
try {
    Write-Host "`n===============================================" -ForegroundColor Cyan
    Write-Host "   SYSMON CONFIGURATION VALIDATOR" -ForegroundColor Cyan
    Write-Host "===============================================`n" -ForegroundColor Cyan

    Write-Host "Validating: $ConfigPath`n" -ForegroundColor White

    # Check file exists
    if (-not (Test-Path $ConfigPath)) {
        Write-Host "ERROR: Configuration file not found: $ConfigPath" -ForegroundColor Red
        exit 1
    }

    # Run validation tests
    $config = Test-XMLSyntax -FilePath $ConfigPath

    if ($config) {
        Test-SysmonSchema -Config $config
        Test-RuleGroups -Config $config
        Test-EventTypes -Config $config
        Test-CommonMistakes -Config $config

        if ($CheckPerformance) {
            Get-PerformanceEstimate -Config $config
        }
    }

    # Show summary
    Show-ValidationSummary

    # Exit with appropriate code
    if ($Script:ValidationResults.Passed) {
        exit 0
    } else {
        exit 1
    }

} catch {
    Write-Host "`nUNEXPECTED ERROR: $_" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    exit 1
}
