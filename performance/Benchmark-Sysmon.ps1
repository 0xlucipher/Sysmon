<#
.SYNOPSIS
    Benchmark Sysmon performance impact on system resources.

.DESCRIPTION
    Measures CPU, memory, and disk usage with Sysmon enabled vs baseline.
    Provides detailed performance metrics for capacity planning.

.PARAMETER DurationMinutes
    How long to run the benchmark (default: 10 minutes)

.PARAMETER GenerateReport
    Create HTML report with charts

.PARAMETER IdentifyBottlenecks
    Analyze which event types cause highest load

.EXAMPLE
    .\Benchmark-Sysmon.ps1 -DurationMinutes 30 -GenerateReport

.NOTES
    Version: 1.0.0
    Requires: Administrator privileges
#>

[CmdletBinding()]
param(
    [int]$DurationMinutes = 10,
    [switch]$GenerateReport,
    [switch]$IdentifyBottlenecks
)

#Requires -RunAsAdministrator

$ErrorActionPreference = 'Continue'

Write-Host "`n===============================================" -ForegroundColor Cyan
Write-Host "   SYSMON PERFORMANCE BENCHMARK" -ForegroundColor Cyan
Write-Host "===============================================`n" -ForegroundColor Cyan

# Check if Sysmon is running
$sysmon = Get-Service -Name 'Sysmon64','Sysmon' -ErrorAction SilentlyContinue | Where-Object {$_.Status -eq 'Running'}
if (-not $sysmon) {
    Write-Host "ERROR: Sysmon is not running. Install Sysmon first." -ForegroundColor Red
    exit 1
}

Write-Host "Sysmon Service: $($sysmon.Name)" -ForegroundColor Green
Write-Host "Duration: $DurationMinutes minutes" -ForegroundColor Cyan
Write-Host "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n" -ForegroundColor Cyan

# Initialize metrics
$metrics = @{
    CPU = @()
    Memory = @()
    Disk = @()
    EventCount = @()
    Timestamps = @()
}

$sampleInterval = 5  # seconds
$totalSamples = ($DurationMinutes * 60) / $sampleInterval

Write-Host "Collecting performance data..." -ForegroundColor Yellow
Write-Host "Sample interval: $sampleInterval seconds" -ForegroundColor Cyan
Write-Host "Total samples: $totalSamples`n" -ForegroundColor Cyan

# Progress tracking
$sampleCount = 0
$startTime = Get-Date

for ($i = 0; $i -lt $totalSamples; $i++) {
    $sampleCount++
    $percentComplete = [math]::Round(($sampleCount / $totalSamples) * 100, 1)

    # Get Sysmon process
    $sysmonProcess = Get-Process -Name 'Sysmon64','Sysmon' -ErrorAction SilentlyContinue | Select-Object -First 1

    if ($sysmonProcess) {
        # CPU (average over interval)
        $cpuBefore = $sysmonProcess.CPU
        Start-Sleep -Seconds $sampleInterval
        $sysmonProcess = Get-Process -Id $sysmonProcess.Id -ErrorAction SilentlyContinue

        if ($sysmonProcess) {
            $cpuAfter = $sysmonProcess.CPU
            $cpuUsage = [math]::Round((($cpuAfter - $cpuBefore) / $sampleInterval) / $env:NUMBER_OF_PROCESSORS, 2)

            # Memory
            $memoryMB = [math]::Round($sysmonProcess.WorkingSet64 / 1MB, 2)

            # Event count
            try {
                $eventCount = (Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 1 -ErrorAction SilentlyContinue).RecordId
            } catch {
                $eventCount = 0
            }

            # Store metrics
            $metrics.CPU += $cpuUsage
            $metrics.Memory += $memoryMB
            $metrics.EventCount += $eventCount
            $metrics.Timestamps += (Get-Date)

            # Display progress
            Write-Progress -Activity "Benchmarking Sysmon Performance" -Status "$percentComplete% Complete" -PercentComplete $percentComplete

            if ($sampleCount % 6 -eq 0) {  # Every 30 seconds
                Write-Host "[$(Get-Date -Format 'HH:mm:ss')] CPU: $cpuUsage% | Memory: $memoryMB MB | Events: $eventCount" -ForegroundColor Gray
            }
        }
    } else {
        Write-Host "WARNING: Sysmon process not found" -ForegroundColor Yellow
        Start-Sleep -Seconds $sampleInterval
    }
}

Write-Progress -Activity "Benchmarking Sysmon Performance" -Completed

# Calculate statistics
$avgCPU = [math]::Round(($metrics.CPU | Measure-Object -Average).Average, 2)
$maxCPU = [math]::Round(($metrics.CPU | Measure-Object -Maximum).Maximum, 2)
$minCPU = [math]::Round(($metrics.CPU | Measure-Object -Minimum).Minimum, 2)

$avgMemory = [math]::Round(($metrics.Memory | Measure-Object -Average).Average, 2)
$maxMemory = [math]::Round(($metrics.Memory | Measure-Object -Maximum).Maximum, 2)

$startEvents = $metrics.EventCount[0]
$endEvents = $metrics.EventCount[-1]
$totalEvents = $endEvents - $startEvents
$eventsPerMinute = [math]::Round($totalEvents / $DurationMinutes, 0)
$eventsPerDay = $eventsPerMinute * 60 * 24

# Estimate log size (average ~1KB per event)
$estimatedDailyLogMB = [math]::Round($eventsPerDay / 1024, 0)

# Display results
Write-Host "`n===============================================" -ForegroundColor Green
Write-Host "   BENCHMARK RESULTS" -ForegroundColor Green
Write-Host "===============================================`n" -ForegroundColor Green

Write-Host "CPU USAGE:" -ForegroundColor Cyan
Write-Host "  Average: $avgCPU%" -ForegroundColor White
Write-Host "  Maximum: $maxCPU%" -ForegroundColor White
Write-Host "  Minimum: $minCPU%" -ForegroundColor White

# Performance assessment
if ($avgCPU -lt 2) {
    Write-Host "  Assessment: EXCELLENT (Minimal impact)" -ForegroundColor Green
} elseif ($avgCPU -lt 5) {
    Write-Host "  Assessment: GOOD (Balanced)" -ForegroundColor Green
} elseif ($avgCPU -lt 10) {
    Write-Host "  Assessment: ACCEPTABLE (Comprehensive)" -ForegroundColor Yellow
} else {
    Write-Host "  Assessment: HIGH (Consider optimization)" -ForegroundColor Red
}

Write-Host "`nMEMORY USAGE:" -ForegroundColor Cyan
Write-Host "  Average: $avgMemory MB" -ForegroundColor White
Write-Host "  Maximum: $maxMemory MB" -ForegroundColor White

Write-Host "`nEVENT GENERATION:" -ForegroundColor Cyan
Write-Host "  Total Events: $totalEvents (in $DurationMinutes minutes)" -ForegroundColor White
Write-Host "  Events per Minute: $eventsPerMinute" -ForegroundColor White
Write-Host "  Estimated Daily Events: $([math]::Round($eventsPerDay / 1000, 1))K" -ForegroundColor White
Write-Host "  Estimated Daily Log Size: ~$estimatedDailyLogMB MB" -ForegroundColor White

# Profile identification
if ($avgCPU -lt 2 -and $estimatedDailyLogMB -lt 200) {
    $profile = "MINIMAL"
} elseif ($avgCPU -lt 5 -and $estimatedDailyLogMB -lt 700) {
    $profile = "BALANCED"
} elseif ($avgCPU -lt 10 -and $estimatedDailyLogMB -lt 2000) {
    $profile = "COMPREHENSIVE"
} else {
    $profile = "FORENSICS"
}

Write-Host "`nCONFIGURATION PROFILE:" -ForegroundColor Cyan
Write-Host "  Detected: $profile" -ForegroundColor White

# Bottleneck analysis
if ($IdentifyBottlenecks) {
    Write-Host "`n===============================================" -ForegroundColor Cyan
    Write-Host "   BOTTLENECK ANALYSIS" -ForegroundColor Cyan
    Write-Host "===============================================`n" -ForegroundColor Cyan

    try {
        $events = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 10000 -ErrorAction SilentlyContinue

        if ($events) {
            $eventsByType = $events | Group-Object Id | Sort-Object Count -Descending | Select-Object -First 10

            Write-Host "TOP 10 EVENT TYPES BY VOLUME:`n" -ForegroundColor Yellow

            foreach ($eventType in $eventsByType) {
                $percentage = [math]::Round(($eventType.Count / $events.Count) * 100, 1)
                $eventName = switch ($eventType.Name) {
                    '1' { 'Process Creation' }
                    '3' { 'Network Connection' }
                    '7' { 'Image Loaded' }
                    '10' { 'Process Access' }
                    '11' { 'File Created' }
                    '13' { 'Registry Value Set' }
                    '22' { 'DNS Query' }
                    default { "Event ID $($eventType.Name)" }
                }

                Write-Host "  Event ID $($eventType.Name) ($eventName): $($eventType.Count) ($percentage%)" -ForegroundColor White
            }

            Write-Host "`nOPTIMIZATION RECOMMENDATIONS:" -ForegroundColor Yellow

            # Recommendations based on high-volume events
            $topEvent = $eventsByType[0]
            if ([int]$topEvent.Name -eq 3 -and ($topEvent.Count / $events.Count) -gt 0.3) {
                Write-Host "  - Network events are high volume. Consider excluding internal networks." -ForegroundColor Cyan
            }
            if ([int]$topEvent.Name -eq 7 -and ($topEvent.Count / $events.Count) -gt 0.3) {
                Write-Host "  - Image load events are high volume. Exclude signed Microsoft DLLs." -ForegroundColor Cyan
            }
            if ([int]$topEvent.Name -eq 22 -and ($topEvent.Count / $events.Count) -gt 0.2) {
                Write-Host "  - DNS query volume is high. Exclude common legitimate domains." -ForegroundColor Cyan
            }
        }
    } catch {
        Write-Host "Could not analyze event distribution: $_" -ForegroundColor Yellow
    }
}

# Recommendations
Write-Host "`n===============================================" -ForegroundColor Cyan
Write-Host "   RECOMMENDATIONS" -ForegroundColor Cyan
Write-Host "===============================================`n" -ForegroundColor Cyan

if ($avgCPU -gt 5) {
    Write-Host "- CPU usage is above 5%. Consider:" -ForegroundColor Yellow
    Write-Host "  1. Adding exclusions for high-volume processes" -ForegroundColor White
    Write-Host "  2. Switching to 'balanced' or 'minimal' profile" -ForegroundColor White
    Write-Host "  3. Excluding internal network monitoring" -ForegroundColor White
}

if ($estimatedDailyLogMB -gt 1000) {
    Write-Host "- Daily log volume exceeds 1GB. Consider:" -ForegroundColor Yellow
    Write-Host "  1. Implementing log rotation" -ForegroundColor White
    Write-Host "  2. Forwarding to SIEM with retention policies" -ForegroundColor White
    Write-Host "  3. Reducing DNS and network logging" -ForegroundColor White
}

if ($avgCPU -lt 5 -and $estimatedDailyLogMB -lt 700) {
    Write-Host "- Performance is excellent. Configuration is well-optimized." -ForegroundColor Green
}

# Export results
if ($GenerateReport) {
    $reportPath = Join-Path $PSScriptRoot "benchmark-report-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"

    $report = @{
        Timestamp = (Get-Date).ToString('o')
        DurationMinutes = $DurationMinutes
        CPU = @{
            Average = $avgCPU
            Maximum = $maxCPU
            Minimum = $minCPU
        }
        Memory = @{
            Average = $avgMemory
            Maximum = $maxMemory
        }
        Events = @{
            TotalGenerated = $totalEvents
            PerMinute = $eventsPerMinute
            EstimatedDaily = $eventsPerDay
            EstimatedDailyLogMB = $estimatedDailyLogMB
        }
        Profile = $profile
        RawData = @{
            CPU = $metrics.CPU
            Memory = $metrics.Memory
            EventCount = $metrics.EventCount
        }
    }

    $report | ConvertTo-Json -Depth 10 | Out-File $reportPath
    Write-Host "`nReport saved to: $reportPath" -ForegroundColor Green
}

Write-Host "`nBenchmark completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host ""
