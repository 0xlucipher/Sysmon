<#
.SYNOPSIS
    Measure Sysmon log volume and analyze event distribution.

.DESCRIPTION
    Analyzes Sysmon event log to measure volume, event types, and trends.
    Helps with capacity planning and identifying noisy event sources.

.PARAMETER Days
    Number of days to analyze (default: 7)

.PARAMETER GroupBy
    Group results by: EventID, Image, User (default: EventID)

.PARAMETER ExportCSV
    Export results to CSV file

.EXAMPLE
    .\Measure-LogVolume.ps1 -Days 7
    Analyze last 7 days of logs

.EXAMPLE
    .\Measure-LogVolume.ps1 -Days 1 -GroupBy Image
    Find noisiest processes in last 24 hours

.NOTES
    Version: 1.0.0
#>

[CmdletBinding()]
param(
    [int]$Days = 7,

    [ValidateSet('EventID','Image','User')]
    [string]$GroupBy = 'EventID',

    [switch]$ExportCSV
)

Write-Host "`n===============================================" -ForegroundColor Cyan
Write-Host "   SYSMON LOG VOLUME ANALYZER" -ForegroundColor Cyan
Write-Host "===============================================`n" -ForegroundColor Cyan

Write-Host "Analysis Period: Last $Days day(s)" -ForegroundColor Cyan
Write-Host "Grouping By: $GroupBy" -ForegroundColor Cyan
Write-Host "Start Time: $(Get-Date)`n" -ForegroundColor Cyan

# Calculate time range
$startTime = (Get-Date).AddDays(-$Days)

Write-Host "Querying Sysmon event log..." -ForegroundColor Yellow
Write-Host "This may take several minutes for large logs...`n" -ForegroundColor Gray

try {
    # Get all events in time range
    $filterXml = @"
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-Sysmon/Operational">
    <Select Path="Microsoft-Windows-Sysmon/Operational">*[System[TimeCreated[@SystemTime&gt;='$($startTime.ToUniversalTime().ToString("o"))']]]</Select>
  </Query>
</QueryList>
"@

    $events = Get-WinEvent -FilterXml $filterXml -ErrorAction Stop

    if (-not $events) {
        Write-Host "No Sysmon events found in the specified time range." -ForegroundColor Yellow
        return
    }

    $totalEvents = $events.Count
    Write-Host "Total Events Found: $totalEvents" -ForegroundColor Green

    # Calculate rates
    $eventsPerDay = [math]::Round($totalEvents / $Days, 0)
    $eventsPerHour = [math]::Round($eventsPerDay / 24, 0)
    $eventsPerMinute = [math]::Round($eventsPerHour / 60, 1)

    # Estimate log size (average 1KB per event)
    $totalSizeMB = [math]::Round($totalEvents / 1024, 2)
    $dailySizeMB = [math]::Round($totalSizeMB / $Days, 0)

    Write-Host "`n===============================================" -ForegroundColor Cyan
    Write-Host "   VOLUME METRICS" -ForegroundColor Cyan
    Write-Host "===============================================`n" -ForegroundColor Cyan

    Write-Host "Event Generation Rate:" -ForegroundColor Yellow
    Write-Host "  Per Minute: $eventsPerMinute" -ForegroundColor White
    Write-Host "  Per Hour: $eventsPerHour" -ForegroundColor White
    Write-Host "  Per Day: $eventsPerDay" -ForegroundColor White

    Write-Host "`nEstimated Log Size:" -ForegroundColor Yellow
    Write-Host "  Total ($Days days): $totalSizeMB MB" -ForegroundColor White
    Write-Host "  Per Day: $dailySizeMB MB" -ForegroundColor White
    Write-Host "  Per Month (30 days): $([math]::Round($dailySizeMB * 30 / 1024, 2)) GB" -ForegroundColor White
    Write-Host "  Per Year: $([math]::Round($dailySizeMB * 365 / 1024, 2)) GB" -ForegroundColor White

    # Group and analyze
    Write-Host "`n===============================================" -ForegroundColor Cyan
    Write-Host "   DISTRIBUTION ANALYSIS" -ForegroundColor Cyan
    Write-Host "===============================================`n" -ForegroundColor Cyan

    switch ($GroupBy) {
        'EventID' {
            Write-Host "Events by Type (Event ID):`n" -ForegroundColor Yellow

            $grouped = $events | Group-Object Id | Sort-Object Count -Descending

            foreach ($group in $grouped) {
                $percentage = [math]::Round(($group.Count / $totalEvents) * 100, 2)
                $eventName = switch ($group.Name) {
                    '1' { 'Process Creation' }
                    '2' { 'File Creation Time Changed' }
                    '3' { 'Network Connection' }
                    '5' { 'Process Terminated' }
                    '6' { 'Driver Loaded' }
                    '7' { 'Image Loaded' }
                    '8' { 'CreateRemoteThread' }
                    '9' { 'RawAccessRead' }
                    '10' { 'Process Access' }
                    '11' { 'File Created' }
                    '12' { 'Registry Object Added/Deleted' }
                    '13' { 'Registry Value Set' }
                    '14' { 'Registry Object Renamed' }
                    '15' { 'File Stream Created' }
                    '17' { 'Pipe Created' }
                    '18' { 'Pipe Connected' }
                    '19' { 'WMI Event Filter' }
                    '20' { 'WMI Event Consumer' }
                    '21' { 'WMI Event Consumer To Filter' }
                    '22' { 'DNS Query' }
                    '23' { 'File Delete' }
                    '25' { 'Process Tampering' }
                    default { "Event ID $($group.Name)" }
                }

                $bar = '#' * [math]::Round($percentage / 2, 0)
                Write-Host "  [$($group.Name.PadLeft(2))] $($eventName.PadRight(35)) : " -NoNewline -ForegroundColor White
                Write-Host "$($group.Count.ToString().PadLeft(8)) " -NoNewline -ForegroundColor Cyan
                Write-Host "($($percentage.ToString().PadLeft(5))%) " -NoNewline -ForegroundColor Gray
                Write-Host $bar -ForegroundColor Green
            }
        }

        'Image' {
            Write-Host "Events by Process (Top 20):`n" -ForegroundColor Yellow

            $grouped = $events | ForEach-Object {
                [xml]$xml = $_.ToXml()
                $image = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'} | Select-Object -ExpandProperty '#text' -ErrorAction SilentlyContinue
                if ($image) {
                    [PSCustomObject]@{
                        Image = Split-Path $image -Leaf
                        FullPath = $image
                    }
                }
            } | Group-Object Image | Sort-Object Count -Descending | Select-Object -First 20

            foreach ($group in $grouped) {
                $percentage = [math]::Round(($group.Count / $totalEvents) * 100, 2)
                Write-Host "  $($group.Name.PadRight(40)) : $($group.Count.ToString().PadLeft(8)) ($percentage%)" -ForegroundColor White
            }
        }

        'User' {
            Write-Host "Events by User (Top 15):`n" -ForegroundColor Yellow

            $grouped = $events | ForEach-Object {
                [xml]$xml = $_.ToXml()
                $user = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'User'} | Select-Object -ExpandProperty '#text' -ErrorAction SilentlyContinue
                if ($user) { $user } else { 'SYSTEM' }
            } | Group-Object | Sort-Object Count -Descending | Select-Object -First 15

            foreach ($group in $grouped) {
                $percentage = [math]::Round(($group.Count / $totalEvents) * 100, 2)
                Write-Host "  $($group.Name.PadRight(40)) : $($group.Count.ToString().PadLeft(8)) ($percentage%)" -ForegroundColor White
            }
        }
    }

    # Capacity planning recommendations
    Write-Host "`n===============================================" -ForegroundColor Cyan
    Write-Host "   CAPACITY PLANNING" -ForegroundColor Cyan
    Write-Host "===============================================`n" -ForegroundColor Cyan

    $monthlyGB = [math]::Round($dailySizeMB * 30 / 1024, 2)

    Write-Host "Storage Requirements:" -ForegroundColor Yellow
    if ($monthlyGB -lt 10) {
        Write-Host "  Tier: LOW (<10 GB/month)" -ForegroundColor Green
        Write-Host "  Recommendation: Local storage sufficient" -ForegroundColor White
    } elseif ($monthlyGB -lt 50) {
        Write-Host "  Tier: MODERATE (10-50 GB/month)" -ForegroundColor Yellow
        Write-Host "  Recommendation: Forward to SIEM or log aggregator" -ForegroundColor White
    } else {
        Write-Host "  Tier: HIGH (>50 GB/month)" -ForegroundColor Red
        Write-Host "  Recommendation: SIEM required, consider optimization" -ForegroundColor White
    }

    Write-Host "`nEvent Log Size Configuration:" -ForegroundColor Yellow
    $recommendedSizeMB = [math]::Max(1024, $dailySizeMB * 3)  # 3 days retention minimum
    Write-Host "  Recommended Log Size: $recommendedSizeMB MB" -ForegroundColor White
    Write-Host "  Current Configuration:" -ForegroundColor White

    try {
        $logConfig = wevtutil gl "Microsoft-Windows-Sysmon/Operational"
        $maxSize = ($logConfig | Select-String "maxSize:").ToString() -replace '.*maxSize:\s*', ''
        Write-Host "    Max Size: $maxSize bytes ($([math]::Round([int64]$maxSize / 1MB, 0)) MB)" -ForegroundColor Cyan
    } catch {
        Write-Host "    Could not retrieve current log size" -ForegroundColor Yellow
    }

    Write-Host "`nOptimization Opportunities:" -ForegroundColor Yellow

    # Analyze high-volume event types
    $topEvents = $events | Group-Object Id | Sort-Object Count -Descending | Select-Object -First 3

    foreach ($topEvent in $topEvents) {
        $percentage = [math]::Round(($topEvent.Count / $totalEvents) * 100, 1)

        if ($percentage -gt 30) {
            $eventName = switch ($topEvent.Name) {
                '1' { 'Process Creation'; 'Add exclusions for noisy system processes' }
                '3' { 'Network Connection'; 'Exclude internal networks or reduce port monitoring' }
                '7' { 'Image Loaded'; 'Exclude signed Microsoft DLLs from system paths' }
                '11' { 'File Created'; 'Narrow file path monitoring to critical directories' }
                '13' { 'Registry Value Set'; 'Focus on security-relevant registry keys only' }
                '22' { 'DNS Query'; 'Exclude common legitimate domains (Microsoft, Google, CDNs)' }
                default { "Event ID $($topEvent.Name)"; 'Review configuration for this event type' }
            }

            Write-Host "  - Event ID $($topEvent.Name) is $percentage% of volume: $($eventName[1])" -ForegroundColor Cyan
        }
    }

    # Export to CSV if requested
    if ($ExportCSV) {
        $csvPath = Join-Path $PSScriptRoot "log-volume-analysis-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"

        $grouped = $events | Group-Object Id | Sort-Object Count -Descending
        $csvData = $grouped | Select-Object @{
            Name='EventID'; Expression={$_.Name}
        }, @{
            Name='Count'; Expression={$_.Count}
        }, @{
            Name='Percentage'; Expression={[math]::Round(($_.Count / $totalEvents) * 100, 2)}
        }, @{
            Name='EventsPerDay'; Expression={[math]::Round($_.Count / $Days, 0)}
        }

        $csvData | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Host "`nResults exported to: $csvPath" -ForegroundColor Green
    }

} catch {
    Write-Host "`nERROR: Failed to analyze logs: $_" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
}

Write-Host "`nAnalysis completed at $(Get-Date)" -ForegroundColor Cyan
Write-Host ""
