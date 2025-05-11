# ====================================================================
# Beaconing Detection Script - Enhanced
# Author: Ekrem Ozdemir
# Compatible with Windows PowerShell 5.1
# Includes VirusTotal API scan for public IPs
# ====================================================================

$startTimeScript = Get-Date
$scriptPath = $MyInvocation.MyCommand.Path
$scriptDir = Split-Path $scriptPath
$logFile = "$scriptDir\sample.csv"  # <-- Replace with your CSV file
$csvName = Split-Path $logFile -Leaf
$outFile = "$scriptDir\beaconing_results_$csvName.txt"
$specificIP =  $null  # Optional filter, e.g., "192.0.2.123" or $null

# === VirusTotal setup ===
$vtApiKey = "YOUR_VIRUSTOTAL_API_KEY"  # Replace with your real key "YOUR_VIRUSTOTAL_API_KEY"
$vtHeaders = @{ "x-apikey" = $vtApiKey }

function Write-Log {
    param ([string]$message, [ConsoleColor]$color = "White")
    Write-Host $message -ForegroundColor $color
    Add-Content -Path $outFile -Value $message
}

function Check-VirusTotalIP {
    param ([string]$ip)
    $vtUrl = "https://www.virustotal.com/api/v3/ip_addresses/$ip"
    try {
        $response = Invoke-RestMethod -Uri $vtUrl -Headers $vtHeaders -Method Get
        $malicious = $response.data.attributes.last_analysis_stats.malicious
        $harmless = $response.data.attributes.last_analysis_stats.harmless
        $suspicious = $response.data.attributes.last_analysis_stats.suspicious
        Write-Host "[VT] $ip - Harmless: $harmless / Malicious: $malicious / Suspicious: $suspicious" -ForegroundColor Cyan
    } catch {
        Write-Host "[VT] $ip - Lookup failed: $_" -ForegroundColor DarkGray
    }
}

$acceptedFormats = @(
    "yyyy-MM-ddTHH:mm:ss",
    "yyyy-MM-ddTHH:mm:ssZ",
    "yyyy-MM-ddTHH:mm:ss.fff",
    "yyyy-MM-ddTHH:mm:ss.fffZ"
)

$data = @()
$lines = Get-Content $logFile | Select-Object -Skip 1

foreach ($line in $lines) {
    if ($line -like '*All Values*') { continue }

    $parts = [regex]::Split($line, ',(?=(?:[^"]*"[^"]*")*[^"]*$)')
    if ($parts.Count -lt 3) { continue }

    $rawTime = $parts[0].Trim('"', ' ')
    $parsed = $null
    $valid = $false

    foreach ($fmt in $acceptedFormats) {
        try {
            $parsed = [datetime]::ParseExact($rawTime, $fmt, [System.Globalization.CultureInfo]::InvariantCulture)
            $valid = $true
            break
        } catch { continue }
    }

    if (-not $valid) { continue }
    $normalizedTime = $parsed.ToString("yyyy-MM-ddTHH:mm:ss")

    if ($parts.Count -ge 7) {
        $srcIP = $parts[1].Trim('"', ' ')
        $srcPort = $parts[2].Trim('"', ' ')
        $dstIP = $parts[3].Trim('"', ' ')
        $dstPort = $parts[4].Trim('"', ' ')
        $asset = $parts[5].Trim('"', ' ')
        $user = $parts[6].Trim('"', ' ')
    } else {
        $srcIP = $parts[1].Trim('"', ' ')
        $dstIP = $parts[2].Trim('"', ' ')
        $srcPort = ""; $dstPort = ""; $asset = ""; $user = ""
    }

    if ($specificIP -and ($srcIP -ne $specificIP -and $dstIP -ne $specificIP)) {
        continue
    }

    $data += [PSCustomObject]@{
        Timestamp        = [datetime]$normalizedTime
        SourceIP         = $srcIP
        DestinationIP    = $dstIP
        SourcePort       = $srcPort
        DestinationPort  = $dstPort
        Asset            = $asset
        User             = $user
    }
}

$grouped = $data | Group-Object SourceIP, DestinationIP
$results = @()
$nonBeaconingList = @()
$beaconingFound = $false
$beaconingSummary = @()

foreach ($group in $grouped) {
    $events = $group.Group | Sort-Object Timestamp
    $src = $events[0].SourceIP
    $dst = $events[0].DestinationIP

    if ($events.Count -lt 4) {
        $nonBeaconingList += "$src -> $dst (not enough data)"
        continue
    }

    $intervals = @()
    for ($i = 1; $i -lt $events.Count; $i++) {
        $diff = ($events[$i].Timestamp - $events[$i - 1].Timestamp).TotalSeconds
        $intervals += [math]::Round($diff, 2)
    }

    $groupedIntervals = $intervals | Group-Object | Sort-Object Count -Descending
    $mode = [double]$groupedIntervals[0].Name
    $tolerance = 10
    $matchCount = ($intervals | Where-Object { ($_ -ge $mode - $tolerance) -and ($_ -le $mode + $tolerance) }).Count
    $percent = [math]::Round(($matchCount / $intervals.Count) * 100, 2)

    $startTime = $events[0].Timestamp.ToString("yyyy-MM-ddTHH:mm:ss")
    $endTime = $events[-1].Timestamp.ToString("yyyy-MM-ddTHH:mm:ss")

    $results += [PSCustomObject]@{
        SourceIP = $src
        DestinationIP = $dst
        Interval = $mode
        Consistency = $percent
        StartTime = $startTime
        EndTime = $endTime
        Meta = $events[0]
    }

    if ($percent -ge 80 -and $mode -gt 0) {
        $beaconingFound = $true
        $beaconingSummary += "- $src → $dst, every $mode s ($percent% consistent)"
    } else {
        $nonBeaconingList += "$src -> $dst"
    }
}

# RFI message
if ($beaconingFound) {
    $rfiHeader = "======================== REQUEST FOR INFORMATION ========================"
    $rfiBody = "MDR team reviewed the available firewall logs from the dataset $csvName, and identified beaconing activity.`n`nDetails:`n$($beaconingSummary -join "`n")"
    "$rfiHeader`n$rfiBody`n=========================================================================" | Set-Content -Path $outFile
} else {
    "" | Set-Content -Path $outFile
}

# Log findings
Write-Log "- Analyzing File: $logFile" "Cyan"
Write-Log "- Output File: $outFile" "Cyan"
Write-Log "- Found $($grouped.Count) source-destination pairs to analyze." "Cyan"

$resultsSorted = $results | Sort-Object {[double]$_.Consistency} -Descending

foreach ($r in $resultsSorted) {
    if ($r.Consistency -ge 80 -and $r.Interval -gt 0) {
        Write-Log "- BEACONING DETECTED:" "Green"
        Write-Log "`tSource IP:        $($r.SourceIP)"
        Write-Log "`tDestination IP:   $($r.DestinationIP)"
        if ($r.Meta.SourcePort)       { Write-Log "`tSource Port:      $($r.Meta.SourcePort)" }
        if ($r.Meta.DestinationPort)  { Write-Log "`tDestination Port: $($r.Meta.DestinationPort)" }
        if ($r.Meta.Asset)            { Write-Log "`tAsset:            $($r.Meta.Asset)" }
        if ($r.Meta.User)             { Write-Log "`tUser:             $($r.Meta.User)" }
        Write-Log "`tInterval:         $($r.Interval) seconds ($($r.Consistency)% consistent)"
        Write-Log "`tTime Frame:       $($r.StartTime) to $($r.EndTime)"
        Write-Log "`tVirusTotal Lookup: https://www.virustotal.com/gui/ip-address/$($r.DestinationIP)`n"

        # Check only public IPs
       if (-not ($r.DestinationIP -match '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)')) 
	    {
			Check-VirusTotalIP -ip $r.DestinationIP
		} 
		else 
		{
			Write-Host "[VT] $($r.DestinationIP) - Skipped (Private IP)" -ForegroundColor DarkGray
		}

    }
}

if ($nonBeaconingList.Count -gt 0) {
    Write-Log "- BEACONING NOT DETECTED:" "Yellow"
    foreach ($entry in $nonBeaconingList) {
        Write-Log "`t$entry"
    }
}

$endTimeScript = Get-Date
$duration = $endTimeScript - $startTimeScript
Write-Log "- Script completed in $($duration.TotalSeconds) seconds." "Magenta"
