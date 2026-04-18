<#
.SYNOPSIS
  NT230 PoC — Multi-Engine AV Scan (offline hash check + VirusTotal API)

.DESCRIPTION
  Kiểm tra malicious payload files với:
    1. Windows Defender (local scan)
    2. SHA-256 hash submit lên VirusTotal API (nếu có API key)
    3. Hashing tất cả payload files để manual check trên VirusTotal web

  Giải quyết hạn chế "Chỉ test Windows Defender" trong PoC.

.PARAMETER VTApiKey
  VirusTotal API key (free tier: 4 req/min, 500 req/day).
  Nếu không cung cấp, script chỉ tính hash để user check thủ công.

.EXAMPLE
  .\scripts\test-multi-av.ps1
  .\scripts\test-multi-av.ps1 -VTApiKey "your_api_key_here"
#>

param(
    [string]$VTApiKey = ""
)

$ErrorActionPreference = "Continue"
$ProjectRoot = Split-Path -Parent $PSScriptRoot

# ─── Config: payload files cần scan ────────────────────────────────────────
$PayloadFiles = @(
    "$ProjectRoot\packages\safe-marker-package\scripts\postinstall-ci-attack.js",
    "$ProjectRoot\packages\safe-marker-package\scripts\postinstall-stealth.js",
    "$ProjectRoot\packages\safe-marker-package\scripts\loader.js",
    "$ProjectRoot\packages\safe-marker-package\scripts\config.json",
    "$ProjectRoot\ci\inject-malicious-artifact.js",
    "$ProjectRoot\attacker-server\receiver.js"
)

$ReportFile = "$ProjectRoot\artifacts\multi-av-report.txt"

function Write-Section($title) {
    $sep = "=" * 60
    Write-Host "`n$sep" -ForegroundColor Cyan
    Write-Host "  $title" -ForegroundColor Cyan
    Write-Host "$sep" -ForegroundColor Cyan
}

function Get-FileSHA256($filePath) {
    if (-not (Test-Path $filePath)) { return $null }
    return (Get-FileHash -Path $filePath -Algorithm SHA256).Hash
}

# ─── Report header ─────────────────────────────────────────────────────────
$report = @()
$report += "NT230 Supply Chain PoC — Multi-Engine AV Scan Report"
$report += "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$report += "Machine: $env:COMPUTERNAME ($env:OS)"
$report += "=" * 60
$report += ""

Write-Section "1. Tính SHA-256 hash payload files"

$hashResults = @()
foreach ($file in $PayloadFiles) {
    $name = Split-Path -Leaf $file
    if (-not (Test-Path $file)) {
        Write-Host "  SKIP: $name (not found)" -ForegroundColor DarkGray
        continue
    }
    $hash = Get-FileSHA256 $file
    $size = (Get-Item $file).Length
    Write-Host "  $name" -ForegroundColor White -NoNewline
    Write-Host "  $hash" -ForegroundColor Yellow
    $hashResults += [PSCustomObject]@{ File = $name; SHA256 = $hash; Size = $size }
    $report += "File: $name"
    $report += "  SHA-256: $hash"
    $report += "  Size:    $size bytes"
    $report += ""
}

# ─── 2. Windows Defender scan ──────────────────────────────────────────────
Write-Section "2. Windows Defender — Custom Scan"

$defenderVersion = $null
try {
    $mpStatus = Get-MpComputerStatus -ErrorAction Stop
    $defenderVersion = $mpStatus.AntivirusSignatureVersion
    $lastUpdate = $mpStatus.AntivirusSignatureLastUpdated
    Write-Host "  Defender version: $defenderVersion" -ForegroundColor White
    Write-Host "  Signatures updated: $lastUpdate" -ForegroundColor White
    $report += "Defender version: $defenderVersion"
    $report += "Signatures: $lastUpdate"
    $report += ""
} catch {
    Write-Host "  WARNING: Cannot query Defender status (not Admin?)" -ForegroundColor Yellow
    $report += "Defender: cannot query (not Admin)"
    $report += ""
}

# Scan package directory
$scanTarget = "$ProjectRoot\packages\safe-marker-package"
Write-Host "  Scanning: $scanTarget" -ForegroundColor White
try {
    Start-MpScan -ScanPath $scanTarget -ScanType CustomScan -ErrorAction Stop
    Write-Host "  Waiting 15s for scan completion..." -ForegroundColor DarkGray
    Start-Sleep -Seconds 15

    # Check threat history (last 1 hour)
    $threats = Get-MpThreatDetection -ErrorAction SilentlyContinue |
        Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddHours(-1) }

    if ($threats -and $threats.Count -gt 0) {
        Write-Host "  DETECTED: $($threats.Count) threat(s)!" -ForegroundColor Red
        $report += "Defender result: DETECTED ($($threats.Count) threats)"
        foreach ($t in $threats) {
            $report += "  Threat: $($t.ThreatName) — $($t.Resources)"
        }
    } else {
        Write-Host "  RESULT: No threats detected — BYPASS confirmed" -ForegroundColor Green
        $report += "Defender result: CLEAN (bypass confirmed)"
    }
} catch {
    Write-Host "  Scan failed: $($_.Exception.Message)" -ForegroundColor Yellow
    $report += "Defender scan: failed ($($_.Exception.Message))"
}
$report += ""

# ─── 3. VirusTotal API check ──────────────────────────────────────────────
Write-Section "3. VirusTotal — Multi-Engine Hash Check"

if ($VTApiKey) {
    Write-Host "  API key provided — checking hashes..." -ForegroundColor White
    $report += "VirusTotal: API key provided"
    $report += ""

    $vtBase = "https://www.virustotal.com/api/v3/files"
    foreach ($hr in $hashResults) {
        $hash = $hr.SHA256
        $name = $hr.File
        Write-Host "  Checking $name..." -ForegroundColor White -NoNewline

        try {
            $headers = @{ "x-apikey" = $VTApiKey }
            $resp = Invoke-RestMethod -Uri "$vtBase/$hash" -Headers $headers -Method Get -ErrorAction Stop
            $stats = $resp.data.attributes.last_analysis_stats
            $malicious  = $stats.malicious
            $undetected = $stats.undetected
            $total      = $malicious + $stats.harmless + $undetected + $stats.suspicious

            if ($malicious -gt 0) {
                Write-Host "  $malicious/$total engines DETECTED" -ForegroundColor Red
                $report += "VT $name : $malicious/$total DETECTED"
            } else {
                Write-Host "  0/$total — CLEAN" -ForegroundColor Green
                $report += "VT $name : 0/$total CLEAN"
            }
        } catch {
            $statusCode = $_.Exception.Response.StatusCode.value__
            if ($statusCode -eq 404) {
                Write-Host "  NOT FOUND (never uploaded)" -ForegroundColor Yellow
                $report += "VT $name : NOT IN DATABASE (never uploaded)"
            } else {
                Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red
                $report += "VT $name : ERROR $($_.Exception.Message)"
            }
        }

        # VirusTotal free API rate limit: 4 requests/minute
        Start-Sleep -Seconds 16
    }
} else {
    Write-Host "  No API key — manual check mode" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Copy hashes below and check on https://www.virustotal.com/" -ForegroundColor White
    $report += "VirusTotal: no API key (manual mode)"
    $report += ""

    foreach ($hr in $hashResults) {
        $url = "https://www.virustotal.com/gui/file/$($hr.SHA256)"
        Write-Host "  $($hr.File):" -ForegroundColor White
        Write-Host "    $url" -ForegroundColor Cyan
        $report += "  $($hr.File): $url"
    }
}
$report += ""

# ─── 4. Summary ────────────────────────────────────────────────────────────
Write-Section "4. Summary"

$report += "=" * 60
$report += "SUMMARY"
$report += "=" * 60
$report += "Files scanned: $($hashResults.Count)"
$report += "Defender: $(if ($defenderVersion) { $defenderVersion } else { 'N/A' })"
$report += "VirusTotal: $(if ($VTApiKey) { 'API check completed' } else { 'Manual mode (paste hashes)' })"

Write-Host "  Files scanned: $($hashResults.Count)" -ForegroundColor White
Write-Host "  Report saved: $ReportFile" -ForegroundColor White

# Save report
$report | Out-File -FilePath $ReportFile -Encoding UTF8
Write-Host "`n  Done." -ForegroundColor Green
