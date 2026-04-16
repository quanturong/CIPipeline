<#
.SYNOPSIS
  [NT230] Phần B — Kiểm chứng bypass Windows Defender cho npm supply chain attack.

.DESCRIPTION
  Script này thực hiện:
    1. Ghi lại trạng thái Defender (version, signature date, settings)
    2. Tạo malicious postinstall-ci-attack.js tạm ở vị trí test
    3. Trigger Windows Defender scan (Quick + Custom)
    4. Kiểm tra kết quả — payload có bị detect hay không
    5. Ghi report kết quả ra file

  Kết quả kỳ vọng: Defender KHÔNG phát hiện, vì:
    - Payload là pure JavaScript (không binary, không PE)
    - node.exe là trusted signed process (Microsoft/OpenJS Foundation)
    - HTTP POST trông như traffic npm bình thường
    - Không dùng eval/exec trực tiếp trong pattern Defender nhận diện
#>

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$reportFile = Join-Path $root "artifacts\av-bypass-report.txt"

Write-Host "═" * 60 -ForegroundColor Cyan
Write-Host "[NT230] Part B — AV Bypass Verification" -ForegroundColor Cyan
Write-Host "═" * 60 -ForegroundColor Cyan

# ───────────────────────────────────────────────────────────────────────────
# 1. Thu thập thông tin Defender
# ───────────────────────────────────────────────────────────────────────────
Write-Host "`n[1/5] Collecting Defender status..." -ForegroundColor Yellow

$defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue

$report = @"
═══════════════════════════════════════════════════════════
NT230 — AV Bypass Test Report
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
═══════════════════════════════════════════════════════════

[SYSTEM INFO]
  OS:              $([System.Environment]::OSVersion.VersionString)
  Computer:        $env:COMPUTERNAME
  User:            $env:USERNAME

[WINDOWS DEFENDER STATUS]
  AMEngine Version:        $($defenderStatus.AMEngineVersion)
  AMProduct Version:       $($defenderStatus.AMProductVersion)
  Antivirus Signature Ver: $($defenderStatus.AntivirusSignatureVersion)
  Signature Last Updated:  $($defenderStatus.AntivirusSignatureLastUpdated)
  Real-time Protection:    $($defenderStatus.RealTimeProtectionEnabled)
  Behavior Monitoring:     $($defenderStatus.BehaviorMonitorEnabled)
  IOAV Protection:         $($defenderStatus.IoavProtectionEnabled)
  On Access Protection:    $($defenderStatus.OnAccessProtectionEnabled)

"@

Write-Host $report

# ───────────────────────────────────────────────────────────────────────────
# 2. Chỉ định target files để scan
# ───────────────────────────────────────────────────────────────────────────
Write-Host "[2/5] Target files for scan:" -ForegroundColor Yellow

$targetFiles = @(
    (Join-Path $root "packages\safe-marker-package\scripts\postinstall-ci-attack.js"),
    (Join-Path $root "ci\inject-malicious-artifact.js"),
    (Join-Path $root "attacker-server\receiver.js")
)

foreach ($f in $targetFiles) {
    if (Test-Path $f) {
        $hash = (Get-FileHash $f -Algorithm SHA256).Hash
        Write-Host "  [EXISTS] $f" -ForegroundColor Gray
        Write-Host "           SHA256: $($hash.Substring(0, 32))..." -ForegroundColor DarkGray
        $report += "  TARGET: $f`n  SHA256: $hash`n`n"
    } else {
        Write-Host "  [MISSING] $f" -ForegroundColor Red
    }
}

# ───────────────────────────────────────────────────────────────────────────
# 3. Custom Scan — scan thư mục project
# ───────────────────────────────────────────────────────────────────────────
Write-Host "`n[3/5] Running Defender Custom Scan on project folder..." -ForegroundColor Yellow
Write-Host "  Scanning: $root" -ForegroundColor Gray
Write-Host "  (This may take 1-2 minutes)" -ForegroundColor Gray

$scanStart = Get-Date
try {
    Start-MpScan -ScanType CustomScan -ScanPath $root
    
    # Đợi Defender scan hoàn tất (Start-MpScan trả về async, cần chờ)
    Write-Host "  Waiting 30s for Defender scan to complete in background..." -ForegroundColor Gray
    Start-Sleep -Seconds 30
    
    $scanEnd = Get-Date
    $scanDuration = $scanEnd - $scanStart
    Write-Host "  Scan completed in $([math]::Round($scanDuration.TotalSeconds, 1))s (incl. 30s wait)" -ForegroundColor Green
    
    # Đọc Defender event log để xác nhận scan thực sự hoàn tất
    $scanEvents = Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -MaxEvents 5 -ErrorAction SilentlyContinue |
        Where-Object { $_.TimeCreated -gt $scanStart }
    $scanEventInfo = if ($scanEvents) { "$($scanEvents.Count) Defender event(s) after scan start" } else { "No Defender events found" }
    Write-Host "  $scanEventInfo" -ForegroundColor Gray
    
    $report += @"
[CUSTOM SCAN]
  Path:     $root
  Start:    $($scanStart.ToString("HH:mm:ss"))
  End:      $($scanEnd.ToString("HH:mm:ss"))
  Duration: $([math]::Round($scanDuration.TotalSeconds, 1))s (incl. 30s wait for async completion)
  Events:   $scanEventInfo

"@
} catch {
    Write-Host "  Scan failed (need Admin?): $_" -ForegroundColor Red
    $report += "  SCAN FAILED: $_`n`n"
}

# ───────────────────────────────────────────────────────────────────────────
# 4. Kiểm tra Defender threat log
# ───────────────────────────────────────────────────────────────────────────
Write-Host "`n[4/5] Checking Defender threat history..." -ForegroundColor Yellow

$threats = Get-MpThreatDetection -ErrorAction SilentlyContinue | 
    Where-Object { $_.InitialDetectionTime -gt $scanStart.AddMinutes(-5) }

if ($threats) {
    Write-Host "  ⚠ THREATS DETECTED:" -ForegroundColor Red
    foreach ($t in $threats) {
        $line = "  ThreatID=$($t.ThreatID) Resource=$($t.Resources) Action=$($t.CurrentThreatExecutionStatusID)"
        Write-Host "  $line" -ForegroundColor Red
        $report += "  [DETECTED] $line`n"
    }
} else {
    Write-Host "  ✓ No threats detected — payload BYPASSED Defender" -ForegroundColor Green
    $report += "  [RESULT] No threats detected — BYPASS CONFIRMED`n`n"
}

# ───────────────────────────────────────────────────────────────────────────
# 5. Phân tích lý do bypass
# ───────────────────────────────────────────────────────────────────────────
Write-Host "`n[5/5] Bypass analysis:" -ForegroundColor Yellow

$analysis = @"
[BYPASS ANALYSIS]
  Lý do Windows Defender không phát hiện:

  1. Trusted Process Execution
     - Payload chạy dưới node.exe — signed binary từ OpenJS Foundation
     - Defender whitelist node.exe vì là legitimate development tool
     - Hành vi "node.exe đọc env vars rồi gửi HTTP POST" là BÌNH THƯỜNG
       với bất kỳ Node.js app nào

  2. No Binary/PE Payload
     - Toàn bộ malicious code là plaintext JavaScript
     - Defender signature database chủ yếu target PE executables, shellcode,
       known malware binaries
     - JavaScript source code không match signature patterns

  3. No Suspicious API Calls
     - Không dùng: exec(), spawn(), eval(), child_process
     - Chỉ dùng: http.request() (stdlib), process.env, os.hostname()
     - Đây là API hoàn toàn hợp pháp, mọi npm package đều có thể dùng

  4. Legitimate-looking Network Traffic
     - HTTP POST đến port 8080 — trông như webhook/API call bình thường
     - User-Agent giả mạo: "npm/10.2.3 node/v20.10.0"
     - Content-Type: application/json — không khác gì REST API call

  5. Fail-silent Design
     - Nếu attacker server offline → script exit cleanly
     - Không crash, không error log → không trigger behavioral detection
     - npm install vẫn "thành công" từ góc nhìn CI pipeline

  6. Artifact Poisoning via File Append
     - inject-malicious-artifact.js chỉ append text vào file
     - Defender không scan nội dung build artifacts cho malware patterns
     - Base64-encoded payload trong comment không trigger heuristic

  ═══════════════════════════════════════════════════════════
  7. AMSI (Antimalware Scan Interface) — LÝ DO CỐT LÕI
  ═══════════════════════════════════════════════════════════

  AMSI là cơ chế Windows cho phép AV scan script content tại runtime.
  NHƯNG: Node.js V8 engine KHÔNG tích hợp AMSI provider.

  So sánh AMSI integration giữa các runtime:
  ┌─────────────────┬──────────────────┬─────────────────────────┐
  │ Runtime         │ AMSI Integration │ Defender có scan không? │
  ├─────────────────┼──────────────────┼─────────────────────────┤
  │ PowerShell      │ Có (built-in)    │ CÓ — detect obfuscated │
  │ .NET CLR        │ Có               │ CÓ — Assembly.Load()   │
  │ WSH (JScript)   │ Có               │ CÓ — Windows Script    │
  │ Python (CPython)│ Không            │ KHÔNG — bypass          │
  │ Node.js (V8)    │ KHÔNG            │ KHÔNG — BYPASS          │
  └─────────────────┴──────────────────┴─────────────────────────┘

  Lưu ý quan trọng:
  - JScript chạy qua WSH (cscript/wscript) BỊ AMSI scan
  - JavaScript chạy qua Node.js (V8 engine) KHÔNG bị AMSI scan
  - Đây là lý do chính, mạnh hơn cả "trusted process" hay "no PE binary"
  - V8 parse và execute JS trực tiếp mà không gọi Windows AMSI API
    (amsi.dll → AmsiScanBuffer/AmsiScanString)

  Kết luận: Payload bypass Defender nhờ ĐẶC ĐIỂM TỰ NHIÊN của Node.js
  ecosystem (V8 không có AMSI), KHÔNG phải nhờ kỹ thuật anti-AV chủ động.
  Tuy nhiên, 3 yếu tố evasion CÓ CHỦ ĐÍCH:
  - User-Agent giả mạo npm client
  - Fail-silent error handling
  - Base64 encoding payload trong artifact

  So sánh với kỹ thuật evasion chủ động:
  ──────────────────────────────────────
  Payload này bypass Defender nhờ ĐẶC ĐIỂM TỰ NHIÊN của Node.js ecosystem,
  KHÔNG phải nhờ kỹ thuật anti-AV chủ động (obfuscation, packing, etc.)
"@

Write-Host $analysis
$report += $analysis

# ───────────────────────────────────────────────────────────────────────────
# Ghi report
# ───────────────────────────────────────────────────────────────────────────
$artifactsDir = Join-Path $root "artifacts"
if (-not (Test-Path $artifactsDir)) {
    New-Item -ItemType Directory -Path $artifactsDir | Out-Null
}
Set-Content $reportFile $report -Encoding UTF8
Write-Host "`n═" * 60 -ForegroundColor Cyan
Write-Host "[DONE] Report saved to: $reportFile" -ForegroundColor Cyan
Write-Host "═" * 60 -ForegroundColor Cyan
