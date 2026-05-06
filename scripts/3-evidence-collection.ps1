<#
.SYNOPSIS
  [NT230 PoC] ACTOR 3: Forensics — Thu thập bằng chứng sau sự cố.

.DESCRIPTION
  Script này đóng vai incident response / forensics analyst.
  Chạy SAU khi phát hiện nghi ngờ bị tấn công (hoặc sau khi CI pipeline kết thúc).

  Thu thập:
    1. Docker logs từ attacker receiver
    2. Loot files (secrets + poison confirm)
    3. Artifact evidence (build-output.txt bị inject)
    4. Evidence summary

  Usage:
    .\3-evidence-collection.ps1                         # chạy trên Machine C (lấy loot từ thư mục local)
    .\3-evidence-collection.ps1 -LootDir C:\path\loot   # chỉ rõ lấy loot từ đường dẫn khác
#>

param(
    # Đường dẫn đến thư mục loot của attacker.
    # Mặc định: attacker-server\loot (relative to project root — dùng khi chạy trên Machine C)
    [string]$LootDir = ""
)

$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot

if ([string]::IsNullOrEmpty($LootDir)) {
    $LootDir = Join-Path $root "attacker-server\loot"
}

Write-Host "═" * 60 -ForegroundColor Magenta
Write-Host "[FORENSICS] Incident Response — Evidence Collection" -ForegroundColor Magenta
Write-Host "═" * 60 -ForegroundColor Magenta
Write-Host ""

$secretsCount = 0
$poisonCount = 0
$artifactPoisoned = $false

# ───────────────────────────────────────────────────────────────────────────
# Evidence 1: Attacker server loot files
# ───────────────────────────────────────────────────────────────────────────
Write-Host "[1/4] Checking attacker loot directory..." -ForegroundColor Yellow

$lootDir = $LootDir
if (Test-Path $lootDir) {
    $lootFiles = Get-ChildItem $lootDir -File
    Write-Host "  Found $($lootFiles.Count) loot file(s):" -ForegroundColor White
    foreach ($f in $lootFiles) {
        $icon = if ($f.Name -match "secrets") { "🔑" } elseif ($f.Name -match "poison") { "💀" } else { "📄" }
        Write-Host "    $icon $($f.Name) ($($f.Length) bytes)" -ForegroundColor Gray
    }

    # Show secrets content
    $secretFiles = $lootFiles | Where-Object { $_.Name -match "secrets" }
    $secretsCount = $secretFiles.Count
    foreach ($sf in $secretFiles) {
        Write-Host ""
        Write-Host "  ── Secrets exfil evidence: $($sf.Name) ──" -ForegroundColor Red
        Get-Content $sf.FullName | Write-Host -ForegroundColor DarkRed
    }

    # Show poison confirm content
    $poisonFiles = $lootFiles | Where-Object { $_.Name -match "poison" }
    $poisonCount = $poisonFiles.Count
    foreach ($pf in $poisonFiles) {
        Write-Host ""
        Write-Host "  ── Poison confirm evidence: $($pf.Name) ──" -ForegroundColor Red
        Get-Content $pf.FullName | Write-Host -ForegroundColor DarkRed
    }
} else {
    Write-Host "  No loot directory found." -ForegroundColor Yellow
}

# ───────────────────────────────────────────────────────────────────────────
# Evidence 2: Artifact tampering
# ───────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[2/4] Checking artifact integrity..." -ForegroundColor Yellow

$buildOutput = Join-Path $root "artifacts\build-output.txt"
if (Test-Path $buildOutput) {
    $content = Get-Content $buildOutput -Raw
    if ($content -match "INJECTED BY SUPPLY CHAIN") {
        $artifactPoisoned = $true
        Write-Host "  ⚠ ARTIFACT POISONED — build-output.txt contains injected payload!" -ForegroundColor Red
        Write-Host ""
        # Show injection markers
        Select-String -Path $buildOutput -Pattern "INJECTED|artifact_poisoning|eval\(Buffer" | ForEach-Object {
            Write-Host "  > $($_.Line.Trim())" -ForegroundColor DarkRed
        }
    } else {
        Write-Host "  Artifact appears clean." -ForegroundColor Green
    }
} else {
    Write-Host "  build-output.txt not found." -ForegroundColor Yellow
}

$ciMarker = Join-Path $root "artifacts\ci-injected-marker.txt"
if (Test-Path $ciMarker) {
    Write-Host ""
    Write-Host "  ⚠ CI injection marker file exists!" -ForegroundColor Red
    Get-Content $ciMarker | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkRed }
}

# ───────────────────────────────────────────────────────────────────────────
# Evidence 3: Kiểm tra receiver process
# ───────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[3/4] Receiver process status..." -ForegroundColor Yellow

$receiverProcs = Get-Process -Name "node" -ErrorAction SilentlyContinue
if ($receiverProcs) {
    Write-Host "  node.exe đang chạy: $($receiverProcs.Count) process" -ForegroundColor Gray
    foreach ($p in $receiverProcs) {
        Write-Host "    PID $($p.Id) — started $($p.StartTime)" -ForegroundColor DarkGray
    }
    Write-Host "  Tip: xem log receiver trong cửa sổ terminal của nó." -ForegroundColor Cyan
} else {
    Write-Host "  Không có node.exe — receiver có thể đã exit." -ForegroundColor Yellow
    Write-Host "  Loot files vẫn tồn tại nếu exfil đã xảy ra trước đó." -ForegroundColor DarkGray
}

# ───────────────────────────────────────────────────────────────────────────
# Evidence 4: Summary
# ───────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "═" * 60 -ForegroundColor Magenta
Write-Host "[FORENSICS] Evidence Summary" -ForegroundColor Magenta
Write-Host "─" * 60 -ForegroundColor DarkGray
Write-Host "  Secrets exfil files   : $secretsCount" -ForegroundColor $(if ($secretsCount -gt 0) { "Red" } else { "Green" })
Write-Host "  Artifact poison files : $poisonCount" -ForegroundColor $(if ($poisonCount -gt 0) { "Red" } else { "Green" })
Write-Host "  Build artifact tamper : $artifactPoisoned" -ForegroundColor $(if ($artifactPoisoned) { "Red" } else { "Green" })
Write-Host "─" * 60 -ForegroundColor DarkGray
if ($secretsCount -gt 0 -or $poisonCount -gt 0 -or $artifactPoisoned) {
    Write-Host "  VERDICT: COMPROMISED — Supply chain attack confirmed!" -ForegroundColor Red
} else {
    Write-Host "  VERDICT: No evidence of compromise found." -ForegroundColor Green
}
Write-Host ""
Write-Host "  Next steps:" -ForegroundColor Cyan
Write-Host "    1. Run detector:  node detector\detect-supply-chain.js full . artifacts" -ForegroundColor Cyan
Write-Host "    2. Verify hashes: node detector\detect-supply-chain.js verify artifacts" -ForegroundColor Cyan
Write-Host "    3. AV bypass:     .\scripts\test-av-bypass.ps1" -ForegroundColor Cyan
Write-Host "═" * 60 -ForegroundColor Magenta
