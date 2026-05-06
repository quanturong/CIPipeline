<#
.SYNOPSIS
  [NT230 PoC] Machine C (Attacker): Khởi động Verdaccio + receiver.js natively.

.DESCRIPTION
  Chạy script này trên Machine C TRƯỚC KHI chạy 1-attacker-publish.ps1.
  Mở 2 terminal window riêng biệt để dễ quan sát log realtime.

  Yêu cầu:
    - Node.js >= 18
    - verdaccio (tự động cài nếu chưa có)

  Usage:
    .\start-attacker-services.ps1

  Sau khi chạy xong:
    .\1-attacker-publish.ps1 -AttackerHost <LAN_IP_CUA_MAY_NAY> -Mode stealth
#>

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

Write-Host ("═" * 60) -ForegroundColor DarkRed
Write-Host "[ATTACKER SERVICES] Starting natively (no Docker)" -ForegroundColor DarkRed
Write-Host ("═" * 60) -ForegroundColor DarkRed
Write-Host ""

# ─── 1. Cài verdaccio nếu chưa có ────────────────────────────
Write-Host "[1/3] Checking verdaccio..." -ForegroundColor Yellow

$verdaccioCmd = Get-Command verdaccio -ErrorAction SilentlyContinue
if (-not $verdaccioCmd) {
    Write-Host "  verdaccio chưa cài. Đang cài globally..." -ForegroundColor Yellow
    npm install -g verdaccio
    Write-Host "  verdaccio installed." -ForegroundColor Green
} else {
    Write-Host "  verdaccio: OK ($($verdaccioCmd.Source))" -ForegroundColor Green
}

# Ensure storage dir exists (verdaccio sẽ tạo htpasswd vào đây)
$storageDir = Join-Path $root "infra\verdaccio\storage"
if (-not (Test-Path $storageDir)) {
    New-Item -ItemType Directory -Path $storageDir -Force | Out-Null
    Write-Host "  Created storage dir: $storageDir" -ForegroundColor Gray
}

# ─── 2. Start Verdaccio trong cửa sổ mới ─────────────────────
Write-Host ""
Write-Host "[2/3] Starting Verdaccio (new window)..." -ForegroundColor Yellow

$verdaccioConfig = Join-Path $root "infra\verdaccio\config-native.yaml"
$verdaccioWorkDir = Join-Path $root "infra\verdaccio"

if (-not (Test-Path $verdaccioConfig)) {
    Write-Host "  ERROR: $verdaccioConfig not found!" -ForegroundColor Red
    Write-Host "  Tạo file config-native.yaml trước." -ForegroundColor Yellow
    exit 1
}

Start-Process powershell -ArgumentList @(
    "-NoExit",
    "-Command",
    "Set-Location '$verdaccioWorkDir'; `$host.UI.RawUI.WindowTitle = 'NT230 - Verdaccio Registry :4873'; Write-Host '[VERDACCIO] Starting on 0.0.0.0:4873...' -ForegroundColor Cyan; verdaccio --config '$verdaccioConfig' --listen '0.0.0.0:4873'"
) -WindowStyle Normal

# ─── 3. Start receiver.js trong cửa sổ mới ───────────────────
Write-Host "[3/3] Starting receiver.js (new window)..." -ForegroundColor Yellow

$receiverJs = Join-Path $root "attacker-server\receiver.js"
Start-Process powershell -ArgumentList @(
    "-NoExit",
    "-Command",
    "`$host.UI.RawUI.WindowTitle = 'NT230 - Attacker Receiver :8080'; Write-Host '[RECEIVER] Starting on 0.0.0.0:8080...' -ForegroundColor Red; node '$receiverJs'"
) -WindowStyle Normal

# ─── Health check ─────────────────────────────────────────────
Write-Host ""
Write-Host "  Chờ 6s để services boot..." -ForegroundColor Gray
Start-Sleep -Seconds 6

$allOk = $true
try {
    $null = Invoke-WebRequest -Uri "http://localhost:4873" -UseBasicParsing -TimeoutSec 5
    Write-Host "  Verdaccio : OK  → http://localhost:4873" -ForegroundColor Green
} catch {
    Write-Host "  Verdaccio : TIMEOUT — kiểm tra cửa sổ Verdaccio" -ForegroundColor Red
    $allOk = $false
}

try {
    $null = Invoke-WebRequest -Uri "http://localhost:8080/beacon" -UseBasicParsing -TimeoutSec 5
    Write-Host "  Receiver  : OK  → http://localhost:8080" -ForegroundColor Green
} catch {
    Write-Host "  Receiver  : TIMEOUT — kiểm tra cửa sổ Receiver" -ForegroundColor Red
    $allOk = $false
}

# ─── Đăng ký user demo trong Verdaccio ───────────────────────
if ($allOk) {
    Write-Host ""
    Write-Host "  Registering user 'demo' in Verdaccio..." -ForegroundColor Gray
    $ts = [int][double]::Parse((Get-Date -UFormat %s))
    $userBody = "{`"name`":`"demo`",`"password`":`"demo`",`"email`":`"demo@test.com`",`"_id`":`"org.couchdb.user:demo`",`"type`":`"user`",`"roles`":[],`"date`":`"$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ss.fffZ')`"}"
    try {
        $null = Invoke-RestMethod -Method PUT `
            -Uri "http://localhost:4873/-/user/org.couchdb.user:demo" `
            -Body $userBody -ContentType "application/json" -TimeoutSec 5
        Write-Host "  User 'demo' registered." -ForegroundColor Green
    } catch {
        # 409 = user already exists — fine
        if ($_.Exception.Response.StatusCode -eq 409) {
            Write-Host "  User 'demo' already exists." -ForegroundColor Gray
        } else {
            Write-Host "  User registration: $($_.Exception.Message)" -ForegroundColor DarkGray
        }
    }
}

# ─── Print LAN IP ─────────────────────────────────────────────
Write-Host ""
$lanIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
    $_.InterfaceAlias -notmatch "Loopback|Bluetooth|vEthernet|WSL" -and
    $_.IPAddress -notmatch "^169\." -and $_.IPAddress -ne "127.0.0.1"
} | Sort-Object PrefixLength -Descending | Select-Object -First 1).IPAddress

Write-Host ("═" * 60) -ForegroundColor DarkRed
if ($allOk) {
    Write-Host "  Services đang chạy. Bước tiếp theo:" -ForegroundColor Green
    if ($lanIP) {
        Write-Host "    .\scripts\1-attacker-publish.ps1 -AttackerHost $lanIP -Mode stealth" -ForegroundColor Yellow
    } else {
        Write-Host "    .\scripts\1-attacker-publish.ps1 -AttackerHost <LAN_IP> -Mode stealth" -ForegroundColor Yellow
        Write-Host "    (Kiểm tra LAN IP bằng: ipconfig)" -ForegroundColor Gray
    }
} else {
    Write-Host "  Một hoặc cả hai service TIMEOUT." -ForegroundColor Red
    Write-Host "  Kiểm tra terminal windows vừa mở." -ForegroundColor Yellow
}
Write-Host ("═" * 60) -ForegroundColor DarkRed
