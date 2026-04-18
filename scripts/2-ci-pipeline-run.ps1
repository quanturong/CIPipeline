<#
.SYNOPSIS
  [NT230 PoC] ACTOR 2: CI Pipeline Runner — Mô phỏng pipeline thật.

.DESCRIPTION
  Script này mô phỏng GitLab/GitHub CI pipeline.
  KHÔNG biết gì về attacker — chỉ chạy các stage chuẩn:
    Stage 1: Setup CI environment (set env vars — điều này xảy ra tự động trong real CI)
    Stage 2: npm install (→ trigger postinstall → secrets bị đánh cắp — pipeline không biết)
    Stage 3: Build artifact (tạo build-output.txt)
    Stage 4: Post-build (artifact injection — trong real attack, step này cũng bị compromise)
    Stage 5: Cleanup

  Pipeline exit code 0 = "thành công" — nhưng thực tế đã bị tấn công.
  Đây chính là lý do supply chain attack nguy hiểm: CI KHÔNG CÓ DẤU HIỆU BẤT THƯỜNG.

  Usage:
    .\2-ci-pipeline-run.ps1
#>

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

Write-Host "═" * 60 -ForegroundColor Cyan
Write-Host "[CI PIPELINE] Triggered by git push — running stages..." -ForegroundColor Cyan
Write-Host "═" * 60 -ForegroundColor Cyan
Write-Host ""

# ───────────────────────────────────────────────────────────────────────────
# Stage 1: Setup CI environment
# ───────────────────────────────────────────────────────────────────────────
Write-Host "[Stage 1/5] Setting up CI environment..." -ForegroundColor Cyan

# Xóa real secrets trước khi set fake (tránh leak credentials thật)
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

# CI environment variables — tự động có trong real CI runner
$env:CI = "true"
$env:CI_JOB_TOKEN = "glpat-FAKE-CI-TOKEN-xxxxxxxxxxxx"
$env:CI_PROJECT_PATH = "nt230-demo/supply-chain-victim"
$env:CI_SERVER_URL = "https://gitlab.example.com"
$env:CI_JOB_ID = "12345"
$env:GITHUB_TOKEN = "ghp_FAKE_GITHUB_TOKEN_xxxxxxxxxxxxxxxxxxxx"
$env:AWS_SECRET_ACCESS_KEY = "FAKE+AWS+SECRET+KEY/xxxxxxxxxxxxxxxxxx"
$env:NPM_TOKEN = "npm_FAKE_PUBLISH_TOKEN_xxxxxxxxxxxxxxx"
$env:DEPLOY_KEY = "-----BEGIN RSA PRIVATE KEY----- FAKE_KEY -----END RSA PRIVATE KEY-----"

Write-Host "  CI environment configured (5 secrets injected by CI runner)" -ForegroundColor Gray

# ───────────────────────────────────────────────────────────────────────────
# Stage 2: npm install (dependencies)
# ───────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[Stage 2/5] npm install (installing dependencies)..." -ForegroundColor Cyan

$consumerDir = Join-Path $root "consumer-app"
Push-Location $consumerDir

# Clean install
if (Test-Path "node_modules") { Remove-Item -Recurse -Force "node_modules" }
if (Test-Path "package-lock.json") { Remove-Item -Force "package-lock.json" }

# Install from Verdaccio — postinstall chạy tự động
# CI KHÔNG BIẾT postinstall đang gửi secrets về attacker
npm install --registry http://localhost:4873 2>&1 | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
Pop-Location

Write-Host "  npm install completed (exit code: $LASTEXITCODE)" -ForegroundColor Green

# ───────────────────────────────────────────────────────────────────────────
# Stage 3: Build
# ───────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[Stage 3/5] Building artifacts..." -ForegroundColor Cyan

node (Join-Path $root "ci\build-clean.js")
Write-Host "  Build artifact created." -ForegroundColor Green

# ───────────────────────────────────────────────────────────────────────────
# Stage 4: Post-build steps (artifact injection happens here in real attacks)
# ───────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[Stage 4/5] Post-build processing..." -ForegroundColor Cyan

# Trong real attack: nếu attacker cũng compromise CI config, step này
# sẽ inject payload vào artifact. Ở đây mô phỏng step đó.
node (Join-Path $root "ci\inject-malicious-artifact.js")
Write-Host "  Post-build finalized." -ForegroundColor Green

# ───────────────────────────────────────────────────────────────────────────
# Stage 5: Cleanup
# ───────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[Stage 5/5] Cleanup..." -ForegroundColor Cyan

Remove-Item env:CI_JOB_TOKEN -ErrorAction SilentlyContinue
Remove-Item env:CI_PROJECT_PATH -ErrorAction SilentlyContinue
Remove-Item env:CI_SERVER_URL -ErrorAction SilentlyContinue
Remove-Item env:CI_JOB_ID -ErrorAction SilentlyContinue
Remove-Item env:GITHUB_TOKEN -ErrorAction SilentlyContinue
Remove-Item env:AWS_SECRET_ACCESS_KEY -ErrorAction SilentlyContinue
Remove-Item env:NPM_TOKEN -ErrorAction SilentlyContinue
Remove-Item env:DEPLOY_KEY -ErrorAction SilentlyContinue
Remove-Item env:CI -ErrorAction SilentlyContinue

Write-Host "  CI variables cleaned up." -ForegroundColor Gray

# ───────────────────────────────────────────────────────────────────────────
# Pipeline result
# ───────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "═" * 60 -ForegroundColor Green
Write-Host "[CI PIPELINE] All stages completed successfully ✓" -ForegroundColor Green
Write-Host "  Exit code: 0" -ForegroundColor Green
Write-Host "  Duration: ~15s" -ForegroundColor Green
Write-Host "" -ForegroundColor Green
Write-Host "  ⚠ Pipeline reported SUCCESS — nhưng thực tế:" -ForegroundColor Yellow
Write-Host "    - Secrets đã bị exfiltrate trong Stage 2 (npm install)" -ForegroundColor Yellow
Write-Host "    - Artifact đã bị inject backdoor trong Stage 4" -ForegroundColor Yellow
Write-Host "    - CI runner KHÔNG có bất kỳ warning nào" -ForegroundColor Yellow
Write-Host "═" * 60 -ForegroundColor Green
