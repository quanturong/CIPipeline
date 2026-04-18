<#
.SYNOPSIS
  [NT230 PoC] ACTOR 2: CI Pipeline Runner — Mô phỏng GitLab Runner thật.

.DESCRIPTION
  Script này khởi chạy gitlab-runner-sim.js — một mini GitLab Runner simulator.
  Runner simulator sẽ:
    1. Đọc & parse .gitlab-ci.compromised.yml (hoặc .gitlab-ci.yml)
    2. Resolve stages, jobs, variables, artifacts, dependencies
    3. Set CI predefined variables (CI_PIPELINE_ID, CI_COMMIT_SHA, CI_JOB_NAME...)
    4. Inject fake secrets (giống real CI runner)
    5. Chạy từng job theo thứ tự stage, output format giống GitLab Runner thật
    6. Cleanup sau khi pipeline kết thúc

  So sánh với GitLab Runner thật:
    ✓ Parse .gitlab-ci.yml (không hardcode stages)
    ✓ CI predefined variables
    ✓ Job/stage ordering từ YAML
    ✓ Output format ($ command, job status, duration)
    ✗ Docker executor (chạy trực tiếp trên host — giống shell executor)
    ✗ Artifact caching giữa stages

  Usage:
    .\2-ci-pipeline-run.ps1                          # Pipeline compromised (default)
    .\2-ci-pipeline-run.ps1 -CIConfig ".gitlab-ci.yml"  # Pipeline sạch
    .\2-ci-pipeline-run.ps1 -Compare                 # Chạy cả 2, so sánh

.PARAMETER CIConfig
  Path tới file .gitlab-ci.yml (relative to project root).
  Default: .gitlab-ci.compromised.yml

.PARAMETER Compare
  Chạy cả compromised và clean pipeline, so sánh kết quả.
#>

param(
    [string]$CIConfig = ".gitlab-ci.compromised.yml",
    [switch]$Compare
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

# ── Pre-flight checks ──
$runner = Join-Path $root "ci\gitlab-runner-sim.js"
if (-not (Test-Path $runner)) {
    Write-Host "ERROR: gitlab-runner-sim.js not found at $runner" -ForegroundColor Red
    exit 1
}

# Ensure consumer-app clean state
$consumerDir = Join-Path $root "consumer-app"
if (Test-Path (Join-Path $consumerDir "node_modules")) {
    Remove-Item -Recurse -Force (Join-Path $consumerDir "node_modules")
}
if (Test-Path (Join-Path $consumerDir "package-lock.json")) {
    Remove-Item -Force (Join-Path $consumerDir "package-lock.json")
}

function Run-GitLabRunner {
    param([string]$ConfigFile)

    $fullPath = Join-Path $root $ConfigFile
    if (-not (Test-Path $fullPath)) {
        Write-Host "ERROR: CI config not found: $fullPath" -ForegroundColor Red
        return $false
    }

    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host "  GitLab Runner Simulator" -ForegroundColor Cyan
    Write-Host "  Config: $ConfigFile" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host ""

    # Chạy runner simulator — output trực tiếp
    node $runner $fullPath
    $exitCode = $LASTEXITCODE

    Write-Host ""
    return ($exitCode -eq 0)
}

if ($Compare) {
    # ── Compare mode: chạy cả compromised và clean ──
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
    Write-Host "║  COMPARE MODE: Compromised vs Clean Pipeline            ║" -ForegroundColor Yellow
    Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Yellow

    Write-Host ""
    Write-Host ">>> [1/2] Running COMPROMISED pipeline..." -ForegroundColor Red
    $r1 = Run-GitLabRunner -ConfigFile ".gitlab-ci.compromised.yml"

    # Clean lại consumer-app giữa 2 lần chạy
    Push-Location $consumerDir
    if (Test-Path "node_modules") { Remove-Item -Recurse -Force "node_modules" }
    if (Test-Path "package-lock.json") { Remove-Item -Force "package-lock.json" }
    Pop-Location

    Write-Host ""
    Write-Host ""
    Write-Host ">>> [2/2] Running CLEAN pipeline..." -ForegroundColor Green
    $r2 = Run-GitLabRunner -ConfigFile ".gitlab-ci.yml"

    Write-Host ""
    Write-Host ("═" * 60) -ForegroundColor Magenta
    Write-Host "  COMPARISON RESULT:" -ForegroundColor Magenta
    Write-Host "    Compromised pipeline: $(if ($r1) { 'PASS ✓' } else { 'FAIL ✗' })" -ForegroundColor $(if ($r1) { "Green" } else { "Red" })
    Write-Host "    Clean pipeline:       $(if ($r2) { 'PASS ✓' } else { 'FAIL ✗' })" -ForegroundColor $(if ($r2) { "Green" } else { "Red" })
    Write-Host ""
    Write-Host "  ⚠ Cả 2 đều PASS — nhưng compromised pipeline đã" -ForegroundColor Yellow
    Write-Host "    exfiltrate secrets trong npm install stage." -ForegroundColor Yellow
    Write-Host "    Kiểm tra attacker server log để xác nhận." -ForegroundColor Yellow
    Write-Host ("═" * 60) -ForegroundColor Magenta
} else {
    # ── Normal mode: chạy 1 pipeline ──
    $result = Run-GitLabRunner -ConfigFile $CIConfig
    if (-not $result) {
        Write-Host "Pipeline failed!" -ForegroundColor Red
        exit 1
    }
}
