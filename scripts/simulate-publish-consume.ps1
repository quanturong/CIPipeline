param(
  [switch]$UseVerdaccio
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$pkgDir = Join-Path $root "packages\safe-marker-package"
$consumerDir = Join-Path $root "consumer-app"
$distDir = Join-Path $root "dist"

if (-not (Test-Path $distDir)) {
  New-Item -ItemType Directory -Path $distDir | Out-Null
}

Write-Host "[1/4] Packing safe package..."
Push-Location $pkgDir
npm pack --pack-destination $distDir
$tarball = Get-ChildItem $distDir -Filter "demo-safe-marker-package-*.tgz" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
Pop-Location

if (-not $tarball) {
  throw "Could not find packaged tarball."
}

Write-Host "[2/4] Installing package into consumer-app..."
Push-Location $consumerDir
if (Test-Path "node_modules") {
  Remove-Item -Recurse -Force "node_modules"
}
if (Test-Path "package-lock.json") {
  Remove-Item -Force "package-lock.json"
}

if ($UseVerdaccio) {
  Write-Host "Using Verdaccio registry mode (expects package already published to localhost:4873)."
  npm install @demo/safe-marker-package --registry http://localhost:4873
} else {
  npm install $tarball.FullName
}

Write-Host "[3/4] Running consumer app..."
npm start
Pop-Location

Write-Host "[4/4] Done. Check your OS temp folder for marker files:"
Write-Host "  - safe-marker-postinstall.log"
Write-Host "  - safe-marker-consumer-runtime.log"
