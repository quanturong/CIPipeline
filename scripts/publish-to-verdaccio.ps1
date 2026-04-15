$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$pkgDir = Join-Path $root "packages\safe-marker-package"

Write-Host "Publishing @demo/safe-marker-package to local Verdaccio registry..."
Write-Host "Tip: run npm adduser --registry http://localhost:4873 in this package folder first."

Push-Location $pkgDir
npm publish --registry http://localhost:4873
Pop-Location

Write-Host "Publish complete."
