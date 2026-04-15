$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

Write-Host "[CI-SIM] Running clean build step..."
Push-Location $root
node .\ci\build-clean.js

Write-Host "[CI-SIM] Running simulated injected step (safe marker only)..."
node .\ci\inject-safe-marker.js

Write-Host "[CI-SIM] Done. Inspect .\artifacts folder."
Pop-Location
