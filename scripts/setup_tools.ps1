# Windows: download pinned syft, osv-scanner and grype into tools\bin (SHA256-verified).
# Usage:  powershell -ExecutionPolicy Bypass -File scripts\setup_tools.ps1 [-Force]
param([switch]$Force)
$kit = Split-Path -Parent $PSScriptRoot
$args2 = @("$kit\scripts\setup_tools.py")
if ($Force) { $args2 += "--force" }
python @args2
exit $LASTEXITCODE
