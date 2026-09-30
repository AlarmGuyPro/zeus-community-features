# SPDX-License-Identifier: GPL-2.0-or-later
# Report-only security scan of every version already in registry.json. It
# downloads each catalog package, verifies its SHA-256, runs the static
# scanner, and uses ClamAV when clamscan is installed. It never writes to the
# network and never fails because of a finding; read the Markdown table.
[CmdletBinding()]
param(
    [string] $RegistryPath = (Join-Path $PSScriptRoot "../registry.json"),
    [string] $OutputDirectory = (Join-Path $PSScriptRoot "../artifacts/security-backfill"),
    [ValidateSet("Required", "Auto", "Off")][string] $ClamAv = "Auto",
    [string] $ClamAvDatabase = "",
    [string] $OsvScannerPath = "",
    [string] $RunUrl = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$output = [IO.Path]::GetFullPath($OutputDirectory)
foreach ($name in @("security-report.json", "security-report.md", "work")) {
    $existing = Join-Path $output $name
    if (Test-Path -LiteralPath $existing) { Remove-Item -LiteralPath $existing -Recurse -Force }
}
& (Join-Path $PSScriptRoot "invoke-security-scan.ps1") `
    -Mode backfill `
    -RegistryPath ([IO.Path]::GetFullPath($RegistryPath)) `
    -OutputDirectory $output `
    -ClamAv $ClamAv `
    -ClamAvDatabase $ClamAvDatabase `
    -OsvScannerPath $OsvScannerPath `
    -RunUrl $RunUrl
if ($LASTEXITCODE -ne 0) { throw "Backfill scan failed with exit code $LASTEXITCODE" }
Write-Host "Backfill report written to $(Join-Path $output 'security-report.md')"
