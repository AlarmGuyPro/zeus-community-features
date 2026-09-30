# SPDX-License-Identifier: GPL-2.0-or-later
# Package security scan orchestrator. For every target version it downloads
# the bytes, verifies SHA-256 before anything else, then runs ClamAV, the
# static package scanner, and an OSV dependency scan of the pinned source
# lockfiles. Package and contributor code are never executed.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet("pull_request", "backfill")][string] $Mode,
    [Parameter(Mandatory)][string] $RegistryPath,
    [string] $BaseRegistryPath = "",
    [Parameter(Mandatory)][string] $OutputDirectory,
    [string] $AllowlistPath = (Join-Path $PSScriptRoot "package-security-allowlist.json"),
    [ValidateSet("Required", "Auto", "Off")][string] $ClamAv = "Auto",
    [string] $ClamAvDatabase = "",
    [string] $OsvScannerPath = "",
    [switch] $SkipScannerBuild,
    [string] $RunUrl = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$ProgressPreference = "SilentlyContinue"
Import-Module (Join-Path $PSScriptRoot "SecurityScan.psm1") -Force

if ($Mode -eq "pull_request" -and [string]::IsNullOrWhiteSpace($BaseRegistryPath)) {
    throw "Pull request mode requires BaseRegistryPath"
}
$outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null
$workRoot = Join-Path $outputRoot "work"
if (Test-Path -LiteralPath $workRoot) { throw "Output directory already contains a work tree" }
New-Item -ItemType Directory -Path $workRoot | Out-Null

$candidate = Get-Content -Raw -LiteralPath $RegistryPath | ConvertFrom-Json -Depth 100
if ($Mode -eq "backfill") {
    $targets = Get-SecurityScanTargets -CandidateRegistry $candidate -All
}
else {
    $base = Get-Content -Raw -LiteralPath $BaseRegistryPath | ConvertFrom-Json -Depth 100
    $targets = Get-SecurityScanTargets -CandidateRegistry $candidate -BaseRegistry $base
}
Write-Host "Scanning $(@($targets).Count) version(s) in $Mode mode."

# Tool requirements only apply when there is something to scan; a pull
# request that changes no community version must pass without ClamAV or OSV.
# One version per pull request is checked first: a violating pull request
# fails without downloading, scanning, or requiring any scan tool.
$policyFinding = if ($Mode -eq "pull_request") { Get-OneVersionPolicyFinding -Targets @($targets) } else { $null }
$scanTargets = @(if ($null -eq $policyFinding) { $targets })
$hasTargets = $scanTargets.Count -gt 0
$clamAvAvailable = $null -ne (Get-Command clamscan -CommandType Application -ErrorAction SilentlyContinue)
if ($hasTargets -and $ClamAv -eq "Required" -and -not $clamAvAvailable) {
    throw "ClamAV is required but clamscan is not installed"
}
$useClamAv = $ClamAv -ne "Off" -and $clamAvAvailable
$useOsv = -not [string]::IsNullOrWhiteSpace($OsvScannerPath)
if ($hasTargets -and $useOsv -and -not (Test-Path -LiteralPath $OsvScannerPath -PathType Leaf)) {
    throw "osv-scanner not found at $OsvScannerPath"
}
$allowlist = ""
if ($AllowlistPath -and (Test-Path -LiteralPath $AllowlistPath -PathType Leaf)) {
    $allowlist = [IO.Path]::GetFullPath($AllowlistPath)
}

$scannerReady = $false
$results = [Collections.Generic.List[object]]::new()
$index = 0
if ($null -ne $policyFinding) {
    $results.Add([pscustomobject][ordered]@{
        featureId = "(pull request)"; version = ""; channel = "community"; packageUrl = ""; sha256 = ""
        sourceRepository = ""; sourceCommit = ""; disposition = "fail"
        checks = [pscustomobject]@{ policy = "failed" }
        findings = @($policyFinding)
    })
}
try {
    foreach ($target in $scanTargets) {
        $work = Join-Path $workRoot ($index++).ToString()
        New-Item -ItemType Directory -Path $work | Out-Null
        $findings = [Collections.Generic.List[object]]::new()
        $checks = [ordered]@{ download = "skipped"; clamav = "skipped"; scanner = "skipped"; osv = "skipped" }
        $packageUrl = if ($null -ne $target.source) { [string]$target.source.package } else { $target.downloadUrl }
        Write-Host "== $($target.featureId)@$($target.version) from $packageUrl"

        $package = $null
        try {
            $package = Get-VerifiedPackage -Target $target -DestinationDirectory $work
            $checks.download = "passed"
        }
        catch {
            $checks.download = "failed"
            $findings.Add((New-SecurityFinding -Check "download" -RuleId "package-download-or-hash" `
                -Severity fail -Detail $_.Exception.Message))
        }

        if ($null -ne $package) {
            $extracted = $null
            try {
                $extracted = Expand-PackageForScan -PackagePath $package.path -Target $target `
                    -DestinationDirectory (Join-Path $work "extracted")
            }
            catch {
                $findings.Add((New-SecurityFinding -Check "archive" -RuleId "package-archive-unsafe" `
                    -Severity fail -Detail $_.Exception.Message))
            }

            if ($useClamAv) {
                try {
                    $paths = @($package.path)
                    if ($extracted) { $paths += $extracted }
                    $clamFindings = @(Invoke-ClamAvScan -Paths $paths -DisplayRoot $work `
                        -LogPath (Join-Path $work "clamav.log") -DatabaseDirectory $ClamAvDatabase)
                    foreach ($finding in $clamFindings) { $findings.Add($finding) }
                    $checks.clamav = if ($clamFindings.Count -gt 0) { "failed" } else { "passed" }
                }
                catch {
                    $checks.clamav = "error"
                    $findings.Add((New-SecurityFinding -Check "clamav" -RuleId "clamav-error" `
                        -Severity fail -Detail $_.Exception.Message))
                }
            }
            elseif ($ClamAv -ne "Off") {
                $findings.Add((New-SecurityFinding -Check "clamav" -RuleId "clamav-unavailable" -Severity info `
                    -Detail "clamscan is not installed; malware signatures were not checked"))
            }

            try {
                if (-not $SkipScannerBuild -and -not $scannerReady) {
                    Initialize-PackageScanner
                    $scannerReady = $true
                }
                $scan = Invoke-PackageScanner -Mode scan -PackagePath $package.path `
                    -JsonPath (Join-Path $work "scanner.json") -AllowlistPath $allowlist
                foreach ($finding in @(ConvertFrom-ScannerFindings -Result $scan -Check "scanner")) {
                    $findings.Add($finding)
                }
                $checks.scanner = [string]$scan.disposition
            }
            catch {
                $checks.scanner = "error"
                $findings.Add((New-SecurityFinding -Check "scanner" -RuleId "scanner-error" `
                    -Severity fail -Detail $_.Exception.Message))
            }
        }

        if ($useOsv -and $null -ne $target.source) {
            try {
                $sourceDirectory = Get-SourceCheckout -Repository ([string]$target.source.repository) `
                    -Commit ([string]$target.source.commit) -Destination (Join-Path $work "source") -DataOnly
                $osv = Invoke-OsvScan -OsvScannerPath $OsvScannerPath -SourceDirectory $sourceDirectory `
                    -WorkDirectory $work
                foreach ($finding in @($osv.findings)) { $findings.Add($finding) }
                $checks.osv = Get-WorstDisposition -Values @($osv.findings | ForEach-Object { $_.severity })
            }
            catch {
                $checks.osv = "error"
                $findings.Add((New-SecurityFinding -Check "osv" -RuleId "osv-error" `
                    -Severity $(if ($Mode -eq "pull_request") { "fail" } else { "review" }) `
                    -Detail $_.Exception.Message))
            }
        }
        elseif ($useOsv) {
            $findings.Add((New-SecurityFinding -Check "osv" -RuleId "osv-no-source" -Severity info `
                -Detail "No source provenance is recorded for this version; dependencies were not checked"))
        }

        $results.Add([pscustomobject][ordered]@{
            featureId = $target.featureId
            version = $target.version
            channel = $target.channel
            packageUrl = $packageUrl
            sha256 = $target.sha256
            sourceRepository = if ($null -ne $target.source) { [string]$target.source.repository } else { "" }
            sourceCommit = if ($null -ne $target.source) { [string]$target.source.commit } else { "" }
            disposition = Get-WorstDisposition -Values @($findings | ForEach-Object { $_.severity })
            checks = [pscustomobject]$checks
            findings = $findings.ToArray()
        })
        Write-Host "   result: $($results[-1].disposition)"
        Remove-Item -LiteralPath $work -Recurse -Force
    }
}
finally {
    if (Test-Path -LiteralPath $workRoot) { Remove-Item -LiteralPath $workRoot -Recurse -Force }
}

$report = New-SecurityReport -Mode $Mode -Results $results.ToArray()
$jsonPath = Join-Path $outputRoot "security-report.json"
$markdownPath = Join-Path $outputRoot "security-report.md"
[IO.File]::WriteAllText($jsonPath, ($report | ConvertTo-Json -Depth 20) + "`n", [Text.UTF8Encoding]::new($false))
$markdown = ConvertTo-SecurityReportMarkdown -Report $report -RunUrl $RunUrl
[IO.File]::WriteAllText($markdownPath, $markdown + "`n", [Text.UTF8Encoding]::new($false))
if ($env:GITHUB_STEP_SUMMARY) {
    Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY -Value $markdown
}
Write-Host "Overall result: $($report.disposition). Report: $jsonPath"
if ($Mode -eq "pull_request" -and $report.disposition -eq "fail") { exit 2 }
exit 0
