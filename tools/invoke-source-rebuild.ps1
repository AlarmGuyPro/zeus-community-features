# SPDX-License-Identifier: GPL-2.0-or-later
# Source rebuild check for a catalog pull request. A listing pull request may
# add or change exactly one community version; for it this script clones
# source.repository at source.commit (as data: links are not created),
# requires zeus-build.json and global.json, downloads and verifies the
# package, and runs verify-source-build.ps1.
#
# -Phase Prepare (trusted, runs no contributor code) clones the source,
# validates global.json, and writes a sanitized copy pinning the exact SDK so
# the workflow can install it before the build.
# -Phase Build runs contributor build code, but only inside the
# verify-source-build.ps1 sandbox, and stages the rebuilt tree under
# WorkDirectory/trees/<id>-<version>/rebuilt.
# -Phase Verify runs in a separate clean job: it re-clones the source,
# re-validates everything, and compares the transferred tree with the
# verified package. Only this phase decides the check result.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $BaseRegistryPath,
    [Parameter(Mandatory)][string] $CandidateRegistryPath,
    [Parameter(Mandatory)][string] $WorkDirectory,
    [Parameter(Mandatory)][ValidateSet("Prepare", "Build", "Verify")][string] $Phase,
    [string] $TreesDirectory = "",
    [string] $PinnedGlobalJsonPath = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$ProgressPreference = "SilentlyContinue"
Import-Module (Join-Path $PSScriptRoot "SecurityScan.psm1") -Force
Import-Module (Join-Path $PSScriptRoot "SourceRebuild.psm1") -Force

$workRoot = [IO.Path]::GetFullPath($WorkDirectory)
New-Item -ItemType Directory -Path $workRoot -Force | Out-Null
$base = Get-Content -Raw -LiteralPath $BaseRegistryPath | ConvertFrom-Json -Depth 100
$candidate = Get-Content -Raw -LiteralPath $CandidateRegistryPath | ConvertFrom-Json -Depth 100
$targets = @(Get-SecurityScanTargets -CandidateRegistry $candidate -BaseRegistry $base)
Write-Host "Source rebuild $Phase phase for $($targets.Count) changed community version(s)."
$treesRoot = if ($TreesDirectory) { [IO.Path]::GetFullPath($TreesDirectory) } else { Join-Path $workRoot "trees" }

function Get-TargetSource {
    param([Parameter(Mandatory)] $Target)
    if ($null -eq $Target.source) {
        throw "New community versions must declare source.repository, source.commit, and source.package"
    }
    $destination = Join-Path $workRoot "source"
    if (Test-Path -LiteralPath $destination) {
        $head = (& git -C $destination rev-parse HEAD).Trim()
        if ($LASTEXITCODE -ne 0 -or $head -cne [string]$Target.source.commit) {
            throw "Existing checkout at $destination is not the pinned commit"
        }
        return $destination
    }
    return Get-SourceCheckout -Repository ([string]$Target.source.repository) `
        -Commit ([string]$Target.source.commit) -Destination $destination -DataOnly
}

function Write-StepOutput {
    param([Parameter(Mandatory)][string] $Line)
    if ($env:GITHUB_OUTPUT) { Add-Content -LiteralPath $env:GITHUB_OUTPUT -Value $Line }
    Write-Host $Line
}

if ($Phase -eq "Prepare") {
    Write-StepOutput "count=$($targets.Count)"
    if ($targets.Count -eq 0) { exit 0 }
    $policyFinding = Get-OneVersionPolicyFinding -Targets $targets
    if ($null -ne $policyFinding) { throw "$($policyFinding.detail): $($policyFinding.evidence)" }
    if (-not $PinnedGlobalJsonPath) { throw "Prepare requires PinnedGlobalJsonPath" }
    $sourceDirectory = Get-TargetSource -Target $targets[0]
    [void](Read-BuildContract -Root $sourceDirectory)
    $sdk = Read-PinnedSdkVersion -Root $sourceDirectory
    # setup-dotnet reads this sanitized copy, never the contributor's file.
    $pinned = [ordered]@{ sdk = [ordered]@{ version = $sdk; rollForward = "disable" } }
    $pinnedPath = [IO.Path]::GetFullPath($PinnedGlobalJsonPath)
    New-Item -ItemType Directory -Path (Split-Path -Parent $pinnedPath) -Force | Out-Null
    [IO.File]::WriteAllText($pinnedPath, ($pinned | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
    Write-StepOutput "global-json=$pinnedPath"
    Write-StepOutput "sdk=$sdk"
    exit 0
}

$results = [Collections.Generic.List[object]]::new()
$policyFinding = Get-OneVersionPolicyFinding -Targets $targets
if ($null -ne $policyFinding) {
    $results.Add([pscustomobject][ordered]@{
        featureId = "(pull request)"; version = ""; channel = "community"; disposition = "fail"
        checks = [pscustomobject]@{ policy = "failed" }
        findings = @($policyFinding)
    })
}
else {
    foreach ($target in $targets) {
        $work = Join-Path $workRoot "target"
        New-Item -ItemType Directory -Path $work -Force | Out-Null
        $findings = [Collections.Generic.List[object]]::new()
        $checks = [ordered]@{ source = "skipped"; download = "skipped"; rebuild = "skipped" }
        Write-Host "== $($target.featureId)@$($target.version)"
        try {
            $sourceDirectory = Get-TargetSource -Target $target
            if (-not (Test-Path -LiteralPath (Join-Path $sourceDirectory "zeus-build.json") -PathType Leaf)) {
                throw "zeus-build.json is missing from $($target.source.repository) at $($target.source.commit)"
            }
            $checks.source = "passed"
            $package = Get-VerifiedPackage -Target $target -DestinationDirectory $work
            $checks.download = "passed"
            $treeName = "$($target.featureId)-$($target.version)"
            if ($Phase -eq "Build") {
                # The feed, sandbox home, and logs stay outside the uploaded
                # trees directory; only a link-free rebuilt/ is moved there.
                $output = Join-Path (Join-Path $workRoot "build") $treeName
                & (Join-Path $PSScriptRoot "verify-source-build.ps1") -PackagePath $package.path `
                    -SourceDirectory $sourceDirectory -OutputDirectory $output -Phase Build | Out-Null
                $buildCode = $LASTEXITCODE
                $rebuiltTree = Join-Path $output "rebuilt"
                if (Test-Path -LiteralPath $rebuiltTree -PathType Container) {
                    $links = @(Get-LinkFindings -Directory $rebuiltTree)
                    if ($links.Count -gt 0) {
                        foreach ($link in $links) { $findings.Add($link) }
                        Remove-Item -LiteralPath $rebuiltTree -Recurse -Force
                    }
                    else {
                        $treeTarget = Join-Path $treesRoot $treeName
                        New-Item -ItemType Directory -Path $treeTarget -Force | Out-Null
                        Move-Item -LiteralPath $rebuiltTree -Destination (Join-Path $treeTarget "rebuilt")
                    }
                }
                $global:LASTEXITCODE = $buildCode
            }
            else {
                Initialize-PackageScanner
                $output = Join-Path $work "verify"
                & (Join-Path $PSScriptRoot "verify-source-build.ps1") -PackagePath $package.path `
                    -SourceDirectory $sourceDirectory -OutputDirectory $output -Phase Verify `
                    -RebuiltDirectory (Join-Path (Join-Path $treesRoot $treeName) "rebuilt") -SkipScannerBuild | Out-Null
            }
            $code = $LASTEXITCODE
            $resultPath = Join-Path $output "source-build.json"
            if ($code -notin @(0, 2) -or -not (Test-Path -LiteralPath $resultPath -PathType Leaf)) {
                throw "verify-source-build.ps1 failed with exit code $code"
            }
            $rebuild = Get-Content -Raw -LiteralPath $resultPath | ConvertFrom-Json -Depth 30
            foreach ($finding in @($rebuild.findings)) {
                if ($null -ne $finding) {
                    $findings.Add((New-SecurityFinding -Check ([string]$finding.check) -RuleId ([string]$finding.ruleId) `
                        -Severity ([string]$finding.severity) -File ([string]$finding.file) `
                        -Detail ([string]$finding.detail) -Evidence ([string]$finding.evidence)))
                }
            }
            $checks.rebuild = [string]$rebuild.disposition
        }
        catch {
            $findings.Add((New-SecurityFinding -Check "rebuild" -RuleId "rebuild-error" -Severity fail `
                -Detail $_.Exception.Message))
            foreach ($key in @($checks.Keys)) {
                if ($checks[$key] -eq "skipped") { $checks[$key] = "not run"; break }
            }
        }
        $results.Add([pscustomobject][ordered]@{
            featureId = $target.featureId
            version = $target.version
            channel = $target.channel
            disposition = Get-WorstDisposition -Values @($findings | ForEach-Object { $_.severity })
            checks = [pscustomobject]$checks
            findings = $findings.ToArray()
        })
        Write-Host "   result: $($results[-1].disposition)"
    }
}

$report = New-SecurityReport -Mode pull_request -Results $results.ToArray()
[IO.File]::WriteAllText((Join-Path $workRoot "source-rebuild-$($Phase.ToLowerInvariant())-report.json"),
    ($report | ConvertTo-Json -Depth 20) + "`n", [Text.UTF8Encoding]::new($false))
$markdown = (ConvertTo-SecurityReportMarkdown -Report $report).Replace(
    "## Package security scan", "## Source rebuild ($Phase)")
if ($env:GITHUB_STEP_SUMMARY) { Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY -Value $markdown }
Write-Host "Overall rebuild result: $($report.disposition)"
if ($report.disposition -eq "fail") { exit 2 }
exit 0
