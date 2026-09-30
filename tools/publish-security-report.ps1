# SPDX-License-Identifier: GPL-2.0-or-later
# Publishes the package security scan result to a pull request: one sticky
# comment identified by a hidden marker, plus the security-review-required
# label. The report JSON is untrusted data derived from contributor packages;
# this script re-renders it with protected-main code and never uses Markdown
# from the artifact.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $Repository,
    [Parameter(Mandatory)][string] $PullRequestNumber,
    [string] $ReportPath = "",
    [string] $ScanResult = "",
    [string] $RunUrl = "",
    [switch] $RenderOnly
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot "SecurityScan.psm1") -Force

$labelName = "security-review-required"
if ($Repository -cnotmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') { throw "Invalid repository" }
if ($PullRequestNumber -cnotmatch '^[1-9][0-9]*$') { throw "Invalid pull request number" }

function Read-SecurityReport {
    param([string] $Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    if ((Get-Item -LiteralPath $Path).Length -gt 20971520) { return $null }
    try { $report = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json -Depth 30 }
    catch { return $null }
    if ($report -isnot [Management.Automation.PSCustomObject] -or
        $report.PSObject.Properties["schemaVersion"] -eq $null -or $report.schemaVersion -ne 1 -or
        $report.PSObject.Properties["results"] -eq $null -or
        [string]$report.disposition -notin @("fail", "review", "clear")) {
        return $null
    }
    $results = @($report.results | Where-Object { $null -ne $_ } | Select-Object -First 200)
    $clean = foreach ($result in $results) {
        $findings = @(@($result.findings) | Where-Object { $null -ne $_ } | ForEach-Object {
            $severity = [string]$_.severity
            if ($severity -notin @("fail", "review", "info")) { $severity = "fail" }
            New-SecurityFinding -Check ([string]$_.check) -RuleId ([string]$_.ruleId) -Severity $severity `
                -File ([string]$_.file) -Detail ([string]$_.detail) -Evidence ([string]$_.evidence)
        })
        $checks = [ordered]@{}
        if ($result.PSObject.Properties["checks"] -and $result.checks -is [Management.Automation.PSCustomObject]) {
            foreach ($property in @($result.checks.PSObject.Properties | Select-Object -First 8)) {
                $checks[[string]$property.Name] = [string]$property.Value
            }
        }
        [pscustomobject][ordered]@{
            featureId = [string]$result.featureId
            version = [string]$result.version
            channel = [string]$result.channel
            disposition = Get-WorstDisposition -Values @(@($findings | ForEach-Object { $_.severity }) +
                @(if ([string]$result.disposition -in @("fail", "review")) { [string]$result.disposition }))
            checks = [pscustomobject]$checks
            findings = $findings
        }
    }
    $overall = Get-WorstDisposition -Values @(@($clean | ForEach-Object { $_.disposition }) + [string]$report.disposition)
    return [pscustomobject][ordered]@{
        schemaVersion = 1
        mode = "pull_request"
        disposition = $overall
        results = @($clean)
    }
}

$report = Read-SecurityReport -Path $ReportPath
if ($null -eq $report) {
    $incomplete = New-SecurityFinding -Check "pipeline" -RuleId "scan-incomplete" -Severity fail `
        -Detail "The package security scan did not produce a valid report (scan job result: $ScanResult)"
    $report = [pscustomobject][ordered]@{
        schemaVersion = 1
        mode = "pull_request"
        disposition = "fail"
        results = @([pscustomobject][ordered]@{
            featureId = "(scan incomplete)"; version = ""; channel = ""; disposition = "fail"
            checks = [pscustomobject]@{}; findings = @($incomplete)
        })
    }
}
elseif ($ScanResult -cne "success") {
    # A scan job that did not succeed is a failure even if it left a report.
    $notSuccessful = New-SecurityFinding -Check "pipeline" -RuleId "scan-job-not-successful" -Severity fail `
        -Detail "The package security scan job finished with result '$ScanResult'"
    $report = [pscustomobject][ordered]@{
        schemaVersion = 1
        mode = "pull_request"
        disposition = "fail"
        results = @($report.results) + @([pscustomobject][ordered]@{
            featureId = "(scan job $ScanResult)"; version = ""; channel = ""; disposition = "fail"
            checks = [pscustomobject]@{}; findings = @($notSuccessful)
        })
    }
}
$body = ConvertTo-SecurityReportMarkdown -Report $report -RunUrl $RunUrl
$needsReview = $report.disposition -in @("fail", "review")
if ($RenderOnly) {
    [pscustomobject]@{ body = $body; needsReview = $needsReview; disposition = $report.disposition }
    return
}
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) { throw "GitHub CLI is required" }

$marker = Get-SecurityReportMarker
$comments = @(gh api --paginate "repos/$Repository/issues/$PullRequestNumber/comments?per_page=100" --jq '.[] | {id, login: .user.login, head: (.body[0:64])}' |
    Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json })
if ($LASTEXITCODE -ne 0) { throw "Could not list pull request comments" }
$existing = @($comments | Where-Object {
    $_.login -ceq "github-actions[bot]" -and ([string]$_.head).StartsWith($marker, [StringComparison]::Ordinal)
} | Select-Object -First 1)

$payload = Join-Path ([IO.Path]::GetTempPath()) "zeus-security-comment-$([Guid]::NewGuid().ToString('N')).json"
try {
    [IO.File]::WriteAllText($payload, (@{ body = $body } | ConvertTo-Json -Depth 3), [Text.UTF8Encoding]::new($false))
    if ($existing.Count -eq 1) {
        gh api --method PATCH "repos/$Repository/issues/comments/$($existing[0].id)" --input $payload --silent
        if ($LASTEXITCODE -ne 0) { throw "Could not update the security scan comment" }
    }
    elseif (@($report.results).Count -gt 0) {
        gh api --method POST "repos/$Repository/issues/$PullRequestNumber/comments" --input $payload --silent
        if ($LASTEXITCODE -ne 0) { throw "Could not create the security scan comment" }
    }
}
finally {
    Remove-Item -LiteralPath $payload -Force -ErrorAction SilentlyContinue
}

if ($needsReview) {
    gh api "repos/$Repository/labels/$labelName" --silent 2>$null
    if ($LASTEXITCODE -ne 0) {
        gh api --method POST "repos/$Repository/labels" -f name=$labelName -f color=d93f0b `
            -f description="Package security scan found items a maintainer must review" --silent
        if ($LASTEXITCODE -ne 0) {
            gh api "repos/$Repository/labels/$labelName" --silent 2>$null
            if ($LASTEXITCODE -ne 0) { throw "Could not create the $labelName label" }
        }
    }
    gh api --method POST "repos/$Repository/issues/$PullRequestNumber/labels" -f "labels[]=$labelName" --silent
    if ($LASTEXITCODE -ne 0) { throw "Could not add the $labelName label" }
    Write-Host "Added $labelName ($($report.disposition))."
}
else {
    $current = @(gh api "repos/$Repository/issues/$PullRequestNumber/labels" --jq '.[].name')
    if ($LASTEXITCODE -ne 0) { throw "Could not read pull request labels" }
    if ($current -ccontains $labelName) {
        $actors = @(gh api --paginate "repos/$Repository/issues/$PullRequestNumber/events?per_page=100" `
            --jq ".[] | select(.event == `"labeled`" and .label.name == `"$labelName`") | .actor.login")
        if ($LASTEXITCODE -ne 0) { throw "Could not read pull request label events" }
        if (Test-BotOwnsLabel -LabeledEventActors $actors) {
            gh api --method DELETE "repos/$Repository/issues/$PullRequestNumber/labels/$labelName" --silent
            if ($LASTEXITCODE -ne 0) { throw "Could not remove the $labelName label" }
            Write-Host "Removed $labelName."
        }
        else {
            Write-Host "Kept $labelName because a maintainer applied it most recently."
        }
    }
}
if ($report.disposition -eq "fail") {
    # This job is a required check: a failed or incomplete scan blocks merge.
    Write-Error "Package security scan failed or did not complete; see the pull request comment" -ErrorAction Continue
    exit 1
}
