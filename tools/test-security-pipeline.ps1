# SPDX-License-Identifier: GPL-2.0-or-later
# Network-free regression tests for the package security scan pipeline:
# target selection, dispositions, OSV mapping, lockfile discovery, and the
# sanitised pull request report.
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot "SecurityScan.psm1") -Force

$tempRoot = Join-Path ([IO.Path]::GetTempPath()) "zeus-security-pipeline-test-$([Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $tempRoot | Out-Null

function Assert-Equal {
    param($Actual, $Expected, [string] $Label)
    if ([string]$Actual -cne [string]$Expected) { throw "${Label}: expected '$Expected', got '$Actual'" }
}

try {
    # Dispositions: the worst severity wins and info never blocks.
    Assert-Equal (Get-WorstDisposition -Values @()) "clear" "empty disposition"
    Assert-Equal (Get-WorstDisposition -Values @("info", "clear")) "clear" "info disposition"
    Assert-Equal (Get-WorstDisposition -Values @("info", "review")) "review" "review disposition"
    Assert-Equal (Get-WorstDisposition -Values @("review", "fail", "clear")) "fail" "fail disposition"
    $rejected = $false
    try { Get-WorstDisposition -Values @("bogus") | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw "Unknown dispositions must not be ignored" }

    # Target selection: only new or changed community versions in PR mode.
    $registry = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot "../registry.json") | ConvertFrom-Json -Depth 100
    $unchanged = @(Get-SecurityScanTargets -CandidateRegistry $registry -BaseRegistry $registry)
    Assert-Equal $unchanged.Count 0 "unchanged registry targets"
    $allCount = @($registry.plugins | ForEach-Object { @($_.versions) }).Count
    Assert-Equal @(Get-SecurityScanTargets -CandidateRegistry $registry -All).Count $allCount "backfill targets"

    $candidate = ($registry | ConvertTo-Json -Depth 100 | ConvertFrom-Json -Depth 100)
    $community = @($candidate.plugins | Where-Object channel -ceq "community")[0]
    $release = ($community.versions[0] | ConvertTo-Json -Depth 20 | ConvertFrom-Json -Depth 20)
    $release.version = "99.0.0"
    $release | Add-Member -NotePropertyName source -NotePropertyValue ([pscustomobject][ordered]@{
        repository = "https://github.com/example/feature"
        commit = ("ab" * 20)
        package = "https://github.com/example/feature/releases/download/v99.0.0/feature.zip"
    })
    $community.versions = @($release) + @($community.versions)
    $official = @($candidate.plugins | Where-Object channel -ceq "official")[0]
    $official.versions[0].sha256 = ("0" * 64)
    $targets = @(Get-SecurityScanTargets -CandidateRegistry $candidate -BaseRegistry $registry)
    Assert-Equal $targets.Count 1 "changed community targets"
    Assert-Equal "$($targets[0].featureId)@$($targets[0].version)" "$($community.id)@99.0.0" "changed target identity"
    Assert-Equal $targets[0].source.commit ("ab" * 20) "target source"

    # A changed hash on an existing community version is re-scanned.
    $rehash = ($registry | ConvertTo-Json -Depth 100 | ConvertFrom-Json -Depth 100)
    @($rehash.plugins | Where-Object channel -ceq "community")[0].versions[0].sha256 = ("1" * 64)
    Assert-Equal @(Get-SecurityScanTargets -CandidateRegistry $rehash -BaseRegistry $registry).Count 1 "rehash targets"

    # OSV: MAL advisories fail, other advisories need review.
    $osv = @'
{"results":[{"source":{"path":"/src/web/package-lock.json","type":"lockfile"},"packages":[
 {"package":{"name":"evil","version":"1.0.0","ecosystem":"npm"},"vulnerabilities":[{"id":"MAL-2025-1"}],"groups":[{"ids":["MAL-2025-1"]}]},
 {"package":{"name":"old","version":"2.0.0","ecosystem":"npm"},"vulnerabilities":[{"id":"GHSA-xxxx","aliases":["CVE-2024-1"]}],"groups":[{"ids":["GHSA-xxxx"],"aliases":["CVE-2024-1"]}]}
]}]}
'@ | ConvertFrom-Json -Depth 20
    $osvFindings = @(ConvertFrom-OsvResult -Result $osv -SourceRoot "/src")
    Assert-Equal $osvFindings.Count 2 "OSV finding count"
    Assert-Equal "$($osvFindings[0].severity):$($osvFindings[0].ruleId):$($osvFindings[0].file)" `
        "fail:osv-malicious-package:web/package-lock.json" "malicious package finding"
    Assert-Equal "$($osvFindings[1].severity):$($osvFindings[1].ruleId)" "review:osv-vulnerable-dependency" "vulnerable dependency finding"
    Assert-Equal $osvFindings[1].evidence "CVE-2024-1, GHSA-xxxx" "OSV evidence"

    # Lockfile discovery skips build output, node_modules, and links.
    $source = Join-Path $tempRoot "source"
    foreach ($directory in @("src", "web", "web/node_modules/dep", "src/obj", "linked")) {
        New-Item -ItemType Directory -Path (Join-Path $source $directory) -Force | Out-Null
    }
    Set-Content -LiteralPath (Join-Path $source "web/package-lock.json") -Value "{}"
    Set-Content -LiteralPath (Join-Path $source "web/node_modules/dep/package-lock.json") -Value "{}"
    Set-Content -LiteralPath (Join-Path $source "src/obj/packages.lock.json") -Value "{}"
    Set-Content -LiteralPath (Join-Path $source "Directory.Packages.props") -Value @'
<Project><ItemGroup><PackageVersion Include="Central.Package" Version="3.1.0" /></ItemGroup></Project>
'@
    Set-Content -LiteralPath (Join-Path $source "src/Feature.csproj") -Value @'
<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>
  <PackageReference Include="Exact.Package" Version="1.2.3" />
  <PackageReference Include="Pinned.Package" Version="[4.5.6]" />
  <PackageReference Include="Central.Package" />
  <PackageReference Include="Floating.Package" Version="1.*" />
  <PackageReference Include="Property.Package" Version="$(SomeVersion)" />
</ItemGroup></Project>
'@
    Set-Content -LiteralPath (Join-Path $source "src/Dtd.csproj") -Value @'
<?xml version="1.0"?><!DOCTYPE p [<!ENTITY a "aaaa">]><Project><ItemGroup><PackageReference Include="X" Version="&a;" /></ItemGroup></Project>
'@
    New-Item -ItemType SymbolicLink -Path (Join-Path $source "linked/package-lock.json") `
        -Target (Join-Path $source "web/package-lock.json") | Out-Null
    $lockfiles = @(Get-DependencyLockfiles -SourceDirectory $source)
    Assert-Equal (($lockfiles | ForEach-Object { "$($_.kind):$($_.path)" }) -join ",") `
        "nuget-central:Directory.Packages.props,csproj:src/Dtd.csproj,csproj:src/Feature.csproj,npm-lock:web/package-lock.json" `
        "discovered lockfiles"

    $synthesized = New-SynthesizedNuGetLocks -SourceDirectory $source -Lockfiles $lockfiles `
        -OutputDirectory (Join-Path $tempRoot "synth")
    Assert-Equal @($synthesized.paths).Count 1 "synthesized lock count"
    $lock = Get-Content -Raw -LiteralPath $synthesized.paths[0] | ConvertFrom-Json -Depth 10
    $resolved = @($lock.dependencies.'net10.0'.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value.resolved)" }) -join ","
    Assert-Equal $resolved "Exact.Package=1.2.3,Pinned.Package=4.5.6,Central.Package=3.1.0" "synthesized dependencies"
    $synthRules = @($synthesized.findings | ForEach-Object { "$($_.severity):$($_.ruleId):$($_.file)" } | Sort-Object)
    Assert-Equal ($synthRules -join ",") (@(
        "info:osv-transitive-unchecked:src/Feature.csproj",
        "review:osv-unpinned-dependency:src/Feature.csproj",
        "review:osv-unpinned-dependency:src/Feature.csproj",
        "review:osv-unreadable-manifest:src/Dtd.csproj"
    ) -join ",") "synthesized findings"
    if (-not $synthesized.pathMap.ContainsKey([IO.Path]::GetFullPath($synthesized.paths[0]))) {
        throw "Synthesized lockfile is not mapped back to its project"
    }

    # Untrusted report text renders inert: code spans only, no raw mention,
    # link, HTML, or table break; the marker leads the comment.
    $hostile = 'x` @maintainer [click](https://evil.example) <img src=x> | #1' + "`n## injected"
    $finding = New-SecurityFinding -Check "scanner" -RuleId "network-api" -Severity review `
        -File "ui/a|b.js" -Detail $hostile -Evidence ('A' * 5000)
    $report = New-SecurityReport -Mode pull_request -Results @([pscustomobject][ordered]@{
        featureId = "com.example.hostile"; version = "1.0.0"; channel = "community"
        disposition = "review"; checks = [pscustomobject]@{ scanner = "review" }; findings = @($finding)
    })
    Assert-Equal $report.disposition "review" "report disposition"
    $markdown = ConvertTo-SecurityReportMarkdown -Report $report
    if (-not $markdown.StartsWith((Get-SecurityReportMarker), [StringComparison]::Ordinal)) {
        throw "Report does not start with the sticky-comment marker"
    }
    $detailLine = @($markdown -split "`n" | Where-Object { $_ -like "*@maintainer*" })
    Assert-Equal $detailLine.Count 1 "hostile detail line count"
    $outsideCode = [regex]::Replace($detailLine[0], '`[^`]*`', '')
    if ($outsideCode -match '@|\[|<|https?:') { throw "Untrusted text escaped its code span: $outsideCode" }
    if ($markdown -match "(?m)^## injected") { throw "Untrusted newline created a heading" }
    if ($detailLine[0] -notmatch [regex]::Escape('ui/a\|b.js')) { throw "Pipe in a file name was not escaped" }
    if ($markdown.Contains('A' * 200)) { throw "Evidence length was not capped" }
    Assert-Equal (ConvertTo-SafeMarkdownCode "") "" "empty code span"

    $long = ConvertTo-SecurityReportMarkdown -Report (New-SecurityReport -Mode pull_request -Results @(
        1..300 | ForEach-Object {
            [pscustomobject][ordered]@{
                featureId = "com.example.f$_"; version = "1.0.0"; channel = "community"; disposition = "fail"
                checks = [pscustomobject]@{}
                findings = @(1..60 | ForEach-Object { New-SecurityFinding -Check scanner -RuleId r -Severity fail -Detail ('d' * 250) })
            }
        })) -MaxLength 60000
    if ($long.Length -gt 60000) { throw "Report exceeded the comment length cap: $($long.Length)" }

    # The PR publisher re-renders report JSON and fails closed on bad data.
    $publisher = Join-Path $PSScriptRoot "publish-security-report.ps1"
    $missing = & $publisher -Repository "Zeus-SDR/zeus-community-features" -PullRequestNumber 1 `
        -ReportPath (Join-Path $tempRoot "missing.json") -ScanResult failure -RenderOnly
    if (-not $missing.needsReview -or $missing.body -notmatch "scan-incomplete") {
        throw "A missing report did not request security review"
    }
    $reportPath = Join-Path $tempRoot "report.json"
    [IO.File]::WriteAllText($reportPath, ($report | ConvertTo-Json -Depth 20))
    $rendered = & $publisher -Repository "Zeus-SDR/zeus-community-features" -PullRequestNumber 1 `
        -ReportPath $reportPath -ScanResult success -RenderOnly
    if (-not $rendered.needsReview -or $rendered.body -notmatch "network-api") {
        throw "A review report did not request security review"
    }
    $downgraded = ($report | ConvertTo-Json -Depth 20 | ConvertFrom-Json -Depth 20)
    $downgraded.disposition = "clear"
    $downgraded.results[0].disposition = "clear"
    [IO.File]::WriteAllText($reportPath, ($downgraded | ConvertTo-Json -Depth 20))
    $recomputed = & $publisher -Repository "Zeus-SDR/zeus-community-features" -PullRequestNumber 1 `
        -ReportPath $reportPath -ScanResult success -RenderOnly
    if (-not $recomputed.needsReview) { throw "Publisher trusted a disposition that its findings contradict" }
    $clear = New-SecurityReport -Mode pull_request -Results @()
    [IO.File]::WriteAllText($reportPath, ($clear | ConvertTo-Json -Depth 20))
    $clearRendered = & $publisher -Repository "Zeus-SDR/zeus-community-features" -PullRequestNumber 1 `
        -ReportPath $reportPath -ScanResult success -RenderOnly
    if ($clearRendered.needsReview) { throw "A clear report requested security review" }
    foreach ($scanResult in @("failure", "cancelled", "skipped", "")) {
        $notSuccess = & $publisher -Repository "Zeus-SDR/zeus-community-features" -PullRequestNumber 1 `
            -ReportPath $reportPath -ScanResult $scanResult -RenderOnly
        if (-not $notSuccess.needsReview -or $notSuccess.disposition -ne "fail" -or
            $notSuccess.body -notmatch "scan-job-not-successful") {
            throw "A clear report from a '$scanResult' scan job was not treated as a failure"
        }
    }

    # The review label is removed automatically only when the bot applied it last.
    if (Test-BotOwnsLabel -LabeledEventActors @()) { throw "An unlabeled history was treated as bot-owned" }
    if (-not (Test-BotOwnsLabel -LabeledEventActors @("github-actions[bot]"))) { throw "A bot-applied label was not removable" }
    if (Test-BotOwnsLabel -LabeledEventActors @("github-actions[bot]", "Kb2uka")) { throw "A maintainer-applied label was removable" }
    if (-not (Test-BotOwnsLabel -LabeledEventActors @("iamexemplar", "github-actions[bot]"))) { throw "The most recent bot label was not removable" }
    if (Test-BotOwnsLabel -LabeledEventActors @("github-actions")) { throw "A look-alike actor was treated as the bot" }
    [IO.File]::WriteAllText($reportPath, '{"schemaVersion":1,"disposition":"maybe","results":[]}')
    $invalid = & $publisher -Repository "Zeus-SDR/zeus-community-features" -PullRequestNumber 1 `
        -ReportPath $reportPath -ScanResult success -RenderOnly
    if (-not $invalid.needsReview) { throw "An invalid report did not request security review" }
    foreach ($badArguments in @(
        @{ Repository = "evil/repo; rm"; PullRequestNumber = "1" },
        @{ Repository = "Zeus-SDR/zeus-community-features"; PullRequestNumber = "1 --method DELETE" }
    )) {
        $rejected = $false
        try { & $publisher @badArguments -RenderOnly | Out-Null } catch { $rejected = $true }
        if (-not $rejected) { throw "Publisher accepted invalid arguments" }
    }

    # A pull request that changes no community version (a maintainer tooling
    # change) must pass even though ClamAV and osv-scanner were never set up.
    $registryPath = Join-Path (Split-Path -Parent $PSScriptRoot) "registry.json"
    $noTargetOutput = Join-Path $tempRoot "no-target-scan"
    & (Join-Path $PSScriptRoot "invoke-security-scan.ps1") `
        -Mode pull_request `
        -RegistryPath $registryPath `
        -BaseRegistryPath $registryPath `
        -OutputDirectory $noTargetOutput `
        -ClamAv Required `
        -OsvScannerPath (Join-Path $tempRoot "missing-osv-scanner") `
        -SkipScannerBuild | Out-Null
    Assert-Equal $LASTEXITCODE 0 "no-target scan exit code"
    $noTargetReport = Get-Content -Raw -LiteralPath (Join-Path $noTargetOutput "security-report.json") |
        ConvertFrom-Json -Depth 50
    Assert-Equal $noTargetReport.disposition "clear" "no-target scan disposition"

    # Two community versions in one pull request fail before any download,
    # scan, or scan-tool requirement. A dead proxy makes any download attempt
    # show up as a finding instead of reaching the network.
    $twoVersions = ($registry | ConvertTo-Json -Depth 100 | ConvertFrom-Json -Depth 100)
    $twoPlugin = @($twoVersions.plugins | Where-Object channel -ceq "community")[0]
    $added = foreach ($newVersion in @("98.0.0", "99.0.0")) {
        $release = ($twoPlugin.versions[0] | ConvertTo-Json -Depth 20 | ConvertFrom-Json -Depth 20)
        $release.version = $newVersion
        $release | Add-Member -NotePropertyName source -NotePropertyValue ([pscustomobject][ordered]@{
            repository = "https://github.com/example/feature"; commit = ("cd" * 20)
            package = "https://github.com/example/feature/releases/download/v$newVersion/feature.zip"
        })
        $release
    }
    $twoPlugin.versions = @($added) + @($twoPlugin.versions)
    $twoPath = Join-Path $tempRoot "two-versions.json"
    [IO.File]::WriteAllText($twoPath, ($twoVersions | ConvertTo-Json -Depth 100))
    $twoOutput = Join-Path $tempRoot "two-version-scan"
    $savedProxy = $env:HTTPS_PROXY
    $env:HTTPS_PROXY = "http://127.0.0.1:9"
    try {
        & (Join-Path $PSScriptRoot "invoke-security-scan.ps1") -Mode pull_request -RegistryPath $twoPath `
            -BaseRegistryPath $registryPath -OutputDirectory $twoOutput -ClamAv Required `
            -OsvScannerPath (Join-Path $tempRoot "missing-osv-scanner") -SkipScannerBuild | Out-Null
        $twoCode = $LASTEXITCODE
    }
    finally { $env:HTTPS_PROXY = $savedProxy }
    Assert-Equal $twoCode 2 "two-version scan exit code"
    $twoReport = Get-Content -Raw -LiteralPath (Join-Path $twoOutput "security-report.json") | ConvertFrom-Json -Depth 50
    Assert-Equal (@($twoReport.results | ForEach-Object { @($_.findings) } | ForEach-Object { $_.ruleId }) -join ",") `
        "one-version-per-pull-request" "two-version scan findings"
}
finally {
    $resolved = [IO.Path]::GetFullPath($tempRoot)
    $systemTemp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if ($resolved.StartsWith($systemTemp, [StringComparison]::OrdinalIgnoreCase) -and
        (Test-Path -LiteralPath $resolved)) {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}

Write-Host "Package security pipeline regression tests passed."
