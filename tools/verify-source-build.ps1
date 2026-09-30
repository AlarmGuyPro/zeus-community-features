# SPDX-License-Identifier: GPL-2.0-or-later
# Rebuilds a community feature from its pinned source checkout and compares
# the result with the submitted ZIP. Contributor code (MSBuild, npm scripts)
# runs ONLY inside a bubblewrap sandbox with no network, its own PID
# namespace, no capabilities, and a read-only view of the host filesystem.
# Run it only in an unprivileged, secret-free job (pull_request, never
# pull_request_target).
#
# Contract (schema/zeus-build.schema.json): zeus-build.json and global.json
# at the source root, plus packages.lock.json beside every project that
# restores NuGet packages.
#   1. Validate zeus-build.json (relative, contained, link-free paths) and
#      global.json (one exact SDK, rollForward "disable").
#   2. Delete every mapped build output (and .zeus-build/) so a committed
#      prebuilt file cannot satisfy the build. A tracked file is kept only if
#      its ZIP path and source path look like text or images and its header
#      is not an executable or archive.
#   3. Fail on tracked executables and archives, detected by header or
#      extension.
#   4. Trusted code downloads each package in packages.lock.json from
#      nuget.org, verifies its SHA-512 contentHash, and builds a local feed.
#      Packages that ship analyzers, source generators, or MSBuild targets
#      fail unless a maintainer allowlisted them. npm ci --ignore-scripts runs
#      outside the sandbox (npm itself runs no contributor code) with every
#      contributor .npmrc removed, empty user/global config, and the public
#      registry; every package-lock.json entry must resolve from
#      registry.npmjs.org with an integrity hash.
#   5. Prove the sandbox is isolated, then inside it: dotnet restore
#      --locked-mode from the local feed only, npm run <script>, and dotnet
#      build --no-restore into .zeus-build/out.
#   6. Stage the rebuilt tree from the ZIP's own file list and run the
#      package scanner's strict compare. The rebuild check has no review
#      tier: anything short of a clear match fails.
#
# -Phase Build runs steps 1, 2, 4, 5 and stages OutputDirectory/rebuilt.
# -Phase Verify runs steps 1, 3, 4 (trusted feed checks only) and 6 against
# -RebuiltDirectory without running contributor code, so CI computes the
# verdict in a separate clean job. -Phase All (default) does everything.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $PackagePath,
    [Parameter(Mandatory)][string] $SourceDirectory,
    [Parameter(Mandatory)][string] $OutputDirectory,
    [ValidateSet("All", "Build", "Verify")][string] $Phase = "All",
    [string] $RebuiltDirectory = "",
    [string] $AllowlistPath = (Join-Path $PSScriptRoot "rebuild-package-allowlist.json"),
    [string[]] $HostWriteProbe = @(),
    [switch] $ValidateOnly,
    [switch] $SkipScannerBuild
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$ProgressPreference = "SilentlyContinue"
Import-Module (Join-Path $PSScriptRoot "SecurityScan.psm1") -Force
Import-Module (Join-Path $PSScriptRoot "SourceRebuild.psm1") -Force

function Get-PackageFileList {
    param([Parameter(Mandatory)][string] $Path)
    $archive = [IO.Compression.ZipFile]::OpenRead($Path)
    try {
        $files = @($archive.Entries | Where-Object { -not [string]::IsNullOrEmpty($_.Name) } |
            ForEach-Object { $_.FullName })
        $manifestEntry = $archive.GetEntry("plugin.json")
        if ($null -eq $manifestEntry) { throw "Package has no top-level plugin.json" }
        $reader = [IO.StreamReader]::new($manifestEntry.Open())
        try { $manifest = $reader.ReadToEnd() | ConvertFrom-Json -Depth 50 }
        finally { $reader.Dispose() }
        return [pscustomobject]@{
            files = $files
            id = [string]$manifest.id
            version = [string]$manifest.version
            entrypoint = [string]$manifest.entrypoint.assembly
        }
    }
    finally { $archive.Dispose() }
}

function Add-Findings {
    param([Collections.Generic.List[object]] $List, [AllowNull()][AllowEmptyCollection()][object[]] $Items)
    foreach ($item in @($Items)) { if ($null -ne $item) { $List.Add($item) } }
}

function Test-HasFailure {
    param([Collections.Generic.List[object]] $List)
    return @($List | Where-Object severity -eq "fail").Count -gt 0
}

$findings = [Collections.Generic.List[object]]::new()
$packageFull = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $PackagePath))
$rootItem = Get-Item -LiteralPath ([IO.Path]::GetFullPath($SourceDirectory)) -Force
if ($rootItem -isnot [IO.DirectoryInfo] -or (Test-IsLinkedItem $rootItem)) {
    throw "SourceDirectory must be a real directory"
}
$root = $rootItem.FullName.TrimEnd([IO.Path]::DirectorySeparatorChar)
$outputRoot = [IO.Path]::GetFullPath($OutputDirectory).TrimEnd([IO.Path]::DirectorySeparatorChar)
$separator = [IO.Path]::DirectorySeparatorChar
if ($outputRoot.StartsWith($root + $separator, [StringComparison]::Ordinal) -or $outputRoot -ceq $root -or
    $root.StartsWith($outputRoot + $separator, [StringComparison]::Ordinal)) {
    throw "OutputDirectory and SourceDirectory must not contain each other"
}

$package = Get-PackageFileList -Path $packageFull
# Archive safety (paths, links, sizes) before any ZIP path is used on disk.
Invoke-PackageValidator -Arguments @{
    PackagePath = $packageFull; ExpectedId = $package.id; ExpectedVersion = $package.version
}
$contract = Read-BuildContract -Root $root
$depsName = [IO.Path]::GetFileNameWithoutExtension($package.entrypoint) + ".deps.json"
$fromBuild = [Collections.Generic.List[string]]::new()
foreach ($file in $package.files) {
    if ((Test-IsBuildOutputName $file) -or $file -ieq $depsName) {
        if ($contract.package.ContainsKey($file)) { throw "package must not map build output $file" }
        $fromBuild.Add($file)
    }
    elseif (-not $contract.package.ContainsKey($file)) {
        $findings.Add((New-SecurityFinding -Check "rebuild" -RuleId "rebuild-unmapped-file" -Severity fail `
            -File $file -Detail "ZIP file is neither a DLL, a .deps.json, nor mapped in zeus-build.json"))
    }
}
foreach ($key in $contract.package.Keys) {
    if ($package.files -cnotcontains $key) {
        $findings.Add((New-SecurityFinding -Check "rebuild" -RuleId "rebuild-mapping-not-in-package" -Severity fail `
            -File $key -Detail "zeus-build.json maps a file that the ZIP does not contain"))
    }
}
if ($ValidateOnly) {
    [pscustomobject]@{
        valid = -not (Test-HasFailure $findings)
        findings = $findings.ToArray()
        fromBuild = $fromBuild.ToArray()
        mappings = $contract.package
        sdkVersion = $contract.sdkVersion
    }
    return
}

New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null
$staged = Join-Path $outputRoot "rebuilt"
$tracked = @(& git -C $root ls-files -z | ForEach-Object { $_ -split "`0" } | Where-Object { $_ })
if ($LASTEXITCODE -ne 0) { throw "SourceDirectory must be a Git checkout" }
$trackedSet = [Collections.Generic.HashSet[string]]::new([string[]]$tracked, [StringComparer]::Ordinal)
$allowlist = Read-RebuildPackageAllowlist -Path $AllowlistPath

# Trusted dependency preparation shared by both phases: lock files are read as
# data, packages come only from nuget.org with verified SHA-512 hashes.
$lockedPackages = @()
$feed = Join-Path $outputRoot "nuget-feed"
$nodeDirectories = @($contract.node | ForEach-Object { $_.directory })
Add-Findings $findings (Get-MsBuildLintFindings -Root $root -NodeDirectories $nodeDirectories `
    -TrackedFiles $tracked -MappedOutputs @($contract.package.Values))
Add-Findings $findings (Get-NodeProjectOverlapFindings -Root $root -NodeDirectories $nodeDirectories)
$projectDirectories = @(Get-ProjectDirectories -Root $root)
Add-Findings $findings (Get-UnlockedProjectFindings -Root $root)
foreach ($step in $contract.node) {
    Add-Findings $findings (Get-NpmShrinkwrapFindings -Root $root -Directory $step.directory)
    try { Add-Findings $findings (Get-NpmLockFindings -Root $root -Directory $step.directory) }
    catch {
        $findings.Add((New-SecurityFinding -Check "rebuild" -RuleId "rebuild-npm-registry" -Severity fail `
            -Detail $_.Exception.Message))
    }
}
try {
    $lockedPackages = @(Get-NuGetLockPackages -Root $root)
    [void](New-VerifiedNuGetFeed -Packages $lockedPackages -FeedDirectory $feed)
    Add-Findings $findings (Get-FeedBuildTimePackageFindings -Packages $lockedPackages -FeedDirectory $feed -Allowlist $allowlist)
}
catch {
    $findings.Add((New-SecurityFinding -Check "rebuild" -RuleId "rebuild-dependency-verification" -Severity fail `
        -Detail $_.Exception.Message))
}

if ($Phase -in @("All", "Build")) {
    if (-not $IsLinux) { throw "The offline rebuild requires Linux" }
    if (Test-Path -LiteralPath $staged) { throw "OutputDirectory already contains a rebuilt tree" }
    # Snapshot .git before any contributor code runs: the live .git is
    # writable from the sandbox, so the trusted status check reads this copy.
    $gitSnapshot = Join-Path $outputRoot "git-snapshot"
    if (Test-Path -LiteralPath $gitSnapshot) { Remove-Item -LiteralPath $gitSnapshot -Recurse -Force }
    Copy-Item -LiteralPath (Join-Path $root ".git") -Destination $gitSnapshot -Recurse
    $buildDirectory = Join-Path $root (Get-BuildDirectoryName)
    if (Test-Path -LiteralPath $buildDirectory) { Remove-Item -LiteralPath $buildDirectory -Recurse -Force }
    foreach ($entry in $contract.package.GetEnumerator()) {
        $full = Join-Path $root $entry.Value
        $item = Get-Item -LiteralPath $full -Force -ErrorAction SilentlyContinue
        if ($null -eq $item) { continue }
        if ($item -is [IO.DirectoryInfo] -and -not (Test-IsLinkedItem $item)) {
            throw "package[$($entry.Key)] maps a directory, not a file: $($entry.Value)"
        }
        if (Test-KeepCommittedFile -Root $root -ZipPath $entry.Key -SourcePath $entry.Value -Tracked $trackedSet) {
            continue
        }
        Remove-Item -LiteralPath $full -Force
    }

    $dotnet = (Get-Command dotnet -CommandType Application | Select-Object -First 1).Source
    Push-Location $root
    try { $installedSdk = (& $dotnet --version 2>$null | Select-Object -First 1) }
    finally { Pop-Location }
    if ($LASTEXITCODE -ne 0 -or [string]$installedSdk -cne $contract.sdkVersion) {
        $findings.Add((New-SecurityFinding -Check "rebuild" -RuleId "rebuild-sdk-mismatch" -Severity fail `
            -Detail "global.json pins SDK $($contract.sdkVersion) but the build host resolved '$installedSdk'"))
    }

    $privateRoot = Join-Path $outputRoot "sandbox-private"
    $buildFailed = Test-HasFailure $findings
    if (-not $buildFailed) {
        try {
            if ($contract.node.Count -gt 0) {
                $npm = (Get-Command npm -CommandType Application | Select-Object -First 1).Source
                $emptyUserConfig = Join-Path $outputRoot "empty-user.npmrc"
                $emptyGlobalConfig = Join-Path $outputRoot "empty-global.npmrc"
                [IO.File]::WriteAllText($emptyUserConfig, "")
                [IO.File]::WriteAllText($emptyGlobalConfig, "")
                $npmArguments = Get-NpmCiArguments -EmptyUserConfigPath $emptyUserConfig -EmptyGlobalConfigPath $emptyGlobalConfig
                foreach ($step in $contract.node) {
                    $removed = @(Remove-ContributorNpmConfig -Root $root -Directory $step.directory)
                    if ($removed.Count -gt 0) { Write-Host "Ignored contributor npm configuration: $($removed -join ', ')" }
                    Write-Host "-- npm $($npmArguments -join ' ') ($($step.directory))"
                    Push-Location $step.directory
                    try { & $npm @npmArguments | Out-Host }
                    finally { Pop-Location }
                    if ($LASTEXITCODE -ne 0) { throw "npm ci failed in $($step.directory) with exit code $LASTEXITCODE" }
                }
            }

            $probes = @($outputRoot, (Split-Path -Parent $root), $PSScriptRoot, [Environment]::GetFolderPath("UserProfile"),
                $env:GITHUB_WORKSPACE, $env:RUNNER_TEMP, $env:RUNNER_WORKSPACE, $env:RUNNER_TOOL_CACHE) + $HostWriteProbe
            Assert-SandboxIsolation -SourceRoot $root -PrivateRoot $privateRoot -HostWriteProbes @($probes | Where-Object { $_ })

            foreach ($step in $contract.node) {
                Write-Host "-- sandboxed npm run $($step.script) ($($step.directory))"
                $code = Invoke-Sandboxed -SourceRoot $root -PrivateRoot $privateRoot -WorkingDirectory $step.directory `
                    -Command @((Get-Command npm -CommandType Application | Select-Object -First 1).Source, "run", $step.script, "--ignore-scripts")
                if ($code -ne 0) { throw "Sandboxed npm run $($step.script) failed with exit code $code" }
            }
            # Trusted check: nothing uncommitted may sit in a project directory
            # when MSBuild's default item globs run.
            Add-Findings $findings (Get-UntrackedSourceFindings -Root $root -GitDirectory $gitSnapshot -ProjectDirectories $projectDirectories)
            if (Test-HasFailure $findings) { throw "Uncommitted files are inside a project directory" }

            $config = New-TrustedNuGetConfig -Path (Join-Path $outputRoot "nuget.config") -FeedDirectory $feed
            $globals = @(Get-TrustedMSBuildGlobals -SdkDirectory (Join-Path (Join-Path (Get-DotnetRoot) "sdk") $contract.sdkVersion))
            $restore = @($dotnet, "restore", $contract.project, "--source", $feed, "--configfile", $config,
                "-p:Configuration=$($contract.configuration)", "-p:ContinuousIntegrationBuild=true",
                "--nologo", "--disable-build-servers") + $globals
            if ($lockedPackages.Count -gt 0) { $restore += "--locked-mode" }
            Write-Host "-- sandboxed dotnet restore (verified local feed only)"
            $code = Invoke-Sandboxed -SourceRoot $root -PrivateRoot $privateRoot -WorkingDirectory $root -Command $restore `
                -ReadOnlyPaths @($feed, $config)
            if ($code -ne 0) { throw "Sandboxed dotnet restore failed with exit code $code" }
            Add-Findings $findings (Get-AssetsFilePackageFindings -Root $root -ProjectPath $contract.project `
                -Packages $lockedPackages -Allowlist $allowlist `
                -PackagesFolder (Join-Path $privateRoot "nuget-packages") -SdkRoot (Get-DotnetRoot))
            if (Test-HasFailure $findings) { throw "Restore used packages that are not allowed" }
            Add-Findings $findings (Get-UntrackedSourceFindings -Root $root -GitDirectory $gitSnapshot -ProjectDirectories $projectDirectories)
            if (Test-HasFailure $findings) { throw "Restore left uncommitted files inside a project directory" }

            Write-Host "-- sandboxed dotnet build"
            $build = @($dotnet, "build", $contract.project, "--no-restore", "-c", $contract.configuration,
                "-o", (Join-Path $buildDirectory "out"), "-p:ContinuousIntegrationBuild=true",
                "--nologo", "-nodeReuse:false", "--disable-build-servers") + $globals
            $code = Invoke-Sandboxed -SourceRoot $root -PrivateRoot $privateRoot -WorkingDirectory $root -Command $build
            if ($code -ne 0) { throw "Sandboxed dotnet build failed with exit code $code" }
        }
        catch {
            $buildFailed = $true
            $findings.Add((New-SecurityFinding -Check "rebuild" -RuleId "rebuild-build-failed" -Severity fail `
                -Detail $_.Exception.Message))
        }
    }

    # The sandbox's PID namespace has ended, so nothing it started can still
    # be changing the tree while it is staged.
    if (-not $buildFailed) {
        New-Item -ItemType Directory -Path $staged | Out-Null
        foreach ($file in $package.files) {
            $relative = if ($contract.package.ContainsKey($file)) { $contract.package[$file] }
                else { "$(Get-BuildDirectoryName)/out/$file" }
            $full = [IO.Path]::GetFullPath((Join-Path $root $relative))
            try {
                Assert-NoLinkedComponents -Root $root -FullPath $full -Label "rebuilt $file"
                if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { throw "not produced by the build" }
                $destination = Join-Path $staged $file
                New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
                Copy-Item -LiteralPath $full -Destination $destination
            }
            catch {
                $findings.Add((New-SecurityFinding -Check "rebuild" -RuleId "rebuild-missing-file" -Severity fail `
                    -File $file -Detail "Expected at $relative after the build: $($_.Exception.Message)"))
            }
        }
        # The rebuilt tree is uploaded; it must not contain any link.
        $links = @(Get-LinkFindings -Directory $staged)
        if ($links.Count -gt 0) {
            Add-Findings $findings $links
            Remove-Item -LiteralPath $staged -Recurse -Force
        }
    }
}

if ($Phase -in @("All", "Verify")) {
    # Everything below is recomputed from the pinned source, the verified
    # package, and the verified feed, so a build that tampered with its own
    # job cannot hide findings.
    Add-Findings $findings (Get-TrackedBinaryFindings -Root $root -Tracked $tracked)
    foreach ($entry in $contract.package.GetEnumerator()) {
        if (Test-KeepCommittedFile -Root $root -ZipPath $entry.Key -SourcePath $entry.Value -Tracked $trackedSet) {
            $findings.Add((New-SecurityFinding -Check "rebuild" -RuleId "rebuild-committed-source-file" -Severity info `
                -File $entry.Key -Detail "Packaged from committed source file $($entry.Value)"))
        }
    }
    $rebuilt = if ($RebuiltDirectory) { [IO.Path]::GetFullPath($RebuiltDirectory) } else { $staged }
    if (-not (Test-Path -LiteralPath $rebuilt -PathType Container)) {
        $findings.Add((New-SecurityFinding -Check "compare" -RuleId "rebuild-output-missing" -Severity fail `
            -Detail "No rebuilt tree was produced"))
    }
    else {
        try {
            if (-not $SkipScannerBuild) { Initialize-PackageScanner }
            $compare = Invoke-PackageScanner -Mode compare -PackagePath $packageFull -IlStrict `
                -RebuiltDirectory $rebuilt -JsonPath (Join-Path $outputRoot "compare.json")
            Add-Findings $findings (ConvertFrom-ScannerFindings -Result $compare -Check "compare")
        }
        catch {
            $findings.Add((New-SecurityFinding -Check "compare" -RuleId "compare-error" -Severity fail `
                -Detail $_.Exception.Message))
        }
    }
    # No review tier: anything that would need review fails the rebuild check.
    [void](ConvertTo-RebuildVerdict -Findings $findings.ToArray())
}

$commit = (& git -C $root rev-parse HEAD).Trim()
$result = [pscustomobject][ordered]@{
    schemaVersion = 1
    phase = $Phase
    package = [IO.Path]::GetFileName($packageFull)
    sha256 = (Get-FileHash -LiteralPath $packageFull -Algorithm SHA256).Hash.ToLowerInvariant()
    sourceCommit = $commit
    sdkVersion = $contract.sdkVersion
    disposition = Get-WorstDisposition -Values @($findings | ForEach-Object { $_.severity })
    lockedPackages = @($lockedPackages | ForEach-Object { "$($_.id) $($_.version)" })
    findings = $findings.ToArray()
}
[IO.File]::WriteAllText((Join-Path $outputRoot "source-build.json"),
    ($result | ConvertTo-Json -Depth 20) + "`n", [Text.UTF8Encoding]::new($false))
Write-Host "Source rebuild ($Phase) result: $($result.disposition)"
$result
if ($result.disposition -eq "fail") { exit 2 }
exit 0
