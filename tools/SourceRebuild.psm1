# SPDX-License-Identifier: GPL-2.0-or-later
# Helpers for the source rebuild check (verify-source-build.ps1). Everything in
# this module is trusted code: it reads contributor files as data and never
# runs contributor code. Contributor code runs only through Invoke-Sandboxed,
# inside bubblewrap with no network and a read-only host filesystem.
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot "SecurityScan.psm1")
Import-Module (Join-Path $PSScriptRoot "CommunityCustody.psm1")

$script:BuildDirectoryName = ".zeus-build"
$script:SourceTextExtensions = @(
    ".json", ".md", ".txt", ".css", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp"
)
$script:SourceTextNames = "^(?i:(LICENSE|LICENCE|COPYING|NOTICE|NOTICES|AUTHORS|README|THIRD[-_]PARTY[-_]NOTICES)([.-][A-Za-z0-9.-]+)?)$"
$script:BinaryExtensions = @(
    ".dll", ".exe", ".so", ".dylib", ".zip", ".nupkg", ".a", ".lib", ".wasm", ".node", ".jar", ".7z", ".tgz", ".gz"
)
# Both prefixes are reserved on nuget.org, so only Microsoft can publish them.
$script:ExemptPackagePrefixes = @("Microsoft.", "System.")
$script:NpmRegistry = "https://registry.npmjs.org/"
$script:BuildTimeAssetFolders = @("analyzers/", "build/", "buildTransitive/", "buildMultiTargeting/", "contentFiles/", "tools/")
$script:NuGetFlatContainer = "https://api.nuget.org/v3-flatcontainer"

function Get-BuildDirectoryName { return $script:BuildDirectoryName }

function Assert-SafeRelativePath {
    param(
        [AllowNull()] $Path,
        [Parameter(Mandatory)][string] $Label,
        [switch] $AllowRoot
    )
    if ($Path -isnot [string] -or [string]::IsNullOrWhiteSpace($Path) -or $Path.Length -gt 512) {
        throw "$Label must be a non-empty relative path of at most 512 characters"
    }
    if ($AllowRoot -and $Path -ceq ".") { return }
    if ($Path.Contains("\") -or $Path -match '[\x00-\x1F\x7F]' -or $Path.StartsWith("/") -or
        $Path -match '^[A-Za-z]:' -or [IO.Path]::IsPathRooted($Path) -or $Path.EndsWith("/")) {
        throw "$Label must be a forward-slash relative path: $Path"
    }
    foreach ($segment in $Path.Split("/")) {
        if ([string]::IsNullOrEmpty($segment) -or $segment -in @(".", "..")) {
            throw "$Label must not contain empty, '.', or '..' segments: $Path"
        }
    }
}

function Assert-NoLinkedComponents {
    param([Parameter(Mandatory)][string] $Root, [Parameter(Mandatory)][string] $FullPath, [string] $Label)
    $relative = [IO.Path]::GetRelativePath($Root, $FullPath)
    $current = $Root
    foreach ($segment in $relative.Split([IO.Path]::DirectorySeparatorChar)) {
        if ($segment -eq ".") { continue }
        $current = Join-Path $current $segment
        $item = Get-Item -LiteralPath $current -Force -ErrorAction SilentlyContinue
        if ($null -eq $item) { return }
        if (Test-IsLinkedItem $item) { throw "$Label must not traverse a filesystem link: $relative" }
    }
}

function Resolve-SourcePath {
    param(
        [Parameter(Mandatory)][string] $Root,
        [Parameter(Mandatory)][AllowNull()] $RelativePath,
        [Parameter(Mandatory)][string] $Label,
        [switch] $AllowRoot
    )
    Assert-SafeRelativePath -Path $RelativePath -Label $Label -AllowRoot:$AllowRoot
    $full = [IO.Path]::GetFullPath((Join-Path $Root $RelativePath))
    $prefix = $Root.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not ($full -ceq $Root -and $AllowRoot) -and -not $full.StartsWith($prefix, [StringComparison]::Ordinal)) {
        throw "$Label escapes the source repository: $RelativePath"
    }
    Assert-NoLinkedComponents -Root $Root -FullPath $full -Label $Label
    $relative = [IO.Path]::GetRelativePath($Root, $full).Replace("\", "/")
    if ($relative -ceq ".git" -or $relative.StartsWith(".git/", [StringComparison]::Ordinal)) {
        throw "$Label must not point inside .git: $RelativePath"
    }
    return $full
}

function Assert-ExactProperties {
    param($Object, [string[]] $Required, [string[]] $Optional = @(), [string] $Label)
    if ($Object -isnot [Management.Automation.PSCustomObject]) { throw "$Label must be an object" }
    $names = @($Object.PSObject.Properties.Name)
    foreach ($name in $Required) {
        if ($names -cnotcontains $name) { throw "$Label is missing $name" }
    }
    foreach ($name in $names) {
        if ($name -cnotin ($Required + $Optional)) { throw "$Label has unsupported property $name" }
    }
}

function Read-SmallRegularFile {
    param([Parameter(Mandatory)][string] $Path, [Parameter(Mandatory)][string] $Label, [long] $MaxBytes = 262144)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if ($null -eq $item -or $item -isnot [IO.FileInfo]) { throw "$Label is missing from the source repository root" }
    if (Test-IsLinkedItem $item) { throw "$Label must not be a filesystem link" }
    if ($item.Length -gt $MaxBytes) { throw "$Label exceeds $MaxBytes bytes" }
    return [IO.File]::ReadAllText($Path)
}

function Read-PinnedSdkVersion {
    <#
      global.json must pin one exact SDK with rollForward "disable" and nothing
      else, so the build job installs exactly that SDK and MSBuild SDK
      resolution cannot fetch anything.
    #>
    param([Parameter(Mandatory)][string] $Root)
    $text = Read-SmallRegularFile -Path (Join-Path $Root "global.json") -Label "global.json" -MaxBytes 16384
    try { $json = $text | ConvertFrom-Json -Depth 10 }
    catch { throw "global.json is not valid JSON: $($_.Exception.Message)" }
    Assert-ExactProperties $json @("sdk") @() "global.json"
    Assert-ExactProperties $json.sdk @("version", "rollForward") @("allowPrerelease") "global.json sdk"
    if ($json.sdk.version -isnot [string] -or
        $json.sdk.version -cnotmatch '^[0-9]+\.[0-9]+\.[0-9]{3}(-[0-9A-Za-z][0-9A-Za-z.-]{0,63})?$') {
        throw "global.json sdk.version must be one exact SDK version such as 10.0.100"
    }
    if ($json.sdk.rollForward -cne "disable") { throw 'global.json sdk.rollForward must be "disable"' }
    if ($json.sdk.PSObject.Properties["allowPrerelease"] -and $json.sdk.allowPrerelease -isnot [bool]) {
        throw "global.json sdk.allowPrerelease must be a boolean"
    }
    return [string]$json.sdk.version
}

function Read-BuildContract {
    param([Parameter(Mandatory)][string] $Root)
    $text = Read-SmallRegularFile -Path (Join-Path $Root "zeus-build.json") -Label "zeus-build.json"
    try { $contract = $text | ConvertFrom-Json -Depth 20 }
    catch { throw "zeus-build.json is not valid JSON: $($_.Exception.Message)" }

    Assert-ExactProperties $contract @("schemaVersion", "dotnet", "package") @("node") "zeus-build.json"
    if (($contract.schemaVersion -isnot [long] -and $contract.schemaVersion -isnot [int]) -or
        $contract.schemaVersion -ne 1) {
        throw "zeus-build.json schemaVersion must be 1"
    }
    Assert-ExactProperties $contract.dotnet @("project", "configuration") @() "zeus-build.json dotnet"
    $project = Resolve-SourcePath -Root $Root -RelativePath $contract.dotnet.project -Label "dotnet.project"
    if (-not $project.EndsWith(".csproj", [StringComparison]::Ordinal) -or
        -not (Test-Path -LiteralPath $project -PathType Leaf)) {
        throw "dotnet.project must name an existing .csproj file: $($contract.dotnet.project)"
    }
    if ($contract.dotnet.configuration -isnot [string] -or
        $contract.dotnet.configuration -cnotmatch '^[A-Za-z][A-Za-z0-9_-]{0,31}$') {
        throw "dotnet.configuration must be a plain MSBuild configuration name"
    }

    $nodeSteps = [Collections.Generic.List[object]]::new()
    if ($contract.PSObject.Properties["node"]) {
        $steps = $contract.node
        if ($steps -isnot [array] -or $steps.Count -gt 8) { throw "node must be an array of at most 8 steps" }
        foreach ($step in $steps) {
            Assert-ExactProperties $step @("directory", "script") @() "node step"
            $directory = Resolve-SourcePath -Root $Root -RelativePath $step.directory -Label "node.directory" -AllowRoot
            foreach ($required in @("package.json", "package-lock.json")) {
                $file = Join-Path $directory $required
                $fileItem = Get-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
                if ($null -eq $fileItem -or $fileItem -isnot [IO.FileInfo] -or (Test-IsLinkedItem $fileItem)) {
                    throw "node.directory $($step.directory) must contain a regular $required"
                }
            }
            if ($step.script -isnot [string] -or $step.script -cnotmatch '^[A-Za-z0-9][A-Za-z0-9:_.-]{0,63}$') {
                throw "node.script must be a plain npm script name"
            }
            $nodeSteps.Add([pscustomobject]@{ directory = $directory; script = [string]$step.script })
        }
    }

    if ($contract.package -isnot [Management.Automation.PSCustomObject]) { throw "package must be an object" }
    $mappings = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::Ordinal)
    $targets = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($property in @($contract.package.PSObject.Properties)) {
        Assert-SafeRelativePath -Path $property.Name -Label "package key"
        if (Test-IsBuildOutputName $property.Name) {
            throw "package must not map $($property.Name); DLLs and .deps.json come from the dotnet build"
        }
        $source = Resolve-SourcePath -Root $Root -RelativePath $property.Value -Label "package[$($property.Name)]"
        $relative = [IO.Path]::GetRelativePath($Root, $source).Replace("\", "/")
        if ($relative -ieq "zeus-build.json" -or $relative -ieq "global.json") {
            throw "package must not map $relative"
        }
        if (-not $targets.Add($relative)) { throw "package maps two ZIP paths to the same source file: $relative" }
        $mappings[$property.Name] = $relative
    }
    if ($mappings.Count -eq 0) { throw "package must map at least plugin.json" }
    return [pscustomobject]@{
        project = $project
        configuration = [string]$contract.dotnet.configuration
        sdkVersion = Read-PinnedSdkVersion -Root $Root
        node = $nodeSteps.ToArray()
        package = $mappings
    }
}

function Test-IsBuildOutputName {
    <# DLLs and any .deps.json come from the dotnet build, compared case-insensitively. #>
    param([Parameter(Mandatory)][string] $Path)
    return ($Path -imatch '\.dll$') -or ($Path -imatch '(^|/)[^/]+\.deps\.json$')
}

function Get-BinaryMagicKind {
    <# Identifies executables and archives by header, whatever the extension. #>
    param([Parameter(Mandatory)][string] $Path)
    $bytes = [byte[]]::new(8)
    $stream = [IO.File]::OpenRead($Path)
    try { $count = $stream.Read($bytes, 0, 8) }
    finally { $stream.Dispose() }
    if ($count -ge 2 -and $bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A) { return "PE (MZ)" }
    if ($count -ge 2 -and $bytes[0] -eq 0x1F -and $bytes[1] -eq 0x8B) { return "gzip" }
    if ($count -lt 4) { return $null }
    $magic = [BitConverter]::ToString($bytes, 0, 4).Replace("-", "")
    switch ($magic) {
        "7F454C46" { return "ELF" }
        "FEEDFACE" { return "Mach-O" }
        "FEEDFACF" { return "Mach-O" }
        "CEFAEDFE" { return "Mach-O" }
        "CFFAEDFE" { return "Mach-O" }
        "CAFEBABE" { return "Mach-O universal or Java class" }
        "BEBAFECA" { return "Mach-O universal" }
        "504B0304" { return "ZIP" }
        "504B0506" { return "ZIP" }
        "504B0708" { return "ZIP" }
        "0061736D" { return "WebAssembly" }
    }
    return $null
}

function Test-IsSourceTextName {
    param([Parameter(Mandatory)][string] $RelativePath)
    $name = [IO.Path]::GetFileName($RelativePath)
    return ($name -cmatch $script:SourceTextNames) -or
        ([IO.Path]::GetExtension($name).ToLowerInvariant() -in $script:SourceTextExtensions)
}

function Test-KeepCommittedFile {
    <#
      A mapped file is packaged as committed only when it is tracked, both the
      ZIP path and the source path look like plain text or images, and the
      file header is not an executable or archive. Everything else is deleted
      before the build and must be produced by it.
    #>
    param(
        [Parameter(Mandatory)][string] $Root,
        [Parameter(Mandatory)][string] $ZipPath,
        [Parameter(Mandatory)][string] $SourcePath,
        [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.HashSet[string]] $Tracked
    )
    if (-not $Tracked.Contains($SourcePath)) { return $false }
    if (-not (Test-IsSourceTextName $ZipPath) -or -not (Test-IsSourceTextName $SourcePath)) { return $false }
    $full = Join-Path $Root $SourcePath
    $item = Get-Item -LiteralPath $full -Force -ErrorAction SilentlyContinue
    if ($null -eq $item -or $item -isnot [IO.FileInfo] -or (Test-IsLinkedItem $item)) { return $false }
    return $null -eq (Get-BinaryMagicKind -Path $full)
}

function Get-TrackedBinaryFindings {
    param([Parameter(Mandatory)][string] $Root, [Parameter(Mandatory)][AllowEmptyCollection()][string[]] $Tracked)
    $findings = [Collections.Generic.List[object]]::new()
    foreach ($path in $Tracked) {
        $full = Join-Path $Root $path
        $item = Get-Item -LiteralPath $full -Force -ErrorAction SilentlyContinue
        if ($null -eq $item -or $item -isnot [IO.FileInfo] -or (Test-IsLinkedItem $item)) { continue }
        $kind = Get-BinaryMagicKind -Path $full
        $byExtension = [IO.Path]::GetExtension($path).ToLowerInvariant() -in $script:BinaryExtensions
        if ($kind -or $byExtension) {
            $what = if ($kind) { "$kind header" } else { "binary file extension" }
            $findings.Add((New-SecurityFinding -Check "rebuild" -RuleId "rebuild-tracked-binary" -Severity fail `
                -File $path -Detail "Source repository tracks a binary or archive ($what); the rebuild must come from source only"))
        }
    }
    return $findings.ToArray()
}

function Test-IsExemptPackage {
    param([Parameter(Mandatory)][string] $Id)
    foreach ($prefix in $script:ExemptPackagePrefixes) {
        if ($Id.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

function Read-RebuildPackageAllowlist {
    param([Parameter(Mandatory)][string] $Path)
    $json = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json -Depth 10
    Assert-ExactProperties $json @("schemaVersion", "entries") @() "rebuild package allowlist"
    if ($json.schemaVersion -ne 1) { throw "rebuild package allowlist schemaVersion must be 1" }
    $allowed = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in @($json.entries)) {
        if ($null -eq $entry) { continue }
        Assert-ExactProperties $entry @("id", "version", "reason", "approvedBy") @() "rebuild package allowlist entry"
        foreach ($name in @("id", "version", "reason", "approvedBy")) {
            if ($entry.$name -isnot [string] -or [string]::IsNullOrWhiteSpace($entry.$name)) {
                throw "rebuild package allowlist entry $name must be a non-empty string"
            }
        }
        [void]$allowed.Add("$($entry.id)/$($entry.version)")
    }
    return , $allowed
}

function Get-NuGetLockPackages {
    <#
      Reads every packages.lock.json in the source as data and returns the
      exact packages (id, resolved version, contentHash) that restore needs.
    #>
    param([Parameter(Mandatory)][string] $Root)
    $packages = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
    $lockfiles = @(Get-DependencyLockfiles -SourceDirectory $Root | Where-Object kind -eq "nuget-lock")
    foreach ($lockfile in $lockfiles) {
        $text = Read-SmallRegularFile -Path (Join-Path $Root $lockfile.path) -Label $lockfile.path -MaxBytes 16777216
        try { $lock = $text | ConvertFrom-Json -Depth 20 }
        catch { throw "$($lockfile.path) is not valid JSON" }
        if ($null -eq $lock.PSObject.Properties["version"] -or $lock.version -notin @(1, 2) -or
            $null -eq $lock.PSObject.Properties["dependencies"]) {
            throw "$($lockfile.path) is not a supported NuGet lock file"
        }
        foreach ($framework in @($lock.dependencies.PSObject.Properties)) {
            foreach ($dependency in @($framework.Value.PSObject.Properties)) {
                $info = $dependency.Value
                $type = [string]$info.type
                if ($type -ceq "Project") { continue }
                $id = [string]$dependency.Name
                $version = [string]$info.resolved
                $hash = [string]$info.contentHash
                if ($id -cnotmatch '^[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}$') { throw "$($lockfile.path) has an invalid package id: $id" }
                if ($version -cnotmatch '^[0-9]+(\.[0-9]+){1,3}(-[0-9A-Za-z][0-9A-Za-z.-]*)?(\+[0-9A-Za-z.-]+)?$') {
                    throw "$($lockfile.path) has an invalid resolved version for ${id}: $version"
                }
                $digest = $null
                try { $digest = [Convert]::FromBase64String($hash) } catch { }
                if ($null -eq $digest -or $digest.Length -ne 64) {
                    throw "$($lockfile.path) has no SHA-512 contentHash for $id $version"
                }
                $normalized = ($version -replace '\+.*$', '').ToLowerInvariant()
                $key = "$id/$normalized"
                $existing = $null
                if ($packages.TryGetValue($key, [ref]$existing)) {
                    if ($existing.contentHash -cne $hash) { throw "Lock files disagree on the contentHash of $id $version" }
                    continue
                }
                $packages[$key] = [pscustomobject][ordered]@{
                    id = $id; version = $normalized; contentHash = $hash; lockfile = $lockfile.path
                }
                if ($packages.Count -gt 1000) { throw "More than 1000 NuGet packages are locked" }
            }
        }
    }
    return @($packages.Values | Sort-Object id, version)
}

function Get-UnlockedProjectFindings {
    <# A project with PackageReference items must have a packages.lock.json beside it. #>
    param([Parameter(Mandatory)][string] $Root)
    $findings = [Collections.Generic.List[object]]::new()
    $inputs = @(Get-DependencyLockfiles -SourceDirectory $Root)
    $locked = @($inputs | Where-Object kind -eq "nuget-lock" | ForEach-Object { [IO.Path]::GetDirectoryName($_.path) })
    foreach ($project in @($inputs | Where-Object kind -in @("csproj", "nuget-central"))) {
        if ($project.kind -eq "csproj" -and [IO.Path]::GetDirectoryName($project.path) -in $locked) { continue }
        $text = Read-SmallRegularFile -Path (Join-Path $Root $project.path) -Label $project.path -MaxBytes 1048576
        $tag = if ($project.kind -eq "csproj") { "PackageReference" } else { "GlobalPackageReference" }
        if ($text -match "<\s*$tag\b") {
            $findings.Add((New-SecurityFinding -Check "rebuild" -RuleId "rebuild-missing-lockfile" -Severity fail `
                -File $project.path -Detail "$tag items need a committed packages.lock.json (RestorePackagesWithLockFile=true) beside every project that restores them"))
        }
    }
    return $findings.ToArray()
}

function Initialize-NuGetPackaging {
    <#
      NuGet's lock-file contentHash is not a plain file hash for signed
      packages (the repository signature is excluded). Compute it with the
      NuGet.Packaging assembly that ships in the installed .NET SDK, the same
      code restore uses; no contributor code is involved.
    #>
    if ($null -ne ("NuGet.Packaging.PackageArchiveReader" -as [type])) { return }
    $dotnet = Get-Command dotnet -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $dotnet) { throw "The .NET SDK is required to verify NuGet content hashes" }
    $sdks = @(& $dotnet.Source --list-sdks | ForEach-Object {
        if ($_ -match '^(?<version>\S+) \[(?<path>.+)\]$') {
            Join-Path $Matches.path $Matches.version
        }
    })
    $sdk = @($sdks | Where-Object { Test-Path -LiteralPath (Join-Path $_ "NuGet.Packaging.dll") } | Select-Object -Last 1)
    if ($sdk.Count -ne 1) { throw "No installed .NET SDK provides NuGet.Packaging.dll" }
    foreach ($name in @("NuGet.Common", "NuGet.Frameworks", "NuGet.Versioning", "NuGet.Packaging")) {
        Add-Type -Path (Join-Path $sdk[0] "$name.dll")
    }
}

function Get-NuGetContentHash {
    param([Parameter(Mandatory)][string] $Path)
    Initialize-NuGetPackaging
    $stream = [IO.File]::OpenRead($Path)
    try {
        $reader = [NuGet.Packaging.PackageArchiveReader]::new($stream, $true)
        try { return $reader.GetContentHash([Threading.CancellationToken]::None) }
        finally { $reader.Dispose() }
    }
    finally { $stream.Dispose() }
}

function New-VerifiedNuGetFeed {
    <#
      Downloads each locked package from nuget.org with the bounded HTTPS
      downloader, verifies the lock file's SHA-512 contentHash, and writes it
      to a local folder feed. -Download exists so tests can supply bytes
      without the network.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]] $Packages,
        [Parameter(Mandatory)][string] $FeedDirectory,
        [scriptblock] $Download = $null
    )
    $feed = [IO.Path]::GetFullPath($FeedDirectory)
    New-Item -ItemType Directory -Path $feed -Force | Out-Null
    foreach ($package in $Packages) {
        $idLower = $package.id.ToLowerInvariant()
        $versionLower = $package.version.ToLowerInvariant()
        $url = "$script:NuGetFlatContainer/$idLower/$versionLower/$idLower.$versionLower.nupkg"
        $destination = Join-Path $feed "$idLower.$versionLower.nupkg"
        if ($null -ne $Download) { & $Download $url $destination }
        else { [void](Copy-HttpsFileWithLimit -SourceUrl $url -DestinationPath $destination) }
        $actual = $null
        try { $actual = Get-NuGetContentHash -Path $destination }
        catch { $actual = "unreadable: $($_.Exception.Message)" }
        if ($actual -cne $package.contentHash) {
            Remove-Item -LiteralPath $destination -Force
            throw "NuGet package $($package.id) $($package.version) does not match the contentHash in $($package.lockfile)"
        }
    }
    return $feed
}

function New-TrustedNuGetConfig {
    param([Parameter(Mandatory)][string] $Path, [Parameter(Mandatory)][string] $FeedDirectory)
    $feed = [Security.SecurityElement]::Escape([IO.Path]::GetFullPath($FeedDirectory))
    $xml = @"
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="zeus-verified-feed" value="$feed" />
  </packageSources>
  <fallbackPackageFolders>
    <clear />
  </fallbackPackageFolders>
  <disabledPackageSources>
    <clear />
  </disabledPackageSources>
  <packageSourceMapping>
    <clear />
  </packageSourceMapping>
</configuration>
"@
    [IO.File]::WriteAllText($Path, $xml, [Text.UTF8Encoding]::new($false))
    return $Path
}

function Get-BuildTimeAssetEntries {
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]] $Paths)
    return @($Paths | Where-Object {
        $path = $_.Replace("\", "/")
        @($script:BuildTimeAssetFolders | Where-Object { $path.StartsWith($_, [StringComparison]::OrdinalIgnoreCase) }).Count -gt 0
    })
}

function Get-FeedBuildTimePackageFindings {
    <#
      Analyzers, source generators, and MSBuild targets in a package inject
      code that is not in the contributor's source. Inspect the verified
      nupkgs themselves (trusted bytes) and fail on any such asset unless a
      maintainer allowlisted that exact package version.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]] $Packages,
        [Parameter(Mandatory)][string] $FeedDirectory,
        [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.HashSet[string]] $Allowlist
    )
    $findings = [Collections.Generic.List[object]]::new()
    foreach ($package in $Packages) {
        if (Test-IsExemptPackage $package.id) { continue }
        if ($Allowlist.Contains("$($package.id)/$($package.version)")) { continue }
        $path = Join-Path $FeedDirectory "$($package.id.ToLowerInvariant()).$($package.version).nupkg"
        $archive = [IO.Compression.ZipFile]::OpenRead($path)
        try { $entries = @($archive.Entries | ForEach-Object { $_.FullName }) }
        finally { $archive.Dispose() }
        $buildTime = @(Get-BuildTimeAssetEntries -Paths $entries)
        if ($buildTime.Count -gt 0) {
            $findings.Add((New-SecurityFinding -Check "rebuild" -RuleId "rebuild-build-time-package" -Severity fail `
                -File "$($package.id) $($package.version)" `
                -Detail "Package ships analyzers, source generators, or MSBuild targets that change the build; it must be in tools/rebuild-package-allowlist.json" `
                -Evidence (($buildTime | Select-Object -First 5) -join ", ")))
        }
    }
    return $findings.ToArray()
}

function Get-AssetsFilePackageFindings {
    <#
      Cross-checks what restore actually used (obj/project.assets.json of the
      project and every project it references) against the verified feed.
    #>
    param(
        [Parameter(Mandatory)][string] $Root,
        [Parameter(Mandatory)][string] $ProjectPath,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]] $Packages,
        [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.HashSet[string]] $Allowlist,
        [Parameter(Mandatory)][string] $PackagesFolder,
        [Parameter(Mandatory)][string] $SdkRoot
    )
    $findings = [Collections.Generic.List[object]]::new()
    $verified = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($package in $Packages) { [void]$verified.Add("$($package.id)/$($package.version)") }
    $prefix = $Root.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $pending = [Collections.Generic.Queue[string]]::new()
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $pending.Enqueue([IO.Path]::GetFullPath($ProjectPath))
    while ($pending.Count -gt 0) {
        $project = $pending.Dequeue()
        if (-not $seen.Add($project)) { continue }
        if (-not $project.StartsWith($prefix, [StringComparison]::Ordinal)) {
            throw "Project reference outside the source repository: $project"
        }
        $relativeProject = [IO.Path]::GetRelativePath($Root, $project).Replace("\", "/")
        $assetsPath = Join-Path (Split-Path -Parent $project) "obj/project.assets.json"
        Assert-NoLinkedComponents -Root $Root -FullPath $assetsPath -Label "project.assets.json"
        if (-not (Test-Path -LiteralPath $assetsPath -PathType Leaf)) {
            throw "Restore produced no obj/project.assets.json for $relativeProject; keep the default intermediate output path"
        }
        $assets = Get-Content -Raw -LiteralPath $assetsPath | ConvertFrom-Json -Depth 100 -AsHashtable
        foreach ($library in @($assets["libraries"].GetEnumerator())) {
            if ([string]$library.Value["type"] -cne "package") { continue }
            $parts = ([string]$library.Key).Split("/")
            if ($parts.Count -ne 2) { throw "Unexpected library key in $relativeProject assets: $($library.Key)" }
            $key = "$($parts[0])/$($parts[1].ToLowerInvariant())"
            if (Test-IsExemptPackage $parts[0]) {
                $folders = @(if ($assets.ContainsKey("packageFolders") -and $null -ne $assets["packageFolders"]) {
                    $assets["packageFolders"].Keys })
                if ($verified.Contains($key) -or
                    (Test-IsSdkProvidedPackage -Id $parts[0] -Version $parts[1] -PackagesFolder $PackagesFolder `
                        -SdkRoot $SdkRoot -PackageFolders $folders)) { continue }
                $findings.Add((New-SecurityFinding -Check "rebuild" -RuleId "rebuild-unverified-package" -Severity fail `
                    -File "$($parts[0]) $($parts[1])" `
                    -Detail "Restore for $relativeProject used a Microsoft/System package that is neither locked nor provided by the installed .NET SDK"))
                continue
            }
            if (-not $verified.Contains($key)) {
                $findings.Add((New-SecurityFinding -Check "rebuild" -RuleId "rebuild-unverified-package" -Severity fail `
                    -File "$($parts[0]) $($parts[1])" -Detail "Restore for $relativeProject used a package that is not in any packages.lock.json"))
                continue
            }
            $files = @($library.Value["files"] | Where-Object { $_ } | ForEach-Object { [string]$_ })
            $buildTime = @(Get-BuildTimeAssetEntries -Paths $files)
            if ($buildTime.Count -gt 0 -and -not $Allowlist.Contains($key)) {
                $findings.Add((New-SecurityFinding -Check "rebuild" -RuleId "rebuild-build-time-package" -Severity fail `
                    -File "$($parts[0]) $($parts[1])" `
                    -Detail "Package ships analyzers, source generators, or MSBuild targets that change the build; it must be in tools/rebuild-package-allowlist.json" `
                    -Evidence (($buildTime | Select-Object -First 5) -join ", ")))
            }
        }
        $restore = $assets["project"]["restore"]
        foreach ($framework in @($restore["frameworks"].GetEnumerator())) {
            $references = $framework.Value["projectReferences"]
            if ($null -eq $references) { continue }
            foreach ($reference in @($references.Keys)) {
                $pending.Enqueue([IO.Path]::GetFullPath([string]$reference))
            }
        }
    }
    return $findings.ToArray()
}

function ConvertTo-RebuildVerdict {
    <# The rebuild check has no review tier: review findings become failures. #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]] $Findings)
    foreach ($finding in $Findings) {
        if ($null -ne $finding -and $finding.severity -eq "review") {
            $finding.severity = "fail"
            $finding.detail = "$($finding.detail) (the rebuild check has no review tier)"
        }
    }
    return $Findings
}

function Remove-ContributorNpmConfig {
    <#
      npm ci runs outside the sandbox, so it must not honour contributor
      configuration: delete every .npmrc from the node directory up to the
      source root. A linked .npmrc fails closed.
    #>
    param([Parameter(Mandatory)][string] $Root, [Parameter(Mandatory)][string] $Directory)
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $current = [IO.Path]::GetFullPath($Directory).TrimEnd([IO.Path]::DirectorySeparatorChar)
    if ($current -cne $rootFull -and
        -not $current.StartsWith($rootFull + [IO.Path]::DirectorySeparatorChar, [StringComparison]::Ordinal)) {
        throw "npm directory is outside the source repository: $Directory"
    }
    $removed = [Collections.Generic.List[string]]::new()
    while ($true) {
        $npmrc = Join-Path $current ".npmrc"
        $item = Get-Item -LiteralPath $npmrc -Force -ErrorAction SilentlyContinue
        if ($null -ne $item) {
            $relative = [IO.Path]::GetRelativePath($rootFull, $npmrc).Replace("\", "/")
            if (Test-IsLinkedItem $item) { throw "$relative must not be a filesystem link" }
            if ($item -isnot [IO.FileInfo]) { throw "$relative must be a regular file" }
            Remove-Item -LiteralPath $npmrc -Force
            $removed.Add($relative)
        }
        if ($current -ceq $rootFull) { break }
        $current = Split-Path -Parent $current
    }
    return $removed.ToArray()
}

function Get-NpmCiArguments {
    <# npm ci with the public registry and empty user and global configuration. #>
    param([Parameter(Mandatory)][string] $EmptyUserConfigPath, [Parameter(Mandatory)][string] $EmptyGlobalConfigPath)
    # npm refuses to load one file as both user and global configuration.
    return @("ci", "--ignore-scripts", "--registry=$script:NpmRegistry",
        "--userconfig", $EmptyUserConfigPath, "--globalconfig", $EmptyGlobalConfigPath, "--no-audit", "--no-fund")
}

function Get-NpmLockFindings {
    <#
      Every package in package-lock.json must come from the public npm
      registry over HTTPS and carry an integrity hash, so npm ci can fetch
      nothing else. A workspace link is allowed only when it resolves inside
      the source repository. An inBundle entry is skipped only when its
      parent entry declares it in bundleDependencies (it then ships inside
      that verified tarball); otherwise it is checked like any package.
    #>
    param([Parameter(Mandatory)][string] $Root, [Parameter(Mandatory)][string] $Directory)
    $lockPath = Join-Path $Directory "package-lock.json"
    $relativeLock = [IO.Path]::GetRelativePath($Root, $lockPath).Replace("\", "/")
    $text = Read-SmallRegularFile -Path $lockPath -Label $relativeLock -MaxBytes 67108864
    try { $lock = $text | ConvertFrom-Json -Depth 100 -AsHashtable }
    catch { throw "$relativeLock is not valid JSON" }
    $entries = [Collections.Generic.List[object]]::new()
    if ($lock.ContainsKey("packages")) {
        foreach ($entry in $lock["packages"].GetEnumerator()) {
            if ($entry.Key -ceq "") { continue }
            $entries.Add([pscustomobject]@{ name = $entry.Key; value = $entry.Value })
        }
    }
    elseif ($lock.ContainsKey("dependencies")) {
        $pending = [Collections.Generic.Stack[object]]::new()
        $pending.Push([pscustomobject]@{ prefix = ""; deps = $lock["dependencies"] })
        while ($pending.Count -gt 0) {
            $next = $pending.Pop()
            foreach ($entry in $next.deps.GetEnumerator()) {
                $name = "$($next.prefix)$($entry.Key)"
                $entries.Add([pscustomobject]@{ name = $name; value = $entry.Value })
                if ($entry.Value -is [hashtable] -and $entry.Value.ContainsKey("dependencies")) {
                    $pending.Push([pscustomobject]@{ prefix = "$name > "; deps = $entry.Value["dependencies"] })
                }
            }
        }
    }
    else { throw "$relativeLock has neither packages nor dependencies" }
    $findings = [Collections.Generic.List[object]]::new()
    $packagesTable = if ($lock.ContainsKey("packages")) { $lock["packages"] } else { $null }
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar)
    foreach ($entry in $entries) {
        $value = $entry.value
        if ($value -isnot [hashtable]) { continue }
        if ($null -ne $packagesTable -and $value["link"] -eq $true) {
            $target = [string]$value["resolved"]
            $inside = $false
            if ($target -and -not $target.Contains("://") -and -not [IO.Path]::IsPathRooted($target) -and
                $target -notmatch '^[A-Za-z]:') {
                $full = [IO.Path]::GetFullPath((Join-Path $Directory $target))
                $inside = $full.StartsWith($rootFull + [IO.Path]::DirectorySeparatorChar, [StringComparison]::Ordinal)
            }
            if (-not $inside) {
                $findings.Add((New-SecurityFinding -Check "rebuild" -RuleId "rebuild-npm-registry" -Severity fail `
                    -File $relativeLock -Detail "$($entry.name) links outside the source repository" -Evidence $target))
            }
            continue
        }
        if ($null -ne $packagesTable -and $value["inBundle"] -eq $true) {
            $marker = "/node_modules/"
            $index = $entry.name.LastIndexOf($marker, [StringComparison]::Ordinal)
            if ($index -ge 0) {
                $parentKey = $entry.name.Substring(0, $index)
                $childName = $entry.name.Substring($index + $marker.Length)
            }
            else {
                $parentKey = ""
                $childName = $entry.name -replace '^node_modules/', ''
            }
            $parent = if ($packagesTable.ContainsKey($parentKey)) { $packagesTable[$parentKey] } else { $null }
            $declared = $null
            if ($parent -is [hashtable]) {
                $declared = if ($parent.ContainsKey("bundleDependencies")) { $parent["bundleDependencies"] }
                    elseif ($parent.ContainsKey("bundledDependencies")) { $parent["bundledDependencies"] } else { $null }
            }
            if (($declared -is [bool] -and $declared) -or ($declared -isnot [bool] -and @($declared) -ccontains $childName)) { continue }
        }
        $resolved = [string]$value["resolved"]
        $integrity = [string]$value["integrity"]
        $problem = $null
        if (-not $resolved.StartsWith($script:NpmRegistry, [StringComparison]::Ordinal)) {
            $problem = "is not resolved from $script:NpmRegistry"
        }
        elseif ($integrity -cnotmatch '^sha(256|384|512)-[A-Za-z0-9+/=]+( sha(256|384|512)-[A-Za-z0-9+/=]+)*$') {
            $problem = "has no integrity hash"
        }
        if ($problem) {
            $findings.Add((New-SecurityFinding -Check "rebuild" -RuleId "rebuild-npm-registry" -Severity fail `
                -File $relativeLock -Detail "$($entry.name) $problem" -Evidence $resolved))
        }
    }
    return $findings.ToArray()
}

# ---------------------------------------------------------------------------
# MSBuild allowlist lint. Community project files may contain only plain
# declarative data from the lists below. Maintainers extend a list by pull
# request when a real feature needs another property, item, or metadata.
# ---------------------------------------------------------------------------
$script:AllowedProjectSdks = @("Microsoft.NET.Sdk", "Microsoft.NET.Sdk.Web", "Microsoft.NET.Sdk.Razor")

# Property name => $null (any safe value) or a regex the value must match.
$script:AllowedMsBuildProperties = [ordered]@{
    TargetFramework = $null; TargetFrameworks = $null; OutputType = '^(Library|Exe)$'
    AssemblyName = $null; RootNamespace = $null; Title = $null; NeutralLanguage = $null
    Version = $null; VersionPrefix = $null; VersionSuffix = $null; AssemblyVersion = $null
    FileVersion = $null; InformationalVersion = $null; PackageVersion = $null
    IncludeSourceRevisionInInformationalVersion = $null; SourceRevisionId = $null
    Authors = $null; Company = $null; Product = $null; Description = $null; Copyright = $null
    PackageId = $null; PackageLicenseExpression = $null; PackageProjectUrl = $null; PackageTags = $null
    RepositoryUrl = $null; RepositoryType = $null
    LangVersion = $null; Nullable = $null; ImplicitUsings = $null
    TreatWarningsAsErrors = $null; WarningsAsErrors = $null; WarningsNotAsErrors = $null
    NoWarn = $null; WarningLevel = $null; AnalysisLevel = $null
    Deterministic = $null; ContinuousIntegrationBuild = $null; Optimize = $null
    DebugType = $null; DebugSymbols = $null; GenerateDocumentationFile = $null
    IsPackable = $null; CopyLocalLockFileAssemblies = $null; EnableDynamicLoading = $null
    ProduceReferenceAssembly = $null; GenerateAssemblyInfo = $null; UseAppHost = $null
    ManagePackageVersionsCentrally = $null; CentralPackageTransitivePinningEnabled = $null
    InvariantGlobalization = $null; SatelliteResourceLanguages = $null
    EnableDefaultItems = $null; EnableDefaultCompileItems = $null; EnableDefaultNoneItems = $null
    Platforms = $null; Configurations = $null; PlatformTarget = $null
    RestorePackagesWithLockFile = '^true$'
    AllowUnsafeBlocks = '^false$'; RunAnalyzers = '^false$'; EnableNETAnalyzers = '^false$'
    SelfContained = '^false$'; PublishAot = '^false$'; SignAssembly = '^false$'
}
$script:AllowedItemTypes = @(
    "Compile", "None", "Content", "EmbeddedResource", "PackageReference", "PackageVersion",
    "ProjectReference", "FrameworkReference", "Using", "InternalsVisibleTo", "AssemblyAttribute", "Folder"
)
$script:PathItemTypes = @("Compile", "None", "Content", "EmbeddedResource", "Folder")
$script:AllowedItemMetadata = @(
    "Version", "PrivateAssets", "IncludeAssets", "ExcludeAssets", "CopyToOutputDirectory",
    "CopyToPublishDirectory", "Link", "DependentUpon", "Visible", "Pack", "PackagePath", "Private",
    "LogicalName", "Aliases", "Alias", "Static", "Key"
)
$script:RestoreOverrideProperties = @(
    "RestoreOutputPath", "ProjectAssetsFile", "RestoreAdditionalProjectSources", "RestoreSources",
    "RestoreFallbackFolders", "RestorePackagesPath", "RestoreLockedMode", "BaseIntermediateOutputPath",
    "MSBuildProjectExtensionsPath", "NuGetPackageRoot", "RestoreConfigFile", "NuGetLockFilePath",
    "RestoreAdditionalProjectFallbackFolders", "RestoreAdditionalProjectFallbackFoldersExcludes"
)
$script:AllowedMsBuildFunctions = @(
    "EnsureTrailingSlash", "NormalizePath", "NormalizeDirectory", "MakeRelative",
    "VersionGreaterThan", "VersionGreaterThanOrEquals", "VersionLessThan", "VersionLessThanOrEquals",
    "VersionEquals", "VersionNotEquals", "GetTargetFrameworkIdentifier", "GetTargetFrameworkVersion",
    "IsTargetFrameworkCompatible", "GetTargetPlatformIdentifier", "GetTargetPlatformVersion"
)
$script:AllowedStringFunctions = @("IsNullOrEmpty", "IsNullOrWhiteSpace", "Copy", "Equals", "Concat", "Join")
$script:ForbiddenFileExtensions = @(".targets", ".tasks", ".overridetasks", ".user", ".rsp", ".vbproj", ".fsproj", ".proj")
$script:ForbiddenDirectoryNames = @("bin", "obj")

function Get-MsBuildLintFiles {
    <# Returns the project files to lint plus every file or directory that is not allowed at all. #>
    param([Parameter(Mandatory)][string] $Root)
    $rootFull = [IO.Path]::GetFullPath($Root)
    $lint = [Collections.Generic.List[string]]::new()
    $forbidden = [Collections.Generic.List[string]]::new()
    $pending = [Collections.Generic.Stack[string]]::new()
    $pending.Push($rootFull)
    while ($pending.Count -gt 0) {
        foreach ($item in [IO.DirectoryInfo]::new($pending.Pop()).EnumerateFileSystemInfos()) {
            $relative = [IO.Path]::GetRelativePath($rootFull, $item.FullName).Replace("\", "/")
            if ($item -is [IO.DirectoryInfo]) {
                if ($item.Name -in @(".git", "node_modules") -or (Test-IsLinkedItem $item)) { continue }
                if ($item.Name.ToLowerInvariant() -in $script:ForbiddenDirectoryNames) { $forbidden.Add("$relative/"); continue }
                $pending.Push($item.FullName)
                continue
            }
            $extension = $item.Extension.ToLowerInvariant()
            if ($extension -in $script:ForbiddenFileExtensions) { $forbidden.Add($relative) }
            elseif ($extension -in @(".csproj", ".props")) { $lint.Add($relative) }
        }
    }
    return [pscustomobject]@{ lint = @($lint | Sort-Object); forbidden = @($forbidden | Sort-Object) }
}

function Get-MsBuildValueProblem {
    <#
      Checks a decoded attribute value or element text. Only plain $(Name)
      property references and allowlisted [MSBuild]::/[System.String]::
      functions may appear; item and metadata references are not allowed.
    #>
    param([AllowNull()][AllowEmptyString()][string] $Value)
    if ([string]::IsNullOrEmpty($Value)) { return $null }
    if ($Value.Contains("@(") -or $Value.Contains("%(")) { return "Item or metadata references are not allowed" }
    $index = $Value.IndexOf('$(', [StringComparison]::Ordinal)
    while ($index -ge 0) {
        $rest = $Value.Substring($index)
        $plain = [regex]::Match($rest, '^\$\(\s*[A-Za-z_][A-Za-z0-9_-]*\s*\)')
        $function = [regex]::Match($rest, '^\$\(\s*\[\s*([A-Za-z.]+)\s*\]\s*::\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(')
        $ok = $plain.Success -or ($function.Success -and (
            ($function.Groups[1].Value -ieq "MSBuild" -and $function.Groups[2].Value -in $script:AllowedMsBuildFunctions) -or
            ($function.Groups[1].Value -in @("System.String", "string") -and $function.Groups[2].Value -in $script:AllowedStringFunctions)))
        if (-not $ok) {
            $snippet = $rest.Substring(0, [Math]::Min(80, $rest.Length))
            return "Property function or reference not allowed: $snippet"
        }
        $index = $Value.IndexOf('$(', $index + 2, [StringComparison]::Ordinal)
    }
    return $null
}

function Get-MsBuildLintFindings {
    <#
      Allowlist lint for contributor MSBuild. Everything not explicitly
      allowed fails: element types, attributes, property names, item types,
      metadata, and value syntax. Values are checked after XML decoding, so
      entity-encoded text cannot hide a property function.
    #>
    param(
        [Parameter(Mandatory)][string] $Root,
        [AllowEmptyCollection()][string[]] $NodeDirectories = @(),
        [AllowNull()][string[]] $TrackedFiles = $null,
        [AllowEmptyCollection()][string[]] $MappedOutputs = @()
    )
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $separator = [IO.Path]::DirectorySeparatorChar
    $findings = [Collections.Generic.List[object]]::new()
    if ($null -eq $TrackedFiles) {
        try { $TrackedFiles = @(Get-TrackedFiles -Root $rootFull) } catch { $TrackedFiles = @() }
    }
    $trackedSet = [Collections.Generic.HashSet[string]]::new([string[]]@($TrackedFiles), [StringComparer]::Ordinal)
    $mappedSet = [Collections.Generic.HashSet[string]]::new([string[]]@($MappedOutputs), [StringComparer]::Ordinal)
    $inventory = Get-MsBuildLintFiles -Root $rootFull
    $lintSet = [Collections.Generic.HashSet[string]]::new([string[]]$inventory.lint, [StringComparer]::Ordinal)
    $projectDirectories = @($inventory.lint | Where-Object { $_ -like "*.csproj" } |
        ForEach-Object { [IO.Path]::GetDirectoryName((Join-Path $rootFull $_)) })
    $watchedDirectories = @($projectDirectories + @($NodeDirectories | Where-Object { $_ } |
        ForEach-Object { [IO.Path]::GetFullPath($_).TrimEnd($separator) }))
    $advice = "Community builds may use only the allowlisted MSBuild in tools/SourceRebuild.psm1; ask a maintainer if the feature needs more"
    function Add-Lint([string] $File, [string] $Detail, [string] $Evidence = "", [string] $Rule = "rebuild-msbuild-code") {
        $findings.Add((New-SecurityFinding -Check "rebuild" -RuleId $Rule -Severity fail -File $File `
            -Detail "$Detail. $advice" -Evidence $Evidence))
    }
    function Test-InRepoTarget([string] $FromFile, [string] $Path, [string[]] $Extensions) {
        if (-not $Path -or $Path -match '[\$@%*?;]' -or [IO.Path]::IsPathRooted($Path) -or $Path -match '^[A-Za-z]:') { return $false }
        $candidate = [IO.Path]::GetFullPath((Join-Path (Split-Path -Parent (Join-Path $rootFull $FromFile)) $Path.Replace("\", "/")))
        if (-not $candidate.StartsWith($rootFull + $separator, [StringComparison]::Ordinal)) { return $false }
        $relative = [IO.Path]::GetRelativePath($rootFull, $candidate).Replace("\", "/")
        return $lintSet.Contains($relative) -and ([IO.Path]::GetExtension($relative).ToLowerInvariant() -in $Extensions)
    }
    function Get-UntrackedItemProblem([string] $File, [string] $ItemType, [string] $Value) {
        # Items that add files may only name committed files. Paths resolve
        # against the project directory and cannot contain "..", so every
        # match stays inside the project.
        $projectDirectory = Split-Path -Parent (Join-Path $rootFull $File)
        foreach ($raw in $Value.Split(";")) {
            $path = $raw.Trim().Replace("\", "/")
            if (-not $path) { continue }
            if ($path -notmatch '[*?]') {
                $relative = [IO.Path]::GetRelativePath($rootFull, [IO.Path]::GetFullPath((Join-Path $projectDirectory $path))).Replace("\", "/")
                $mappedOutside = $ItemType -in @("Content", "None") -and $mappedSet.Contains($relative) -and
                    -not @($projectDirectories | Where-Object { Test-IsUnderDirectory -Path (Join-Path $rootFull $relative) -Directory $_ })
                if (-not $trackedSet.Contains($relative) -and -not $mappedOutside) {
                    return "Item path must be a tracked file: $path"
                }
                continue
            }
            $segments = $path.Split("/")
            $prefix = @(); $patternParts = @()
            $inWildcard = $false
            foreach ($segment in $segments) {
                if ($segment -match '[*?]') { $inWildcard = $true }
                if (-not $inWildcard) { $prefix += $segment; continue }
                if ($segment -ceq "**") { $patternParts += "(?:[^/]+/)*" ; continue }
                $patternParts += ([regex]::Escape($segment).Replace('\*', '[^/]*').Replace('\?', '[^/]') + "/")
            }
            $regex = "^" + (($patternParts -join "").TrimEnd("/")) + "$"
            $regex = $regex.Replace("(?:[^/]+/)*$", ".*$")
            $base = Join-Path $projectDirectory ($prefix -join "/")
            if (-not (Test-Path -LiteralPath $base -PathType Container)) { continue }
            foreach ($candidate in [IO.Directory]::EnumerateFiles($base, "*", [IO.SearchOption]::AllDirectories)) {
                $underBase = [IO.Path]::GetRelativePath($base, $candidate).Replace("\", "/")
                if ($underBase -notmatch $regex) { continue }
                $relative = [IO.Path]::GetRelativePath($rootFull, $candidate).Replace("\", "/")
                if (-not $trackedSet.Contains($relative)) { return "Wildcard item path matches an untracked file: $relative" }
            }
        }
        return $null
    }
    function Get-ItemPathProblem([string] $File, [string] $Value, [bool] $IsProject) {
        foreach ($raw in $Value.Split(";")) {
            $path = $raw.Trim()
            if (-not $path) { continue }
            if ($path -match '[\$@%]') { return "Item path must be literal (no properties, items, metadata, or escapes): $path" }
            $normalized = $path.Replace("\", "/")
            if ($normalized.StartsWith("/") -or $normalized -match '^[A-Za-z]:' -or [IO.Path]::IsPathRooted($normalized)) {
                return "Item path must be relative to the repository: $path"
            }
            $segments = $normalized.Split("/")
            if ($segments -contains "..") { return "Item path must not contain '..': $path" }
            if (@($segments | Where-Object { $_.ToLowerInvariant() -in @("node_modules", "obj", "bin", ".git") }).Count -gt 0) {
                return "Item path must not point into node_modules, obj, bin, or .git: $path"
            }
            if ($normalized -match '[*?]') {
                $prefix = @()
                foreach ($segment in $segments) { if ($segment -match '[*?]') { break }; $prefix += $segment }
                if ($prefix.Count -eq 0) { return "Wildcard item path needs a literal directory prefix: $path" }
                $base = [IO.Path]::GetFullPath((Join-Path (Split-Path -Parent (Join-Path $rootFull $File)) ($prefix -join "/")))
                foreach ($watched in $watchedDirectories) {
                    if ($watched -ceq $base -or $watched.StartsWith($base + $separator, [StringComparison]::Ordinal)) {
                        return "Wildcard item path would include a project or browser build directory (obj, bin, node_modules): $path"
                    }
                }
            }
        }
        return $null
    }

    foreach ($path in $inventory.forbidden) {
        if ($path.EndsWith("/")) { Add-Lint $path.TrimEnd("/") "Committed build output directory (bin/ or obj/) is not allowed" }
        else { Add-Lint $path "File type is not allowed in a community source repository ($([IO.Path]::GetExtension($path)))" }
    }

    foreach ($file in $inventory.lint) {
        $full = Join-Path $rootFull $file
        $isProject = $file -like "*.csproj"
        if (Test-IsLinkedItem (Get-Item -LiteralPath $full -Force)) { Add-Lint $file "MSBuild file is a filesystem link"; continue }
        try { $document = Read-SafeXml -Path $full -MaxBytes 4194304 }
        catch { Add-Lint $file "MSBuild file is not valid XML (DTDs are not allowed)" $_.Exception.Message; continue }

        $stack = [Collections.Generic.Stack[object]]::new()
        $stack.Push([pscustomobject]@{ node = $document.DocumentElement; context = "document" })
        while ($stack.Count -gt 0) {
            $entry = $stack.Pop()
            $element = $entry.node
            $name = $element.LocalName
            $context = $entry.context
            # Every decoded attribute value is checked, including Conditions.
            foreach ($attribute in @($element.Attributes)) {
                if ($attribute.Name -ceq "xmlns") { continue }
                $problem = Get-MsBuildValueProblem $attribute.Value
                if ($problem) { Add-Lint $file "$problem (attribute $($attribute.Name) on <$name>)" $attribute.Value }
            }
            $attributeNames = @($element.Attributes | ForEach-Object { $_.Name } | Where-Object { $_ -cne "xmlns" })
            $allowedAttributes = @()
            $childContext = $null
            switch ($context) {
                "document" {
                    if ($name -cne "Project") { Add-Lint $file "Root element must be <Project>"; continue }
                    $allowedAttributes = @("Sdk")
                    $sdk = $element.GetAttribute("Sdk")
                    if ($element.HasAttribute("Sdk") -and $sdk.Trim() -cnotin $script:AllowedProjectSdks) {
                        Add-Lint $file "Project Sdk must be exactly Microsoft.NET.Sdk, Microsoft.NET.Sdk.Web, or Microsoft.NET.Sdk.Razor" $sdk
                    }
                    if ($element.HasAttribute("TreatAsLocalProperty")) {
                        Add-Lint $file "TreatAsLocalProperty lets a project override restore settings" $element.GetAttribute("TreatAsLocalProperty") "rebuild-restore-override"
                    }
                    $childContext = "project"
                }
                { $_ -in @("project", "when") } {
                    switch -CaseSensitive ($name) {
                        "PropertyGroup" { $allowedAttributes = @("Condition", "Label"); $childContext = "properties" }
                        "ItemGroup" { $allowedAttributes = @("Condition", "Label"); $childContext = "items" }
                        "Choose" { $allowedAttributes = @(); $childContext = "choose" }
                        "Import" {
                            if ($context -cne "project") { Add-Lint $file "Element <Import> is not allowed inside <Choose>"; break }
                            $allowedAttributes = @("Project", "Condition", "Label")
                            $target = $element.GetAttribute("Project") -replace '^\$\(MSBuildThisFileDirectory\)', ''
                            if (-not (Test-InRepoTarget $file $target @(".props"))) {
                                Add-Lint $file "Import must be a literal path to a linted .props file in the repository" $element.GetAttribute("Project")
                            }
                        }
                        default { Add-Lint $file "Element <$name> is not allowed"; $allowedAttributes = $attributeNames }
                    }
                }
                "choose" {
                    if ($name -ceq "When") {
                        $allowedAttributes = @("Condition"); $childContext = "when"
                        if (-not $element.HasAttribute("Condition")) { Add-Lint $file "<When> needs a Condition" }
                    }
                    elseif ($name -ceq "Otherwise") { $allowedAttributes = @(); $childContext = "when" }
                    else { Add-Lint $file "Element <$name> is not allowed inside <Choose>"; $allowedAttributes = $attributeNames }
                }
                "properties" {
                    $allowedAttributes = @("Condition")
                    $value = $element.InnerText.Trim()
                    if ($element.SelectNodes("*").Count -gt 0) { Add-Lint $file "Property $name must contain only text" }
                    if ($name -in $script:RestoreOverrideProperties) {
                        Add-Lint $file "Property $name overrides how the rebuild restores packages" $value "rebuild-restore-override"
                    }
                    elseif ($name -ceq "RestorePackagesWithLockFile" -and $value -cne "true") {
                        Add-Lint $file "Property RestorePackagesWithLockFile overrides how the rebuild restores packages; it must be true" $value "rebuild-restore-override"
                    }
                    elseif (-not $script:AllowedMsBuildProperties.Contains($name)) {
                        Add-Lint $file "Property $name is not in the allowed list" $value
                    }
                    elseif ($null -ne $script:AllowedMsBuildProperties[$name] -and $value -notmatch $script:AllowedMsBuildProperties[$name]) {
                        Add-Lint $file "Property $name must match $($script:AllowedMsBuildProperties[$name])" $value
                    }
                    $problem = Get-MsBuildValueProblem $element.InnerText
                    if ($problem) { Add-Lint $file "$problem (property $name)" $value }
                }
                "items" {
                    if ($name -cnotin $script:AllowedItemTypes) {
                        Add-Lint $file "Item type $name is not allowed"
                        $allowedAttributes = $attributeNames
                        break
                    }
                    $metadata = [ordered]@{}
                    foreach ($attributeName in $attributeNames) {
                        if ($attributeName -notin @("Include", "Update", "Remove", "Exclude", "Condition")) {
                            $metadata[$attributeName] = $element.GetAttribute($attributeName)
                        }
                    }
                    foreach ($child in @($element.SelectNodes("*"))) {
                        foreach ($childAttribute in @($child.Attributes)) {
                            if ($childAttribute.Name -cne "Condition") { Add-Lint $file "Attribute $($childAttribute.Name) is not allowed on metadata <$($child.LocalName)>" }
                            $problem = Get-MsBuildValueProblem $childAttribute.Value
                            if ($problem) { Add-Lint $file "$problem (metadata condition)" $childAttribute.Value }
                        }
                        if ($child.SelectNodes("*").Count -gt 0) { Add-Lint $file "Metadata $($child.LocalName) must contain only text" }
                        $metadata[$child.LocalName] = $child.InnerText.Trim()
                    }
                    foreach ($key in @($metadata.Keys)) {
                        if ($key -cnotin $script:AllowedItemMetadata -and $key -cnotmatch '^_Parameter[0-9]+$') {
                            Add-Lint $file "Metadata $key is not allowed on <$name>" $metadata[$key]
                        }
                        $problem = Get-MsBuildValueProblem $metadata[$key]
                        if ($problem) { Add-Lint $file "$problem (metadata $key)" $metadata[$key] }
                        if ($key -in @("Link", "DependentUpon", "PackagePath", "LogicalName") -and $metadata[$key]) {
                            $pathProblem = Get-ItemPathProblem $file $metadata[$key] $isProject
                            if ($pathProblem) { Add-Lint $file "$pathProblem (metadata $key)" $metadata[$key] }
                        }
                    }
                    $allowedAttributes = @("Include", "Update", "Remove", "Exclude", "Condition") + @($metadata.Keys)
                    $specs = @("Include", "Update", "Remove", "Exclude") | Where-Object { $element.HasAttribute($_) }
                    if (@($specs | Where-Object { $_ -in @("Include", "Update", "Remove") }).Count -ne 1) {
                        Add-Lint $file "Item <$name> needs exactly one of Include, Update, or Remove"
                    }
                    foreach ($spec in $specs) {
                        $specValue = $element.GetAttribute($spec)
                        if ($name -in $script:PathItemTypes) {
                            $pathProblem = Get-ItemPathProblem $file $specValue $isProject
                            if ($pathProblem) { Add-Lint $file $pathProblem $specValue; continue }
                            if ($spec -ceq "Include" -and $name -cne "Folder") {
                                if (-not $isProject) {
                                    Add-Lint $file "Items that add files ($name Include) must be declared in a .csproj" $specValue
                                    continue
                                }
                                $untracked = Get-UntrackedItemProblem $file $name $specValue
                                if ($untracked) { Add-Lint $file $untracked $specValue }
                            }
                            continue
                        }
                        $pattern = switch -CaseSensitive ($name) {
                            { $_ -in @("PackageReference", "PackageVersion") } { '^[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}$' }
                            "FrameworkReference" { '^Microsoft\.[A-Za-z0-9.]+$' }
                            "ProjectReference" { $null }
                            default { '^[A-Za-z_][A-Za-z0-9_.]*$' }
                        }
                        if ($name -ceq "ProjectReference") {
                            if ($spec -cne "Include" -or -not (Test-InRepoTarget $file $specValue @(".csproj"))) {
                                Add-Lint $file "ProjectReference must be a literal path to a linted project in the repository" $specValue
                            }
                        }
                        elseif ($specValue -cnotmatch $pattern) { Add-Lint $file "$name value is not allowed" $specValue }
                    }
                    if ($metadata.Contains("Version") -and $name -in @("PackageReference", "PackageVersion") -and
                        $metadata["Version"] -cnotmatch '^[\[\(]?[0-9A-Za-z.+-]+(\s*,\s*[0-9A-Za-z.+-]*)?[\]\)]?$') {
                        Add-Lint $file "Package version must be literal" $metadata["Version"]
                    }
                    foreach ($copyKey in @("CopyToOutputDirectory", "CopyToPublishDirectory")) {
                        if (-not $metadata.Contains($copyKey)) { continue }
                        $copyValue = [string]$metadata[$copyKey]
                        if ($copyValue -cnotin @("Never", "Always", "PreserveNewest", "IfDifferent")) {
                            Add-Lint $file "$copyKey value is not allowed" $copyValue; continue
                        }
                        if ($copyValue -ceq "Never") { continue }
                        $include = $element.GetAttribute("Include")
                        $ok = $isProject -and $name -in $script:PathItemTypes -and $include -and $include -notmatch '[*?;\$@%]'
                        if ($ok) {
                            $copied = [IO.Path]::GetFullPath((Join-Path (Split-Path -Parent $full) $include.Replace("\", "/")))
                            $copiedItem = Get-Item -LiteralPath $copied -Force -ErrorAction SilentlyContinue
                            $ok = $copied.StartsWith($rootFull + $separator, [StringComparison]::Ordinal) -and
                                $null -ne $copiedItem -and $copiedItem -is [IO.FileInfo] -and -not (Test-IsLinkedItem $copiedItem) -and
                                (Test-IsSourceTextName $copied) -and $null -eq (Get-BinaryMagicKind -Path $copied)
                        }
                        if (-not $ok) {
                            Add-Lint $file "Copied item must be one literal committed text or image file in a .csproj" $include
                        }
                    }
                }
            }
            foreach ($attributeName in $attributeNames) {
                if ($attributeName -cnotin $allowedAttributes) {
                    $rule = if ($attributeName -ceq "TreatAsLocalProperty") { "rebuild-restore-override" } else { "rebuild-msbuild-code" }
                    if ($attributeName -cne "TreatAsLocalProperty") {
                        Add-Lint $file "Attribute $attributeName is not allowed on <$name>" $element.GetAttribute($attributeName) $rule
                    }
                }
            }
            foreach ($child in @($element.ChildNodes)) {
                if ($child -is [Xml.XmlElement]) {
                    if ($null -ne $childContext) { $stack.Push([pscustomobject]@{ node = $child; context = $childContext }) }
                    elseif ($context -notin @("properties", "items")) { Add-Lint $file "Element <$($child.LocalName)> is not allowed inside <$name>" }
                }
                elseif ($child -is [Xml.XmlText] -or $child -is [Xml.XmlCDataSection]) {
                    if ($context -notin @("properties") -and $child.Value.Trim()) {
                        Add-Lint $file "Text is not allowed inside <$name>"
                    }
                }
                elseif ($child -is [Xml.XmlProcessingInstruction]) { Add-Lint $file "Processing instructions are not allowed" }
            }
        }
    }
    return $findings.ToArray()
}

function Invoke-TrustedGit {
    <#
      Runs host git with no system, global, or user configuration and with
      command-executing settings forced off, so nothing a contributor wrote
      can run on the host. -GitDirectory points at a snapshot of .git taken
      before any contributor code ran; the live .git is sandbox-writable.
    #>
    param(
        [Parameter(Mandatory)][string] $WorkTree,
        [Parameter(Mandatory)][string[]] $Arguments,
        [string] $GitDirectory = ""
    )
    $emptyHome = Join-Path ([IO.Path]::GetTempPath()) "zeus-git-home-$([Guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $emptyHome | Out-Null
    $saved = @{}
    $overrides = @{
        HOME = $emptyHome; XDG_CONFIG_HOME = $emptyHome; GIT_CONFIG_NOSYSTEM = "1"; GIT_CONFIG_GLOBAL = "/dev/null"
        GIT_TERMINAL_PROMPT = "0"; GIT_OPTIONAL_LOCKS = "0"; GIT_PAGER = "cat"; GIT_EXTERNAL_DIFF = ""
        GIT_DIR = ""; GIT_WORK_TREE = ""; GIT_INDEX_FILE = ""; GIT_CONFIG_COUNT = ""; GIT_CONFIG_PARAMETERS = ""
    }
    foreach ($key in $overrides.Keys) {
        $saved[$key] = [Environment]::GetEnvironmentVariable($key)
        $value = $overrides[$key]
        if ($value -eq "") { [Environment]::SetEnvironmentVariable($key, [NullString]::Value) }
        else { [Environment]::SetEnvironmentVariable($key, $value) }
    }
    try {
        $gitArguments = @("-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", "-c", "core.hooksPath=/dev/null",
            "-c", "core.attributesFile=/dev/null", "-c", "status.showUntrackedFiles=all")
        if ($GitDirectory) { $gitArguments += @("--git-dir=$GitDirectory", "--work-tree=$WorkTree") }
        else { $gitArguments += @("-C", $WorkTree) }
        $output = & git @gitArguments @Arguments
        $code = $LASTEXITCODE
        return [pscustomobject]@{ output = (@($output) -join "`n"); exitCode = $code }
    }
    finally {
        foreach ($key in $saved.Keys) {
            if ($null -eq $saved[$key]) { [Environment]::SetEnvironmentVariable($key, [NullString]::Value) }
            else { [Environment]::SetEnvironmentVariable($key, $saved[$key]) }
        }
        Remove-Item -LiteralPath $emptyHome -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Get-TrackedFiles {
    param([Parameter(Mandatory)][string] $Root, [string] $GitDirectory = "")
    $result = Invoke-TrustedGit -WorkTree $Root -GitDirectory $GitDirectory -Arguments @("ls-files", "-z")
    if ($result.exitCode -ne 0) { throw "Could not list tracked files in $Root" }
    return @($result.output -split "`0" | Where-Object { $_ })
}

function Get-ProjectDirectories {
    <# Full paths of every directory that holds a .csproj in the source tree. #>
    param([Parameter(Mandatory)][string] $Root)
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar)
    return @((Get-MsBuildLintFiles -Root $rootFull).lint | Where-Object { $_ -like "*.csproj" } |
        ForEach-Object { [IO.Path]::GetDirectoryName((Join-Path $rootFull $_)).TrimEnd([IO.Path]::DirectorySeparatorChar) } |
        Sort-Object -Unique)
}

function Test-IsUnderDirectory {
    param([Parameter(Mandatory)][string] $Path, [Parameter(Mandatory)][string] $Directory)
    $separator = [IO.Path]::DirectorySeparatorChar
    $p = [IO.Path]::GetFullPath($Path).TrimEnd($separator)
    $d = [IO.Path]::GetFullPath($Directory).TrimEnd($separator)
    return $p -ceq $d -or $p.StartsWith($d + $separator, [StringComparison]::Ordinal)
}

function Get-NodeProjectOverlapFindings {
    <#
      Browser build directories and .NET project directories must be
      disjoint, so SDK default item globs can never pick up npm output or
      node_modules.
    #>
    param(
        [Parameter(Mandatory)][string] $Root,
        [AllowEmptyCollection()][string[]] $NodeDirectories = @()
    )
    $findings = [Collections.Generic.List[object]]::new()
    $projects = @(Get-ProjectDirectories -Root $Root)
    foreach ($node in @($NodeDirectories | Where-Object { $_ })) {
        foreach ($project in $projects) {
            if ((Test-IsUnderDirectory -Path $node -Directory $project) -or (Test-IsUnderDirectory -Path $project -Directory $node)) {
                $findings.Add((New-SecurityFinding -Check "rebuild" -RuleId "rebuild-node-in-project" -Severity fail `
                    -File ([IO.Path]::GetRelativePath($Root, $node).Replace("\", "/")) `
                    -Detail "Browser build directory overlaps the .NET project directory $([IO.Path]::GetRelativePath($Root, $project).Replace('\', '/')); keep them in separate directories"))
            }
        }
    }
    return $findings.ToArray()
}

function Get-UntrackedSourceFindings {
    <#
      Run by trusted code after the browser build and before restore and
      build: every file under a project directory must be exactly the
      committed file, except the project's own obj/ and bin/. Untracked,
      ignored, and modified files fail; deletions (mapped outputs removed
      before the build) cannot feed the compiler and are skipped.
    #>
    param(
        [Parameter(Mandatory)][string] $Root,
        [Parameter(Mandatory)][string] $GitDirectory,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]] $ProjectDirectories
    )
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $result = Invoke-TrustedGit -WorkTree $rootFull -GitDirectory $GitDirectory `
        -Arguments @("status", "--porcelain=v1", "--ignored", "--untracked-files=all", "-z")
    if ($result.exitCode -ne 0) { throw "Could not read the source tree status" }
    $findings = [Collections.Generic.List[object]]::new()
    $records = @($result.output -split "`0")
    for ($i = 0; $i -lt $records.Count; $i++) {
        $record = $records[$i]
        if ($record.Length -lt 4) { continue }
        $status = $record.Substring(0, 2)
        $path = $record.Substring(3)
        if ($status[0] -in @([char]'R', [char]'C')) { $i++ }
        if ($status -in @(" D", "D ", "DD")) { continue }
        $full = [IO.Path]::GetFullPath((Join-Path $rootFull $path))
        foreach ($project in $ProjectDirectories) {
            if (-not (Test-IsUnderDirectory -Path $full -Directory $project)) { continue }
            if ((Test-IsUnderDirectory -Path $full -Directory (Join-Path $project "obj")) -or
                (Test-IsUnderDirectory -Path $full -Directory (Join-Path $project "bin"))) { continue }
            $what = switch ($status) { "??" { "untracked" } "!!" { "ignored" } default { "modified ($status)" } }
            $findings.Add((New-SecurityFinding -Check "rebuild" -RuleId "rebuild-untracked-source" -Severity fail `
                -File $path.TrimEnd("/") -Detail "A $what file is inside a .NET project directory before the build; only committed files may be compiled or packaged"))
            break
        }
    }
    return $findings.ToArray()
}

function Get-TrustedMSBuildGlobals {
    <#
      Global properties passed to every sandboxed restore and build. Global
      properties beat project values, so these pin the compiler and target
      imports to the installed SDK even if a project tried to redirect them.
    #>
    param([Parameter(Mandatory)][string] $SdkDirectory)
    $sdk = [IO.Path]::GetFullPath($SdkDirectory).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $roslyn = Join-Path $sdk "Roslyn"
    foreach ($required in @((Join-Path $roslyn "Microsoft.CSharp.Core.targets"), (Join-Path $sdk "Microsoft.CSharp.targets"))) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw "The installed SDK lacks $required" }
    }
    $globals = [ordered]@{
        DisableImplicitNuGetFallbackFolder = "true"
        CscToolPath = ""
        CscToolExe = ""
        RoslynTargetsPath = $roslyn
        CSharpCoreTargetsPath = Join-Path $roslyn "Microsoft.CSharp.Core.targets"
        LanguageTargets = Join-Path $sdk "Microsoft.CSharp.targets"
        CustomBeforeMicrosoftCommonProps = ""
        CustomAfterMicrosoftCommonProps = ""
        CustomBeforeMicrosoftCommonTargets = ""
        CustomAfterMicrosoftCommonTargets = ""
        CustomBeforeMicrosoftCSharpTargets = ""
        CustomAfterMicrosoftCSharpTargets = ""
        ImportDirectoryBuildTargets = "false"
    }
    foreach ($when in @("Before", "After")) {
        foreach ($what in @("MicrosoftCommonTargets", "MicrosoftCSharpTargets", "MicrosoftNetFrameworkProps",
                "MicrosoftNetFrameworkTargets", "MicrosoftVisualBasicTargets")) {
            $globals["ImportUserLocationsByWildcard$when$what"] = "false"
        }
    }
    return @($globals.GetEnumerator() | ForEach-Object { "-p:$($_.Key)=$($_.Value)" })
}

function Get-DotnetRoot {
    <# Directory that holds the dotnet host and its SDKs, packs, and library-packs. #>
    if ($env:DOTNET_ROOT -and (Test-Path -LiteralPath $env:DOTNET_ROOT -PathType Container)) {
        return [IO.Path]::GetFullPath($env:DOTNET_ROOT).TrimEnd([IO.Path]::DirectorySeparatorChar)
    }
    $dotnet = Get-Command dotnet -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $dotnet) { throw "dotnet is not installed" }
    $item = Get-Item -LiteralPath $dotnet.Source
    $real = if ($item.LinkTarget) { $item.ResolveLinkTarget($true).FullName } else { $item.FullName }
    return [IO.Path]::GetDirectoryName($real)
}

function Test-IsSdkProvidedPackage {
    <#
      A Microsoft./System. package is exempt only when it came from the
      verified feed or from inside the installed .NET directory (packs,
      library-packs, SDK fallback folders).
    #>
    param(
        [Parameter(Mandatory)][string] $Id,
        [Parameter(Mandatory)][string] $Version,
        [Parameter(Mandatory)][string] $PackagesFolder,
        [Parameter(Mandatory)][string] $SdkRoot,
        [AllowEmptyCollection()][string[]] $PackageFolders = @()
    )
    $sdkPrefix = [IO.Path]::GetFullPath($SdkRoot).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $relative = Join-Path $Id.ToLowerInvariant() $Version.ToLowerInvariant()
    foreach ($folder in $PackageFolders) {
        if (-not $folder) { continue }
        $full = [IO.Path]::GetFullPath($folder)
        if ($full.StartsWith($sdkPrefix, [StringComparison]::Ordinal) -and
            (Test-Path -LiteralPath (Join-Path $full $relative) -PathType Container)) { return $true }
    }
    $metadata = Join-Path (Join-Path $PackagesFolder $relative) ".nupkg.metadata"
    if (Test-Path -LiteralPath $metadata -PathType Leaf) {
        try { $source = [string](Get-Content -Raw -LiteralPath $metadata | ConvertFrom-Json -Depth 5).source }
        catch { return $false }
        if ($source -and -not $source.Contains("://") -and
            [IO.Path]::GetFullPath($source).TrimEnd([IO.Path]::DirectorySeparatorChar).StartsWith(
                $sdkPrefix.TrimEnd([IO.Path]::DirectorySeparatorChar), [StringComparison]::Ordinal)) {
            return $true
        }
    }
    return $false
}

function Get-LinkFindings {
    <# Any symbolic link in a tree that will be uploaded fails. #>
    param([Parameter(Mandatory)][string] $Directory, [string] $Label = "rebuilt tree")
    $findings = [Collections.Generic.List[object]]::new()
    $root = [IO.Path]::GetFullPath($Directory)
    $pending = [Collections.Generic.Stack[string]]::new()
    $pending.Push($root)
    while ($pending.Count -gt 0) {
        foreach ($item in [IO.DirectoryInfo]::new($pending.Pop()).EnumerateFileSystemInfos()) {
            if (Test-IsLinkedItem $item) {
                $findings.Add((New-SecurityFinding -Check "rebuild" -RuleId "rebuild-staged-link" -Severity fail `
                    -File ([IO.Path]::GetRelativePath($root, $item.FullName).Replace("\", "/")) `
                    -Detail "The $Label contains a symbolic link"))
            }
            elseif ($item -is [IO.DirectoryInfo]) { $pending.Push($item.FullName) }
        }
    }
    return $findings.ToArray()
}

function Get-NpmShrinkwrapFindings {
    <# npm-shrinkwrap.json overrides package-lock.json and is not verified, so it fails. #>
    param([Parameter(Mandatory)][string] $Root, [Parameter(Mandatory)][string] $Directory)
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $current = [IO.Path]::GetFullPath($Directory).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $findings = [Collections.Generic.List[object]]::new()
    while ($true) {
        $shrinkwrap = Join-Path $current "npm-shrinkwrap.json"
        if ($null -ne (Get-Item -LiteralPath $shrinkwrap -Force -ErrorAction SilentlyContinue)) {
            $findings.Add((New-SecurityFinding -Check "rebuild" -RuleId "rebuild-npm-shrinkwrap" -Severity fail `
                -File ([IO.Path]::GetRelativePath($rootFull, $shrinkwrap).Replace("\", "/")) `
                -Detail "npm-shrinkwrap.json is not allowed; commit package-lock.json instead"))
        }
        if ($current -ceq $rootFull -or -not $current.StartsWith($rootFull, [StringComparison]::Ordinal)) { break }
        $current = Split-Path -Parent $current
    }
    return $findings.ToArray()
}

function Get-SandboxEnvironment {
    param([Parameter(Mandatory)][string] $PrivateRoot)
    $environment = [ordered]@{
        PATH = $env:PATH
        HOME = Join-Path $PrivateRoot "home"
        DOTNET_CLI_HOME = Join-Path $PrivateRoot "home"
        NUGET_PACKAGES = Join-Path $PrivateRoot "nuget-packages"
        NUGET_HTTP_CACHE_PATH = Join-Path $PrivateRoot "nuget-http"
        npm_config_cache = Join-Path $PrivateRoot "npm-cache"
        TMPDIR = "/tmp"
        LANG = "C.UTF-8"
        DOTNET_CLI_TELEMETRY_OPTOUT = "1"
        DOTNET_NOLOGO = "1"
        DOTNET_SKIP_FIRST_TIME_EXPERIENCE = "1"
        DOTNET_GENERATE_ASPNET_CERTIFICATE = "false"
        MSBUILDDISABLENODEREUSE = "1"
        npm_config_ignore_scripts = "true"
        npm_config_audit = "false"
        npm_config_fund = "false"
        npm_config_update_notifier = "false"
    }
    if ($env:DOTNET_ROOT) { $environment.DOTNET_ROOT = $env:DOTNET_ROOT }
    return $environment
}

function Get-SandboxArguments {
    <#
      bubblewrap: read-only host filesystem, fresh /tmp and /run, writable
      source tree and private home only, every namespace unshared (no
      network, own PID namespace so nothing outlives the sandbox), all
      capabilities dropped, and a minimal explicit environment.
    #>
    param(
        [Parameter(Mandatory)][string] $SourceRoot,
        [Parameter(Mandatory)][string] $PrivateRoot,
        [Parameter(Mandatory)][string] $WorkingDirectory,
        [Parameter(Mandatory)][string[]] $Command,
        [AllowEmptyCollection()][string[]] $ReadOnlyPaths = @()
    )
    $arguments = [Collections.Generic.List[string]]::new()
    $arguments.AddRange([string[]]@(
        "--ro-bind", "/", "/",
        "--dev", "/dev",
        "--proc", "/proc",
        "--tmpfs", "/tmp",
        "--tmpfs", "/run",
        "--bind", $SourceRoot, $SourceRoot,
        "--bind", $PrivateRoot, $PrivateRoot
    ))
    # Trusted inputs (the verified feed, our nuget.config) are re-exposed
    # read-only after the private /tmp and /run mounts, so they stay
    # visible when the work tree lives below /tmp.
    foreach ($path in @($ReadOnlyPaths | Where-Object { $_ })) {
        $full = [IO.Path]::GetFullPath($path)
        if (-not (Test-Path -LiteralPath $full)) { throw "Read-only sandbox input does not exist: $full" }
        $arguments.AddRange([string[]]@("--ro-bind", $full, $full))
    }
    $arguments.AddRange([string[]]@(
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--cap-drop", "ALL",
        "--clearenv"
    ))
    foreach ($entry in (Get-SandboxEnvironment -PrivateRoot $PrivateRoot).GetEnumerator()) {
        $arguments.AddRange([string[]]@("--setenv", $entry.Key, [string]$entry.Value))
    }
    $arguments.AddRange([string[]]@("--chdir", $WorkingDirectory, "--"))
    $arguments.AddRange($Command)
    return $arguments.ToArray()
}

function Get-Bubblewrap {
    $bwrap = Get-Command bwrap -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $bwrap) { throw "The offline rebuild requires bubblewrap (bwrap)" }
    return $bwrap.Source
}

function Initialize-SandboxPrivateRoot {
    param([Parameter(Mandatory)][string] $PrivateRoot)
    foreach ($name in @("home", "nuget-packages", "nuget-http", "npm-cache")) {
        New-Item -ItemType Directory -Path (Join-Path $PrivateRoot $name) -Force | Out-Null
    }
}

function Invoke-Sandboxed {
    param(
        [Parameter(Mandatory)][string] $SourceRoot,
        [Parameter(Mandatory)][string] $PrivateRoot,
        [Parameter(Mandatory)][string] $WorkingDirectory,
        [Parameter(Mandatory)][string[]] $Command,
        [AllowEmptyCollection()][string[]] $ReadOnlyPaths = @()
    )
    $bwrap = Get-Bubblewrap
    Initialize-SandboxPrivateRoot -PrivateRoot $PrivateRoot
    $arguments = Get-SandboxArguments -SourceRoot $SourceRoot -PrivateRoot $PrivateRoot `
        -WorkingDirectory $WorkingDirectory -Command $Command -ReadOnlyPaths $ReadOnlyPaths
    & $bwrap @arguments | Out-Host
    return $LASTEXITCODE
}

function Assert-SandboxIsolation {
    <#
      Fails closed unless a probe run through the exact sandbox proves: own
      PID and network namespaces, loopback only, no TCP, no name resolution,
      no host resolver or docker socket, no capabilities, no write access to
      any host directory outside the source tree and private root, and a
      private /tmp.
    #>
    param(
        [Parameter(Mandatory)][string] $SourceRoot,
        [Parameter(Mandatory)][string] $PrivateRoot,
        [Parameter(Mandatory)][string[]] $HostWriteProbes
    )
    $bwrap = Get-Bubblewrap
    Initialize-SandboxPrivateRoot -PrivateRoot $PrivateRoot
    $token = "zeus-sandbox-probe-$([Guid]::NewGuid().ToString('N'))"
    $hostPid = (Get-Item -LiteralPath /proc/self/ns/pid).LinkTarget
    $hostNet = (Get-Item -LiteralPath /proc/self/ns/net).LinkTarget
    $writable = @($SourceRoot, $PrivateRoot) | ForEach-Object {
        [IO.Path]::GetFullPath($_).TrimEnd([IO.Path]::DirectorySeparatorChar) }
    $probes = @($HostWriteProbes | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Container) } |
        ForEach-Object { [IO.Path]::GetFullPath($_).TrimEnd([IO.Path]::DirectorySeparatorChar) } |
        Where-Object {
            $candidate = $_
            -not @($writable | Where-Object {
                $candidate -ceq $_ -or $candidate.StartsWith($_ + [IO.Path]::DirectorySeparatorChar, [StringComparison]::Ordinal)
            })
        } | Sort-Object -Unique)
    if ($probes.Count -eq 0) { throw "No host directories were available to prove the sandbox is read-only" }
    $script = @'
token=$1; hostpid=$2; hostnet=$3; shift 3
[ "$(readlink /proc/self/ns/pid)" != "$hostpid" ] || { echo "shares the host PID namespace"; exit 20; }
[ "$(readlink /proc/self/ns/net)" != "$hostnet" ] || { echo "shares the host network namespace"; exit 21; }
interfaces=$(awk 'NR>2 { sub(/:.*/, "", $1); print $1 }' /proc/net/dev | tr -d ' ' | sort | tr '\n' ' ')
[ "$interfaces" = "lo " ] || { echo "network interfaces present: $interfaces"; exit 10; }
if command -v bash >/dev/null 2>&1; then
  if timeout 5 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' 2>/dev/null; then echo "tcp reachable"; exit 11; fi
  if timeout 5 bash -c 'exec 3<>/dev/tcp/140.82.112.3/443' 2>/dev/null; then echo "tcp reachable"; exit 11; fi
fi
if timeout 5 getent hosts github.com >/dev/null 2>&1; then echo "name resolution works"; exit 12; fi
[ -e /run/systemd/resolve ] && { echo "resolver socket visible"; exit 13; }
[ -e /var/run/docker.sock ] && { echo "docker socket visible"; exit 14; }
grep -q '^CapEff:[[:space:]]*0*$' /proc/self/status || { echo "capabilities retained"; exit 15; }
verified=0
while [ "$#" -ge 2 ]; do
  dir=$1; id=$2; shift 2
  # Only the host directory itself matters. Under a sandbox tmpfs (for
  # example a work tree below /tmp) a path can name a private stand-in
  # instead; writing there never reaches the host.
  [ "$(stat -c %d:%i "$dir" 2>/dev/null)" = "$id" ] || continue
  if ( : > "$dir/$token" ) 2>/dev/null; then echo "wrote host directory $dir"; exit 16; fi
  verified=$((verified + 1))
done
[ "$verified" -gt 0 ] || { echo "no host directory was visible to prove the host filesystem is read-only"; exit 19; }
( : > "/tmp/$token" ) 2>/dev/null || { echo "private /tmp is not writable"; exit 17; }
( : > "$HOME/$token" ) 2>/dev/null || { echo "private home is not writable"; exit 18; }
echo "$token"
'@
    # Pair every probe directory with its host device:inode identity.
    $identities = foreach ($probe in $probes) {
        $statOutput = @(& stat -c '%d:%i' -- $probe 2>$null)
        $statCode = $LASTEXITCODE
        $identity = if ($statOutput.Count -gt 0) { [string]$statOutput[0] } else { "" }
        if ($statCode -ne 0 -or $identity -cnotmatch '^[0-9]+:[0-9]+$') { throw "Could not read the identity of $probe" }
        $probe
        [string]$identity
    }
    $command = @("sh", "-c", $script, "zeus-probe", $token, $hostPid, $hostNet) + @($identities)
    $arguments = Get-SandboxArguments -SourceRoot $SourceRoot -PrivateRoot $PrivateRoot `
        -WorkingDirectory $SourceRoot -Command $command
    $output = @(& $bwrap @arguments 2>&1 | ForEach-Object { [string]$_ })
    $code = $LASTEXITCODE
    $leaks = @(@($probes + "/tmp") | Sort-Object -Unique |
        ForEach-Object { Join-Path $_ $token } | Where-Object { Test-Path -LiteralPath $_ })
    foreach ($leak in $leaks) { Remove-Item -LiteralPath $leak -Force }
    $privateMarker = Join-Path (Join-Path $PrivateRoot "home") $token
    $privateWritten = Test-Path -LiteralPath $privateMarker
    if ($privateWritten) { Remove-Item -LiteralPath $privateMarker -Force }
    if ($code -ne 0 -or ($output -cnotcontains $token) -or $leaks.Count -gt 0 -or -not $privateWritten) {
        throw "Could not prove the build sandbox is isolated (exit $code, leaked: $($leaks -join ', ')): $($output -join ' ')"
    }
    Write-Host "Build sandbox verified: own PID and network namespaces, loopback only, no name resolution, no host sockets, no capabilities, host filesystem read-only."
}

Export-ModuleMember -Function `
    Get-BuildDirectoryName, `
    Assert-SafeRelativePath, `
    Assert-NoLinkedComponents, `
    Resolve-SourcePath, `
    Read-PinnedSdkVersion, `
    Read-BuildContract, `
    Test-IsBuildOutputName, `
    Get-BinaryMagicKind, `
    Test-IsSourceTextName, `
    Test-KeepCommittedFile, `
    Get-TrackedBinaryFindings, `
    Test-IsExemptPackage, `
    Read-RebuildPackageAllowlist, `
    Get-NuGetLockPackages, `
    Get-UnlockedProjectFindings, `
    Get-NuGetContentHash, `
    New-VerifiedNuGetFeed, `
    New-TrustedNuGetConfig, `
    Get-FeedBuildTimePackageFindings, `
    Get-AssetsFilePackageFindings, `
    ConvertTo-RebuildVerdict, `
    Remove-ContributorNpmConfig, `
    Get-NpmCiArguments, `
    Get-NpmLockFindings, `
    Get-MsBuildLintFiles, `
    Get-MsBuildLintFindings, `
    Get-MsBuildValueProblem, `
    Get-TrustedMSBuildGlobals, `
    Invoke-TrustedGit, `
    Get-TrackedFiles, `
    Get-ProjectDirectories, `
    Get-NodeProjectOverlapFindings, `
    Get-UntrackedSourceFindings, `
    Get-DotnetRoot, `
    Test-IsSdkProvidedPackage, `
    Get-LinkFindings, `
    Get-NpmShrinkwrapFindings, `
    Get-SandboxEnvironment, `
    Get-SandboxArguments, `
    Invoke-Sandboxed, `
    Assert-SandboxIsolation
