# SPDX-License-Identifier: GPL-2.0-or-later
# Regression tests for the source rebuild hardening: binary detection by
# header, the keep-committed-file rule, the verified NuGet feed, build-time
# package detection, the no-review-tier verdict, and (on Linux with
# bubblewrap) the build sandbox itself. No network access is used.
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot "SecurityScan.psm1") -Force
Import-Module (Join-Path $PSScriptRoot "SourceRebuild.psm1") -Force

$tempRoot = Join-Path ([IO.Path]::GetTempPath()) "zeus-rebuild-hardening-$([Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $tempRoot | Out-Null

function Assert-Equal {
    param($Actual, $Expected, [string] $Label)
    if ([string]$Actual -cne [string]$Expected) { throw "${Label}: expected '$Expected', got '$Actual'" }
}

function Assert-Throws {
    param([Parameter(Mandatory)][scriptblock] $Block, [Parameter(Mandatory)][string] $Label, [string] $Pattern = "")
    $thrown = $false
    try { & $Block | Out-Null }
    catch {
        $thrown = (-not $Pattern) -or ($_.Exception.Message -match $Pattern)
        if (-not $thrown) { throw "${Label}: unexpected error '$($_.Exception.Message)'" }
    }
    if (-not $thrown) { throw "${Label}: expected an error" }
}

function Write-Bytes {
    param([string] $Path, [byte[]] $Bytes)
    New-Item -ItemType Directory -Path (Split-Path -Parent $Path) -Force | Out-Null
    [IO.File]::WriteAllBytes($Path, $Bytes)
}

function New-Nupkg {
    param([string] $Path, [string[]] $Entries)
    New-Item -ItemType Directory -Path (Split-Path -Parent $Path) -Force | Out-Null
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Create)
    $archive = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Create, $false)
    try {
        foreach ($name in $Entries) {
            $writer = [IO.StreamWriter]::new($archive.CreateEntry($name).Open())
            try { $writer.Write("fixture") } finally { $writer.Dispose() }
        }
    }
    finally { $archive.Dispose(); $stream.Dispose() }
    $sha = [Security.Cryptography.SHA512]::Create()
    try { return [Convert]::ToBase64String($sha.ComputeHash([IO.File]::ReadAllBytes($Path))) }
    finally { $sha.Dispose() }
}

function New-TrackedSet {
    param([string[]] $Paths)
    return , [Collections.Generic.HashSet[string]]::new([string[]]$Paths, [StringComparer]::Ordinal)
}

try {
    # --- Binary detection by header, regardless of extension.
    $magic = [ordered]@{
        "pe.txt" = [byte[]](0x4D, 0x5A, 0x90, 0x00)
        "elf.md" = [byte[]](0x7F, 0x45, 0x4C, 0x46, 0x02)
        "macho.css" = [byte[]](0xCF, 0xFA, 0xED, 0xFE, 0x07)
        "zip.json" = [byte[]](0x50, 0x4B, 0x03, 0x04, 0x14)
        "gz.png" = [byte[]](0x1F, 0x8B, 0x08, 0x00)
        "wasm.ico" = [byte[]](0x00, 0x61, 0x73, 0x6D, 0x01)
    }
    foreach ($entry in $magic.GetEnumerator()) {
        $path = Join-Path $tempRoot "magic/$($entry.Key)"
        Write-Bytes -Path $path -Bytes $entry.Value
        if ($null -eq (Get-BinaryMagicKind -Path $path)) { throw "Binary header not detected: $($entry.Key)" }
    }
    $text = Join-Path $tempRoot "magic/plain.txt"
    Set-Content -LiteralPath $text -Value "MIT License"
    if ($null -ne (Get-BinaryMagicKind -Path $text)) { throw "Plain text reported as binary" }

    # --- Case-insensitive build-output names.
    foreach ($name in @("A.dll", "A.DLL", "sub/B.Dll", "A.deps.json", "A.DEPS.JSON")) {
        if (-not (Test-IsBuildOutputName $name)) { throw "Build output name not recognised: $name" }
    }
    foreach ($name in @("plugin.json", "ui/app.js", "dll.txt")) {
        if (Test-IsBuildOutputName $name) { throw "Non-build file treated as build output: $name" }
    }

    # --- Keep-committed rule: ZIP path, source path, and header must all agree.
    $src = Join-Path $tempRoot "keep"
    New-Item -ItemType Directory -Path (Join-Path $src "web") -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $src "LICENSE") -Value "GPL"
    Set-Content -LiteralPath (Join-Path $src "notes.txt") -Value "text"
    Set-Content -LiteralPath (Join-Path $src "web/app.js") -Value "export default 1"
    Write-Bytes -Path (Join-Path $src "README.md") -Bytes ([byte[]](0x4D, 0x5A, 0x90, 0x00))
    $trackedKeep = New-TrackedSet @("LICENSE", "notes.txt", "web/app.js", "README.md")
    if (-not (Test-KeepCommittedFile -Root $src -ZipPath "LICENSE" -SourcePath "LICENSE" -Tracked $trackedKeep)) {
        throw "A tracked LICENSE was not kept"
    }
    $keepCases = @(
        @{ Label = "code ZIP path from text source"; Zip = "ui/app.js"; Source = "notes.txt" },
        @{ Label = "text ZIP path from code source"; Zip = "notes.txt"; Source = "web/app.js" },
        @{ Label = "executable header behind a text name"; Zip = "README.md"; Source = "README.md" }
    )
    foreach ($case in $keepCases) {
        if (Test-KeepCommittedFile -Root $src -ZipPath $case.Zip -SourcePath $case.Source -Tracked $trackedKeep) {
            throw "Keep-committed rule accepted $($case.Label)"
        }
    }
    if (Test-KeepCommittedFile -Root $src -ZipPath "LICENSE" -SourcePath "LICENSE" -Tracked (New-TrackedSet @())) {
        throw "An untracked file was kept"
    }

    # --- Tracked binaries fail, by header or by extension.
    $bin = Join-Path $tempRoot "tracked"
    Write-Bytes -Path (Join-Path $bin "docs/readme.txt") -Bytes ([byte[]](0x7F, 0x45, 0x4C, 0x46, 0x02))
    Write-Bytes -Path (Join-Path $bin "tools/helper.bin") -Bytes ([byte[]](0x4D, 0x5A, 0x00, 0x00))
    Set-Content -LiteralPath (Join-Path $bin "lib.DLL") -Value "not really a dll"
    Set-Content -LiteralPath (Join-Path $bin "src.cs") -Value "class A {}"
    $binaryFindings = @(Get-TrackedBinaryFindings -Root $bin -Tracked @("docs/readme.txt", "tools/helper.bin", "lib.DLL", "src.cs"))
    Assert-Equal (($binaryFindings | ForEach-Object { "$($_.severity):$($_.file)" } | Sort-Object) -join ",") `
        "fail:docs/readme.txt,fail:lib.DLL,fail:tools/helper.bin" "tracked binary findings"

    # --- Verified NuGet feed from packages.lock.json.
    $lockRoot = Join-Path $tempRoot "lock"
    New-Item -ItemType Directory -Path (Join-Path $lockRoot "src") -Force | Out-Null
    $packageSource = Join-Path $tempRoot "packages"
    $goodHash = New-Nupkg -Path (Join-Path $packageSource "example.lib.1.2.3.nupkg") -Entries @("lib/net10.0/Example.Lib.dll")
    $genHash = New-Nupkg -Path (Join-Path $packageSource "example.generator.2.0.0.nupkg") -Entries @("analyzers/dotnet/cs/Gen.dll")
    $msHash = New-Nupkg -Path (Join-Path $packageSource "microsoft.build.tasks.git.1.0.0.nupkg") -Entries @("build/Microsoft.Build.Tasks.Git.targets")
    $runtimeHash = New-Nupkg -Path (Join-Path $packageSource "runtime.evil.native.1.0.0.nupkg") -Entries @("buildTransitive/runtime.evil.targets")
    $lock = [ordered]@{
        version = 1
        dependencies = [ordered]@{
            "net10.0" = [ordered]@{
                "Example.Lib" = [ordered]@{ type = "Direct"; requested = "[1.2.3, )"; resolved = "1.2.3"; contentHash = $goodHash }
                "Example.Generator" = [ordered]@{ type = "Direct"; requested = "[2.0.0, )"; resolved = "2.0.0"; contentHash = $genHash }
                "Microsoft.Build.Tasks.Git" = [ordered]@{ type = "Transitive"; resolved = "1.0.0"; contentHash = $msHash }
                "runtime.evil.native" = [ordered]@{ type = "Transitive"; resolved = "1.0.0"; contentHash = $runtimeHash }
                "Sibling.Project" = [ordered]@{ type = "Project" }
            }
        }
    }
    Set-Content -LiteralPath (Join-Path $lockRoot "src/packages.lock.json") -Value ($lock | ConvertTo-Json -Depth 10)
    Set-Content -LiteralPath (Join-Path $lockRoot "src/F.csproj") -Value '<Project><ItemGroup><PackageReference Include="Example.Lib" /></ItemGroup></Project>'
    $packages = @(Get-NuGetLockPackages -Root $lockRoot)
    Assert-Equal (($packages | ForEach-Object { "$($_.id)/$($_.version)" }) -join ",") `
        "Example.Generator/2.0.0,Example.Lib/1.2.3,Microsoft.Build.Tasks.Git/1.0.0,runtime.evil.native/1.0.0" "locked packages"
    $urls = [Collections.Generic.List[string]]::new()
    $localDownload = {
        param($Url, $Destination)
        $urls.Add($Url)
        Copy-Item -LiteralPath (Join-Path $packageSource ([IO.Path]::GetFileName($Destination))) -Destination $Destination
    }
    $feed = New-VerifiedNuGetFeed -Packages $packages -FeedDirectory (Join-Path $tempRoot "feed") -Download $localDownload
    Assert-Equal $urls[1] "https://api.nuget.org/v3-flatcontainer/example.lib/1.2.3/example.lib.1.2.3.nupkg" "nuget.org flat-container URL"
    Assert-Equal @(Get-UnlockedProjectFindings -Root $lockRoot).Count 0 "locked project findings"

    $tampered = @($packages | ForEach-Object { $_.PSObject.Copy() })
    $tampered[1].contentHash = $genHash
    Assert-Throws -Label "contentHash mismatch" -Pattern "contentHash" -Block {
        New-VerifiedNuGetFeed -Packages $tampered -FeedDirectory (Join-Path $tempRoot "feed-tampered") -Download $localDownload
    }
    if (Test-Path -LiteralPath (Join-Path $tempRoot "feed-tampered/example.lib.1.2.3.nupkg")) {
        throw "A package with a mismatched hash was left in the feed"
    }

    foreach ($badLock in @(
        @{ Label = "missing contentHash"; Json = '{"version":1,"dependencies":{"net10.0":{"A":{"type":"Direct","resolved":"1.0.0"}}}}' },
        @{ Label = "floating version"; Json = '{"version":1,"dependencies":{"net10.0":{"A":{"type":"Direct","resolved":"1.*","contentHash":"' + $goodHash + '"}}}}' },
        @{ Label = "path in id"; Json = '{"version":1,"dependencies":{"net10.0":{"../A":{"type":"Direct","resolved":"1.0.0","contentHash":"' + $goodHash + '"}}}}' },
        @{ Label = "unsupported lock version"; Json = '{"version":9,"dependencies":{}}' }
    )) {
        $badRoot = Join-Path $tempRoot "badlock-$([Guid]::NewGuid().ToString('N'))"
        New-Item -ItemType Directory -Path $badRoot | Out-Null
        Set-Content -LiteralPath (Join-Path $badRoot "packages.lock.json") -Value $badLock.Json
        Assert-Throws -Label $badLock.Label -Block { Get-NuGetLockPackages -Root $badRoot }
    }
    $conflictRoot = Join-Path $tempRoot "conflict"
    foreach ($dir in @("a", "b")) {
        New-Item -ItemType Directory -Path (Join-Path $conflictRoot $dir) -Force | Out-Null
        $hash = if ($dir -eq "a") { $goodHash } else { $genHash }
        Set-Content -LiteralPath (Join-Path $conflictRoot "$dir/packages.lock.json") `
            -Value ('{"version":1,"dependencies":{"net10.0":{"A":{"type":"Direct","resolved":"1.0.0","contentHash":"' + $hash + '"}}}}')
    }
    Assert-Throws -Label "conflicting contentHash" -Pattern "disagree" -Block { Get-NuGetLockPackages -Root $conflictRoot }

    $unlocked = Join-Path $tempRoot "unlocked"
    New-Item -ItemType Directory -Path (Join-Path $unlocked "src") -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $unlocked "src/F.csproj") -Value '<Project><ItemGroup><PackageReference Include="A" Version="1.0.0" /></ItemGroup></Project>'
    Set-Content -LiteralPath (Join-Path $unlocked "Directory.Packages.props") -Value '<Project><ItemGroup><GlobalPackageReference Include="B" Version="1.0.0" /></ItemGroup></Project>'
    Assert-Equal ((@(Get-UnlockedProjectFindings -Root $unlocked) | ForEach-Object { "$($_.severity):$($_.ruleId):$($_.file)" } | Sort-Object) -join ",") `
        "fail:rebuild-missing-lockfile:Directory.Packages.props,fail:rebuild-missing-lockfile:src/F.csproj" "unlocked project findings"

    # --- Build-time packages (analyzers, generators, targets) fail unless allowlisted.
    $empty = Read-RebuildPackageAllowlist -Path (Join-Path $PSScriptRoot "rebuild-package-allowlist.json")
    Assert-Equal $empty.Count 0 "shipped allowlist entries"
    $buildTime = @(Get-FeedBuildTimePackageFindings -Packages $packages -FeedDirectory $feed -Allowlist $empty)
    # Microsoft. and System. are reserved on nuget.org; runtime. is not exempt.
    Assert-Equal (($buildTime | ForEach-Object { "$($_.severity):$($_.ruleId):$($_.file)" }) -join ",") `
        "fail:rebuild-build-time-package:Example.Generator 2.0.0,fail:rebuild-build-time-package:runtime.evil.native 1.0.0" "build-time package findings"
    if (-not (Test-IsExemptPackage "System.Text.Json") -or -not (Test-IsExemptPackage "microsoft.extensions.logging") -or
        (Test-IsExemptPackage "runtime.native.System") -or (Test-IsExemptPackage "MicrosoftX.Evil")) {
        throw "Exempt package prefixes are not exactly Microsoft. and System."
    }
    $allowPath = Join-Path $tempRoot "allow.json"
    Set-Content -LiteralPath $allowPath -Value '{"schemaVersion":1,"entries":[{"id":"example.generator","version":"2.0.0","reason":"reviewed","approvedBy":"KB2UKA"}]}'
    $allowed = Read-RebuildPackageAllowlist -Path $allowPath
    Assert-Equal (@(Get-FeedBuildTimePackageFindings -Packages $packages -FeedDirectory $feed -Allowlist $allowed) |
        ForEach-Object { $_.file }) "runtime.evil.native 1.0.0" "allowlisted build-time package"
    Set-Content -LiteralPath $allowPath -Value '{"schemaVersion":1,"entries":[{"id":"example.generator","version":"2.0.0"}]}'
    Assert-Throws -Label "allowlist entry without reason" -Block { Read-RebuildPackageAllowlist -Path $allowPath }

    # --- Restore cross-check from obj/project.assets.json.
    $assetsRoot = Join-Path $tempRoot "assets"
    New-Item -ItemType Directory -Path (Join-Path $assetsRoot "src/obj"), (Join-Path $assetsRoot "lib/obj") -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $assetsRoot "src/F.csproj") -Value "<Project />"
    Set-Content -LiteralPath (Join-Path $assetsRoot "lib/L.csproj") -Value "<Project />"
    $libProject = [IO.Path]::GetFullPath((Join-Path $assetsRoot "lib/L.csproj"))
    $assetsPackages = Join-Path $tempRoot "assets-packages"
    $assetsSdk = Join-Path $tempRoot "dotnet-root"
    New-Item -ItemType Directory -Path $assetsPackages, (Join-Path $assetsSdk "library-packs") -Force | Out-Null
    $rootAssets = @{
        libraries = @{
            "Example.Lib/1.2.3" = @{ type = "package"; files = @("lib/net10.0/Example.Lib.dll") }
            "L/1.0.0" = @{ type = "project"; path = "../lib/L.csproj" }
        }
        project = @{ restore = @{ frameworks = @{ "net10.0" = @{ projectReferences = @{ $libProject = @{ projectPath = $libProject } } } } } }
    }
    $libAssets = @{
        libraries = @{
            "Sneaky.Package/9.9.9" = @{ type = "package"; files = @("lib/net10.0/Sneaky.dll") }
            "Example.Generator/2.0.0" = @{ type = "package"; files = @("analyzers/dotnet/cs/Gen.dll") }
            "Microsoft.Build.Tasks.Git/1.0.0" = @{ type = "package"; files = @("build/x.targets") }
            "Microsoft.Unlocked.Thing/1.0.0" = @{ type = "package"; files = @("lib/net10.0/x.dll") }
            "System.FromSdk.Pack/2.0.0" = @{ type = "package"; files = @("lib/net10.0/y.dll") }
        }
        project = @{ restore = @{ frameworks = @{ "net10.0" = @{ projectReferences = @{} } } } }
    }
    Set-Content -LiteralPath (Join-Path $assetsRoot "src/obj/project.assets.json") -Value ($rootAssets | ConvertTo-Json -Depth 20)
    Set-Content -LiteralPath (Join-Path $assetsRoot "lib/obj/project.assets.json") -Value ($libAssets | ConvertTo-Json -Depth 20)
    $sdkPack = Join-Path $assetsPackages "system.fromsdk.pack/2.0.0"
    New-Item -ItemType Directory -Path $sdkPack -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $sdkPack ".nupkg.metadata") `
        -Value (@{ version = 2; contentHash = "x"; source = (Join-Path $assetsSdk "library-packs") } | ConvertTo-Json)
    $assetFindings = @(Get-AssetsFilePackageFindings -Root $assetsRoot -ProjectPath (Join-Path $assetsRoot "src/F.csproj") `
        -Packages $packages -Allowlist $empty -PackagesFolder $assetsPackages -SdkRoot $assetsSdk)
    Assert-Equal (($assetFindings | ForEach-Object { "$($_.ruleId):$($_.file)" } | Sort-Object) -join ",") `
        "rebuild-build-time-package:Example.Generator 2.0.0,rebuild-unverified-package:Microsoft.Unlocked.Thing 1.0.0,rebuild-unverified-package:Sneaky.Package 9.9.9" "assets findings"

    # Microsoft./System. packages outside the feed are exempt only when they
    # came from inside the installed .NET directory.
    $fromSdkMetadata = Join-Path $assetsPackages "system.fromsdk.pack/2.0.0"
    New-Item -ItemType Directory -Path $fromSdkMetadata -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $fromSdkMetadata ".nupkg.metadata") `
        -Value (@{ version = 2; contentHash = "x"; source = (Join-Path $assetsSdk "library-packs") } | ConvertTo-Json)
    if (-not (Test-IsSdkProvidedPackage -Id "System.FromSdk.Pack" -Version "2.0.0" -PackagesFolder $assetsPackages -SdkRoot $assetsSdk)) {
        throw "A package restored from the SDK library-packs was not recognised"
    }
    Set-Content -LiteralPath (Join-Path $fromSdkMetadata ".nupkg.metadata") `
        -Value (@{ version = 2; contentHash = "x"; source = "https://api.nuget.org/v3/index.json" } | ConvertTo-Json)
    if (Test-IsSdkProvidedPackage -Id "System.FromSdk.Pack" -Version "2.0.0" -PackagesFolder $assetsPackages -SdkRoot $assetsSdk) {
        throw "A Microsoft/System package from nuget.org was treated as SDK-provided"
    }
    New-Item -ItemType Directory -Path (Join-Path $assetsSdk "sdk/NuGetFallbackFolder/system.fromsdk.pack/2.0.0") -Force | Out-Null
    if (-not (Test-IsSdkProvidedPackage -Id "System.FromSdk.Pack" -Version "2.0.0" -PackagesFolder $assetsPackages `
            -SdkRoot $assetsSdk -PackageFolders @((Join-Path $assetsSdk "sdk/NuGetFallbackFolder")))) {
        throw "A package in an SDK fallback folder was not recognised"
    }
    if (Test-IsSdkProvidedPackage -Id "System.FromSdk.Pack" -Version "2.0.0" -PackagesFolder $assetsPackages `
            -SdkRoot $assetsSdk -PackageFolders @($assetsPackages)) {
        throw "A package folder outside the SDK was treated as SDK-provided"
    }
    Remove-Item -LiteralPath (Join-Path $assetsRoot "lib/obj/project.assets.json")
    Assert-Throws -Label "missing assets file" -Pattern "project.assets.json" -Block {
        Get-AssetsFilePackageFindings -Root $assetsRoot -ProjectPath (Join-Path $assetsRoot "src/F.csproj") -Packages $packages -Allowlist $empty -PackagesFolder $assetsPackages -SdkRoot $assetsSdk
    }
    $rootAssets.project.restore.frameworks."net10.0".projectReferences = @{ "/etc/Outside.csproj" = @{} }
    Set-Content -LiteralPath (Join-Path $assetsRoot "src/obj/project.assets.json") -Value ($rootAssets | ConvertTo-Json -Depth 20)
    Assert-Throws -Label "project reference outside the source" -Pattern "outside" -Block {
        Get-AssetsFilePackageFindings -Root $assetsRoot -ProjectPath (Join-Path $assetsRoot "src/F.csproj") -Packages $packages -Allowlist $empty -PackagesFolder $assetsPackages -SdkRoot $assetsSdk
    }

    # --- The rebuild verdict has no review tier.
    $verdict = @(ConvertTo-RebuildVerdict -Findings @(
        (New-SecurityFinding -Check compare -RuleId compare-il-differ -Severity review),
        (New-SecurityFinding -Check rebuild -RuleId rebuild-committed-source-file -Severity info)
    ))
    Assert-Equal (($verdict | ForEach-Object { $_.severity }) -join ",") "fail,info" "rebuild verdict severities"

    # --- Sandbox arguments: read-only host, all namespaces, no caps, clean env.
    $env:ZEUS_TEST_SECRET = "must-not-leak"
    $arguments = @(Get-SandboxArguments -SourceRoot "/work/src" -PrivateRoot "/work/private" -WorkingDirectory "/work/src" -Command @("true"))
    Remove-Item Env:ZEUS_TEST_SECRET
    $joined = $arguments -join " "
    foreach ($required in @("--ro-bind / /", "--tmpfs /tmp", "--tmpfs /run", "--unshare-all", "--die-with-parent",
        "--new-session", "--cap-drop ALL", "--clearenv", "--bind /work/src /work/src", "--bind /work/private /work/private")) {
        if (-not $joined.Contains($required)) { throw "Sandbox arguments lack '$required'" }
    }
    if ($joined.Contains("must-not-leak") -or $joined -match '(^| )--bind / ') { throw "Sandbox arguments leak the host environment or filesystem" }
    if ($joined.IndexOf("--tmpfs /tmp") -gt $joined.IndexOf("--bind /work/src")) { throw "Source bind must follow the private /tmp mount" }

    # --- Live sandbox checks (Linux with bubblewrap). CI installs bubblewrap.
    $bwrap = Get-Command bwrap -CommandType Application -ErrorAction SilentlyContinue
    if ($IsLinux -and $null -ne $bwrap) {
        $work = Join-Path $tempRoot "sandbox"
        $sandboxSource = Join-Path $work "src"
        $private = Join-Path $work "private"
        $hostDir = Join-Path $work "host-owned"
        New-Item -ItemType Directory -Path $sandboxSource, $private, $hostDir -Force | Out-Null
        Assert-SandboxIsolation -SourceRoot $sandboxSource -PrivateRoot $private -HostWriteProbes @($hostDir, $work)

        # Writes outside the source tree and private root fail; inside succeed.
        $code = Invoke-Sandboxed -SourceRoot $sandboxSource -PrivateRoot $private -WorkingDirectory $sandboxSource `
            -Command @("sh", "-c", "touch '$hostDir/escaped'")
        if ($code -eq 0 -or (Test-Path -LiteralPath (Join-Path $hostDir "escaped"))) { throw "Sandbox wrote a host directory" }
        $code = Invoke-Sandboxed -SourceRoot $sandboxSource -PrivateRoot $private -WorkingDirectory $sandboxSource `
            -Command @("sh", "-c", "touch built.txt")
        if ($code -ne 0 -or -not (Test-Path -LiteralPath (Join-Path $sandboxSource "built.txt"))) { throw "Sandbox could not write its source tree" }

        # No network and no name resolution.
        $code = Invoke-Sandboxed -SourceRoot $sandboxSource -PrivateRoot $private -WorkingDirectory $sandboxSource `
            -Command @("sh", "-c", "getent hosts github.com || timeout 5 bash -c 'exec 3<>/dev/tcp/140.82.112.3/443'")
        if ($code -eq 0) { throw "Sandbox reached the network" }

        # Nothing started in the sandbox outlives it.
        $code = Invoke-Sandboxed -SourceRoot $sandboxSource -PrivateRoot $private -WorkingDirectory $sandboxSource `
            -Command @("sh", "-c", "(sleep 2; touch late.txt) >/dev/null 2>&1 & exit 0")
        Start-Sleep -Seconds 4
        if (Test-Path -LiteralPath (Join-Path $sandboxSource "late.txt")) { throw "A background process outlived the sandbox" }

        # The environment is explicit: host variables do not leak in.
        $env:ZEUS_TEST_SECRET = "must-not-leak"
        $code = Invoke-Sandboxed -SourceRoot $sandboxSource -PrivateRoot $private -WorkingDirectory $sandboxSource `
            -Command @("sh", "-c", 'test -z "$ZEUS_TEST_SECRET" && test -z "$GITHUB_TOKEN"')
        Remove-Item Env:ZEUS_TEST_SECRET
        if ($code -ne 0) { throw "Host environment leaked into the sandbox" }
        Write-Host "Live bubblewrap sandbox checks passed."
    }
    elseif ($env:CI) { throw "bubblewrap is required for the sandbox tests in CI" }
    else { Write-Warning "bubblewrap is not available; live sandbox checks were not run." }

    # --- npm: contributor configuration is removed and the lock must use the public registry.
    $npmRoot = Join-Path $tempRoot "npm/repo"
    $npmDir = Join-Path $npmRoot "web/app"
    New-Item -ItemType Directory -Path $npmDir -Force | Out-Null
    foreach ($dir in @($npmRoot, (Join-Path $npmRoot "web"), $npmDir, (Split-Path -Parent $npmRoot))) {
        Set-Content -LiteralPath (Join-Path $dir ".npmrc") -Value "registry=https://evil.example/"
    }
    $removedNpmrc = @(Remove-ContributorNpmConfig -Root $npmRoot -Directory $npmDir)
    Assert-Equal (($removedNpmrc | Sort-Object) -join ",") ".npmrc,web/.npmrc,web/app/.npmrc" "removed .npmrc files"
    if (-not (Test-Path -LiteralPath (Join-Path (Split-Path -Parent $npmRoot) ".npmrc"))) {
        throw "An .npmrc outside the source repository was deleted"
    }
    New-Item -ItemType SymbolicLink -Path (Join-Path $npmRoot "web/.npmrc") -Target (Join-Path (Split-Path -Parent $npmRoot) ".npmrc") | Out-Null
    Assert-Throws -Label "linked .npmrc" -Pattern "link" -Block { Remove-ContributorNpmConfig -Root $npmRoot -Directory $npmDir }
    Remove-Item -LiteralPath (Join-Path $npmRoot "web/.npmrc") -Force
    Assert-Throws -Label "npm directory outside the source" -Pattern "outside" -Block {
        Remove-ContributorNpmConfig -Root $npmRoot -Directory (Split-Path -Parent $npmRoot)
    }

    $npmArgs = @(Get-NpmCiArguments -EmptyUserConfigPath "/work/empty-user.npmrc" -EmptyGlobalConfigPath "/work/empty-global.npmrc")
    Assert-Equal ($npmArgs -join " ") `
        "ci --ignore-scripts --registry=https://registry.npmjs.org/ --userconfig /work/empty-user.npmrc --globalconfig /work/empty-global.npmrc --no-audit --no-fund" "npm ci arguments"

    $integrity = "sha512-" + [Convert]::ToBase64String([byte[]]::new(64))
    $npmLock = [ordered]@{
        name = "app"; lockfileVersion = 3
        packages = [ordered]@{
            "" = @{ name = "app" }
            "node_modules/good" = @{ version = "1.0.0"; resolved = "https://registry.npmjs.org/good/-/good-1.0.0.tgz"; integrity = $integrity; bundleDependencies = @("bundled") }
            "node_modules/good/node_modules/undeclared" = @{ version = "1.0.0"; inBundle = $true }
            "node_modules/escape" = @{ resolved = "../../../outside"; link = $true }
            "node_modules/plain-http" = @{ version = "1.0.0"; resolved = "http://registry.npmjs.org/plain-http/-/plain-http-1.0.0.tgz"; integrity = $integrity }
            "node_modules/other-registry" = @{ version = "1.0.0"; resolved = "https://registry.evil.example/other/-/other-1.0.0.tgz"; integrity = $integrity }
            "node_modules/lookalike" = @{ version = "1.0.0"; resolved = "https://registry.npmjs.org.evil.example/x.tgz"; integrity = $integrity }
            "node_modules/git-dep" = @{ version = "1.0.0"; resolved = "git+ssh://git@github.com/x/y.git#abc" }
            "node_modules/no-integrity" = @{ version = "1.0.0"; resolved = "https://registry.npmjs.org/no-integrity/-/no-integrity-1.0.0.tgz" }
            "node_modules/workspace" = @{ resolved = "packages/workspace"; link = $true }
            "node_modules/good/node_modules/bundled" = @{ version = "1.0.0"; inBundle = $true }
        }
    }
    Set-Content -LiteralPath (Join-Path $npmDir "package-lock.json") -Value ($npmLock | ConvertTo-Json -Depth 10)
    $npmFindings = @(Get-NpmLockFindings -Root $npmRoot -Directory $npmDir)
    Assert-Equal (($npmFindings | ForEach-Object { "$($_.severity):$($_.ruleId):$(($_.detail -split ' ')[0])" } | Sort-Object) -join ",") `
        "fail:rebuild-npm-registry:node_modules/escape,fail:rebuild-npm-registry:node_modules/git-dep,fail:rebuild-npm-registry:node_modules/good/node_modules/undeclared,fail:rebuild-npm-registry:node_modules/lookalike,fail:rebuild-npm-registry:node_modules/no-integrity,fail:rebuild-npm-registry:node_modules/other-registry,fail:rebuild-npm-registry:node_modules/plain-http" "npm lock findings"
    $v1 = '{"lockfileVersion":1,"dependencies":{"a":{"version":"1.0.0","resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz","integrity":"' + $integrity + '","dependencies":{"b":{"version":"1.0.0","resolved":"https://evil.example/b.tgz","integrity":"' + $integrity + '"}}}}}'
    Set-Content -LiteralPath (Join-Path $npmDir "package-lock.json") -Value $v1
    Assert-Equal ((@(Get-NpmLockFindings -Root $npmRoot -Directory $npmDir) | ForEach-Object { $_.detail }) -join ",") `
        "a > b is not resolved from https://registry.npmjs.org/" "npm v1 lock findings"

    # --- npm-shrinkwrap.json anywhere from the node directory up to the root fails.
    Assert-Equal @(Get-NpmShrinkwrapFindings -Root $npmRoot -Directory $npmDir).Count 0 "no shrinkwrap"
    Set-Content -LiteralPath (Join-Path (Split-Path -Parent $npmRoot) "npm-shrinkwrap.json") -Value "{}"
    Assert-Equal @(Get-NpmShrinkwrapFindings -Root $npmRoot -Directory $npmDir).Count 0 "shrinkwrap outside the root"
    Set-Content -LiteralPath (Join-Path $npmRoot "web/npm-shrinkwrap.json") -Value "{}"
    Assert-Equal ((@(Get-NpmShrinkwrapFindings -Root $npmRoot -Directory $npmDir) | ForEach-Object { "$($_.ruleId):$($_.file)" }) -join ",") `
        "rebuild-npm-shrinkwrap:web/npm-shrinkwrap.json" "shrinkwrap findings"

    # --- Links anywhere in a rebuilt tree fail before upload.
    $tree = Join-Path $tempRoot "tree"
    New-Item -ItemType Directory -Path (Join-Path $tree "ui") -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $tree "plugin.json") -Value "{}"
    Assert-Equal @(Get-LinkFindings -Directory $tree).Count 0 "clean rebuilt tree"
    New-Item -ItemType SymbolicLink -Path (Join-Path $tree "ui/secret") -Target "/etc/hostname" | Out-Null
    New-Item -ItemType SymbolicLink -Path (Join-Path $tree "linkdir") -Target $tempRoot | Out-Null
    Assert-Equal ((@(Get-LinkFindings -Directory $tree) | ForEach-Object { "$($_.ruleId):$($_.file)" } | Sort-Object) -join ",") `
        "rebuild-staged-link:linkdir,rebuild-staged-link:ui/secret" "rebuilt tree links"

    # --- MSBuild allowlist lint.
    function Write-TreeFiles([string] $TreeRoot, [hashtable] $Files) {
        foreach ($entry in $Files.GetEnumerator()) {
            $path = Join-Path $TreeRoot $entry.Key
            New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force | Out-Null
            if ($entry.Value -is [byte[]]) { [IO.File]::WriteAllBytes($path, $entry.Value) }
            else { [IO.File]::WriteAllText($path, [string]$entry.Value) }
        }
    }
    function New-LintTree {
        # Fixtures are real Git repositories: $Files are committed, $Untracked
        # are written afterwards and stay untracked.
        param([string] $Name, [hashtable] $Files, [hashtable] $Untracked = @{})
        $treeRoot = Join-Path $tempRoot "lint/$Name"
        if (Test-Path -LiteralPath $treeRoot) { throw "Lint case directory reused: $treeRoot" }
        New-Item -ItemType Directory -Path $treeRoot -Force | Out-Null
        Write-TreeFiles $treeRoot $Files
        foreach ($gitArgs in @(@("init", "-q"), @("add", "-A", "-f"),
                @("-c", "user.name=test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", "fixture"))) {
            $gitResult = Invoke-TrustedGit -WorkTree $treeRoot -Arguments $gitArgs
            if ($gitResult.exitCode -ne 0) { throw "git $($gitArgs -join ' ') failed for $Name" }
        }
        Write-TreeFiles $treeRoot $Untracked
        return $treeRoot
    }

    # Passing fixture 1: the real hello-world template, SDK contracts, and Directory.Build.props.
    $repoRoot = Split-Path -Parent $PSScriptRoot
    $templateFiles = @{}
    foreach ($relative in @("Directory.Build.props", "templates/hello-world/Zeus.Community.HelloWorld.csproj",
            "templates/hello-world/plugin.json", "sdk/Zeussdr.Zeus.Plugins.Contracts/Zeus.Plugins.Contracts.csproj")) {
        $templateFiles[$relative] = [IO.File]::ReadAllText((Join-Path $repoRoot $relative))
    }
    $templateRoot = New-LintTree -Name "pass-template" -Files $templateFiles
    $templateFindings = @(Get-MsBuildLintFindings -Root $templateRoot)
    if ($templateFindings.Count -ne 0) { throw "The hello-world template failed the lint: $(($templateFindings | ForEach-Object { $_.detail }) -join ' | ')" }

    # Passing fixture 2: a PowerStation-style feature project with a browser build.
    $powerStation = @'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <AssemblyName>Example.PowerStation</AssemblyName>
    <EnableDynamicLoading>true</EnableDynamicLoading>
    <CopyLocalLockFileAssemblies>true</CopyLocalLockFileAssemblies>
    <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>
    <Version Condition="'$(Version)' == ''">1.2.0</Version>
  </PropertyGroup>
  <ItemGroup>
    <FrameworkReference Include="Microsoft.AspNetCore.App" />
    <ProjectReference Include="../sdk/Zeussdr.Zeus.Plugins.Contracts/Zeus.Plugins.Contracts.csproj" Private="false" ExcludeAssets="runtime" />
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    <InternalsVisibleTo Include="Example.PowerStation.Tests" />
    <Using Include="System.Text.Json" />
    <AssemblyAttribute Include="System.Reflection.AssemblyMetadataAttribute" _Parameter1="Channel" _Parameter2="community" />
    <None Include="plugin.json" CopyToOutputDirectory="PreserveNewest" />
    <Content Include="assets/**" />
    <EmbeddedResource Include="Resources/strings.json" LogicalName="Example.strings.json" />
  </ItemGroup>
</Project>
'@
    $psFiles = $templateFiles.Clone()
    $psFiles["powerstation/Example.PowerStation.csproj"] = $powerStation
    $psFiles["powerstation/plugin.json"] = "{}"
    $psFiles["powerstation/Resources/strings.json"] = "{}"
    $psFiles["powerstation/assets/logo.png"] = [byte[]](0x89, 0x50, 0x4E, 0x47)
    $psFiles["powerstation-web/package.json"] = "{}"
    $psRoot = New-LintTree -Name "pass-powerstation" -Files $psFiles
    $psFindings = @(Get-MsBuildLintFindings -Root $psRoot -NodeDirectories @((Join-Path $psRoot "powerstation-web")))
    $psFindings += @(Get-NodeProjectOverlapFindings -Root $psRoot -NodeDirectories @((Join-Path $psRoot "powerstation-web")))
    if ($psFindings.Count -ne 0) { throw "The PowerStation-style project failed the lint: $(($psFindings | ForEach-Object { $_.detail }) -join ' | ')" }

    # Failing fixtures: every known bypass. Each case is its own tree and must
    # produce the named rule with the named detail.
    $ok = '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>'
    function P([string] $Body) { return "<Project Sdk=""Microsoft.NET.Sdk"">$Body</Project>" }
    $mz = [byte[]](0x4D, 0x5A, 0x90, 0x00, 0x03)
    $lintCases = [ordered]@{
        "csproj.user with a target" = @(@{ "F.csproj" = $ok; "F.csproj.user" = '<Project><Target Name="Evil" /></Project>' }, "rebuild-msbuild-code", "File type is not allowed")
        "Directory.Build.targets" = @(@{ "F.csproj" = $ok; "Directory.Build.targets" = '<Project />' }, "rebuild-msbuild-code", "File type is not allowed")
        "Directory.Build.rsp" = @(@{ "F.csproj" = $ok; "Directory.Build.rsp" = '-logger:x.dll' }, "rebuild-msbuild-code", "File type is not allowed")
        "other project type" = @(@{ "F.fsproj" = '<Project />' }, "rebuild-msbuild-code", "File type is not allowed")
        "tracked obj" = @(@{ "F.csproj" = $ok; "obj/F.csproj.nuget.g.props" = '<Project />' }, "rebuild-msbuild-code", "Committed build output directory")
        "tracked bin" = @(@{ "F.csproj" = $ok; "src/bin/Release/x.txt" = 'x' }, "rebuild-msbuild-code", "Committed build output directory")
        "CscToolPath" = @(@{ "F.csproj" = (P '<PropertyGroup><CscToolPath>/tmp/evil</CscToolPath></PropertyGroup>') }, "rebuild-msbuild-code", "Property CscToolPath is not in the allowed list")
        "unknown property" = @(@{ "F.csproj" = (P '<PropertyGroup><Foo>1</Foo></PropertyGroup>') }, "rebuild-msbuild-code", "Property Foo is not in the allowed list")
        "entity-encoded property function" = @(@{ "F.csproj" = (P '<PropertyGroup><Description>&#36;([System.IO.File]::ReadAllText(`payload.txt`))</Description></PropertyGroup>') }, "rebuild-msbuild-code", "Property function or reference not allowed")
        "property function in a condition" = @(@{ "F.csproj" = (P '<PropertyGroup Condition="$([System.IO.File]::Exists(`/x`))"><Nullable>enable</Nullable></PropertyGroup>') }, "rebuild-msbuild-code", "Property function or reference not allowed")
        "property function in metadata" = @(@{ "F.csproj" = (P '<ItemGroup><PackageReference Include="A"><Version>$([System.Convert]::ToString(1))</Version></PackageReference></ItemGroup>') }, "rebuild-msbuild-code", "Property function or reference not allowed")
        "string instance method" = @(@{ "F.csproj" = (P '<PropertyGroup><Description>$(MSBuildProjectDirectory.Substring(0))</Description></PropertyGroup>') }, "rebuild-msbuild-code", "Property function or reference not allowed")
        "registry reference" = @(@{ "F.csproj" = (P '<PropertyGroup><Description>$(Registry:HKLM\Software)</Description></PropertyGroup>') }, "rebuild-msbuild-code", "Property function or reference not allowed")
        "item reference in a condition" = @(@{ "F.csproj" = (P '<PropertyGroup Condition="''@(Compile)'' != ''''"><Nullable>enable</Nullable></PropertyGroup>') }, "rebuild-msbuild-code", "Item or metadata references are not allowed")
        "compile from node_modules" = @(@{ "F.csproj" = (P '<ItemGroup><Compile Include="node_modules/evil/x.cs" /></ItemGroup>') }, "rebuild-msbuild-code", "must not point into node_modules")
        "copy from NuGetPackageRoot" = @(@{ "F.csproj" = (P '<ItemGroup><None Include="$(NuGetPackageRoot)evil/1.0.0/tools/a.dll" CopyToOutputDirectory="PreserveNewest" /></ItemGroup>') }, "rebuild-msbuild-code", "Item path must be literal")
        "escaped item path" = @(@{ "F.csproj" = (P '<ItemGroup><Compile Include="%2E%2E/x.cs" /></ItemGroup>') }, "rebuild-msbuild-code", "Item path must be literal")
        "parent item path" = @(@{ "F.csproj" = (P '<ItemGroup><Compile Include="../x.cs" /></ItemGroup>') }, "rebuild-msbuild-code", "must not contain '..'")
        "absolute item path" = @(@{ "F.csproj" = (P '<ItemGroup><Content Include="/etc/passwd" /></ItemGroup>') }, "rebuild-msbuild-code", "relative to the repository")
        "root wildcard" = @(@{ "F.csproj" = (P '<ItemGroup><Content Include="**/*.js" /></ItemGroup>') }, "rebuild-msbuild-code", "needs a literal directory prefix")
        "wildcard over browser build" = @(@{ "F.csproj" = (P '<ItemGroup><Content Include="web/**/*.js" /></ItemGroup>'); "web/package.json" = "{}" }, "rebuild-msbuild-code", "would include a project or browser build directory")
        "copy of a binary" = @(@{ "F.csproj" = (P '<ItemGroup><None Include="tool.txt" CopyToOutputDirectory="Always" /></ItemGroup>'); "tool.txt" = $mz }, "rebuild-msbuild-code", "Copied item must be")
        "copy of code" = @(@{ "F.csproj" = (P '<ItemGroup><None Include="run.sh" CopyToOutputDirectory="Always" /></ItemGroup>'); "run.sh" = "echo hi" }, "rebuild-msbuild-code", "Copied item must be")
        "unknown item type" = @(@{ "F.csproj" = (P '<ItemGroup><Reference Include="evil.dll" /></ItemGroup>') }, "rebuild-msbuild-code", "Item type Reference is not allowed")
        "analyzer item" = @(@{ "F.csproj" = (P '<ItemGroup><Analyzer Include="gen.dll" /></ItemGroup>') }, "rebuild-msbuild-code", "Item type Analyzer is not allowed")
        "GeneratePathProperty" = @(@{ "F.csproj" = (P '<ItemGroup><PackageReference Include="A" Version="1.0.0" GeneratePathProperty="true" /></ItemGroup>') }, "rebuild-msbuild-code", "Metadata GeneratePathProperty is not allowed")
        "target element" = @(@{ "F.csproj" = (P '<Target Name="X" />') }, "rebuild-msbuild-code", "Element <Target> is not allowed")
        "UsingTask element" = @(@{ "F.csproj" = (P '<UsingTask TaskName="X" TaskFactory="RoslynCodeTaskFactory" />') }, "rebuild-msbuild-code", "Element <UsingTask> is not allowed")
        "ItemDefinitionGroup" = @(@{ "F.csproj" = (P '<ItemDefinitionGroup />') }, "rebuild-msbuild-code", "Element <ItemDefinitionGroup> is not allowed")
        "custom sdk" = @(@{ "F.csproj" = '<Project Sdk="Evil.Sdk/1.0.0" />' }, "rebuild-msbuild-code", "Project Sdk must be exactly")
        "import attribute sdk" = @(@{ "F.csproj" = (P '<Import Project="a.props" Sdk="Evil.Sdk" />'); "a.props" = '<Project />' }, "rebuild-msbuild-code", "Attribute Sdk is not allowed on <Import>")
        "import outside the repo" = @(@{ "F.csproj" = (P '<Import Project="../../outside.props" />') }, "rebuild-msbuild-code", "Import must be a literal path")
        "initial targets" = @(@{ "F.csproj" = '<Project Sdk="Microsoft.NET.Sdk" InitialTargets="Publish" />' }, "rebuild-msbuild-code", "Attribute InitialTargets is not allowed on <Project>")
        "project reference outside" = @(@{ "F.csproj" = (P '<ItemGroup><ProjectReference Include="/opt/Other.csproj" /></ItemGroup>') }, "rebuild-msbuild-code", "ProjectReference must be")
        "dtd" = @(@{ "F.csproj" = '<?xml version="1.0"?><!DOCTYPE Project [<!ENTITY a "b">]><Project Sdk="Microsoft.NET.Sdk" />' }, "rebuild-msbuild-code", "not valid XML")
        "unsafe blocks" = @(@{ "F.csproj" = (P '<PropertyGroup><AllowUnsafeBlocks>true</AllowUnsafeBlocks></PropertyGroup>') }, "rebuild-msbuild-code", "Property AllowUnsafeBlocks must match")
        "restore sources" = @(@{ "F.csproj" = (P '<PropertyGroup><RestoreSources>https://evil.example</RestoreSources></PropertyGroup>') }, "rebuild-restore-override", "Property RestoreSources overrides how the rebuild restores")
        "lock file disabled" = @(@{ "Directory.Build.props" = '<Project><PropertyGroup><RestorePackagesWithLockFile>false</RestorePackagesWithLockFile></PropertyGroup></Project>'; "F.csproj" = $ok }, "rebuild-restore-override", "Property RestorePackagesWithLockFile overrides")
        "treat as local" = @(@{ "F.csproj" = '<Project Sdk="Microsoft.NET.Sdk" TreatAsLocalProperty="RestoreLockedMode" />' }, "rebuild-restore-override", "TreatAsLocalProperty")
        "untracked literal compile" = @(@{ "F.csproj" = (P '<ItemGroup><Compile Include="gen/Payload.cs" /></ItemGroup>') }, "rebuild-msbuild-code", "Item path must be a tracked file", @{ "gen/Payload.cs" = "class P {}" })
        "wildcard over an untracked file" = @(@{ "F.csproj" = (P '<ItemGroup><Compile Include="src/**/*.cs" /></ItemGroup>'); "src/A.cs" = "class A {}" }, "rebuild-msbuild-code", "Wildcard item path matches an untracked file", @{ "src/gen/Payload.cs" = "class P {}" })
        "missing literal content" = @(@{ "F.csproj" = (P '<ItemGroup><Content Include="dist/app.js" /></ItemGroup>') }, "rebuild-msbuild-code", "Item path must be a tracked file")
        "path item in props" = @(@{ "F.csproj" = $ok; "Directory.Build.props" = '<Project><ItemGroup><Compile Include="x.cs" /></ItemGroup></Project>'; "x.cs" = "class X {}" }, "rebuild-msbuild-code", "must be declared in a .csproj")
    }
    $caseNumber = 0
    foreach ($case in $lintCases.GetEnumerator()) {
        $untrackedFiles = if ($case.Value.Count -gt 3) { $case.Value[3] } else { @{} }
        $caseRoot = New-LintTree -Name "fail-$(($caseNumber++))" -Files $case.Value[0] -Untracked $untrackedFiles
        $nodeDirs = @(if ($case.Value[0].ContainsKey("web/package.json")) { Join-Path $caseRoot "web" })
        $caseFindings = @(Get-MsBuildLintFindings -Root $caseRoot -NodeDirectories $nodeDirs)
        $matched = @($caseFindings | Where-Object { $_.ruleId -ceq $case.Value[1] -and $_.detail.Contains($case.Value[2]) })
        if ($matched.Count -eq 0) {
            throw "MSBuild lint missed '$($case.Key)' (got: $(($caseFindings | ForEach-Object { "$($_.ruleId): $($_.detail)" }) -join ' | '))"
        }
    }

    # A tracked wildcard match passes.
    $trackedWildcard = New-LintTree -Name "pass-tracked-wildcard" -Files @{ "F.csproj" = (P '<ItemGroup><Compile Include="src/**/*.cs" /></ItemGroup>'); "src/A.cs" = "class A {}"; "src/deep/B.cs" = "class B {}" }
    Assert-Equal @(Get-MsBuildLintFindings -Root $trackedWildcard).Count 0 "tracked wildcard findings"

    # Browser build and project directories must be disjoint.
    $overlap = New-LintTree -Name "overlap" -Files @{ "app/F.csproj" = $ok; "app/web/package.json" = "{}"; "web2/package.json" = "{}" }
    Assert-Equal ((@(Get-NodeProjectOverlapFindings -Root $overlap -NodeDirectories @((Join-Path $overlap "app/web"), (Join-Path $overlap "web2"), (Join-Path $overlap "app"))) |
        ForEach-Object { "$($_.ruleId):$($_.file)" } | Sort-Object) -join ",") "rebuild-node-in-project:app,rebuild-node-in-project:app/web" "node/project overlap"

    # Trusted untracked-source check against a .git snapshot.
    $statusRoot = New-LintTree -Name "status" -Files @{
        "proj/F.csproj" = $ok; "proj/A.cs" = "class A {}"; "proj/Old.cs" = "class Old {}"; ".gitignore" = "*.gen`n"; "web/package.json" = "{}"
    }
    $snapshot = Join-Path $tempRoot "status-git-snapshot"
    Copy-Item -LiteralPath (Join-Path $statusRoot ".git") -Destination $snapshot -Recurse
    Write-TreeFiles $statusRoot @{
        "proj/gen/Payload.cs" = "class P {}"; "proj/hidden.gen" = "x"; "proj/obj/x.cs" = "generated"; "proj/bin/Release/y.dll" = "x"
        "web/node_modules/dep/index.js" = "x"; "web/dist/app.js" = "x"; "proj/A.cs" = "class A { int x; }"
    }
    Remove-Item -LiteralPath (Join-Path $statusRoot "proj/Old.cs")
    # A hostile .git/config written by the sandbox after the snapshot must not run.
    $marker = Join-Path $tempRoot "fsmonitor-ran"
    Add-Content -LiteralPath (Join-Path $statusRoot ".git/config") -Value "[core]`n`tfsmonitor = touch $marker`n[filter `"x`"]`n`tclean = touch $marker"
    Set-Content -LiteralPath (Join-Path $statusRoot ".gitattributes") -Value "* filter=x"
    $statusFindings = @(Get-UntrackedSourceFindings -Root $statusRoot -GitDirectory $snapshot -ProjectDirectories @((Join-Path $statusRoot "proj")))
    Assert-Equal (($statusFindings | ForEach-Object { "$($_.ruleId):$($_.file)" } | Sort-Object) -join ",") `
        "rebuild-untracked-source:proj/A.cs,rebuild-untracked-source:proj/gen/Payload.cs,rebuild-untracked-source:proj/hidden.gen" "untracked source findings"
    if (Test-Path -LiteralPath $marker) { throw "Contributor git configuration ran on the host" }

    # Value checks directly.
    foreach ($safe in @('plain', '$(Configuration)', '$([MSBuild]::NormalizePath($(A), `b`))', '$([System.String]::IsNullOrEmpty($(X)))')) {
        if (Get-MsBuildValueProblem $safe) { throw "Safe MSBuild value rejected: $safe" }
    }
    foreach ($unsafe in @('$([System.IO.File]::ReadAllText(`a`))', '$( [ System.Convert ]::FromBase64String(`AA==`))',
            '$(X.Replace(`a`,`b`))', '@(Compile)', '%(Identity)', '$([MSBuild]::GetRegistryValue(`a`,`b`))', '$(')) {
        if (-not (Get-MsBuildValueProblem $unsafe)) { throw "Unsafe MSBuild value accepted: $unsafe" }
    }

    # Trusted global properties pin the compiler and imports to the SDK.
    $fakeSdk = Join-Path $tempRoot "fake-sdk"
    New-Item -ItemType Directory -Path (Join-Path $fakeSdk "Roslyn") -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $fakeSdk "Roslyn/Microsoft.CSharp.Core.targets") -Value "<Project />"
    Set-Content -LiteralPath (Join-Path $fakeSdk "Microsoft.CSharp.targets") -Value "<Project />"
    $globals = @(Get-TrustedMSBuildGlobals -SdkDirectory $fakeSdk)
    foreach ($expected in @("-p:DisableImplicitNuGetFallbackFolder=true", "-p:CscToolPath=", "-p:CscToolExe=",
            "-p:RoslynTargetsPath=$(Join-Path $fakeSdk 'Roslyn')", "-p:CSharpCoreTargetsPath=$(Join-Path $fakeSdk 'Roslyn/Microsoft.CSharp.Core.targets')",
            "-p:LanguageTargets=$(Join-Path $fakeSdk 'Microsoft.CSharp.targets')", "-p:CustomBeforeMicrosoftCommonTargets=",
            "-p:CustomAfterMicrosoftCommonTargets=", "-p:CustomBeforeMicrosoftCommonProps=", "-p:CustomAfterMicrosoftCommonProps=",
            "-p:ImportDirectoryBuildTargets=false", "-p:ImportUserLocationsByWildcardBeforeMicrosoftCommonTargets=false",
            "-p:ImportUserLocationsByWildcardAfterMicrosoftCSharpTargets=false")) {
        if ($globals -cnotcontains $expected) { throw "Trusted MSBuild globals lack $expected" }
    }
    Remove-Item -LiteralPath (Join-Path $fakeSdk "Microsoft.CSharp.targets")
    Assert-Throws -Label "SDK without C# targets" -Pattern "lacks" -Block { Get-TrustedMSBuildGlobals -SdkDirectory $fakeSdk }

    # contentFiles/ and tools/ packages are build-time packages too.
    $extraSource = Join-Path $tempRoot "extra-packages"
    $contentHashValue = New-Nupkg -Path (Join-Path $extraSource "example.content.1.0.0.nupkg") -Entries @("contentFiles/cs/any/Injected.cs")
    $toolsHashValue = New-Nupkg -Path (Join-Path $extraSource "example.tools.1.0.0.nupkg") -Entries @("tools/install.ps1")
    $extraPackages = @(
        [pscustomobject]@{ id = "Example.Content"; version = "1.0.0"; contentHash = $contentHashValue; lockfile = "x" },
        [pscustomobject]@{ id = "Example.Tools"; version = "1.0.0"; contentHash = $toolsHashValue; lockfile = "x" }
    )
    Assert-Equal ((@(Get-FeedBuildTimePackageFindings -Packages $extraPackages -FeedDirectory $extraSource -Allowlist $empty) |
        ForEach-Object { $_.file }) -join ",") "Example.Content 1.0.0,Example.Tools 1.0.0" "contentFiles and tools packages"

    # --- One community version per pull request.
    Assert-Equal (Get-OneVersionPolicyFinding -Targets @([pscustomobject]@{ featureId = "a.b"; version = "1.0.0" })) "" "single target policy"
    $policy = Get-OneVersionPolicyFinding -Targets @(
        [pscustomobject]@{ featureId = "a.b"; version = "1.0.0" }, [pscustomobject]@{ featureId = "c.d"; version = "2.0.0" })
    Assert-Equal "$($policy.severity):$($policy.ruleId):$($policy.evidence)" "fail:one-version-per-pull-request:a.b@1.0.0, c.d@2.0.0" "multiple target policy"
}
finally {
    $resolved = [IO.Path]::GetFullPath($tempRoot)
    $systemTemp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if ($resolved.StartsWith($systemTemp, [StringComparison]::OrdinalIgnoreCase) -and
        (Test-Path -LiteralPath $resolved)) {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}

Write-Host "Source rebuild hardening regression tests passed."

# Native commands above may leave a non-zero $LASTEXITCODE from cases that
# are expected to fail; the GitHub pwsh wrapper would exit with it.
exit 0
