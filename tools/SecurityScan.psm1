# SPDX-License-Identifier: GPL-2.0-or-later
# Shared pipeline for the package security scan. Nothing here executes package
# or contributor code: packages are hashed, extracted, and read as data, and
# contributor source is cloned only so its lockfiles can be read.
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot "CommunityCustody.psm1")

$script:ReportMarker = "<!-- zeus-package-security-scan -->"
$script:DispositionRank = @{ clear = 0; info = 0; review = 1; fail = 2 }
$script:MaxPackageBytes = 268435456

function Get-SecurityReportMarker { return $script:ReportMarker }

function Get-WorstDisposition {
    param([AllowEmptyCollection()][string[]] $Values = @())
    $worst = "clear"
    foreach ($value in $Values) {
        if (-not $script:DispositionRank.ContainsKey([string]$value)) {
            throw "Unknown disposition or severity: $value"
        }
        if ($script:DispositionRank[[string]$value] -gt $script:DispositionRank[$worst]) {
            $worst = [string]$value
        }
    }
    if ($worst -eq "info") { return "clear" }
    return $worst
}

function New-SecurityFinding {
    param(
        [Parameter(Mandatory)][string] $Check,
        [Parameter(Mandatory)][string] $RuleId,
        [Parameter(Mandatory)][ValidateSet("fail", "review", "info")][string] $Severity,
        [string] $File = "",
        [string] $Detail = "",
        [string] $Evidence = ""
    )
    return [pscustomobject][ordered]@{
        check = $Check
        ruleId = $RuleId
        severity = $Severity
        file = $File
        detail = $Detail
        evidence = $Evidence
    }
}

function Get-OptionalProperty {
    param([Parameter(Mandatory)] $Object, [Parameter(Mandatory)][string] $Name)
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function New-ScanTarget {
    param([Parameter(Mandatory)] $Plugin, [Parameter(Mandatory)] $Release)
    return [pscustomobject][ordered]@{
        featureId = [string]$Plugin.id
        version = [string]$Release.version
        channel = [string]$Plugin.channel
        downloadUrl = [string]$Release.downloadUrl
        sha256 = [string]$Release.sha256
        sdkAbi = [int]$Release.sdkAbi
        sdkMinVersion = [string]$Release.sdkMinVersion
        source = Get-VersionSource -Release $Release
    }
}

function Get-SecurityScanTargets {
    <#
      Returns the versions to scan. With -All every version of every entry is
      returned (backfill). Otherwise only community versions that are new in
      the candidate, or whose JSON differs from the base, are returned.
    #>
    param(
        [Parameter(Mandatory)] $CandidateRegistry,
        $BaseRegistry = $null,
        [switch] $All
    )
    $targets = [Collections.Generic.List[object]]::new()
    $baseVersions = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::Ordinal)
    if (-not $All) {
        if ($null -eq $BaseRegistry) { throw "BaseRegistry is required unless -All is used" }
        foreach ($plugin in @($BaseRegistry.plugins)) {
            foreach ($release in @($plugin.versions)) {
                $baseVersions["$($plugin.id)@$($release.version)"] =
                    ($release | ConvertTo-Json -Depth 20 -Compress)
            }
        }
    }
    foreach ($plugin in @($CandidateRegistry.plugins)) {
        foreach ($release in @($plugin.versions)) {
            if (-not $All) {
                if ([string]$plugin.channel -cne "community") { continue }
                $key = "$($plugin.id)@$($release.version)"
                $existing = $null
                if ($baseVersions.TryGetValue($key, [ref]$existing) -and
                    $existing -ceq ($release | ConvertTo-Json -Depth 20 -Compress)) {
                    continue
                }
            }
            $targets.Add((New-ScanTarget -Plugin $plugin -Release $release))
        }
    }
    return $targets.ToArray()
}

function Get-VerifiedPackage {
    <#
      Downloads the package bytes (source.package when present, otherwise the
      catalog downloadUrl) with the shared HTTPS-only, size-bounded,
      redirect-limited downloader and verifies SHA-256 before anything else
      reads the file.
    #>
    param(
        [Parameter(Mandatory)] $Target,
        [Parameter(Mandatory)][string] $DestinationDirectory,
        [long] $MaxBytes = $script:MaxPackageBytes
    )
    Assert-CommunityIdentity -FeatureId $Target.featureId -Version $Target.version
    if ($Target.sha256 -cnotmatch "^[0-9a-f]{64}$") { throw "Registry SHA-256 is invalid" }
    $url = $Target.downloadUrl
    if ($null -ne $Target.source) { $url = [string]$Target.source.package }
    $path = Join-Path ([IO.Path]::GetFullPath($DestinationDirectory)) "$($Target.featureId)-$($Target.version).zip"
    $download = @{ SourceUrl = $url; DestinationPath = $path; MaxBytes = $MaxBytes }
    if ($Target.channel -ceq "community") { $download.RequireGitHubRelease = $true }
    [void](Copy-HttpsFileWithLimit @download)
    $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -cne $Target.sha256) {
        Remove-Item -LiteralPath $path -Force
        throw "SHA-256 mismatch for $url (registry $($Target.sha256), downloaded $actual)"
    }
    return [pscustomobject]@{ path = $path; url = $url; sha256 = $actual }
}

function Invoke-PackageValidator {
    <# validate-package.ps1 predates strict mode; run it with strict mode off. #>
    param([Parameter(Mandatory)][hashtable] $Arguments)
    $validator = Join-Path $PSScriptRoot "validate-package.ps1"
    & {
        Set-StrictMode -Off
        & $validator @Arguments
    } | Out-Null
}

function Expand-PackageForScan {
    <#
      Applies the catalog's archive-safety rules (paths, links, size, ratio)
      before extracting, so the extracted tree can be handed to ClamAV.
    #>
    param(
        [Parameter(Mandatory)][string] $PackagePath,
        [Parameter(Mandatory)] $Target,
        [Parameter(Mandatory)][string] $DestinationDirectory
    )
    $validation = @{
        PackagePath = $PackagePath
        ExpectedId = $Target.featureId
        ExpectedVersion = $Target.version
        AllowBundledContracts = ($Target.channel -ceq "official")
    }
    Invoke-PackageValidator -Arguments $validation
    $destination = [IO.Path]::GetFullPath($DestinationDirectory)
    New-Item -ItemType Directory -Path $destination -Force | Out-Null
    [IO.Compression.ZipFile]::ExtractToDirectory($PackagePath, $destination)
    return $destination
}

function Invoke-ClamAvScan {
    param(
        [Parameter(Mandatory)][string[]] $Paths,
        [Parameter(Mandatory)][string] $DisplayRoot,
        [Parameter(Mandatory)][string] $LogPath,
        [string] $DatabaseDirectory = ""
    )
    $clamscan = Get-Command clamscan -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -eq $clamscan) { throw "clamscan is not installed" }
    $arguments = @(
        "--infected", "--recursive", "--scan-archive=yes", "--alert-encrypted=yes",
        "--max-filesize=256M", "--max-scansize=1024M", "--stdout", "--no-summary"
    )
    if ($DatabaseDirectory) { $arguments += "--database=$DatabaseDirectory" }
    $arguments += @("--") + $Paths
    & $clamscan.Source @arguments *> $LogPath
    $code = $LASTEXITCODE
    $findings = [Collections.Generic.List[object]]::new()
    if ($code -eq 0) { return $findings.ToArray() }
    if ($code -ne 1) { throw "clamscan failed with exit code $code; see $LogPath" }
    foreach ($line in [IO.File]::ReadAllLines($LogPath)) {
        if ($line -match '^(?<path>.+): (?<signature>\S+) FOUND$') {
            $display = $Matches.path
            try {
                $relative = [IO.Path]::GetRelativePath($DisplayRoot, $Matches.path)
                if (-not $relative.StartsWith("..")) { $display = $relative.Replace("\", "/") }
            }
            catch { }
            $findings.Add((New-SecurityFinding -Check "clamav" -RuleId "clamav-detection" `
                -Severity fail -File $display -Detail "ClamAV signature $($Matches.signature)" `
                -Evidence $Matches.signature))
        }
    }
    if ($findings.Count -eq 0) {
        $findings.Add((New-SecurityFinding -Check "clamav" -RuleId "clamav-detection" -Severity fail `
            -Detail "clamscan reported an infection but no FOUND line could be parsed"))
    }
    return $findings.ToArray()
}

function Get-PackageScannerProject {
    return [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "PackageSecurityScan"))
}

function Initialize-PackageScanner {
    $project = Get-PackageScannerProject
    & dotnet build $project -c Release --nologo | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "Could not build the package security scanner" }
}

function Invoke-PackageScanner {
    <#
      Runs the scanner CLI (exit 0 clear/review, 2 fail, anything else a tool
      error) and returns its parsed JSON. A tool error always throws so the
      caller fails closed.
    #>
    param(
        [Parameter(Mandatory)][ValidateSet("scan", "compare")][string] $Mode,
        [Parameter(Mandatory)][string] $PackagePath,
        [Parameter(Mandatory)][string] $JsonPath,
        [string] $AllowlistPath = "",
        [string] $RebuiltDirectory = "",
        [switch] $IlStrict
    )
    $arguments = @(
        "run", "--project", (Get-PackageScannerProject), "-c", "Release", "--no-build", "--",
        $Mode, "--package", $PackagePath, "--json", $JsonPath
    )
    if ($Mode -eq "scan" -and $AllowlistPath) { $arguments += @("--allowlist", $AllowlistPath) }
    if ($Mode -eq "compare") {
        if (-not $RebuiltDirectory) { throw "compare requires RebuiltDirectory" }
        $arguments += @("--rebuilt", $RebuiltDirectory)
        if ($IlStrict) { $arguments += "--il-strict" }
    }
    if (Test-Path -LiteralPath $JsonPath) { Remove-Item -LiteralPath $JsonPath -Force }
    & dotnet @arguments | Out-Host
    $code = $LASTEXITCODE
    if ($code -notin @(0, 2)) { throw "Package security scanner $Mode failed with tool error $code" }
    if (-not (Test-Path -LiteralPath $JsonPath -PathType Leaf)) {
        throw "Package security scanner $Mode wrote no JSON result"
    }
    $result = Get-Content -Raw -LiteralPath $JsonPath | ConvertFrom-Json -Depth 50
    $disposition = [string](Get-OptionalProperty $result "disposition")
    if ($disposition -notin @("fail", "review", "clear")) {
        throw "Package security scanner $Mode returned an invalid disposition"
    }
    if (($code -eq 2) -ne ($disposition -eq "fail")) {
        throw "Package security scanner $Mode exit code $code disagrees with disposition $disposition"
    }
    return $result
}

function ConvertFrom-ScannerFindings {
    param([Parameter(Mandatory)] $Result, [Parameter(Mandatory)][string] $Check)
    $findings = [Collections.Generic.List[object]]::new()
    foreach ($finding in @(Get-OptionalProperty $Result "findings")) {
        if ($null -eq $finding) { continue }
        $severity = [string](Get-OptionalProperty $finding "severity")
        if ($severity -notin @("fail", "review", "info")) { $severity = "fail" }
        $findings.Add((New-SecurityFinding -Check $Check `
            -RuleId ([string](Get-OptionalProperty $finding "ruleId")) -Severity $severity `
            -File ([string](Get-OptionalProperty $finding "file")) `
            -Detail ([string](Get-OptionalProperty $finding "detail")) `
            -Evidence ([string](Get-OptionalProperty $finding "evidence"))))
    }
    # A scanner fail disposition must never be lost even if no finding says so.
    if ([string]$Result.disposition -eq "fail" -and
        -not ($findings | Where-Object { $_.severity -eq "fail" })) {
        $findings.Add((New-SecurityFinding -Check $Check -RuleId "scanner-fail" -Severity fail `
            -Detail "Scanner returned a fail disposition"))
    }
    if ([string]$Result.disposition -eq "review" -and
        -not ($findings | Where-Object { $_.severity -in @("fail", "review") })) {
        $findings.Add((New-SecurityFinding -Check $Check -RuleId "scanner-review" -Severity review `
            -Detail "Scanner returned a review disposition"))
    }
    return $findings.ToArray()
}

function Get-SourceCheckout {
    <#
      Fetches exactly one commit. -DataOnly disables symlink creation so a
      link in the repository cannot point a later reader at runner files.
      Git hooks and filter drivers are never taken from a cloned repository.
    #>
    param(
        [Parameter(Mandatory)][string] $Repository,
        [Parameter(Mandatory)][string] $Commit,
        [Parameter(Mandatory)][string] $Destination,
        [switch] $DataOnly
    )
    if ($Repository -cnotmatch '^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' -or
        $Repository.EndsWith(".git", [StringComparison]::OrdinalIgnoreCase) -or
        $Repository -cmatch '/\.{1,2}(/|$)') {
        throw "Source repository must be https://github.com/<owner>/<repo>"
    }
    if ($Commit -cnotmatch '^[0-9a-f]{40}$') { throw "Source commit must be a full lowercase SHA" }
    $target = [IO.Path]::GetFullPath($Destination)
    if (Test-Path -LiteralPath $target) { throw "Checkout destination already exists: $target" }
    $env:GIT_TERMINAL_PROMPT = "0"
    $env:GIT_LFS_SKIP_SMUDGE = "1"
    & git init --quiet $target
    if ($LASTEXITCODE -ne 0) { throw "git init failed" }
    if ($DataOnly) { & git -C $target config core.symlinks false }
    & git -C $target config core.hooksPath /dev/null
    & git -C $target remote add origin $Repository
    & git -C $target -c protocol.version=2 fetch --quiet --depth 1 --no-tags origin "+$($Commit):refs/remotes/origin/pinned"
    if ($LASTEXITCODE -ne 0) { throw "Could not fetch $Repository at $Commit" }
    & git -C $target -c advice.detachedHead=false checkout --quiet --detach refs/remotes/origin/pinned
    if ($LASTEXITCODE -ne 0) { throw "Could not check out $Commit" }
    $head = (& git -C $target rev-parse HEAD).Trim()
    if ($head -cne $Commit) { throw "Checked out $head instead of the pinned commit $Commit" }
    return $target
}

function Test-IsLinkedItem {
    param([Parameter(Mandatory)][IO.FileSystemInfo] $Item)
    return (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
        ($null -ne $Item.LinkTarget)
}

function Get-DependencyLockfiles {
    <#
      Lists the dependency inputs the OSV scan reads: NuGet packages.lock.json,
      npm package-lock.json, and project files that carry PackageReference
      items. Build output, node_modules, .git, and links are skipped.
    #>
    param([Parameter(Mandatory)][string] $SourceDirectory, [int] $MaxFiles = 200000)
    $root = [IO.Path]::GetFullPath($SourceDirectory)
    $results = [Collections.Generic.List[object]]::new()
    $pending = [Collections.Generic.Stack[string]]::new()
    $pending.Push($root)
    $seen = 0
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        foreach ($item in [IO.DirectoryInfo]::new($directory).EnumerateFileSystemInfos()) {
            if (++$seen -gt $MaxFiles) { throw "Source tree has more than $MaxFiles entries" }
            if (Test-IsLinkedItem $item) { continue }
            if ($item -is [IO.DirectoryInfo]) {
                if ($item.Name -notin @(".git", "node_modules", "bin", "obj", ".zeus-build")) {
                    $pending.Push($item.FullName)
                }
                continue
            }
            $kind = $null
            if ($item.Name -ceq "packages.lock.json") { $kind = "nuget-lock" }
            elseif ($item.Name -ceq "package-lock.json") { $kind = "npm-lock" }
            elseif ($item.Name -ceq "Directory.Packages.props") { $kind = "nuget-central" }
            elseif ($item.Extension -ieq ".csproj") { $kind = "csproj" }
            if ($kind) {
                $results.Add([pscustomobject][ordered]@{
                    path = [IO.Path]::GetRelativePath($root, $item.FullName).Replace("\", "/")
                    kind = $kind
                })
            }
        }
    }
    return @($results | Sort-Object path)
}

function Read-SafeXml {
    param([Parameter(Mandatory)][string] $Path, [long] $MaxBytes = 1048576)
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Length -gt $MaxBytes) { throw "$Path exceeds $MaxBytes bytes" }
    $settings = [Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $settings.MaxCharactersInDocument = $MaxBytes * 2
    $reader = [Xml.XmlReader]::Create($Path, $settings)
    try {
        $document = [Xml.XmlDocument]::new()
        $document.XmlResolver = $null
        $document.Load($reader)
        return $document
    }
    finally { $reader.Dispose() }
}

function Get-XmlItemVersion {
    param([Parameter(Mandatory)][Xml.XmlElement] $Element)
    foreach ($name in @("Version", "VersionOverride")) {
        $attribute = $Element.GetAttribute($name)
        if (-not [string]::IsNullOrWhiteSpace($attribute)) { return $attribute.Trim() }
        foreach ($child in $Element.ChildNodes) {
            if ($child -is [Xml.XmlElement] -and $child.LocalName -ceq $name) {
                return $child.InnerText.Trim()
            }
        }
    }
    return ""
}

function New-SynthesizedNuGetLocks {
    <#
      osv-scanner cannot read .csproj files. For each project without a
      sibling packages.lock.json, write a lockfile listing its direct
      PackageReference versions (resolving central package management) so the
      direct dependencies are still checked. Transitive dependencies need a
      committed packages.lock.json.
    #>
    param(
        [Parameter(Mandatory)][string] $SourceDirectory,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]] $Lockfiles,
        [Parameter(Mandatory)][string] $OutputDirectory
    )
    $root = [IO.Path]::GetFullPath($SourceDirectory)
    $findings = [Collections.Generic.List[object]]::new()
    $paths = [Collections.Generic.List[string]]::new()
    $pathMap = @{}
    $nugetLockDirectories = @($Lockfiles | Where-Object kind -eq "nuget-lock" |
        ForEach-Object { [IO.Path]::GetDirectoryName($_.path) })
    $central = @{}
    foreach ($props in @($Lockfiles | Where-Object kind -eq "nuget-central")) {
        try {
            $document = Read-SafeXml -Path (Join-Path $root $props.path)
            foreach ($element in $document.GetElementsByTagName("PackageVersion")) {
                $name = $element.GetAttribute("Include")
                $version = Get-XmlItemVersion -Element $element
                if ($name -and $version) { $central[$name.ToLowerInvariant()] = $version }
            }
        }
        catch {
            $findings.Add((New-SecurityFinding -Check "osv" -RuleId "osv-unreadable-manifest" `
                -Severity review -File $props.path -Detail $_.Exception.Message))
        }
    }
    $index = 0
    foreach ($project in @($Lockfiles | Where-Object kind -eq "csproj")) {
        if ([IO.Path]::GetDirectoryName($project.path) -in $nugetLockDirectories) { continue }
        try { $document = Read-SafeXml -Path (Join-Path $root $project.path) }
        catch {
            $findings.Add((New-SecurityFinding -Check "osv" -RuleId "osv-unreadable-manifest" `
                -Severity review -File $project.path -Detail $_.Exception.Message))
            continue
        }
        $dependencies = [ordered]@{}
        foreach ($element in $document.GetElementsByTagName("PackageReference")) {
            $name = $element.GetAttribute("Include")
            if ([string]::IsNullOrWhiteSpace($name)) { continue }
            $version = Get-XmlItemVersion -Element $element
            if (-not $version -and $central.ContainsKey($name.ToLowerInvariant())) {
                $version = $central[$name.ToLowerInvariant()]
            }
            $exact = $version -replace '^\[([^,\]]+)\]$', '$1'
            if ($exact -cnotmatch '^[0-9]+(\.[0-9]+){1,3}(-[0-9A-Za-z.-]+)?$') {
                $findings.Add((New-SecurityFinding -Check "osv" -RuleId "osv-unpinned-dependency" `
                    -Severity review -File $project.path `
                    -Detail "PackageReference $name has no exact version the dependency scan can check" `
                    -Evidence $version))
                continue
            }
            $dependencies[$name] = [ordered]@{ type = "Direct"; requested = "[$exact, )"; resolved = $exact }
        }
        if ($dependencies.Count -eq 0) { continue }
        $findings.Add((New-SecurityFinding -Check "osv" -RuleId "osv-transitive-unchecked" -Severity info `
            -File $project.path `
            -Detail "No packages.lock.json; only direct NuGet dependencies were checked"))
        $directory = Join-Path $OutputDirectory "synthesized-$index"
        $index++
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
        $lockPath = Join-Path $directory "packages.lock.json"
        $lock = [ordered]@{ version = 1; dependencies = [ordered]@{ "net10.0" = $dependencies } }
        [IO.File]::WriteAllText($lockPath, ($lock | ConvertTo-Json -Depth 10), [Text.UTF8Encoding]::new($false))
        $paths.Add($lockPath)
        $pathMap[[IO.Path]::GetFullPath($lockPath)] = "$($project.path) (direct PackageReference items)"
    }
    return [pscustomobject]@{ paths = $paths.ToArray(); pathMap = $pathMap; findings = $findings.ToArray() }
}

function ConvertFrom-OsvResult {
    <# MAL-* advisories are known-malicious packages (fail); others need review. #>
    param([Parameter(Mandatory)] $Result, [string] $SourceRoot = "", [hashtable] $PathMap = @{})
    $findings = [Collections.Generic.List[object]]::new()
    foreach ($entry in @(Get-OptionalProperty $Result "results")) {
        if ($null -eq $entry) { continue }
        $file = ""
        $source = Get-OptionalProperty $entry "source"
        if ($null -ne $source) {
            $file = [string](Get-OptionalProperty $source "path")
            if ($file -and $PathMap.ContainsKey($file)) { $file = [string]$PathMap[$file] }
            elseif ($SourceRoot -and $file) {
                $relative = [IO.Path]::GetRelativePath($SourceRoot, $file)
                if (-not $relative.StartsWith("..")) { $file = $relative.Replace("\", "/") }
                else { $file = [IO.Path]::GetFileName($file) }
            }
        }
        foreach ($package in @(Get-OptionalProperty $entry "packages")) {
            if ($null -eq $package) { continue }
            $info = Get-OptionalProperty $package "package"
            $label = if ($null -ne $info) {
                "$(Get-OptionalProperty $info 'ecosystem') $(Get-OptionalProperty $info 'name') $(Get-OptionalProperty $info 'version')"
            } else { "unknown package" }
            $groups = @(Get-OptionalProperty $package "groups" | Where-Object { $null -ne $_ })
            $idSets = [Collections.Generic.List[object]]::new()
            if ($groups.Count -gt 0) {
                foreach ($group in $groups) {
                    $idSets.Add(@(@(Get-OptionalProperty $group "ids") + @(Get-OptionalProperty $group "aliases") |
                        Where-Object { $_ } | ForEach-Object { [string]$_ } | Sort-Object -Unique))
                }
            }
            else {
                foreach ($vulnerability in @(Get-OptionalProperty $package "vulnerabilities")) {
                    if ($null -eq $vulnerability) { continue }
                    $idSets.Add(@(@([string](Get-OptionalProperty $vulnerability "id")) +
                        @(Get-OptionalProperty $vulnerability "aliases") |
                        Where-Object { $_ } | ForEach-Object { [string]$_ } | Sort-Object -Unique))
                }
            }
            foreach ($ids in $idSets) {
                $malicious = @($ids | Where-Object { $_ -cmatch '^MAL-' }).Count -gt 0
                $findings.Add((New-SecurityFinding -Check "osv" `
                    -RuleId $(if ($malicious) { "osv-malicious-package" } else { "osv-vulnerable-dependency" }) `
                    -Severity $(if ($malicious) { "fail" } else { "review" }) `
                    -File $file -Detail $label.Trim() -Evidence ($ids -join ", ")))
            }
        }
    }
    return $findings.ToArray()
}

function Invoke-OsvScan {
    param(
        [Parameter(Mandatory)][string] $OsvScannerPath,
        [Parameter(Mandatory)][string] $SourceDirectory,
        [Parameter(Mandatory)][string] $WorkDirectory
    )
    $root = [IO.Path]::GetFullPath($SourceDirectory)
    $lockfiles = @(Get-DependencyLockfiles -SourceDirectory $root)
    $synthesized = New-SynthesizedNuGetLocks -SourceDirectory $root -Lockfiles $lockfiles `
        -OutputDirectory $WorkDirectory
    $findings = [Collections.Generic.List[object]]::new()
    foreach ($finding in @($synthesized.findings)) { $findings.Add($finding) }
    $inputs = @($lockfiles | Where-Object kind -in @("nuget-lock", "npm-lock") |
        ForEach-Object { Join-Path $root $_.path }) + @($synthesized.paths)
    if ($inputs.Count -eq 0) {
        $findings.Add((New-SecurityFinding -Check "osv" -RuleId "osv-no-dependencies" -Severity info `
            -Detail "No NuGet or npm dependency manifests were found"))
        return [pscustomobject]@{ lockfiles = $lockfiles; findings = $findings.ToArray() }
    }
    $jsonPath = Join-Path $WorkDirectory "osv.json"
    $arguments = @("scan", "source", "--format", "json", "--output-file", $jsonPath)
    foreach ($input in $inputs) { $arguments += @("-L", $input) }
    & $OsvScannerPath @arguments *> (Join-Path $WorkDirectory "osv.log")
    $code = $LASTEXITCODE
    if ($code -eq 128) {
        $findings.Add((New-SecurityFinding -Check "osv" -RuleId "osv-no-dependencies" -Severity info `
            -Detail "osv-scanner found no packages in the dependency manifests"))
    }
    elseif ($code -in @(0, 1)) {
        $result = Get-Content -Raw -LiteralPath $jsonPath | ConvertFrom-Json -Depth 50
        foreach ($finding in @(ConvertFrom-OsvResult -Result $result -SourceRoot $root `
            -PathMap $synthesized.pathMap)) {
            $findings.Add($finding)
        }
        if ($code -eq 1 -and -not ($findings | Where-Object {
            $_.check -eq "osv" -and $_.severity -in @("fail", "review") })) {
            $findings.Add((New-SecurityFinding -Check "osv" -RuleId "osv-vulnerable-dependency" -Severity review `
                -Detail "osv-scanner reported vulnerabilities that could not be parsed"))
        }
    }
    else { throw "osv-scanner failed with exit code $code" }
    return [pscustomobject]@{ lockfiles = $lockfiles; findings = $findings.ToArray() }
}

function Get-OneVersionPolicyFinding {
    <# A listing pull request may add or change only one community version. #>
    param([AllowEmptyCollection()][object[]] $Targets = @())
    $all = @($Targets | Where-Object { $null -ne $_ })
    if ($all.Count -le 1) { return $null }
    return New-SecurityFinding -Check "policy" -RuleId "one-version-per-pull-request" -Severity fail `
        -Detail "A listing pull request may add or change only one community feature version" `
        -Evidence (($all | ForEach-Object { "$($_.featureId)@$($_.version)" }) -join ", ")
}

function Test-BotOwnsLabel {
    <#
      The security-review-required label may be removed automatically only
      when the most recent "labeled" event for it came from the workflow bot.
      A label a maintainer added stays until a maintainer removes it.
    #>
    param([AllowEmptyCollection()][string[]] $LabeledEventActors = @())
    $actors = @($LabeledEventActors | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($actors.Count -eq 0) { return $false }
    return $actors[-1] -ceq "github-actions[bot]"
}

function New-SecurityReport {
    param(
        [Parameter(Mandatory)][ValidateSet("pull_request", "backfill")][string] $Mode,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]] $Results
    )
    return [pscustomobject][ordered]@{
        schemaVersion = 1
        tool = "zeus-package-security-pipeline"
        mode = $Mode
        generated = [DateTimeOffset]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
        disposition = Get-WorstDisposition -Values @($Results | ForEach-Object { $_.disposition })
        results = $Results
    }
}

function ConvertTo-SafeMarkdownCode {
    <#
      Renders untrusted text as a single GitHub code span: control characters
      and backticks are replaced, pipes are escaped for tables, and length is
      capped. Mentions, links, and HTML are inert inside a code span.
    #>
    param([AllowNull()][AllowEmptyString()][string] $Text, [int] $MaxLength = 200)
    if ([string]::IsNullOrEmpty($Text)) { return "" }
    $clean = [regex]::Replace($Text, '[\x00-\x1F\x7F\u0085  ​-‏‪-‮⁦-⁩]', ' ')
    $clean = $clean.Replace('`', "'").Trim()
    if ($clean.Length -gt $MaxLength) { $clean = $clean.Substring(0, $MaxLength) + "..." }
    $clean = $clean.Replace('\', '\\').Replace('|', '\|')
    if ([string]::IsNullOrWhiteSpace($clean)) { return "" }
    return '`' + $clean + '`'
}

function ConvertTo-SecurityReportMarkdown {
    param(
        [Parameter(Mandatory)] $Report,
        [int] $MaxFindingsPerResult = 40,
        [int] $MaxLength = 60000,
        [string] $RunUrl = ""
    )
    $lines = [Collections.Generic.List[string]]::new()
    $lines.Add($script:ReportMarker)
    $lines.Add("## Package security scan")
    $lines.Add("")
    $results = @($Report.results)
    $overall = ([string]$Report.disposition).ToUpperInvariant()
    if ($results.Count -eq 0) {
        $lines.Add("No new or changed community versions to scan. Result: **CLEAR**.")
    }
    else {
        $lines.Add("Result: **$overall** for $($results.Count) version(s).")
        $lines.Add("")
        $lines.Add("| Feature | Version | Channel | Result | Fail | Review | Checks |")
        $lines.Add("|---|---|---|---|---|---|---|")
        foreach ($result in $results) {
            $findings = @($result.findings)
            $checks = @($result.checks.PSObject.Properties | ForEach-Object { "$($_.Name): $($_.Value)" }) -join ", "
            $lines.Add("| $(ConvertTo-SafeMarkdownCode $result.featureId 100) | $(ConvertTo-SafeMarkdownCode $result.version 60) | $(ConvertTo-SafeMarkdownCode $result.channel 20) | **$(([string]$result.disposition).ToUpperInvariant())** | $(@($findings | Where-Object severity -eq 'fail').Count) | $(@($findings | Where-Object severity -eq 'review').Count) | $(ConvertTo-SafeMarkdownCode $checks 200) |")
        }
        foreach ($result in $results) {
            $findings = @($result.findings | Where-Object { $_.severity -in @("fail", "review") } |
                Sort-Object @{ Expression = { if ($_.severity -eq "fail") { 0 } else { 1 } } })
            if ($findings.Count -eq 0) { continue }
            $lines.Add("")
            $lines.Add("### $(ConvertTo-SafeMarkdownCode "$($result.featureId)@$($result.version)" 160)")
            $lines.Add("")
            $lines.Add("| Severity | Check | Rule | File | Detail | Evidence |")
            $lines.Add("|---|---|---|---|---|---|")
            foreach ($finding in @($findings | Select-Object -First $MaxFindingsPerResult)) {
                $lines.Add("| $(([string]$finding.severity).ToUpperInvariant()) | $(ConvertTo-SafeMarkdownCode $finding.check 20) | $(ConvertTo-SafeMarkdownCode $finding.ruleId 80) | $(ConvertTo-SafeMarkdownCode $finding.file 160) | $(ConvertTo-SafeMarkdownCode $finding.detail 300) | $(ConvertTo-SafeMarkdownCode $finding.evidence 160) |")
            }
            if ($findings.Count -gt $MaxFindingsPerResult) {
                $lines.Add("")
                $lines.Add("$($findings.Count - $MaxFindingsPerResult) more finding(s) are in the report artifact.")
            }
        }
    }
    $lines.Add("")
    if ($RunUrl -cmatch '^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/runs/[0-9]+$') {
        $lines.Add("Full JSON report: [workflow run]($RunUrl).")
    }
    $lines.Add("Fail blocks the listing. Review requires a maintainer to inspect the findings. Static rules and signatures can be evaded, so a clear result never replaces source review.")
    $text = ($lines -join "`n")
    if ($text.Length -gt $MaxLength) {
        $cut = $text.LastIndexOf("`n", $MaxLength - 200)
        if ($cut -lt 0) { $cut = $MaxLength - 200 }
        $text = $text.Substring(0, $cut) + "`n`nReport truncated; see the report artifact for every finding."
    }
    return $text
}

Export-ModuleMember -Function `
    Get-SecurityReportMarker, `
    Get-WorstDisposition, `
    New-SecurityFinding, `
    Get-SecurityScanTargets, `
    Get-VerifiedPackage, `
    Invoke-PackageValidator, `
    Expand-PackageForScan, `
    Invoke-ClamAvScan, `
    Initialize-PackageScanner, `
    Invoke-PackageScanner, `
    ConvertFrom-ScannerFindings, `
    Get-SourceCheckout, `
    Test-IsLinkedItem, `
    Get-DependencyLockfiles, `
    Read-SafeXml, `
    New-SynthesizedNuGetLocks, `
    ConvertFrom-OsvResult, `
    Invoke-OsvScan, `
    New-SecurityReport, `
    Test-BotOwnsLabel, `
    Get-OneVersionPolicyFinding, `
    ConvertTo-SafeMarkdownCode, `
    ConvertTo-SecurityReportMarkdown
