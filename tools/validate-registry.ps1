# SPDX-License-Identifier: GPL-2.0-or-later
[CmdletBinding()]
param(
    [string] $RegistryPath = (Join-Path $PSScriptRoot "../registry.json"),
    [switch] $DownloadPackages
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
Import-Module (Join-Path $PSScriptRoot "CommunityCustody.psm1") -Force
$catalog = Get-Content -Raw -LiteralPath (Resolve-Path $RegistryPath) |
    ConvertFrom-Json -Depth 100
if ($catalog.schemaVersion -ne 1) { throw "registry schemaVersion must be 1" }
$generated = [DateTimeOffset]::MinValue
if (-not [DateTimeOffset]::TryParse([string]$catalog.generated, [ref]$generated)) {
    throw "registry generated must be an RFC 3339 date-time"
}
$idPattern = "^[a-z][a-z0-9]*(\.[a-z0-9]+)+$"
$platforms = @("any", "linux-x64", "linux-arm64", "win-x64", "win-arm64", "osx-x64", "osx-arm64")
$manifestSchema = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "../schema/plugin.schema.json"))

$ids = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$versions = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$tempRoot = $null
try {
    if ($DownloadPackages) {
        $tempRoot = Join-Path ([IO.Path]::GetTempPath()) "zeus-community-$([Guid]::NewGuid().ToString('N'))"
        New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
    }
    foreach ($plugin in @($catalog.plugins)) {
        if ([string]$plugin.id -cnotmatch $idPattern) {
            throw "Invalid id: $($plugin.id)"
        }
        if (-not $ids.Add([string]$plugin.id)) { throw "Duplicate id: $($plugin.id)" }
        if ($plugin.channel -notin @("official", "community")) {
            throw "$($plugin.id) has invalid channel"
        }
        if ($plugin.channel -eq "community") {
            if ($plugin.verified -ne $false) {
                throw "$($plugin.id) community submissions must set verified=false"
            }
            if ($plugin.PSObject.Properties.Name -contains "subscription") {
                throw "$($plugin.id) community submissions cannot declare subscription"
            }
        }
        foreach ($category in @($plugin.categories)) {
            if ([string]$category -cnotmatch "^[a-z][a-z0-9-]*$") {
                throw "$($plugin.id) has invalid category: $category"
            }
        }
        if (@($plugin.versions).Count -eq 0) { throw "$($plugin.id) has no versions" }
        foreach ($version in @($plugin.versions)) {
            $key = "$($plugin.id)@$($version.version)"
            if (-not $versions.Add($key)) { throw "Duplicate version: $key" }
            if ([string]$version.version -notmatch "^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$") {
                throw "Invalid SemVer: $key"
            }
            $uri = $null
            if (-not [Uri]::TryCreate([string]$version.downloadUrl, [UriKind]::Absolute, [ref]$uri) -or
                $uri.Scheme -cne "https") { throw "$key URL must be absolute HTTPS" }
            if ([string]$version.sha256 -cnotmatch "^[0-9a-f]{64}$") {
                throw "$key SHA-256 must be lowercase hexadecimal"
            }
            $source = Get-VersionSource -Release $version
            if ($null -ne $source) { Assert-VersionSource -Key $key -Source $source }
            if ($plugin.channel -eq "community") {
                Assert-CommunityCustodyUrl `
                    -FeatureId ([string]$plugin.id) `
                    -Version ([string]$version.version) `
                    -DownloadUrl ([string]$version.downloadUrl)
            }
            if ($version.sdkAbi -lt 1 -or
                [string]$version.sdkMinVersion -notmatch "^[0-9]+\.[0-9]+\.[0-9]+$") {
                throw "$key has invalid SDK compatibility"
            }
            if (@($version.platforms).Count -eq 0) { throw "$key has no platforms" }
            foreach ($platform in @($version.platforms)) {
                if ($platform -notin $platforms) { throw "$key has invalid platform: $platform" }
            }
            if (@($version.platforms) -contains "any" -and @($version.platforms).Count -ne 1) {
                throw "$key cannot combine platform 'any' with runtime-specific platforms"
            }
            if ($DownloadPackages) {
                $zip = Join-Path $tempRoot "$($plugin.id)-$($version.version).zip"
                [void](Copy-HttpsFileWithLimit -SourceUrl $uri.AbsoluteUri -DestinationPath $zip)
                $actual = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant()
                if ($actual -cne [string]$version.sha256) { throw "$key SHA-256 mismatch" }
                $packageValidation = @{
                    PackagePath = $zip
                    ExpectedId = [string]$plugin.id
                    ExpectedVersion = [string]$version.version
                    ExpectedSdkAbi = [int]$version.sdkAbi
                    ExpectedSdkMinVersion = [string]$version.sdkMinVersion
                    AllowBundledContracts = ($plugin.channel -eq "official")
                }
                if ($plugin.channel -eq "community") {
                    $packageValidation.ManifestSchemaPath = $manifestSchema
                    $packageValidation.ExpectedName = [string]$plugin.name
                    $packageValidation.ExpectedDescription = [string]$plugin.description
                    $packageValidation.ExpectedAuthor = [string]$plugin.author
                    $packageValidation.ExpectedLicense = [string]$plugin.license
                    $packageValidation.ExpectedHomepage = [string]$plugin.homepage
                }
                & (Join-Path $PSScriptRoot "validate-package.ps1") @packageValidation | Out-Null
            }
        }
    }
}
finally {
    if ($tempRoot -and (Test-Path $tempRoot)) {
        $resolved = [IO.Path]::GetFullPath($tempRoot)
        $systemTemp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
        if ($resolved.StartsWith($systemTemp, [StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $resolved -Recurse -Force
        }
    }
}
Write-Host "Validated $($ids.Count) plugins and $($versions.Count) versions."
