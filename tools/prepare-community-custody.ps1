# SPDX-License-Identifier: GPL-2.0-or-later
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $RegistryPath,
    [Parameter(Mandatory)][string] $FeatureId,
    [Parameter(Mandatory)][string] $Version,
    [Parameter(Mandatory)][string] $ExpectedSha256,
    [Parameter(Mandatory)][string] $OutputDirectory,
    [string] $SourceUrl = "",
    [string] $SourcePackagePath = "",
    [long] $MaxDownloadBytes = 268435456
)

$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "CommunityCustody.psm1") -Force

Assert-CommunityIdentity -FeatureId $FeatureId -Version $Version
if ($ExpectedSha256 -cnotmatch "^[0-9a-f]{64}$") {
    throw "ExpectedSha256 must be exactly 64 lowercase hexadecimal characters"
}
if ([string]::IsNullOrWhiteSpace($SourceUrl) -eq
    [string]::IsNullOrWhiteSpace($SourcePackagePath)) {
    throw "Specify exactly one of SourceUrl or SourcePackagePath"
}

$resolvedRegistry = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $RegistryPath))
& (Join-Path $PSScriptRoot "validate-registry.ps1") -RegistryPath $resolvedRegistry
$catalog = Get-Content -Raw -LiteralPath $resolvedRegistry | ConvertFrom-Json -Depth 100
$plugins = @($catalog.plugins | Where-Object { [string]$_.id -ceq $FeatureId })
if ($plugins.Count -ne 1) { throw "Expected exactly one catalog entry for $FeatureId" }
$plugin = $plugins[0]
if ($plugin.channel -cne "community") { throw "$FeatureId must be a community entry" }
$releases = @($plugin.versions | Where-Object { [string]$_.version -ceq $Version })
if ($releases.Count -ne 1) { throw "Expected exactly one catalog version for $FeatureId@$Version" }
$release = $releases[0]
if ([string]$release.sha256 -cne $ExpectedSha256) {
    throw "Workflow SHA-256 does not match registry.json for $FeatureId@$Version"
}
$releaseSource = Get-VersionSource -Release $release
if ($null -ne $releaseSource -and -not [string]::IsNullOrWhiteSpace($SourceUrl) -and
    $SourceUrl -cne [string]$releaseSource.package) {
    throw "Workflow intake URL does not match source.package in registry.json for $FeatureId@$Version"
}
$custodyUrl = Get-CommunityCustodyUrl -FeatureId $FeatureId -Version $Version
Assert-CommunityCustodyUrl `
    -FeatureId $FeatureId `
    -Version $Version `
    -DownloadUrl ([string]$release.downloadUrl)

$outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null
$assetName = Get-CommunityCustodyAssetName -FeatureId $FeatureId -Version $Version
$packagePath = Join-Path $outputRoot $assetName
$metadataPath = Join-Path $outputRoot "custody.json"
if ((Test-Path -LiteralPath $packagePath) -or (Test-Path -LiteralPath $metadataPath)) {
    throw "Custody output already exists; use an empty output directory"
}

if (-not [string]::IsNullOrWhiteSpace($SourceUrl)) {
    $sourceLabel = $SourceUrl
    [void](Copy-HttpsFileWithLimit `
        -SourceUrl $SourceUrl `
        -DestinationPath $packagePath `
        -MaxBytes $MaxDownloadBytes `
        -RequireGitHubRelease)
}
else {
    $resolvedSource = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $SourcePackagePath))
    $sourceItem = Get-Item -LiteralPath $resolvedSource
    if ($sourceItem.Length -lt 1 -or $sourceItem.Length -gt $MaxDownloadBytes) {
        throw "Compressed package must contain 1..$MaxDownloadBytes bytes"
    }
    Copy-Item -LiteralPath $resolvedSource -Destination $packagePath
    $sourceLabel = $resolvedSource
}

$packageItem = Get-Item -LiteralPath $packagePath
if ($packageItem.Length -lt 1 -or $packageItem.Length -gt $MaxDownloadBytes) {
    throw "Compressed package must contain 1..$MaxDownloadBytes bytes"
}
$actualSha256 = (Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualSha256 -cne $ExpectedSha256) {
    throw "Downloaded package SHA-256 mismatch"
}

$packageValidation = @{
    PackagePath = $packagePath
    ExpectedId = $FeatureId
    ExpectedVersion = $Version
    ExpectedSdkAbi = [int]$release.sdkAbi
    ExpectedSdkMinVersion = [string]$release.sdkMinVersion
    ExpectedName = [string]$plugin.name
    ExpectedDescription = [string]$plugin.description
    ExpectedAuthor = [string]$plugin.author
    ExpectedLicense = [string]$plugin.license
    ExpectedHomepage = [string]$plugin.homepage
    ManifestSchemaPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "../schema/plugin.schema.json"))
}
& (Join-Path $PSScriptRoot "validate-package.ps1") @packageValidation | Out-Host

$result = [ordered]@{
    schemaVersion = 1
    featureId = $FeatureId
    version = $Version
    sha256 = $actualSha256
    size = $packageItem.Length
    source = $sourceLabel
    tag = Get-CommunityCustodyTag -FeatureId $FeatureId -Version $Version
    assetName = $assetName
    custodyUrl = $custodyUrl
}
$json = $result | ConvertTo-Json -Depth 5
[IO.File]::WriteAllText($metadataPath, $json + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
[pscustomobject]$result
