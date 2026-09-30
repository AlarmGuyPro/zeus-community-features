# SPDX-License-Identifier: GPL-2.0-or-later
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $BaseRegistryPath,
    [Parameter(Mandatory)][string] $CandidateRegistryPath,
    [string] $ExpectedFeatureId = "",
    [string] $ExpectedVersion = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot "CommunityCustody.psm1") -Force
if ([string]::IsNullOrWhiteSpace($ExpectedFeatureId) -ne
    [string]::IsNullOrWhiteSpace($ExpectedVersion)) {
    throw "ExpectedFeatureId and ExpectedVersion must be supplied together"
}

function Assert-ExpectedSubmission {
    param(
        [Parameter(Mandatory)][string] $FeatureId,
        [Parameter(Mandatory)][string] $Version
    )
    if (-not [string]::IsNullOrWhiteSpace($ExpectedFeatureId) -and
        ($FeatureId -cne $ExpectedFeatureId -or $Version -cne $ExpectedVersion)) {
        throw "The custody target does not match the feature version added by this pull request"
    }
}

function ConvertTo-CanonicalJson {
    param($Value)
    function ConvertTo-CanonicalValue {
        param($InputValue)
        if ($null -eq $InputValue) { return $null }
        if ($InputValue -is [Management.Automation.PSCustomObject]) {
            $ordered = [ordered]@{}
            foreach ($property in @($InputValue.PSObject.Properties | Sort-Object Name)) {
                $ordered[$property.Name] = ConvertTo-CanonicalValue $property.Value
            }
            return [pscustomobject]$ordered
        }
        if ($InputValue -is [Collections.IEnumerable] -and $InputValue -isnot [string]) {
            $converted = @($InputValue | ForEach-Object { ConvertTo-CanonicalValue $_ })
            Write-Output -NoEnumerate $converted
            return
        }
        return $InputValue
    }
    return (ConvertTo-CanonicalValue $Value | ConvertTo-Json -Depth 100 -Compress)
}

function Get-PluginMetadataJson {
    param([Parameter(Mandatory)] $Plugin)
    $metadata = [ordered]@{}
    foreach ($property in @($Plugin.PSObject.Properties | Sort-Object Name)) {
        if ($property.Name -cne "versions") { $metadata[$property.Name] = $property.Value }
    }
    return ConvertTo-CanonicalJson ([pscustomobject]$metadata)
}

$basePath = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $BaseRegistryPath))
$candidatePath = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $CandidateRegistryPath))
& (Join-Path $PSScriptRoot "validate-registry.ps1") -RegistryPath $basePath | Out-Host
& (Join-Path $PSScriptRoot "validate-registry.ps1") -RegistryPath $candidatePath | Out-Host
$base = Get-Content -Raw -LiteralPath $basePath | ConvertFrom-Json -Depth 100
$candidate = Get-Content -Raw -LiteralPath $candidatePath | ConvertFrom-Json -Depth 100
if ($candidate.schemaVersion -ne $base.schemaVersion) { throw "A listing PR cannot change schemaVersion" }
$baseGenerated = [DateTimeOffset]::Parse([string]$base.generated)
$candidateGenerated = [DateTimeOffset]::Parse([string]$candidate.generated)
if ($candidateGenerated -le $baseGenerated) { throw "A listing PR must advance the generated timestamp" }

$baseById = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
$candidateById = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
foreach ($plugin in @($base.plugins)) { $baseById.Add([string]$plugin.id, $plugin) }
foreach ($plugin in @($candidate.plugins)) { $candidateById.Add([string]$plugin.id, $plugin) }
foreach ($id in $baseById.Keys) {
    if (-not $candidateById.ContainsKey($id)) { throw "A listing PR cannot remove $id" }
}

$newIds = @($candidateById.Keys | Where-Object { -not $baseById.ContainsKey($_) })
$changedIds = [Collections.Generic.List[string]]::new()
foreach ($id in $baseById.Keys) {
    if ((ConvertTo-CanonicalJson $baseById[$id]) -cne
        (ConvertTo-CanonicalJson $candidateById[$id])) {
        $changedIds.Add($id)
    }
}

if ($newIds.Count -eq 1 -and $changedIds.Count -eq 0) {
    $added = $candidateById[$newIds[0]]
    if ($added.channel -cne "community" -or @($added.versions).Count -ne 1) {
        throw "A new listing must add one community feature with one version"
    }
    Assert-NewCommunityVersionSource -FeatureId ([string]$added.id) -Release $added.versions[0]
    Assert-ExpectedSubmission -FeatureId ([string]$added.id) `
        -Version ([string]$added.versions[0].version)
    Write-Host "Validated new community feature: $($added.id)@$($added.versions[0].version)"
    return
}

if ($newIds.Count -eq 0 -and $changedIds.Count -eq 1) {
    $id = $changedIds[0]
    $before = $baseById[$id]
    $after = $candidateById[$id]
    if ($before.channel -cne "community" -or $after.channel -cne "community") {
        throw "Official entries cannot be changed by a community listing PR"
    }
    if ((Get-PluginMetadataJson $before) -cne (Get-PluginMetadataJson $after)) {
        throw "A release PR cannot change existing feature metadata"
    }
    $beforeByVersion = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    $afterByVersion = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    foreach ($release in @($before.versions)) { $beforeByVersion.Add([string]$release.version, $release) }
    foreach ($release in @($after.versions)) { $afterByVersion.Add([string]$release.version, $release) }
    foreach ($existingVersion in $beforeByVersion.Keys) {
        if (-not $afterByVersion.ContainsKey($existingVersion) -or
            (ConvertTo-CanonicalJson $beforeByVersion[$existingVersion]) -cne
            (ConvertTo-CanonicalJson $afterByVersion[$existingVersion])) {
            throw "Published version changed or disappeared: $id@$existingVersion"
        }
    }
    $newVersions = @($afterByVersion.Keys | Where-Object { -not $beforeByVersion.ContainsKey($_) })
    if ($newVersions.Count -ne 1 -or @($after.versions).Count -ne (@($before.versions).Count + 1) -or
        [string]$after.versions[0].version -cne $newVersions[0]) {
        throw "A release PR must prepend exactly one new immutable version"
    }
    Assert-NewCommunityVersionSource -FeatureId $id -Release $after.versions[0]
    Assert-ExpectedSubmission -FeatureId $id -Version ([string]$newVersions[0])
    Write-Host "Validated new community release: $id@$($newVersions[0])"
    return
}

throw "A listing PR must add exactly one feature or one version without changing anything else"
