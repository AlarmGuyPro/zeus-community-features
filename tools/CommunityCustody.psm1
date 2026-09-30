# SPDX-License-Identifier: GPL-2.0-or-later
Set-StrictMode -Version Latest

$script:CommunityRepository = "Zeus-SDR/zeus-community-features"
$script:FeatureIdPattern = "^[a-z][a-z0-9]*(\.[a-z0-9]+)+$"
$script:StrictSemverPattern = "^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$"

function Assert-CommunityIdentity {
    param(
        [Parameter(Mandatory)][string] $FeatureId,
        [Parameter(Mandatory)][string] $Version
    )
    if ($FeatureId -cnotmatch $script:FeatureIdPattern) {
        throw "Invalid community feature id: $FeatureId"
    }
    if ($Version -cnotmatch $script:StrictSemverPattern) {
        throw "Invalid community feature version: $Version"
    }
}

function Get-CommunityCustodyTag {
    param(
        [Parameter(Mandatory)][string] $FeatureId,
        [Parameter(Mandatory)][string] $Version
    )
    Assert-CommunityIdentity -FeatureId $FeatureId -Version $Version
    return "community-$FeatureId-v$Version"
}

function Get-CommunityCustodyAssetName {
    param(
        [Parameter(Mandatory)][string] $FeatureId,
        [Parameter(Mandatory)][string] $Version
    )
    Assert-CommunityIdentity -FeatureId $FeatureId -Version $Version
    return "$FeatureId-$Version.zip"
}

function Get-CommunityCustodyUrl {
    param(
        [Parameter(Mandatory)][string] $FeatureId,
        [Parameter(Mandatory)][string] $Version
    )
    $tag = Get-CommunityCustodyTag -FeatureId $FeatureId -Version $Version
    $asset = Get-CommunityCustodyAssetName -FeatureId $FeatureId -Version $Version
    return "https://github.com/$script:CommunityRepository/releases/download/$tag/$asset"
}

function Assert-CommunityCustodyUrl {
    param(
        [Parameter(Mandatory)][string] $FeatureId,
        [Parameter(Mandatory)][string] $Version,
        [Parameter(Mandatory)][string] $DownloadUrl
    )
    $expected = Get-CommunityCustodyUrl -FeatureId $FeatureId -Version $Version
    if ($DownloadUrl -cne $expected) {
        throw "$FeatureId@$Version community downloadUrl must be the Zeus-SDR custody URL: $expected"
    }
}

function Get-VersionSource {
    param([Parameter(Mandatory)] $Release)
    $property = $Release.PSObject.Properties["source"]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Assert-VersionSource {
    param(
        [Parameter(Mandatory)][string] $Key,
        [AllowNull()] $Source
    )
    if ($null -eq $Source -or $Source -isnot [Management.Automation.PSCustomObject]) {
        throw "$Key source must be an object with repository, commit, and package"
    }
    $names = @($Source.PSObject.Properties.Name | Sort-Object)
    if (($names -join ",") -cne "commit,package,repository") {
        throw "$Key source must contain exactly repository, commit, and package"
    }
    foreach ($name in $names) {
        if ($Source.$name -isnot [string]) { throw "$Key source.$name must be a string" }
    }
    $repository = [string]$Source.repository
    if ($repository -cnotmatch "^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)$" -or
        $Matches[1] -in @(".", "..") -or $Matches[2] -in @(".", "..") -or
        $repository.EndsWith(".git", [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Key source.repository must be https://github.com/<owner>/<repo> without .git or a trailing slash"
    }
    if ([string]$Source.commit -cnotmatch "^[0-9a-f]{40}$") {
        throw "$Key source.commit must be a full 40-character lowercase commit SHA"
    }
    if ([string]$Source.package -cnotmatch
        "^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/releases/download/[^/?#%]+/[^/?#%]+\.zip$" -or
        $Matches[1] -in @(".", "..") -or $Matches[2] -in @(".", "..")) {
        throw "$Key source.package must be a GitHub Releases HTTPS ZIP URL"
    }
}

function Assert-NewCommunityVersionSource {
    param(
        [Parameter(Mandatory)][string] $FeatureId,
        [Parameter(Mandatory)] $Release
    )
    $key = "$FeatureId@$($Release.version)"
    $source = Get-VersionSource -Release $Release
    if ($null -eq $source) {
        throw "$key is a new community version and must declare source.repository, source.commit, and source.package"
    }
    Assert-VersionSource -Key $key -Source $source
}

function Copy-HttpsFileWithLimit {
    param(
        [Parameter(Mandatory)][string] $SourceUrl,
        [Parameter(Mandatory)][string] $DestinationPath,
        [long] $MaxBytes = 268435456,
        [switch] $RequireGitHubRelease
    )
    if ($SourceUrl.Length -gt 2048 -or $SourceUrl.Contains("`r") -or $SourceUrl.Contains("`n")) {
        throw "Package URL is too long or contains a line break"
    }
    $source = $null
    if (-not [Uri]::TryCreate($SourceUrl, [UriKind]::Absolute, [ref]$source) -or
        $source.Scheme -cne "https" -or
        -not [string]::IsNullOrEmpty($source.UserInfo) -or
        -not $source.IsDefaultPort -or
        -not [string]::IsNullOrEmpty($source.Query) -or
        -not [string]::IsNullOrEmpty($source.Fragment)) {
        throw "Package source must be a plain absolute HTTPS URL without credentials, a custom port, query, or fragment"
    }
    if ($RequireGitHubRelease -and
        ($source.Host -cne "github.com" -or
         $source.AbsolutePath -cnotmatch "^/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/releases/download/[^/%]+/[^/%]+\.zip$")) {
        throw "Community intake must be a public GitHub Releases HTTPS ZIP URL"
    }
    if ($MaxBytes -lt 1) { throw "MaxBytes must be positive" }

    $destination = [IO.Path]::GetFullPath($DestinationPath)
    New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $true
    $handler.MaxAutomaticRedirections = 5
    $client = [Net.Http.HttpClient]::new($handler)
    $response = $null
    $inputStream = $null
    $outputStream = $null
    $createdDestination = $false
    $completed = $false
    try {
        $response = $client.GetAsync(
            $source,
            [Net.Http.HttpCompletionOption]::ResponseHeadersRead
        ).GetAwaiter().GetResult()
        $response.EnsureSuccessStatusCode()
        $finalUri = $response.RequestMessage.RequestUri
        if ($finalUri.Scheme -cne "https") {
            throw "Package download redirected away from HTTPS"
        }
        if ($RequireGitHubRelease -and
            $finalUri.Host -notin @("github.com", "release-assets.githubusercontent.com")) {
            throw "Community intake redirected outside GitHub's HTTPS release-asset service"
        }
        $declaredLength = $response.Content.Headers.ContentLength
        if ($null -ne $declaredLength -and $declaredLength -gt $MaxBytes) {
            throw "Compressed package exceeds the $MaxBytes byte custody limit"
        }
        $inputStream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
        $outputStream = [IO.File]::Create($destination)
        $createdDestination = $true
        $buffer = [byte[]]::new(131072)
        [long] $written = 0
        while (($read = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $written += $read
            if ($written -gt $MaxBytes) {
                throw "Compressed package exceeds the $MaxBytes byte custody limit"
            }
            $outputStream.Write($buffer, 0, $read)
        }
        $outputStream.Flush()
        $completed = $true
        return $written
    }
    finally {
        if ($outputStream) { $outputStream.Dispose() }
        if ($inputStream) { $inputStream.Dispose() }
        if ($response) { $response.Dispose() }
        $client.Dispose()
        $handler.Dispose()
        if ($createdDestination -and -not $completed -and (Test-Path -LiteralPath $destination)) {
            Remove-Item -LiteralPath $destination -Force
        }
    }
}

Export-ModuleMember -Function `
    Assert-CommunityIdentity, `
    Get-CommunityCustodyTag, `
    Get-CommunityCustodyAssetName, `
    Get-CommunityCustodyUrl, `
    Assert-CommunityCustodyUrl, `
    Get-VersionSource, `
    Assert-VersionSource, `
    Assert-NewCommunityVersionSource, `
    Copy-HttpsFileWithLimit
