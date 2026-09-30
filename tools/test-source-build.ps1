# SPDX-License-Identifier: GPL-2.0-or-later
# Network-free regression tests for the zeus-build.json rebuild contract:
# path containment, link rejection, and ZIP-to-source mapping completeness.
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$verifier = Join-Path $PSScriptRoot "verify-source-build.ps1"
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) "zeus-source-build-test-$([Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $tempRoot | Out-Null

function New-FixtureZip {
    param([Parameter(Mandatory)][string] $Path, [Parameter(Mandatory)][string[]] $Entries)
    $manifest = [ordered]@{
        schemaVersion = 1
        id = "com.example.rebuildtest"
        name = "Rebuild Test"
        version = "1.0.0"
        entrypoint = [ordered]@{ assembly = "RebuildTest.dll"; type = "Example.RebuildTest" }
    } | ConvertTo-Json -Depth 5
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew)
    $archive = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Create, $false)
    try {
        foreach ($name in $Entries) {
            $entry = $archive.CreateEntry($name)
            $writer = [IO.StreamWriter]::new($entry.Open())
            try { $writer.Write($(if ($name -ceq "plugin.json") { $manifest } else { "fixture $name" })) }
            finally { $writer.Dispose() }
        }
    }
    finally {
        $archive.Dispose()
        $stream.Dispose()
    }
}

function New-SourceTree {
    param([Parameter(Mandatory)][string] $Name, [Parameter(Mandatory)] $Contract)
    $root = Join-Path $tempRoot $Name
    foreach ($directory in @("src", "ui", "web")) {
        New-Item -ItemType Directory -Path (Join-Path $root $directory) -Force | Out-Null
    }
    Set-Content -LiteralPath (Join-Path $root "src/RebuildTest.csproj") -Value "<Project />"
    Set-Content -LiteralPath (Join-Path $root "plugin.json") -Value "{}"
    Set-Content -LiteralPath (Join-Path $root "LICENSE") -Value "GPL"
    Set-Content -LiteralPath (Join-Path $root "web/package.json") -Value "{}"
    Set-Content -LiteralPath (Join-Path $root "web/package-lock.json") -Value "{}"
    Set-Content -LiteralPath (Join-Path $root "global.json") -Value '{ "sdk": { "version": "10.0.100", "rollForward": "disable" } }'
    if ($Contract -is [string]) {
        Set-Content -LiteralPath (Join-Path $root "zeus-build.json") -Value $Contract -NoNewline
    }
    else {
        Set-Content -LiteralPath (Join-Path $root "zeus-build.json") -Value ($Contract | ConvertTo-Json -Depth 10)
    }
    return $root
}

function New-Contract {
    param([hashtable] $Package = $null, $Project = "src/RebuildTest.csproj", $Node = $null)
    $contract = [ordered]@{
        schemaVersion = 1
        dotnet = [ordered]@{ project = $Project; configuration = "Release" }
        package = if ($null -ne $Package) { $Package } else {
            [ordered]@{ "plugin.json" = "plugin.json"; "LICENSE" = "LICENSE"; "ui/panel.js" = "web/dist/panel.js" }
        }
    }
    if ($null -ne $Node) { $contract.node = $Node }
    return $contract
}

$zip = Join-Path $tempRoot "fixture.zip"
New-FixtureZip -Path $zip -Entries @(
    "plugin.json", "LICENSE", "RebuildTest.dll", "RebuildTest.deps.json", "Dependency.DLL", "ui/panel.js"
)
$caseIndex = 0

function Assert-Equal {
    param($Actual, $Expected, [string] $Label)
    if ([string]$Actual -cne [string]$Expected) { throw "${Label}: expected '$Expected', got '$Actual'" }
}

function Invoke-Validation {
    param([Parameter(Mandatory)][string] $Root)
    $script:caseIndex++
    return & $verifier -PackagePath $zip -SourceDirectory $Root `
        -OutputDirectory (Join-Path $tempRoot "out-$script:caseIndex") -ValidateOnly
}

function Assert-ContractRejected {
    param([Parameter(Mandatory)][string] $Label, [Parameter(Mandatory)][string] $Root, [string] $Pattern = "")
    $rejected = $false
    try { Invoke-Validation -Root $Root | Out-Null }
    catch {
        $message = $_.Exception.Message
        $rejected = (-not $Pattern) -or ($message -match $Pattern)
        Write-Host "Rejected ${Label}: $message"
    }
    if (-not $rejected) { throw "Rebuild contract accepted unsafe case: $Label" }
}

try {
    # A valid contract maps every non-DLL file; DLLs and the entrypoint
    # .deps.json come from the dotnet build output.
    $valid = New-SourceTree -Name "valid" -Contract (New-Contract -Node @([ordered]@{ directory = "web"; script = "build" }))
    $result = Invoke-Validation -Root $valid
    if (-not $result.valid -or @($result.findings).Count -ne 0) {
        throw "Valid rebuild contract was rejected: $($result.findings | ConvertTo-Json -Depth 5)"
    }
    $expectedBuild = @("Dependency.DLL", "RebuildTest.deps.json", "RebuildTest.dll")
    if ((@($result.fromBuild | Sort-Object) -join ",") -cne ($expectedBuild -join ",")) {
        throw "Unexpected build-output file list: $($result.fromBuild -join ',')"
    }

    $pathCases = [ordered]@{
        "absolute project" = @{ Project = "/etc/RebuildTest.csproj" }
        "parent project" = @{ Project = "../outside/RebuildTest.csproj" }
        "windows drive project" = @{ Project = "C:/src/RebuildTest.csproj" }
        "backslash project" = @{ Project = "src\RebuildTest.csproj" }
        "dot segment project" = @{ Project = "./src/RebuildTest.csproj" }
        "non-csproj project" = @{ Project = "plugin.json" }
        "missing project" = @{ Project = "src/Missing.csproj" }
        "absolute package source" = @{ Package = [ordered]@{ "plugin.json" = "/etc/passwd"; "LICENSE" = "LICENSE"; "ui/panel.js" = "web/dist/panel.js" } }
        "parent package source" = @{ Package = [ordered]@{ "plugin.json" = "../plugin.json"; "LICENSE" = "LICENSE"; "ui/panel.js" = "web/dist/panel.js" } }
        "nested parent package source" = @{ Package = [ordered]@{ "plugin.json" = "web/../../plugin.json"; "LICENSE" = "LICENSE"; "ui/panel.js" = "web/dist/panel.js" } }
        "parent package key" = @{ Package = [ordered]@{ "../plugin.json" = "plugin.json"; "LICENSE" = "LICENSE"; "ui/panel.js" = "web/dist/panel.js" } }
        "git internals" = @{ Package = [ordered]@{ "plugin.json" = ".git/config"; "LICENSE" = "LICENSE"; "ui/panel.js" = "web/dist/panel.js" } }
        "mapped dll" = @{ Package = [ordered]@{ "plugin.json" = "plugin.json"; "LICENSE" = "LICENSE"; "ui/panel.js" = "web/dist/panel.js"; "RebuildTest.dll" = "prebuilt/RebuildTest.dll" } }
        "mapped upper-case DLL" = @{ Package = [ordered]@{ "plugin.json" = "plugin.json"; "LICENSE" = "LICENSE"; "ui/panel.js" = "web/dist/panel.js"; "Other.DLL" = "prebuilt/Other.DLL" } }
        "mapped mixed-case deps.json" = @{ Package = [ordered]@{ "plugin.json" = "plugin.json"; "LICENSE" = "LICENSE"; "ui/panel.js" = "web/dist/panel.js"; "Other.Deps.Json" = "prebuilt/Other.Deps.Json" } }
        "maps global.json" = @{ Package = [ordered]@{ "plugin.json" = "global.json"; "LICENSE" = "LICENSE"; "ui/panel.js" = "web/dist/panel.js" } }
        "mapped deps.json" = @{ Package = [ordered]@{ "plugin.json" = "plugin.json"; "LICENSE" = "LICENSE"; "ui/panel.js" = "web/dist/panel.js"; "RebuildTest.deps.json" = "prebuilt/RebuildTest.deps.json" } }
        "duplicate source" = @{ Package = [ordered]@{ "plugin.json" = "plugin.json"; "LICENSE" = "plugin.json"; "ui/panel.js" = "web/dist/panel.js" } }
        "maps zeus-build.json" = @{ Package = [ordered]@{ "plugin.json" = "zeus-build.json"; "LICENSE" = "LICENSE"; "ui/panel.js" = "web/dist/panel.js" } }
        "node absolute directory" = @{ Node = @([ordered]@{ directory = "/tmp"; script = "build" }) }
        "node parent directory" = @{ Node = @([ordered]@{ directory = ".."; script = "build" }) }
        "node without lockfile" = @{ Node = @([ordered]@{ directory = "ui"; script = "build" }) }
        "node shell script name" = @{ Node = @([ordered]@{ directory = "web"; script = "build; curl x" }) }
    }
    $i = 0
    foreach ($case in $pathCases.GetEnumerator()) {
        $arguments = $case.Value
        $root = New-SourceTree -Name "path-$(($i++))" -Contract (New-Contract @arguments)
        Assert-ContractRejected -Label $case.Key -Root $root
    }

    $rawCases = [ordered]@{
        "invalid JSON" = "{"
        "unknown property" = '{"schemaVersion":1,"dotnet":{"project":"src/RebuildTest.csproj","configuration":"Release"},"package":{"plugin.json":"plugin.json"},"postBuild":"curl"}'
        "wrong schema version" = '{"schemaVersion":2,"dotnet":{"project":"src/RebuildTest.csproj","configuration":"Release"},"package":{"plugin.json":"plugin.json"}}'
        "configuration injection" = '{"schemaVersion":1,"dotnet":{"project":"src/RebuildTest.csproj","configuration":"Release -p:X=1"},"package":{"plugin.json":"plugin.json"}}'
        "non-string path" = '{"schemaVersion":1,"dotnet":{"project":["src/RebuildTest.csproj"],"configuration":"Release"},"package":{"plugin.json":"plugin.json"}}'
    }
    foreach ($raw in $rawCases.GetEnumerator()) {
        $root = New-SourceTree -Name "raw-$(($i++))" -Contract $raw.Value
        Assert-ContractRejected -Label $raw.Key -Root $root
    }

    # global.json must pin one exact SDK with roll-forward disabled.
    $globalCases = [ordered]@{
        "missing global.json" = $null
        "roll-forward allowed" = '{ "sdk": { "version": "10.0.100", "rollForward": "latestFeature" } }'
        "no roll-forward" = '{ "sdk": { "version": "10.0.100" } }'
        "wildcard version" = '{ "sdk": { "version": "10.0.x", "rollForward": "disable" } }'
        "msbuild-sdks" = '{ "sdk": { "version": "10.0.100", "rollForward": "disable" }, "msbuild-sdks": { "Evil.Sdk": "1.0.0" } }'
        "extra sdk key" = '{ "sdk": { "version": "10.0.100", "rollForward": "disable", "paths": [".dotnet"] } }'
    }
    foreach ($globalCase in $globalCases.GetEnumerator()) {
        $root = New-SourceTree -Name "global-$(($i++))" -Contract (New-Contract)
        $globalPath = Join-Path $root "global.json"
        if ($null -eq $globalCase.Value) { Remove-Item -LiteralPath $globalPath }
        else { Set-Content -LiteralPath $globalPath -Value $globalCase.Value }
        Assert-ContractRejected -Label $globalCase.Key -Root $root -Pattern "global.json"
    }
    $linkedGlobal = New-SourceTree -Name "linked-global" -Contract (New-Contract)
    Move-Item -LiteralPath (Join-Path $linkedGlobal "global.json") -Destination (Join-Path $tempRoot "outside-global.json")
    New-Item -ItemType SymbolicLink -Path (Join-Path $linkedGlobal "global.json") -Target (Join-Path $tempRoot "outside-global.json") | Out-Null
    Assert-ContractRejected -Label "global.json link" -Root $linkedGlobal -Pattern "link"
    Assert-Equal (Invoke-Validation -Root $valid).sdkVersion "10.0.100" "pinned SDK version"

    $missing = New-SourceTree -Name "missing-contract" -Contract (New-Contract)
    Remove-Item -LiteralPath (Join-Path $missing "zeus-build.json")
    Assert-ContractRejected -Label "missing zeus-build.json" -Root $missing -Pattern "zeus-build.json is missing"

    # Links anywhere on a mapped path, or as the contract itself, are refused.
    $linkedDirectory = New-SourceTree -Name "linked-directory" -Contract (New-Contract)
    Remove-Item -LiteralPath (Join-Path $linkedDirectory "web") -Recurse
    New-Item -ItemType SymbolicLink -Path (Join-Path $linkedDirectory "web") -Target $tempRoot | Out-Null
    Assert-ContractRejected -Label "mapped path through a directory link" -Root $linkedDirectory -Pattern "link"

    $linkedFile = New-SourceTree -Name "linked-file" -Contract (New-Contract)
    Remove-Item -LiteralPath (Join-Path $linkedFile "LICENSE")
    New-Item -ItemType SymbolicLink -Path (Join-Path $linkedFile "LICENSE") -Target $zip | Out-Null
    Assert-ContractRejected -Label "mapped file link" -Root $linkedFile -Pattern "link"

    $linkedContract = New-SourceTree -Name "linked-contract" -Contract (New-Contract)
    $realContract = Join-Path $tempRoot "outside-contract.json"
    Move-Item -LiteralPath (Join-Path $linkedContract "zeus-build.json") -Destination $realContract
    New-Item -ItemType SymbolicLink -Path (Join-Path $linkedContract "zeus-build.json") -Target $realContract | Out-Null
    Assert-ContractRejected -Label "zeus-build.json link" -Root $linkedContract -Pattern "link"

    $linkedRoot = Join-Path $tempRoot "linked-root"
    New-Item -ItemType SymbolicLink -Path $linkedRoot -Target $valid | Out-Null
    Assert-ContractRejected -Label "source directory link" -Root $linkedRoot -Pattern "real directory"

    # Output inside the source tree is refused.
    $rejected = $false
    try {
        & $verifier -PackagePath $zip -SourceDirectory $valid -OutputDirectory (Join-Path $valid "out") -ValidateOnly | Out-Null
    }
    catch { $rejected = $true }
    if (-not $rejected) { throw "Rebuild verifier accepted an output directory inside the source tree" }

    # Completeness: an unmapped ZIP file and a mapping the ZIP lacks both fail.
    $unmapped = New-SourceTree -Name "unmapped" -Contract (New-Contract -Package ([ordered]@{
        "plugin.json" = "plugin.json"; "LICENSE" = "LICENSE"; "extra.txt" = "LICENSE.extra"
    }))
    $result = Invoke-Validation -Root $unmapped
    $rules = @($result.findings | ForEach-Object { "$($_.ruleId):$($_.file)" } | Sort-Object)
    $expectedRules = @("rebuild-mapping-not-in-package:extra.txt", "rebuild-unmapped-file:ui/panel.js")
    if ($result.valid -or ($rules -join ",") -cne ($expectedRules -join ",")) {
        throw "Mapping completeness was not enforced: $($rules -join ',')"
    }

    # A package with an unsafe archive path is refused before any ZIP path is used on disk.
    $unsafeZip = Join-Path $tempRoot "unsafe.zip"
    New-FixtureZip -Path $unsafeZip -Entries @("plugin.json", "RebuildTest.dll", "../escape.js")
    $rejected = $false
    try {
        & $verifier -PackagePath $unsafeZip -SourceDirectory $valid `
            -OutputDirectory (Join-Path $tempRoot "unsafe-out") -ValidateOnly | Out-Null
    }
    catch { $rejected = $true; Write-Host "Rejected unsafe archive: $($_.Exception.Message)" }
    if (-not $rejected) { throw "Rebuild verifier accepted an archive with a parent-directory path" }
}
finally {
    $resolved = [IO.Path]::GetFullPath($tempRoot)
    $systemTemp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if ($resolved.StartsWith($systemTemp, [StringComparison]::OrdinalIgnoreCase) -and
        (Test-Path -LiteralPath $resolved)) {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}

Write-Host "Source rebuild contract regression tests passed."

# Native commands above may leave a non-zero $LASTEXITCODE from cases that
# are expected to fail; the GitHub pwsh wrapper would exit with it.
exit 0
