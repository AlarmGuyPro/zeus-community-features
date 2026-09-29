# SPDX-License-Identifier: GPL-2.0-or-later
[CmdletBinding()]
param([string] $SdkPath = (Join-Path $PSScriptRoot "../sdk"))

$ErrorActionPreference = "Stop"
$root = (Resolve-Path -LiteralPath $SdkPath).Path
$allowedExtensions = @(".cs", ".csproj", ".md")
$forbiddenExtensions = @(".dll", ".exe", ".pdb", ".so", ".dylib", ".a", ".lib", ".wasm")
$forbiddenText = @(
    "LicenseRef-Proprietary",
    "namespace ZeusProduct",
    "ZeusProduct/",
    "Station.Engine.Hosting",
    "Zeus.Dsp",
    "Zeus.Protocol1",
    "Zeus.Protocol2",
    "PsEnabled",
    "PureSignal"
)
$approvedFiles = @(
    "SOURCE.md",
    "Zeussdr.Zeus.Plugins.Contracts/AbiVersion.cs",
    "Zeussdr.Zeus.Plugins.Contracts/IOperatorIdentityProvider.cs",
    "Zeussdr.Zeus.Plugins.Contracts/IPluginContext.cs",
    "Zeussdr.Zeus.Plugins.Contracts/IQrzLookup.cs",
    "Zeussdr.Zeus.Plugins.Contracts/IZeusPlugin.cs",
    "Zeussdr.Zeus.Plugins.Contracts/PluginCapabilities.cs",
    "Zeussdr.Zeus.Plugins.Contracts/PluginManifest.cs",
    "Zeussdr.Zeus.Plugins.Contracts/PluginPermissionException.cs",
    "Zeussdr.Zeus.Plugins.Contracts/Zeus.Plugins.Contracts.csproj",
    "Zeussdr.Zeus.Plugins.Contracts/Audio/AudioBlockContext.cs",
    "Zeussdr.Zeus.Plugins.Contracts/Audio/IAudioPlaybackSink.cs",
    "Zeussdr.Zeus.Plugins.Contracts/Extensions/IAudioModemPlugin.cs",
    "Zeussdr.Zeus.Plugins.Contracts/Extensions/IAudioPlugin.cs",
    "Zeussdr.Zeus.Plugins.Contracts/Extensions/IBackendPlugin.cs",
    "Zeussdr.Zeus.Plugins.Contracts/Extensions/ILogbookPlugin.cs",
    "Zeussdr.Zeus.Plugins.Contracts/Extensions/IRxAudioTapPlugin.cs",
    "Zeussdr.Zeus.Plugins.Contracts/Extensions/ITxAudioTapPlugin.cs",
    "Zeussdr.Zeus.Plugins.Contracts/Extensions/IUiPlugin.cs",
    "Zeussdr.Zeus.Plugins.Contracts/Extensions/LogbookTypes.cs",
    "Zeussdr.Zeus.Plugins.Contracts/Registry/RegistryCatalog.cs"
)
$approved = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($path in $approvedFiles) { [void]$approved.Add($path) }

$diskFiles = @(
    Get-ChildItem -LiteralPath $root -Recurse -File |
        Where-Object { $_.FullName -notmatch '[\\/](bin|obj)[\\/]' }
)
$filePaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($file in $diskFiles) { [void]$filePaths.Add($file.FullName) }

# Build output is ignored on disk, but a mistakenly committed binary in bin/obj
# must still be audited. Add every Git-tracked SDK path when this is a checkout.
$repoRoot = Split-Path -Parent $root
if (Get-Command git -ErrorAction SilentlyContinue) {
    $tracked = @(& git -C $repoRoot ls-files -- sdk 2>$null)
    if ($LASTEXITCODE -eq 0) {
        foreach ($path in $tracked) {
            $fullPath = Join-Path $repoRoot $path
            if (Test-Path -LiteralPath $fullPath -PathType Leaf) {
                [void]$filePaths.Add([IO.Path]::GetFullPath($fullPath))
            }
        }
    }
}
$files = @($filePaths | ForEach-Object { Get-Item -LiteralPath $_ } | Sort-Object FullName)
if ($files.Count -eq 0) { throw "SDK boundary is empty" }
if ($files.Count -ne $approved.Count) {
    throw "SDK file count differs from the approved boundary: expected $($approved.Count), found $($files.Count)"
}

foreach ($file in $files) {
    $relative = [IO.Path]::GetRelativePath($root, $file.FullName).Replace("\", "/")
    if (-not $approved.Contains($relative)) {
        throw "SDK file is outside the approved public-contract allowlist: $relative"
    }
    if ($file.Extension -in $forbiddenExtensions) {
        throw "Compiled artifact is forbidden under sdk/: $relative"
    }
    if ($file.Extension -notin $allowedExtensions) {
        throw "Unexpected SDK file type: $relative"
    }
    $content = Get-Content -Raw -LiteralPath $file.FullName
    $header = ($content -split "\r?\n" | Select-Object -First 3) -join "\n"
    if ($header -notmatch "SPDX-License-Identifier:\s*GPL-2\.0-or-later") {
        throw "SDK file lacks the GPL-2.0-or-later SPDX header: $relative"
    }
    if ($relative -ne "SOURCE.md") {
        foreach ($needle in $forbiddenText) {
            if ($content.Contains($needle, [StringComparison]::Ordinal)) {
                throw "SDK file crosses the public-contract boundary ($needle): $relative"
            }
        }
    }
    $sha = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Host "$relative  $sha"
}
Write-Host "Validated $($files.Count) GPL public-contract SDK files."
