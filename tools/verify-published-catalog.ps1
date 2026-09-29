# SPDX-License-Identifier: GPL-2.0-or-later
[CmdletBinding()]
param(
    [string]$RegistryPath = (Join-Path $PSScriptRoot '../registry.json'),
    [ValidateRange(1, 30)][int]$Attempts = 12,
    [ValidateRange(0, 60)][int]$RetrySeconds = 30
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$expected = [System.Text.Json.Nodes.JsonNode]::Parse([IO.File]::ReadAllText((Resolve-Path -LiteralPath $RegistryPath)))
# The download host serializes JSON and proxies GitHub release URLs. Apply that
# deterministic URL mapping only to downloadUrl; every other value must match.
foreach ($plugin in $expected['plugins']) {
    foreach ($version in $plugin['versions']) {
        $url = $version['downloadUrl'].ToString()
        if ($url -cmatch '^https://github\.com/[^/]+/[^/]+/releases/download/([^/?#]+)/([^/?#]+)$') {
            $tag = [Uri]::EscapeDataString($Matches[1])
            $asset = [Uri]::EscapeDataString($Matches[2])
            $mapped = "https://downloads.zeussdr.com/plugins/releases/download/$tag/$asset"
            $version['downloadUrl'] = [System.Text.Json.Nodes.JsonValue]::Create[string]($mapped)
        }
    }
}
$download = [IO.Path]::GetTempFileName()
try {
    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
        try {
            Invoke-WebRequest -Uri 'https://downloads.zeussdr.com/plugins/registry.json' `
                -OutFile $download -TimeoutSec 30 -MaximumRedirection 0
            $actual = [System.Text.Json.Nodes.JsonNode]::Parse([IO.File]::ReadAllText($download))
            if ([System.Text.Json.Nodes.JsonNode]::DeepEquals($actual, $expected)) {
                Write-Host "Public catalog matches the validated registry and download-host URL mapping."
                return
            }
            Write-Warning "Public catalog content differs on attempt $attempt of $Attempts."
        }
        catch {
            Write-Warning "Public catalog download or JSON parsing failed on attempt $attempt of ${Attempts}: $($_.Exception.Message)"
        }
        if ($attempt -lt $Attempts) { Start-Sleep -Seconds $RetrySeconds }
    }
    throw "Public catalog did not match the validated registry after $Attempts attempts."
}
finally {
    Remove-Item -LiteralPath $download -Force
}
