# SPDX-License-Identifier: GPL-2.0-or-later
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
# Exercise the production verifier without network access or real sleeping.
$fixture = [IO.Path]::GetTempFileName()
$catalogTestState = @{ Responses = @(); Requests = 0; Sleeps = 0 }
function Invoke-WebRequest {
    param($Uri, $OutFile, $TimeoutSec, $MaximumRedirection)
    if ($Uri -ne 'https://downloads.zeussdr.com/plugins/registry.json' -or $TimeoutSec -ne 30 -or $MaximumRedirection -ne 0) {
        throw 'Unexpected public download request.'
    }
    $response = $catalogTestState.Responses[$catalogTestState.Requests]
    $catalogTestState.Requests++
    if ($response -eq 'HTTP failure') { throw 'HTTP 503 fixture' }
    [IO.File]::WriteAllText($OutFile, $response)
}
function Start-Sleep {
    param($Seconds)
    $catalogTestState.Sleeps++
}
function Test-Verification {
    param([string[]]$Responses, [bool]$ShouldPass, [int]$ExpectedRequests)
    $catalogTestState.Responses = $Responses
    $catalogTestState.Requests = 0
    $catalogTestState.Sleeps = 0
    $passed = $false
    try {
        & (Join-Path $PSScriptRoot 'verify-published-catalog.ps1') -RegistryPath $fixture -Attempts $Responses.Count -RetrySeconds 0
        $passed = $true
    }
    catch {
        if ($_.Exception.Message -notmatch 'Public catalog did not match') { throw }
    }
    if ($passed -ne $ShouldPass -or $catalogTestState.Requests -ne $ExpectedRequests -or $catalogTestState.Sleeps -ne ($ExpectedRequests - 1)) {
        throw "Unexpected verification result: passed=$passed requests=$catalogTestState.Requests sleeps=$catalogTestState.Sleeps"
    }
}
try {
    $source = '{"generated":"2026-09-29T12:00:00Z","plugins":[{"id":"com.example.feature","verified":false,"versions":[{"downloadUrl":"https://github.com/Zeus-SDR/zeus-community-features/releases/download/community-com.example.feature-v1.0.0/com.example.feature-1.0.0.zip","sha256":"abc123"}]}]}'
    $published = $source.Replace('https://github.com/Zeus-SDR/zeus-community-features/releases/download/', 'https://downloads.zeussdr.com/plugins/releases/download/')
    [IO.File]::WriteAllText($fixture, $source)
    Test-Verification -Responses @($published) -ShouldPass $true -ExpectedRequests 1
    Test-Verification -Responses @('{"plugins":[]}', 'HTTP failure', $published) -ShouldPass $true -ExpectedRequests 3
    Test-Verification -Responses @('{"plugins":[]}', '{"plugins":[]}') -ShouldPass $false -ExpectedRequests 2
    Test-Verification -Responses @('HTTP failure', 'HTTP failure') -ShouldPass $false -ExpectedRequests 2
    Test-Verification -Responses @('invalid JSON', $published) -ShouldPass $true -ExpectedRequests 2
    # Formatting and object-property order do not alter catalog meaning.
    $formatted = ($published | ConvertFrom-Json -AsHashtable | ConvertTo-Json -Depth 20)
    Test-Verification -Responses @($formatted) -ShouldPass $true -ExpectedRequests 1
    $reordered = $published.Replace('"id":"com.example.feature","verified":false', '"verified":false,"id":"com.example.feature"')
    Test-Verification -Responses @($reordered) -ShouldPass $true -ExpectedRequests 1
    foreach ($mutation in @(
        $published.Replace('abc123', 'bad123'),
        $published.Replace('"verified":false', '"verified":true'),
        $published.Replace('2026-09-29', '2026-09-28'),
        $published.Replace('downloads.zeussdr.com', 'example.com'),
        $published.Replace('com.example.feature-1.0.0.zip', 'wrong.zip'),
        $published.Replace('com.example.feature-1.0.0.zip', 'com.example.feature-1.0.0.zip?extra=true'),
        ($published -creplace '\"versions\":\[.*?\]', '"versions":[]'),
        $published.Replace('"sha256":"abc123"', '"sha256":"abc123","extra":true'),
        $source
    )) {
        Test-Verification -Responses @($mutation) -ShouldPass $false -ExpectedRequests 1
    }
    # Existing download-host URLs must remain unchanged.
    [IO.File]::WriteAllText($fixture, $published)
    Test-Verification -Responses @($published) -ShouldPass $true -ExpectedRequests 1
    # A release's + build suffix uses the same escaped path in the public proxy.
    [IO.File]::WriteAllText($fixture, $source.Replace('v1.0.0/', 'v1.0.0+build/'))
    Test-Verification -Responses @($published.Replace('v1.0.0/', 'v1.0.0%2Bbuild/')) -ShouldPass $true -ExpectedRequests 1
    Write-Host 'Public catalog content-verification tests passed.'
}
finally {
    Remove-Item -LiteralPath $fixture -Force
}
