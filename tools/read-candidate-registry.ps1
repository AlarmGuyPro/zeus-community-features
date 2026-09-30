# SPDX-License-Identifier: GPL-2.0-or-later
# Reads registry.json from a pull request head through the GitHub API as inert
# bytes. It never checks out or executes fork content, so it is safe to call
# from a pull_request_target job that runs protected-main tooling.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $CandidateRepository,
    [Parameter(Mandatory)][string] $CandidateSha,
    [Parameter(Mandatory)][string] $OutputPath,
    [long] $MaxBytes = 10485760
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($CandidateRepository -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' -or
    $CandidateSha -cnotmatch '^[0-9a-f]{40}$') {
    throw 'Pull request head identity is invalid'
}
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) { throw 'GitHub CLI is required' }

$json = gh api "repos/$CandidateRepository/contents/registry.json?ref=$CandidateSha"
if ($LASTEXITCODE -ne 0) { throw 'Could not read a bounded candidate registry.json' }
$content = $json | ConvertFrom-Json -Depth 20
if ($content.type -cne 'file' -or $content.encoding -cne 'base64' -or
    $content.size -gt $MaxBytes) {
    throw 'Could not read a bounded candidate registry.json'
}
$bytes = [Convert]::FromBase64String(([string]$content.content -replace '\s', ''))
if ($bytes.Length -gt $MaxBytes) { throw 'Candidate registry.json exceeds the size limit' }
$destination = [IO.Path]::GetFullPath($OutputPath)
New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
[IO.File]::WriteAllBytes($destination, $bytes)
Write-Host "Read candidate registry.json ($($bytes.Length) bytes) from $CandidateRepository@$CandidateSha"
