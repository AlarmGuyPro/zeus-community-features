# SPDX-License-Identifier: GPL-2.0-or-later
<#
  Regression tests for tools/PackageSecurityScan. Every fixture plugin is built at
  test time from source into a temporary directory (tiny C# class libraries plus
  handwritten JavaScript modules and plugin.json), zipped, scanned, and asserted
  against the exact rule ids, severities, disposition, and exit code. Each rule has
  a case that trips it, and the clean package must stay clear, so a rule that stops
  firing (or starts firing on clean code) fails this script.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$scannerProject = Join-Path $PSScriptRoot "PackageSecurityScan/PackageSecurityScan.csproj"
$scannerDll = Join-Path $PSScriptRoot "PackageSecurityScan/bin/Release/net10.0/PackageSecurityScan.dll"
$contractsProject = Join-Path $repoRoot "sdk/Zeussdr.Zeus.Plugins.Contracts/Zeus.Plugins.Contracts.csproj"
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) "zeus-package-security-$([Guid]::NewGuid().ToString('N'))"
$fixturesDir = Join-Path $tempRoot "fixtures"
$packagesDir = Join-Path $tempRoot "packages"
$reportsDir = Join-Path $tempRoot "reports"
$markerPath = Join-Path $tempRoot "module-initializer-ran.txt"
$utf8 = [Text.UTF8Encoding]::new($false)
$script:failures = [Collections.Generic.List[string]]::new()
$script:passed = 0

function Write-Utf8File {
    param([Parameter(Mandatory)][string] $Path, [Parameter(Mandatory)][string] $Content)
    New-Item -ItemType Directory -Path (Split-Path -Parent $Path) -Force | Out-Null
    [IO.File]::WriteAllText($Path, $Content, $utf8)
}

function Get-CleanSource {
    param([string] $Message = "Hello from a Zeus community feature.", [int] $Answer = 41, [string] $Extra = "")
    return @"
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using Zeus.Plugins.Contracts;
using Zeus.Plugins.Contracts.Extensions;

namespace Fixture.Clean;

public sealed class CleanPlugin : IZeusPlugin, IBackendPlugin
{
    private IPluginContext _context;

    public Task InitializeAsync(IPluginContext context, CancellationToken ct)
    {
        _context = context;
        context.Logger.LogInformation("Clean fixture initialized");
        return Task.CompletedTask;
    }

    public Task ShutdownAsync(CancellationToken ct)
    {
        _context = null;
        return Task.CompletedTask;
    }

    public void MapEndpoints(IEndpointRouteBuilder endpoints) =>
        endpoints.MapGet("hello", () => Results.Ok(new { message = "$Message", pluginId = _context?.PluginId }));

    public static int Answer() => $Answer;
$Extra
}
"@
}

function Get-ProbeSource {
    param([Parameter(Mandatory)][string] $Body)
    return @"
namespace Fixture;

public static class Probe
{
$Body
}
"@
}

# name => @{ Source; Web (references ASP.NET Core + the public SDK); AssemblyName }
$fixtures = [ordered]@{
    Clean = @{ Source = (Get-CleanSource); Web = $true; AssemblyName = "Fixture.Clean" }
    CleanTwin = @{ Source = (Get-CleanSource); Web = $true; AssemblyName = "Fixture.Clean" }
    CleanExtraMethod = @{ Source = (Get-CleanSource -Extra "    public static int Extra() => 7;"); Web = $true; AssemblyName = "Fixture.Clean" }
    CleanExtraString = @{ Source = (Get-CleanSource -Message "Hello from a modified build."); Web = $true; AssemblyName = "Fixture.Clean" }
    CleanIlOnly = @{ Source = (Get-CleanSource -Answer 42); Web = $true; AssemblyName = "Fixture.Clean" }
    PInvoke = @{ Source = (Get-ProbeSource '    [System.Runtime.InteropServices.DllImport("libc", EntryPoint = "getpid")] public static extern int GetPid();') }
    ModuleInit = @{ Source = (Get-ProbeSource @'
    internal static int Count;
    [System.Runtime.CompilerServices.ModuleInitializer] internal static void Run() => Count++;
'@) }
    Marker = @{ Source = (Get-ProbeSource @"
    [System.Runtime.CompilerServices.ModuleInitializer]
    internal static void Run() => System.IO.File.WriteAllText(@"$markerPath", "executed");
"@) }
    Process = @{ Source = (Get-ProbeSource '    public static void Go() => System.Diagnostics.Process.Start("sh");') }
    AssemblyLoad = @{ Source = (Get-ProbeSource '    public static object Go(byte[] image) => System.Reflection.Assembly.Load(image);') }
    Http = @{ Source = (Get-ProbeSource '    public static object Make() => new System.Net.Http.HttpClient();') }
    FileWrite = @{ Source = (Get-ProbeSource '    public static void Save() => System.IO.File.WriteAllText("state.txt", "x");') }
    EnvVar = @{ Source = (Get-ProbeSource '    public static string Home() => System.Environment.GetEnvironmentVariable("HOME");') }
    PublicUrl = @{ Source = (Get-ProbeSource '    public static string Url() => "https://updates.attacker-host.net/payload";') }
    PrivateUrl = @{ Source = (Get-ProbeSource '    public static string Url() => "http://192.168.1.10/status";') }
    Secret = @{ Source = (Get-ProbeSource '    public static string Token() => "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";') }
    HostApi = @{ Source = (Get-ProbeSource '    public static string Route() => "/api/tx/mox";') }
    TimeBomb = @{ Source = (Get-ProbeSource '    public static bool Expired() => System.DateTime.UtcNow > new System.DateTime(2027, 1, 1);') }
    XmlFile = @{ Source = (Get-ProbeSource @'
    public static void Save(string path)
    {
        using (var writer = System.Xml.XmlWriter.Create(path)) { writer.WriteStartElement("a"); writer.WriteEndElement(); }
        new System.Xml.Linq.XDocument(new System.Xml.Linq.XElement("a")).Save(path);
    }
'@) }
    ZipExtract = @{ Source = (Get-ProbeSource '    public static void Unpack() => System.IO.Compression.ZipFile.ExtractToDirectory("in.zip", "out");') }
    MemoryMapped = @{ Source = (Get-ProbeSource '    public static object Map() => System.IO.MemoryMappedFiles.MemoryMappedFile.CreateFromFile("data.bin");') }
    FileVersion = @{ Source = (Get-ProbeSource '    public static string Version() => System.Diagnostics.FileVersionInfo.GetVersionInfo("x.dll").FileVersion;') }
    Pipes = @{ Source = (Get-ProbeSource '    public static object Pipe() => new System.IO.Pipes.NamedPipeClientStream("plugin-ipc");') }
    XmlUrl = @{ Source = (Get-ProbeSource '    public static object Read() => System.Xml.XmlReader.Create("https://example.com/feed.xml");') }
    NetCredential = @{ Source = (Get-ProbeSource '    public static object Credential() => new System.Net.NetworkCredential("user", "pass");') }
    # Compiler and framework output that must not be mistaken for hostile code: a source-generated
    # regex (GeneratedCodeAttribute), a collection expression (InlineArray + Unsafe.As helpers in
    # <PrivateImplementationDetails>), an alphabet table, and an XML namespace URI.
    CompilerOutput = @{ Source = @'
namespace Fixture;

public static partial class Probe
{
    public const string Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    [System.Text.RegularExpressions.GeneratedRegex("^[a-z]+$")]
    private static partial System.Text.RegularExpressions.Regex Word();

    public static bool IsWord(string value) => Word().IsMatch(value);
    public static string SvgNamespace() => "http://www.w3.org/2000/svg";
    public static string Digits(int index) => Alphabet.Substring(index, 1);

    public static object[] Pack(object a, object b, object c, object d)
    {
        System.Span<object> items = [a, b, c, d];
        return items.ToArray();
    }
}
'@ }
}

$cleanJs = @'
// SPDX-License-Identifier: GPL-2.0-or-later
// Source: https://github.com/example/zeus-clean-fixture
export default function mount(element, host) {
  const label = document.createElement('p');
  label.textContent = 'Clean fixture';
  element.appendChild(label);
  host.callBackend('hello').then((reply) => {
    label.textContent = reply.message;
  });
}
'@

function Build-Fixtures {
    New-Item -ItemType Directory -Path $fixturesDir -Force | Out-Null
    # Stop MSBuild from importing any Directory.Build.* above the temp directory.
    Write-Utf8File -Path (Join-Path $fixturesDir "Directory.Build.props") -Content @'
<Project>
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>disable</Nullable>
    <Deterministic>true</Deterministic>
    <IsPackable>false</IsPackable>
    <Version>1.0.0</Version>
    <CopyLocalLockFileAssemblies>false</CopyLocalLockFileAssemblies>
    <SatelliteResourceLanguages>en</SatelliteResourceLanguages>
    <TreatWarningsAsErrors>false</TreatWarningsAsErrors>
    <NoWarn>$(NoWarn);CA2255</NoWarn>
  </PropertyGroup>
</Project>
'@
    Write-Utf8File -Path (Join-Path $fixturesDir "Directory.Build.targets") -Content "<Project />`n"
    $solution = [Text.StringBuilder]::new("<Solution>`n")
    foreach ($name in $fixtures.Keys) {
        $fixture = $fixtures[$name]
        $assemblyName = if ($fixture.ContainsKey("AssemblyName")) { $fixture.AssemblyName } else { "Fixture.$name" }
        $references = ""
        if ($fixture.ContainsKey("Web") -and $fixture.Web) {
            $references = @"
  <ItemGroup>
    <FrameworkReference Include="Microsoft.AspNetCore.App" />
    <ProjectReference Include="$contractsProject" Private="false" />
  </ItemGroup>
"@
        }
        Write-Utf8File -Path (Join-Path $fixturesDir "$name/$name.csproj") -Content @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <AssemblyName>$assemblyName</AssemblyName>
  </PropertyGroup>
$references
</Project>
"@
        Write-Utf8File -Path (Join-Path $fixturesDir "$name/Fixture.cs") -Content $fixture.Source
        [void]$solution.Append("  <Project Path=`"$name/$name.csproj`" />`n")
    }
    [void]$solution.Append("</Solution>`n")
    Write-Utf8File -Path (Join-Path $fixturesDir "fixtures.slnx") -Content $solution.ToString()
    $log = Join-Path $tempRoot "fixtures-build.log"
    & dotnet build (Join-Path $fixturesDir "fixtures.slnx") -c Release --nologo *> $log
    if ($LASTEXITCODE -ne 0) {
        Get-Content -LiteralPath $log | Write-Host
        throw "Fixture build failed: $LASTEXITCODE"
    }
}

function Get-FixtureOutput {
    param([Parameter(Mandatory)][string] $Name, [string] $Extension = ".dll")
    $fixture = $fixtures[$Name]
    $assemblyName = if ($fixture.ContainsKey("AssemblyName")) { $fixture.AssemblyName } else { "Fixture.$Name" }
    $path = Join-Path $fixturesDir "$Name/bin/Release/net10.0/$assemblyName$Extension"
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Fixture output missing: $path" }
    return $path
}

function New-Manifest {
    param(
        [Parameter(Mandatory)][string] $Entrypoint,
        [string] $Type = "Fixture.Probe",
        [string[]] $Capabilities = @(),
        [bool] $Network = $false,
        [bool] $FileSystemRead = $false,
        [bool] $FileSystemWrite = $false,
        [switch] $Ui
    )
    $manifest = [ordered]@{
        schemaVersion = 1
        id = "com.example.securityfixture"
        name = "Security fixture"
        version = "1.0.0"
        author = "Fixture author"
        description = "Package security scanner regression fixture."
        homepage = "https://github.com/example/zeus-clean-fixture"
        license = "GPL-2.0-or-later"
        sdk = [ordered]@{ abi = 1; minVersion = "1.5.0" }
        entrypoint = [ordered]@{ assembly = $Entrypoint; type = $Type }
        capabilities = @($Capabilities)
        permissions = [ordered]@{ network = $Network; fileSystemRead = $FileSystemRead; fileSystemWrite = $FileSystemWrite }
    }
    if ($Ui) {
        $manifest.ui = [ordered]@{
            modules = @("ui/clean.js")
            panels = @([ordered]@{ id = "clean"; title = "Clean"; module = "ui/clean.js" })
        }
    }
    return ($manifest | ConvertTo-Json -Depth 10)
}

function Get-CleanFiles {
    $files = [ordered]@{}
    $files["plugin.json"] = New-Manifest -Entrypoint "Fixture.Clean.dll" -Type "Fixture.Clean.CleanPlugin" -Ui
    $files["Fixture.Clean.dll"] = [IO.File]::ReadAllBytes((Get-FixtureOutput "Clean"))
    $files["Fixture.Clean.deps.json"] = [IO.File]::ReadAllBytes((Get-FixtureOutput "Clean" ".deps.json"))
    $files["README.md"] = "# Clean fixture`n"
    $files["LICENSE"] = "GPL-2.0-or-later fixture licence text`n"
    $files["ui/clean.js"] = $cleanJs
    return $files
}

function Get-ProbeFiles {
    param(
        [Parameter(Mandatory)][string] $Fixture,
        [string[]] $Capabilities = @(),
        [bool] $Network = $false
    )
    $dll = "Fixture.$Fixture.dll"
    $files = [ordered]@{}
    $files["plugin.json"] = New-Manifest -Entrypoint $dll -Capabilities $Capabilities -Network $Network
    $files[$dll] = [IO.File]::ReadAllBytes((Get-FixtureOutput $Fixture))
    $files["LICENSE"] = "GPL-2.0-or-later fixture licence text`n"
    return $files
}

function New-Package {
    param([Parameter(Mandatory)][string] $Name, [Parameter(Mandatory)][Collections.IDictionary] $Files)
    New-Item -ItemType Directory -Path $packagesDir -Force | Out-Null
    $path = Join-Path $packagesDir "$Name.zip"
    $stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew)
    $archive = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Create, $false)
    try {
        foreach ($key in $Files.Keys) {
            $value = $Files[$key]
            $bytes = if ($value -is [byte[]]) { $value } else { $utf8.GetBytes([string]$value) }
            $entryStream = $archive.CreateEntry($key).Open()
            try { $entryStream.Write($bytes, 0, $bytes.Length) }
            finally { $entryStream.Dispose() }
        }
    }
    finally {
        $archive.Dispose()
        $stream.Dispose()
    }
    return $path
}

function Invoke-Scanner {
    param([Parameter(Mandatory)][string] $Name, [Parameter(Mandatory)][string[]] $Arguments)
    New-Item -ItemType Directory -Path $reportsDir -Force | Out-Null
    $json = Join-Path $reportsDir "$Name.json"
    $log = Join-Path $reportsDir "$Name.log"
    & dotnet $scannerDll @Arguments --json $json *> $log
    $exitCode = $LASTEXITCODE
    $report = $null
    if (Test-Path -LiteralPath $json) { $report = Get-Content -Raw -LiteralPath $json | ConvertFrom-Json -Depth 20 }
    return [pscustomobject]@{ ExitCode = $exitCode; Report = $report; Log = $log }
}

function Invoke-Scan {
    param([Parameter(Mandatory)][string] $Name, [Parameter(Mandatory)][string] $Package, [string] $Allowlist = "")
    $arguments = @("scan", "--package", $Package)
    if ($Allowlist) { $arguments += @("--allowlist", $Allowlist) }
    return Invoke-Scanner -Name $Name -Arguments $arguments
}

function Invoke-Compare {
    param([Parameter(Mandatory)][string] $Name, [Parameter(Mandatory)][string] $Package, [Parameter(Mandatory)][string] $Rebuilt)
    return Invoke-Scanner -Name $Name -Arguments @("compare", "--package", $Package, "--rebuilt", $Rebuilt)
}

function Complete-Case {
    param([Parameter(Mandatory)][string] $Case, [AllowEmptyCollection()][string[]] $Problems, [string] $Log = "")
    if ($Problems.Count -eq 0) {
        $script:passed++
        Write-Host "PASS $Case"
        return
    }
    $script:failures.Add("${Case}: $($Problems -join '; ')")
    Write-Host "FAIL $Case - $($Problems -join '; ')"
    if ($Log -and (Test-Path -LiteralPath $Log)) { Get-Content -LiteralPath $Log | Write-Host }
}

function Assert-Result {
    param(
        [Parameter(Mandatory)][string] $Case,
        [Parameter(Mandatory)] $Result,
        [Parameter(Mandatory)][int] $ExitCode,
        [Parameter(Mandatory)][string] $Disposition,
        [AllowEmptyCollection()][string[]] $Expected = @(),
        [string] $EvidenceContains = ""
    )
    $problems = [Collections.Generic.List[string]]::new()
    if ($Result.ExitCode -ne $ExitCode) { $problems.Add("exit code $($Result.ExitCode), expected $ExitCode") }
    if ($null -eq $Result.Report) {
        $problems.Add("no JSON report was written")
    }
    else {
        if ([string]$Result.Report.disposition -cne $Disposition) {
            $problems.Add("disposition $($Result.Report.disposition), expected $Disposition")
        }
        $actual = @($Result.Report.findings | Where-Object { $_.ruleId -cne "manifest-capabilities" } |
            ForEach-Object { "$($_.ruleId):$($_.severity)" } | Sort-Object -Unique)
        $wanted = @($Expected | Sort-Object -Unique)
        if (($actual -join ",") -cne ($wanted -join ",")) {
            $problems.Add("findings [$($actual -join ', ')], expected [$($wanted -join ', ')]")
        }
        if ($EvidenceContains -and -not @($Result.Report.findings | Where-Object {
            ([string]$_.evidence).Contains($EvidenceContains) -or ([string]$_.detail).Contains($EvidenceContains)
        })) {
            $problems.Add("no finding evidence contains '$EvidenceContains'")
        }
    }
    Complete-Case -Case $Case -Problems $problems -Log $Result.Log
}

function New-Allowlist {
    param([Parameter(Mandatory)][string] $Name, [Parameter(Mandatory)][string] $Sha256)
    $path = Join-Path $tempRoot "$Name.json"
    $allowlist = [ordered]@{
        schemaVersion = 1
        entries = @([ordered]@{
            id = "com.example.securityfixture"
            version = "1.0.0"
            sha256 = $Sha256
            ruleId = "pinvoke"
            file = "Fixture.PInvoke.dll"
            reason = "Regression fixture"
            approvedBy = "KB2UKA"
        })
    }
    Write-Utf8File -Path $path -Content ($allowlist | ConvertTo-Json -Depth 10)
    return $path
}

function Expand-Fixture {
    param([Parameter(Mandatory)][string] $Package, [Parameter(Mandatory)][string] $Name)
    $directory = Join-Path $tempRoot "rebuilt/$Name"
    [IO.Compression.ZipFile]::ExtractToDirectory($Package, $directory)
    return $directory
}

New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
try {
    $log = Join-Path $tempRoot "scanner-build.log"
    & dotnet build $scannerProject -c Release --nologo *> $log
    if ($LASTEXITCODE -ne 0) {
        Get-Content -LiteralPath $log | Write-Host
        throw "Scanner build failed: $LASTEXITCODE"
    }
    Build-Fixtures

    # --- Clean package (managed backend + UI module) stays clear -------------------------
    $cleanPackage = New-Package -Name "clean" -Files (Get-CleanFiles)
    $result = Invoke-Scan -Name "clean" -Package $cleanPackage
    Assert-Result -Case "clean package is clear" -Result $result -ExitCode 0 -Disposition "clear" `
        -Expected @("js-public-endpoint:info") -EvidenceContains "github.com"
    $problems = [Collections.Generic.List[string]]::new()
    $sha = (Get-FileHash -LiteralPath $cleanPackage -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($result.Report.tool -cne "PackageSecurityScan" -or $result.Report.version -cne "1") { $problems.Add("tool/version header") }
    if ($result.Report.package -cne "clean.zip") { $problems.Add("package name $($result.Report.package)") }
    if ($result.Report.sha256 -cne $sha) { $problems.Add("sha256 $($result.Report.sha256), expected $sha") }
    if ($result.Report.manifest.id -cne "com.example.securityfixture" -or $result.Report.manifest.version -cne "1.0.0") {
        $problems.Add("manifest identity")
    }
    if (-not @($result.Report.findings | Where-Object { $_.ruleId -ceq "manifest-capabilities" -and $_.severity -ceq "info" })) {
        $problems.Add("manifest-capabilities info finding missing")
    }
    Complete-Case -Case "report shape (tool, sha256, manifest, manifest-capabilities)" -Problems $problems -Log $result.Log

    # The documented CLI contract (dotnet run --project ...) behaves the same as the built DLL.
    $runLog = Join-Path $reportsDir "dotnet-run.log"
    & dotnet run --project $scannerProject -c Release --no-build -- scan --package $cleanPackage *> $runLog
    $problems = @()
    if ($LASTEXITCODE -ne 0) { $problems += "dotnet run exit code $LASTEXITCODE, expected 0" }
    if (-not (Select-String -LiteralPath $runLog -SimpleMatch "Disposition: CLEAR" -Quiet)) { $problems += "no CLEAR summary on stdout" }
    Complete-Case -Case "dotnet run CLI contract" -Problems $problems -Log $runLog

    # --- One case per managed rule ------------------------------------------------------
    $managedCases = @(
        @{ Case = "P/Invoke"; Fixture = "PInvoke"; Exit = 2; Disposition = "fail"; Expected = @("pinvoke:fail"); Evidence = "libc!getpid" },
        @{ Case = "module initializer"; Fixture = "ModuleInit"; Exit = 2; Disposition = "fail"; Expected = @("module-initializer:fail"); Evidence = "ModuleInitializer" },
        @{ Case = "Process.Start"; Fixture = "Process"; Exit = 2; Disposition = "fail"; Expected = @("process:fail"); Evidence = "System.Diagnostics.Process" },
        @{ Case = "Assembly.Load(byte[])"; Fixture = "AssemblyLoad"; Exit = 2; Disposition = "fail"; Expected = @("dynamic-code:fail"); Evidence = "System.Reflection.Assembly::Load" },
        @{ Case = "undeclared HttpClient"; Fixture = "Http"; Exit = 2; Disposition = "fail"; Expected = @("undeclared-network:fail"); Evidence = "System.Net.Http.HttpClient" },
        @{ Case = "declared HttpClient"; Fixture = "Http"; Exit = 0; Disposition = "clear"; Expected = @("undeclared-network:info"); Capabilities = @("NetworkAccess"); Network = $true },
        @{ Case = "undeclared File.WriteAllText"; Fixture = "FileWrite"; Exit = 2; Disposition = "fail"; Expected = @("undeclared-filesystem:fail"); Evidence = "System.IO.File::WriteAllText" },
        @{ Case = "Environment.GetEnvironmentVariable"; Fixture = "EnvVar"; Exit = 0; Disposition = "review"; Expected = @("environment:review"); Evidence = "ZEUS_STATION_ACCESS_TOKEN" },
        @{ Case = "public URL string"; Fixture = "PublicUrl"; Exit = 0; Disposition = "review"; Expected = @("public-endpoint:review"); Evidence = "updates.attacker-host.net" },
        @{ Case = "private 192.168.1.10 URL"; Fixture = "PrivateUrl"; Exit = 0; Disposition = "clear"; Expected = @() },
        @{ Case = "ghp_ token"; Fixture = "Secret"; Exit = 0; Disposition = "review"; Expected = @("secret-like:review"); Evidence = "GitHub token: ghp_A1b2C3d4" },
        @{ Case = "/api/tx/mox string in DLL"; Fixture = "HostApi"; Exit = 2; Disposition = "fail"; Expected = @("host-api-string:fail"); Evidence = "/api/tx/mox" },
        @{ Case = "time bomb new DateTime(2027,1,1)"; Fixture = "TimeBomb"; Exit = 0; Disposition = "review"; Expected = @("time-bomb:review"); Evidence = "2027" },
        @{ Case = "XmlWriter.Create(path) and XDocument.Save(path)"; Fixture = "XmlFile"; Exit = 2; Disposition = "fail"; Expected = @("undeclared-filesystem:fail"); Evidence = "System.Xml.Linq.XDocument::Save" },
        @{ Case = "ZipFile.ExtractToDirectory"; Fixture = "ZipExtract"; Exit = 2; Disposition = "fail"; Expected = @("undeclared-filesystem:fail"); Evidence = "ZipFile::ExtractToDirectory" },
        @{ Case = "MemoryMappedFile.CreateFromFile"; Fixture = "MemoryMapped"; Exit = 2; Disposition = "fail"; Expected = @("undeclared-filesystem:fail"); Evidence = "MemoryMappedFile::CreateFromFile" },
        @{ Case = "FileVersionInfo.GetVersionInfo"; Fixture = "FileVersion"; Exit = 2; Disposition = "fail"; Expected = @("undeclared-filesystem:fail"); Evidence = "FileVersionInfo::GetVersionInfo" },
        @{ Case = "named pipe IPC"; Fixture = "Pipes"; Exit = 0; Disposition = "review"; Expected = @("ipc:review"); Evidence = "NamedPipeClientStream" },
        @{ Case = "XmlReader.Create(url)"; Fixture = "XmlUrl"; Exit = 2; Disposition = "fail"; Expected = @("undeclared-filesystem:fail", "undeclared-network:fail"); Evidence = "accepts URLs" },
        @{ Case = "unclassified System.Net API"; Fixture = "NetCredential"; Exit = 0; Disposition = "review"; Expected = @("unclassified-io-api:review"); Evidence = "System.Net.NetworkCredential::.ctor" }
    )
    foreach ($case in $managedCases) {
        $capabilities = if ($case.ContainsKey("Capabilities")) { $case.Capabilities } else { @() }
        $network = if ($case.ContainsKey("Network")) { $case.Network } else { $false }
        $name = ($case.Case -replace "[^A-Za-z0-9]+", "-").Trim("-").ToLowerInvariant()
        $package = New-Package -Name $name -Files (Get-ProbeFiles -Fixture $case.Fixture -Capabilities $capabilities -Network $network)
        $evidence = if ($case.ContainsKey("Evidence")) { $case.Evidence } else { "" }
        $result = Invoke-Scan -Name $name -Package $package
        Assert-Result -Case $case.Case -Result $result -ExitCode $case.Exit -Disposition $case.Disposition `
            -Expected $case.Expected -EvidenceContains $evidence
    }
    $secretReport = Get-Content -Raw -LiteralPath (Join-Path $reportsDir "ghp-token.json")
    Complete-Case -Case "secret evidence is redacted" -Problems @(
        if ($secretReport.Contains("Q7r8")) { "full token appears in the report" })

    # --- The scanner never executes package code -----------------------------------------
    $markerPackage = New-Package -Name "marker" -Files (Get-ProbeFiles -Fixture "Marker")
    $result = Invoke-Scan -Name "marker" -Package $markerPackage
    Assert-Result -Case "module initializer that writes a marker file" -Result $result -ExitCode 2 -Disposition "fail" `
        -Expected @("module-initializer:fail", "undeclared-filesystem:fail")
    Complete-Case -Case "scanning did not run the module initializer" -Problems @(
        if (Test-Path -LiteralPath $markerPath) { "marker file exists after scanning: package code ran" })
    # Positive control: running the fixture's module initializer in a separate process does
    # write the marker, so the absence above is meaningful.
    $pwshCommand = Get-Command pwsh -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    $pwshPath = if ($null -ne $pwshCommand) { $pwshCommand.Source } else { [Environment]::ProcessPath }
    $controlScript = "`$a = [Reflection.Assembly]::LoadFile('$(Get-FixtureOutput "Marker")'); " +
        "[Runtime.CompilerServices.RuntimeHelpers]::RunModuleConstructor(`$a.ManifestModule.ModuleHandle)"
    $controlLog = Join-Path $reportsDir "marker-control.log"
    & $pwshPath -NoProfile -NonInteractive -Command $controlScript *> $controlLog
    Complete-Case -Case "positive control: executing the fixture writes the marker" -Problems @(
        if (-not (Test-Path -LiteralPath $markerPath)) { "marker not written when the fixture was deliberately executed ($pwshPath)" }) `
        -Log $controlLog
    if (Test-Path -LiteralPath $markerPath) { Remove-Item -LiteralPath $markerPath -Force }

    # --- Package-level and JavaScript rules ---------------------------------------------
    $files = Get-CleanFiles
    $files["native/helper"] = [byte[]](@(0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00) + @(0) * 56)
    $result = Invoke-Scan -Name "elf" -Package (New-Package -Name "elf" -Files $files)
    Assert-Result -Case "ELF file in package" -Result $result -ExitCode 2 -Disposition "fail" `
        -Expected @("native-binary:fail", "js-public-endpoint:info") -EvidenceContains ""

    $jsCases = @(
        @{ Case = "JS eval"; Script = "export function run(code) { return eval(code); }`n"; Exit = 2; Disposition = "fail"; Expected = @("js-eval:fail"); Evidence = "1:" },
        @{ Case = "JS fetch"; Script = "export async function load() { const r = await fetch('./data.json'); return r.json(); }`n"; Exit = 0; Disposition = "review"; Expected = @("js-network:review"); Evidence = "fetch(" },
        @{ Case = "JS /api/tx/mox literal"; Script = "export const path = '/api/tx/mox';`n"; Exit = 2; Disposition = "fail"; Expected = @("js-host-api:fail"); Evidence = "/api/tx/mox" },
        @{ Case = "JS global keydown"; Script = "window.addEventListener('keydown', (e) => { if (e.code === 'Space') e.preventDefault(); });`n"; Exit = 0; Disposition = "review"; Expected = @("js-global-keys:review"); Evidence = "keydown" },
        @{ Case = "JS bare Function(src)"; Script = 'export const run = (src) => Function(src)();'; Exit = 2; Disposition = "fail"; Expected = @("js-eval:fail"); Evidence = "Function(src)" },
        @{ Case = "JS (0,eval)(x)"; Script = 'export const run = (x) => (0, eval)(x);'; Exit = 2; Disposition = "fail"; Expected = @("js-eval:fail"); Evidence = "eval" },
        @{ Case = "JS window.eval"; Script = 'export const run = (x) => window.eval(x);'; Exit = 2; Disposition = "fail"; Expected = @("js-eval:fail"); Evidence = "window.eval" },
        @{ Case = "JS globalThis['ev'+'al']"; Script = 'export const run = (x) => globalThis[''ev'' + ''al''](x);'; Exit = 2; Disposition = "fail"; Expected = @("js-computed-access:review", "js-eval:fail", "js-split-name:fail"); Evidence = "reconstructed" },
        @{ Case = "JS [].constructor.constructor"; Script = 'export const run = (s) => [].constructor.constructor(s)();'; Exit = 2; Disposition = "fail"; Expected = @("js-eval:fail"); Evidence = "constructor.constructor" },
        @{ Case = "JS comments between callee and paren"; Script = 'export const open = (u) => new/**/WebSocket/**/(u);'; Exit = 0; Disposition = "review"; Expected = @("js-network:review"); Evidence = "WebSocket" },
        @{ Case = "JS Function(array.join) hiding fetch('/api/tx')"; Script = 'export const run = () => Function(["fe","tch(''/ap","i/tx'')"].join(""))();'; Exit = 2; Disposition = "fail"; Expected = @("js-eval:fail", "js-host-api:fail", "js-network:review", "js-split-name:fail"); Evidence = "fetch('/api/tx')" },
        @{ Case = "JS escaped '\x65val'"; Script = 'export const run = (x) => window[''\x65val''](x);'; Exit = 2; Disposition = "fail"; Expected = @("js-eval:fail", "js-split-name:fail"); Evidence = "reconstructed" },
        @{ Case = "JS iframe srcdoc"; Script = 'export const show = (f, html) => { f.srcdoc = html; };'; Exit = 2; Disposition = "fail"; Expected = @("js-srcdoc:fail"); Evidence = "srcdoc" },
        @{ Case = "JS createElement('iframe') with packaged HTML"; Script = 'export const mount = () => { const f = document.createElement(''iframe''); f.src = ''panel.html''; return f; };'; Exit = 0; Disposition = "review"; Expected = @("js-embed:review"); Evidence = "panel.html" },
        @{ Case = "JS globalThis.Function"; Script = 'export const run = (s) => globalThis.Function(s)();'; Exit = 2; Disposition = "fail"; Expected = @("js-eval:fail"); Evidence = "globalThis.Function" },
        @{ Case = "JS self.Function and parent.Function"; Script = 'export const a = (s) => self.Function(s)(); export const b = (s) => parent.Function(s)();'; Exit = 2; Disposition = "fail"; Expected = @("js-eval:fail"); Evidence = "parent.Function" },
        @{ Case = "JS window['Function']"; Script = 'export const run = (s) => window[''Function''](s)();'; Exit = 2; Disposition = "fail"; Expected = @("js-eval:fail"); Evidence = "Function" },
        @{ Case = "JS Reflect.construct(Function)"; Script = 'export const run = (s) => Reflect.construct(Function, [s])();'; Exit = 2; Disposition = "fail"; Expected = @("js-eval:fail"); Evidence = "Reflect.construct" },
        @{ Case = "JS AsyncFunction constructor idiom"; Script = 'const AsyncFunction = (async () => {}).constructor; export const run = (s) => new AsyncFunction(s)();'; Exit = 2; Disposition = "fail"; Expected = @("js-constructor-access:review", "js-eval:fail"); Evidence = "}).constructor" },
        @{ Case = "JS getPrototypeOf(function*).constructor"; Script = 'const G = Object.getPrototypeOf(function* () {}).constructor; export const run = (s) => new G(s);'; Exit = 2; Disposition = "fail"; Expected = @("js-constructor-access:review", "js-eval:fail"); Evidence = "getPrototypeOf" },
        @{ Case = "JS .constructor read as a value"; Script = 'export const ctorOf = (o) => o.constructor;'; Exit = 0; Disposition = "review"; Expected = @("js-constructor-access:review"); Evidence = "o.constructor" },
        @{ Case = "JS reversed lave split/reverse/join"; Script = 'export const run = (x) => window[''lave''.split('''').reverse().join('''')](x);'; Exit = 2; Disposition = "fail"; Expected = @("js-computed-access:review", "js-eval:fail", "js-split-name:fail"); Evidence = "reconstructed" },
        @{ Case = "JS reversed host API path"; Script = 'export const p = ''xt/ipa/''.split('''').reverse().join('''');'; Exit = 2; Disposition = "fail"; Expected = @("js-host-api:fail", "js-split-name:fail"); Evidence = "/api/tx" },
        @{ Case = "JS replace on a string literal"; Script = 'export const n = ''exxal''.replace(''xx'', ''v'');'; Exit = 0; Disposition = "review"; Expected = @("js-string-transform:review"); Evidence = "exxal" },
        @{ Case = "JS fromCharCode map"; Script = 'export const n = [101, 118, 97, 108].map((c) => String.fromCharCode(c)).join('''');'; Exit = 0; Disposition = "review"; Expected = @("js-string-transform:review"); Evidence = "fromCharCode" },
        @{ Case = "JS _0x obfuscation"; Script = ((0..24 | ForEach-Object { "var _0x{0:x4}ab = {0};" -f (0x1a2b + $_) }) -join "`n") + "`n"; Exit = 2; Disposition = "fail"; Expected = @("js-obfuscation:fail"); Evidence = "25 distinct _0x" }
    )
    foreach ($case in $jsCases) {
        $name = ($case.Case -replace "[^A-Za-z0-9]+", "-").Trim("-").ToLowerInvariant()
        $files = Get-CleanFiles
        $files["ui/case.js"] = $case.Script
        $result = Invoke-Scan -Name $name -Package (New-Package -Name $name -Files $files)
        Assert-Result -Case $case.Case -Result $result -ExitCode $case.Exit -Disposition $case.Disposition `
            -Expected (@($case.Expected) + "js-public-endpoint:info") -EvidenceContains $case.Evidence
    }

    # --- Markup and WebAssembly files ----------------------------------------------------
    $markupCases = @(
        @{ Case = "SVG with onload handler"; Path = "ui/icon.svg"; Content = '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><rect width="4" height="4"/></svg>'; Exit = 2; Disposition = "fail"; Expected = @("markup-script:fail"); Evidence = "onload" },
        @{ Case = "HTML file with iframe"; Path = "ui/help.html"; Content = '<html><body><p>Help</p><iframe src="other.html"></iframe></body></html>'; Exit = 0; Disposition = "review"; Expected = @("markup-embed:review", "markup-html-file:review"); Evidence = "<iframe" },
        @{ Case = "WebAssembly module file"; Path = "ui/module.wasm"; Content = [byte[]](0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00); Exit = 0; Disposition = "review"; Expected = @("wasm-file:review") }
    )
    foreach ($case in $markupCases) {
        $name = ($case.Case -replace "[^A-Za-z0-9]+", "-").Trim("-").ToLowerInvariant()
        $files = Get-CleanFiles
        $files[$case.Path] = $case.Content
        $evidence = if ($case.ContainsKey("Evidence")) { $case.Evidence } else { "" }
        $result = Invoke-Scan -Name $name -Package (New-Package -Name $name -Files $files)
        Assert-Result -Case $case.Case -Result $result -ExitCode $case.Exit -Disposition $case.Disposition `
            -Expected (@($case.Expected) + "js-public-endpoint:info") -EvidenceContains $evidence
    }

    # Locating tens of thousands of matches must stay linear (the line index is bisected, not rescanned).
    $files = Get-CleanFiles
    $files["ui/big.html"] = "<html><body>`n" + ("<iframe></iframe>`n" * 50000) + "</body></html>`n"
    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    $result = Invoke-Scan -Name "large-markup" -Package (New-Package -Name "large-markup" -Files $files)
    $stopwatch.Stop()
    Assert-Result -Case "large HTML with 50000 iframes" -Result $result -ExitCode 0 -Disposition "review" `
        -Expected @("js-public-endpoint:info", "markup-embed:review", "markup-html-file:review") -EvidenceContains "(+"
    Complete-Case -Case "large markup scans in under 5 s ($([int]$stopwatch.Elapsed.TotalMilliseconds) ms)" -Problems @(
        if ($stopwatch.Elapsed.TotalSeconds -ge 5) { "scan took $($stopwatch.Elapsed.TotalSeconds) s" })

    $package = New-Package -Name "compiler-output" -Files (Get-ProbeFiles -Fixture "CompilerOutput")
    $result = Invoke-Scan -Name "compiler-output" -Package $package
    Assert-Result -Case "compiler/framework output stays clear" -Result $result -ExitCode 0 -Disposition "clear" `
        -Expected @("public-endpoint:info") -EvidenceContains "www.w3.org"

    $css = ((1..12 | ForEach-Object { ".panel-$_ { display: grid; gap: ${_}px; color: var(--text-$_); border: 1px solid #1a2b3c; }" }) -join " ")
    $files = Get-CleanFiles
    $files["ui/case.js"] = "const warning = `"You should pass it as a different prop. (https://react.dev/link/special-props)`";`n" +
        "const css = `"$css`";`nexport const ns = 'http://www.w3.org/2000/svg';`nexport { warning, css };`n" +
        "export const csp = `"script-src 'self' 'unsafe-eval'`";`nexport const options = { eval: false, mode: 'x' };`n" +
        "export class Panel { constructor(root) { this.root = root; } kind() { return this.constructor.name; } }`n" +
        "export const label = 'Status: ' + 'ready';`n" +
        "export const isPlain = (v) => v.constructor === Object;`nfunction Foo() {}`nFoo.prototype.constructor = Foo;`n" +
        "export const cls = (v) => v.constructor.name;`nexport const parts = 'a-b'.split('-');`n" +
        "export const call = (api) => api.Function(1);`n"
    $result = Invoke-Scan -Name "js-bundler-output" -Package (New-Package -Name "js-bundler-output" -Files $files)
    Assert-Result -Case "JS framework URLs and long CSS literal stay clear" -Result $result -ExitCode 0 `
        -Disposition "clear" -Expected @("js-public-endpoint:info") -EvidenceContains "react.dev"

    $random = [Random]::new(42)
    $blob = [byte[]]::new(240)
    $random.NextBytes($blob)
    $files = Get-CleanFiles
    $files["ui/case.js"] = "export const payload = '$([Convert]::ToBase64String($blob))';`n"
    $result = Invoke-Scan -Name "js-encoded-blob" -Package (New-Package -Name "js-encoded-blob" -Files $files)
    Assert-Result -Case "JS long base64 blob" -Result $result -ExitCode 0 -Disposition "review" `
        -Expected @("js-obfuscation:review", "js-public-endpoint:info") -EvidenceContains "encoded run"

    # --- Allowlist: suppresses only the exact package bytes ------------------------------
    $pinvokePackage = Join-Path $packagesDir "p-invoke.zip"
    $pinvokeSha = (Get-FileHash -LiteralPath $pinvokePackage -Algorithm SHA256).Hash.ToLowerInvariant()
    $result = Invoke-Scan -Name "allowlist-exact" -Package $pinvokePackage -Allowlist (New-Allowlist -Name "allow-exact" -Sha256 $pinvokeSha)
    Assert-Result -Case "allowlist with the exact sha256 suppresses" -Result $result -ExitCode 0 -Disposition "clear" `
        -Expected @("pinvoke:info") -EvidenceContains "Allowlisted"
    $otherSha = if ($pinvokeSha[0] -eq "0") { "1" + $pinvokeSha.Substring(1) } else { "0" + $pinvokeSha.Substring(1) }
    $result = Invoke-Scan -Name "allowlist-other-sha" -Package $pinvokePackage -Allowlist (New-Allowlist -Name "allow-other" -Sha256 $otherSha)
    Assert-Result -Case "allowlist with a different sha256 does not suppress" -Result $result -ExitCode 2 -Disposition "fail" `
        -Expected @("pinvoke:fail")
    $emptyAllowlist = Join-Path $PSScriptRoot "package-security-allowlist.json"
    $result = Invoke-Scan -Name "allowlist-shipped" -Package $cleanPackage -Allowlist $emptyAllowlist
    Assert-Result -Case "shipped allowlist file loads" -Result $result -ExitCode 0 -Disposition "clear" `
        -Expected @("js-public-endpoint:info")

    # --- compare: package vs rebuilt staging directory -----------------------------------
    $result = Invoke-Compare -Name "compare-identical" -Package $cleanPackage -Rebuilt (Expand-Fixture $cleanPackage "identical")
    Assert-Result -Case "compare identical rebuild" -Result $result -ExitCode 0 -Disposition "clear" -Expected @()

    $rebuilt = Expand-Fixture $cleanPackage "twin"
    Copy-Item -LiteralPath (Get-FixtureOutput "CleanTwin") -Destination (Join-Path $rebuilt "Fixture.Clean.dll") -Force
    $twinBytesEqual = [Linq.Enumerable]::SequenceEqual([IO.File]::ReadAllBytes((Get-FixtureOutput "CleanTwin")),
        [IO.File]::ReadAllBytes((Get-FixtureOutput "Clean")))
    $result = Invoke-Compare -Name "compare-twin" -Package $cleanPackage -Rebuilt $rebuilt
    Assert-Result -Case "compare independent rebuild of the same source (bytes equal: $twinBytesEqual)" -Result $result `
        -ExitCode 0 -Disposition "clear" -Expected @()

    $rebuilt = Expand-Fixture $cleanPackage "extra-method"
    Copy-Item -LiteralPath (Get-FixtureOutput "CleanExtraMethod") -Destination (Join-Path $rebuilt "Fixture.Clean.dll") -Force
    $result = Invoke-Compare -Name "compare-extra-method" -Package $cleanPackage -Rebuilt $rebuilt
    Assert-Result -Case "compare rebuilt DLL with one extra method" -Result $result -ExitCode 2 -Disposition "fail" `
        -Expected @("compare-metadata-differ:fail") -EvidenceContains "only in rebuilt: method Fixture.Clean.CleanPlugin::Extra"

    $rebuilt = Expand-Fixture $cleanPackage "extra-string"
    Copy-Item -LiteralPath (Get-FixtureOutput "CleanExtraString") -Destination (Join-Path $rebuilt "Fixture.Clean.dll") -Force
    $result = Invoke-Compare -Name "compare-extra-string" -Package $cleanPackage -Rebuilt $rebuilt
    Assert-Result -Case "compare rebuilt DLL with a different string" -Result $result -ExitCode 2 -Disposition "fail" `
        -Expected @("compare-metadata-differ:fail") -EvidenceContains "Hello from a modified build."

    $rebuilt = Expand-Fixture $cleanPackage "il-only"
    Copy-Item -LiteralPath (Get-FixtureOutput "CleanIlOnly") -Destination (Join-Path $rebuilt "Fixture.Clean.dll") -Force
    $result = Invoke-Compare -Name "compare-il-only" -Package $cleanPackage -Rebuilt $rebuilt
    Assert-Result -Case "compare same metadata, different IL" -Result $result -ExitCode 0 -Disposition "review" `
        -Expected @("compare-il-differ:review") -EvidenceContains "CleanPlugin::Answer"

    $result = Invoke-Scanner -Name "compare-il-strict" -Arguments @("compare", "--package", $cleanPackage, "--rebuilt", $rebuilt, "--il-strict")
    Assert-Result -Case "compare --il-strict makes different IL a fail" -Result $result -ExitCode 2 -Disposition "fail" `
        -Expected @("compare-il-differ:fail") -EvidenceContains "CleanPlugin::Answer"

    $rebuilt = Expand-Fixture $cleanPackage "js-byte"
    $jsPath = Join-Path $rebuilt "ui/clean.js"
    $jsBytes = [IO.File]::ReadAllBytes($jsPath)
    $jsBytes[$jsBytes.Length - 2] = [byte](($jsBytes[$jsBytes.Length - 2] + 1) % 256)
    [IO.File]::WriteAllBytes($jsPath, $jsBytes)
    $result = Invoke-Compare -Name "compare-js-byte" -Package $cleanPackage -Rebuilt $rebuilt
    Assert-Result -Case "compare JS differing by one byte" -Result $result -ExitCode 2 -Disposition "fail" `
        -Expected @("compare-bytes-differ:fail") -EvidenceContains "first difference at byte offset $($jsBytes.Length - 2)"

    $rebuilt = Expand-Fixture $cleanPackage "missing-in-rebuilt"
    Remove-Item -LiteralPath (Join-Path $rebuilt "README.md")
    $result = Invoke-Compare -Name "compare-missing-rebuilt" -Package $cleanPackage -Rebuilt $rebuilt
    Assert-Result -Case "compare file missing from the rebuild" -Result $result -ExitCode 2 -Disposition "fail" `
        -Expected @("compare-missing-in-rebuilt:fail")

    $rebuilt = Expand-Fixture $cleanPackage "missing-in-package"
    Write-Utf8File -Path (Join-Path $rebuilt "ui/extra.js") -Content "export const extra = 1;`n"
    $result = Invoke-Compare -Name "compare-missing-package" -Package $cleanPackage -Rebuilt $rebuilt
    Assert-Result -Case "compare file missing from the package" -Result $result -ExitCode 2 -Disposition "fail" `
        -Expected @("compare-missing-in-package:fail")

    $rebuilt = Expand-Fixture $cleanPackage "deps-json"
    $depsPath = Join-Path $rebuilt "Fixture.Clean.deps.json"
    $deps = Get-Content -Raw -LiteralPath $depsPath | ConvertFrom-Json -Depth 50
    $deps.libraries.PSObject.Properties | ForEach-Object {
        if ($_.Value.PSObject.Properties["sha512"]) { $_.Value.sha512 = "sha512-rebuilt" }
    }
    Write-Utf8File -Path $depsPath -Content ($deps | ConvertTo-Json -Depth 50 -Compress)
    $result = Invoke-Compare -Name "compare-deps-json" -Package $cleanPackage -Rebuilt $rebuilt
    Assert-Result -Case "compare deps.json differing only in whitespace and sha512" -Result $result -ExitCode 0 `
        -Disposition "clear" -Expected @()

    # --- Tool errors exit 1 and never masquerade as a verdict ----------------------------
    $result = Invoke-Scan -Name "missing-package" -Package (Join-Path $tempRoot "does-not-exist.zip")
    Complete-Case -Case "missing package is a tool error" -Problems @(
        if ($result.ExitCode -ne 1) { "exit code $($result.ExitCode), expected 1" }
        if ($null -ne $result.Report) { "a report was written for a tool error" }) -Log $result.Log
}
finally {
    $resolvedTemp = [IO.Path]::GetFullPath($tempRoot)
    $systemTemp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if ($resolvedTemp.StartsWith($systemTemp, [StringComparison]::OrdinalIgnoreCase) -and
        (Test-Path -LiteralPath $resolvedTemp)) {
        Remove-Item -LiteralPath $resolvedTemp -Recurse -Force
    }
}

if ($script:failures.Count -gt 0) {
    throw "Package security scanner tests failed ($($script:failures.Count) failed, $($script:passed) passed):`n" +
        ($script:failures -join "`n")
}
Write-Host "Package security scanner tests passed: $($script:passed) cases."

# Native commands above may leave a non-zero $LASTEXITCODE from cases that
# are expected to fail; the GitHub pwsh wrapper would exit with it.
exit 0
