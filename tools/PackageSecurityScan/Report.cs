// SPDX-License-Identifier: GPL-2.0-or-later
using System.Text.Json;

namespace PackageSecurityScan;

internal sealed class Report(string mode, string packageName, string sha256, ManifestInfo? manifest,
    FindingSet findings)
{
    public const string ToolName = "PackageSecurityScan";
    public const string FormatVersion = "1";

    public string Mode { get; } = mode;
    public string PackageName { get; } = packageName;
    public string Sha256 { get; } = sha256;
    public ManifestInfo? Manifest { get; } = manifest;
    public FindingSet Findings { get; } = findings;
    public Severity Disposition => Findings.Worst;

    public int ExitCode => Disposition == Severity.Fail ? ExitCodes.Fail : ExitCodes.Ok;

    public void WriteJson(string path)
    {
        var full = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(full);
        if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);
        using var stream = File.Create(full);
        using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true });
        writer.WriteStartObject();
        writer.WriteString("tool", ToolName);
        writer.WriteString("version", FormatVersion);
        writer.WriteString("mode", Mode);
        writer.WriteString("package", Text.Clean(PackageName, 400));
        writer.WriteString("sha256", Sha256);
        if (Manifest is not null)
        {
            writer.WriteStartObject("manifest");
            writer.WriteString("id", Text.Clean(Manifest.Id, 200));
            writer.WriteString("version", Text.Clean(Manifest.Version, 100));
            writer.WriteStartArray("capabilities");
            foreach (var capability in Manifest.Capabilities) writer.WriteStringValue(Text.Clean(capability, 100));
            writer.WriteEndArray();
            writer.WriteStartObject("permissions");
            writer.WriteBoolean("network", Manifest.Network);
            writer.WriteBoolean("fileSystemRead", Manifest.FileSystemRead);
            writer.WriteBoolean("fileSystemWrite", Manifest.FileSystemWrite);
            writer.WriteEndObject();
            writer.WriteEndObject();
        }
        writer.WriteStartArray("findings");
        foreach (var finding in Findings.All)
        {
            writer.WriteStartObject();
            writer.WriteString("ruleId", finding.RuleId);
            writer.WriteString("severity", finding.Severity.ToWire());
            writer.WriteString("file", finding.File);
            writer.WriteString("detail", finding.DetailText);
            writer.WriteString("evidence", finding.EvidenceText);
            writer.WriteEndObject();
        }
        writer.WriteEndArray();
        writer.WriteString("disposition", Disposition.ToDisposition());
        writer.WriteEndObject();
    }

    public void WriteText(TextWriter output)
    {
        output.WriteLine($"{ToolName} {Mode}: {Text.Clean(PackageName, 400)}");
        output.WriteLine($"SHA-256: {Sha256}");
        if (Manifest is not null)
        {
            output.WriteLine($"Feature: {Text.Clean(Manifest.Id)} {Text.Clean(Manifest.Version, 100)}");
        }
        var ordered = Findings.All
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.File, StringComparer.Ordinal)
            .ThenBy(f => f.RuleId, StringComparer.Ordinal);
        foreach (var finding in ordered)
        {
            output.WriteLine($"[{finding.Severity.ToWire().ToUpperInvariant(),-6}] {finding.RuleId}  {finding.File}");
            output.WriteLine($"         {finding.DetailText}");
            foreach (var item in finding.Evidence) output.WriteLine($"           - {item}");
            if (finding.OmittedEvidence > 0) output.WriteLine($"           - (+{finding.OmittedEvidence} more)");
        }
        var fails = Findings.All.Count(f => f.Severity == Severity.Fail);
        var reviews = Findings.All.Count(f => f.Severity == Severity.Review);
        var infos = Findings.All.Count(f => f.Severity == Severity.Info);
        output.WriteLine(
            $"Disposition: {Disposition.ToDisposition().ToUpperInvariant()} ({fails} fail, {reviews} review, {infos} info)");
    }
}

internal static class ExitCodes
{
    public const int Ok = 0;
    public const int ToolError = 1;
    public const int Fail = 2;
}
