// SPDX-License-Identifier: GPL-2.0-or-later
using System.Text.Json;
using System.Text.RegularExpressions;

namespace PackageSecurityScan;

internal sealed record AllowlistEntry(string Id, string Version, string Sha256, string RuleId, string File,
    string Reason, string ApprovedBy);

/// <summary>
/// Maintainer-approved exceptions. An entry suppresses one finding only when the
/// feature id, version, package SHA-256, rule id, and file all match exactly, so an
/// approval can never carry over to different package bytes.
/// </summary>
internal sealed partial class Allowlist
{
    private static readonly string[] Fields = ["id", "version", "sha256", "ruleId", "file", "reason", "approvedBy"];
    private readonly List<AllowlistEntry> _entries;

    private Allowlist(List<AllowlistEntry> entries) => _entries = entries;

    public static Allowlist Empty { get; } = new([]);

    [GeneratedRegex("^[0-9a-f]{64}$")]
    private static partial Regex Sha256Pattern();

    public static Allowlist Load(string path)
    {
        if (!System.IO.File.Exists(path)) throw new ToolException($"Allowlist not found: {path}");
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(System.IO.File.ReadAllBytes(path));
        }
        catch (JsonException ex)
        {
            throw new ToolException($"Allowlist is not valid JSON: {ex.Message}");
        }
        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !root.TryGetProperty("schemaVersion", out var version) ||
                version.ValueKind != JsonValueKind.Number || version.GetInt32() != 1)
            {
                throw new ToolException("Allowlist must be an object with schemaVersion 1");
            }
            foreach (var property in root.EnumerateObject())
            {
                if (property.Name is not ("schemaVersion" or "entries" or "$schema" or "description"))
                {
                    throw new ToolException($"Allowlist has an unknown property: {property.Name}");
                }
            }
            if (!root.TryGetProperty("entries", out var entries) || entries.ValueKind != JsonValueKind.Array)
            {
                throw new ToolException("Allowlist must have an entries array");
            }
            var list = new List<AllowlistEntry>();
            var index = 0;
            foreach (var entry in entries.EnumerateArray())
            {
                list.Add(ParseEntry(entry, index++));
            }
            return new Allowlist(list);
        }
    }

    private static AllowlistEntry ParseEntry(JsonElement entry, int index)
    {
        if (entry.ValueKind != JsonValueKind.Object) throw new ToolException($"Allowlist entry {index} is not an object");
        foreach (var property in entry.EnumerateObject())
        {
            if (!Fields.Contains(property.Name, StringComparer.Ordinal))
            {
                throw new ToolException($"Allowlist entry {index} has an unknown property: {property.Name}");
            }
        }
        string Required(string name)
        {
            if (!entry.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.String ||
                string.IsNullOrWhiteSpace(value.GetString()))
            {
                throw new ToolException($"Allowlist entry {index} is missing a non-empty string '{name}'");
            }
            return value.GetString()!;
        }
        var result = new AllowlistEntry(Required("id"), Required("version"), Required("sha256"), Required("ruleId"),
            Required("file"), Required("reason"), Required("approvedBy"));
        if (!Sha256Pattern().IsMatch(result.Sha256))
        {
            throw new ToolException($"Allowlist entry {index} sha256 must be 64 lowercase hex characters");
        }
        return result;
    }

    public void Apply(FindingSet findings, ManifestInfo manifest, string packageSha256)
    {
        foreach (var finding in findings.All)
        {
            if (finding.Severity == Severity.Info) continue;
            var entry = _entries.FirstOrDefault(e =>
                string.Equals(e.Id, manifest.Id, StringComparison.Ordinal) &&
                string.Equals(e.Version, manifest.Version, StringComparison.Ordinal) &&
                string.Equals(e.Sha256, packageSha256, StringComparison.Ordinal) &&
                string.Equals(e.RuleId, finding.RuleId, StringComparison.Ordinal) &&
                string.Equals(e.File, finding.File, StringComparison.Ordinal));
            if (entry is null) continue;
            var original = finding.Severity.ToWire();
            finding.Severity = Severity.Info;
            finding.Details.Insert(0, Text.Clean(
                $"Allowlisted (was {original}; approved by {entry.ApprovedBy}): {entry.Reason}.", 600));
        }
    }
}
