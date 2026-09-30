// SPDX-License-Identifier: GPL-2.0-or-later
using System.Text.Json;

namespace PackageSecurityScan;

/// <summary>
/// The <c>compare</c> command: proves a published package matches a package rebuilt from
/// its declared source. Assemblies are compared by a normalized metadata fingerprint so a
/// legitimate rebuild on another machine matches, while any added type, method, API
/// reference, string, resource, or native import fails.
/// </summary>
internal static class PackageComparer
{
    private const int MaxJsonDifferences = 20;
    private static readonly string[] IgnoredDepsJsonFields = ["sha512", "signature"];

    public static Report Compare(string packagePath, string rebuiltDirectory, bool ilStrict)
    {
        var package = PackageArchive.Read(packagePath);
        var root = Path.GetFullPath(rebuiltDirectory);
        if (!Directory.Exists(root)) throw new ToolException($"Rebuilt directory not found: {rebuiltDirectory}");

        var rebuilt = Directory.EnumerateFiles(root, "*", new EnumerationOptions
            {
                RecurseSubdirectories = true,
                AttributesToSkip = 0,
                IgnoreInaccessible = false,
                ReturnSpecialDirectories = false,
            })
            .ToDictionary(p => Path.GetRelativePath(root, p).Replace('\\', '/'), p => p, StringComparer.Ordinal);

        var findings = new FindingSet();
        foreach (var file in package.Files.OrderBy(f => f.Path, StringComparer.Ordinal))
        {
            if (!rebuilt.TryGetValue(file.Path, out var rebuiltPath))
            {
                findings.Add("compare-missing-in-rebuilt", Severity.Fail, file.Path,
                    "The package contains a file the rebuild did not produce.");
                continue;
            }
            CompareFile(file, File.ReadAllBytes(rebuiltPath), findings, ilStrict);
        }
        var packaged = package.Files.Select(f => f.Path).ToHashSet(StringComparer.Ordinal);
        foreach (var path in rebuilt.Keys.Where(p => !packaged.Contains(p)).OrderBy(p => p, StringComparer.Ordinal))
        {
            findings.Add("compare-missing-in-package", Severity.Fail, path,
                "The rebuild produced a file the package does not contain.");
        }
        return new Report("compare", package.FileName, package.Sha256, null, findings);
    }

    private static void CompareFile(PackageFile file, byte[] rebuilt, FindingSet findings, bool ilStrict)
    {
        var packageKind = FileKinds.ClassifyPe(file.Bytes, out _);
        var rebuiltKind = FileKinds.ClassifyPe(rebuilt, out _);
        if (packageKind == PeKind.Managed && rebuiltKind == PeKind.Managed)
        {
            CompareAssemblies(file.Path, file.Bytes, rebuilt, findings, ilStrict);
            return;
        }
        if (file.Path.EndsWith(".deps.json", StringComparison.OrdinalIgnoreCase))
        {
            CompareDepsJson(file.Path, file.Bytes, rebuilt, findings);
            return;
        }
        if (file.Bytes.AsSpan().SequenceEqual(rebuilt)) return;
        var offset = file.Bytes.AsSpan().CommonPrefixLength(rebuilt);
        findings.Add("compare-bytes-differ", Severity.Fail, file.Path,
            "The packaged file is not byte-identical to the rebuilt file.",
            [
                $"package sha256 {Text.Sha256(file.Bytes)} ({file.Bytes.Length} bytes)",
                $"rebuilt sha256 {Text.Sha256(rebuilt)} ({rebuilt.Length} bytes)",
                $"first difference at byte offset {offset}",
            ]);
    }

    private static void CompareAssemblies(string path, byte[] packageBytes, byte[] rebuiltBytes, FindingSet findings,
        bool ilStrict)
    {
        AssemblyModel packageModel;
        AssemblyModel rebuiltModel;
        try
        {
            packageModel = AssemblyModel.Read(packageBytes);
            rebuiltModel = AssemblyModel.Read(rebuiltBytes);
        }
        catch (BadImageFormatException ex)
        {
            findings.Add("compare-metadata-differ", Severity.Fail, path, $"Could not read assembly metadata: {ex.Message}");
            return;
        }
        var onlyPackage = Difference(Fingerprint(packageModel), Fingerprint(rebuiltModel));
        var onlyRebuilt = Difference(Fingerprint(rebuiltModel), Fingerprint(packageModel));
        if (onlyPackage.Count > 0 || onlyRebuilt.Count > 0)
        {
            findings.Add("compare-metadata-differ", Severity.Fail, path,
                $"The packaged assembly's metadata does not match the rebuild ({onlyPackage.Count} item(s) only in the " +
                $"package, {onlyRebuilt.Count} only in the rebuild).",
                onlyPackage.Select(i => "only in package: " + i).Concat(onlyRebuilt.Select(i => "only in rebuilt: " + i)));
            return;
        }
        var ilDifferences = IlDifferences(packageModel, rebuiltModel);
        if (ilDifferences.Count > 0)
        {
            if (ilStrict)
            {
                findings.Add("compare-il-differ", Severity.Fail, path,
                    "Metadata matches the rebuild but some method bodies differ, and --il-strict requires identical IL " +
                    "(the SDK is pinned, so the same compiler must produce the same bodies).", ilDifferences);
            }
            else
            {
                findings.Add("compare-il-differ", Severity.Review, path,
                    "Metadata matches the rebuild but some method bodies differ. A different compiler version can do " +
                    "this legitimately; confirm the toolchain before accepting.", ilDifferences);
            }
        }
    }

    /// <summary>
    /// The normalized metadata fingerprint. Compiler-generated names (containing '&lt;')
    /// are left out of the type/method/field items because they vary across compiler
    /// versions; everything they can do still shows up in member refs, type refs,
    /// strings, and static data, which are always compared in full.
    /// </summary>
    public static List<string> Fingerprint(AssemblyModel model)
    {
        var items = new List<string>
        {
            $"assembly {model.Name} {model.Version} publickey={model.PublicKeyHash}",
        };
        items.AddRange(model.AssemblyRefs.Select(r => $"assemblyref {r.Name} {r.Version}"));
        items.AddRange(model.TypeDefs.Where(t => !t.IsGenerated).Select(t => $"typedef {t.FullName} : {t.BaseType}"));
        items.AddRange(model.Methods.Where(m => !m.IsGenerated).Select(m => $"method {m.Display}"));
        items.AddRange(model.Methods.Where(m => m.PInvokeTarget is not null)
            .Select(m => $"pinvoke {m.DeclaringType}::{m.Name} -> {m.PInvokeTarget}"));
        items.AddRange(model.Fields.Where(f => !f.IsGenerated).Select(f =>
            $"field {f.DeclaringType}::{f.Name} : {f.FieldType}" +
            (f.ConstantString is null ? "" : $" = {JsonSerializer.Serialize(f.ConstantString)}")));
        items.AddRange(model.Fields.Where(f => f.RvaHash is not null).Select(f => $"static-data {f.RvaSize} sha256={f.RvaHash}"));
        items.AddRange(model.MemberRefs.Select(m => $"memberref {m.ParentText}::{m.Name}{m.Signature}"));
        items.AddRange(model.TypeRefs.Select(t => $"typeref [{t.Scope}]{t.FullName}"));
        items.AddRange(model.UserStrings.Distinct(StringComparer.Ordinal)
            .Select(s => $"userstring {JsonSerializer.Serialize(s)}"));
        items.AddRange(model.Resources.Select(r => r.Bytes is null
            ? $"resource {r.Name} linked={r.LinkedTo}"
            : $"resource {r.Name} sha256={Text.Sha256(r.Bytes)}"));
        items.AddRange(model.Attributes.Where(a => !a.ParentGenerated)
            .Select(a => $"customattribute {a.CtorType} on {a.Parent} value={a.ValueHash}"));
        return items;
    }

    private static List<string> Difference(List<string> left, List<string> right)
    {
        var remaining = right.GroupBy(i => i, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.Count(), StringComparer.Ordinal);
        var result = new List<string>();
        foreach (var item in left.OrderBy(i => i, StringComparer.Ordinal))
        {
            if (remaining.TryGetValue(item, out var count) && count > 0)
            {
                remaining[item] = count - 1;
                continue;
            }
            result.Add(item);
        }
        return result;
    }

    private static List<string> IlDifferences(AssemblyModel package, AssemblyModel rebuilt)
    {
        static Dictionary<string, string> Bodies(AssemblyModel model) => model.Methods
            .GroupBy(m => m.Display, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => string.Join(",", g.Select(m => m.IlHash ?? "-").Order(StringComparer.Ordinal)),
                StringComparer.Ordinal);
        var left = Bodies(package);
        var right = Bodies(rebuilt);
        var differences = new List<string>();
        foreach (var key in left.Keys.Union(right.Keys).Order(StringComparer.Ordinal))
        {
            var inLeft = left.TryGetValue(key, out var a);
            var inRight = right.TryGetValue(key, out var b);
            if (!inLeft) differences.Add($"generated method only in rebuilt: {key}");
            else if (!inRight) differences.Add($"generated method only in package: {key}");
            else if (!string.Equals(a, b, StringComparison.Ordinal)) differences.Add($"IL differs: {key}");
        }
        return differences;
    }

    private static void CompareDepsJson(string path, byte[] package, byte[] rebuilt, FindingSet findings)
    {
        JsonDocument left;
        JsonDocument right;
        try
        {
            left = JsonDocument.Parse(package);
        }
        catch (JsonException ex)
        {
            findings.Add("compare-bytes-differ", Severity.Fail, path, $"Packaged deps.json is not valid JSON: {ex.Message}");
            return;
        }
        using (left)
        {
            try
            {
                right = JsonDocument.Parse(rebuilt);
            }
            catch (JsonException ex)
            {
                findings.Add("compare-bytes-differ", Severity.Fail, path, $"Rebuilt deps.json is not valid JSON: {ex.Message}");
                return;
            }
            using (right)
            {
                var differences = new List<string>();
                JsonDifferences(left.RootElement, right.RootElement, "$", differences);
                if (differences.Count > 0)
                {
                    findings.Add("compare-bytes-differ", Severity.Fail, path,
                        "The packaged deps.json differs from the rebuild (ignoring whitespace and sha512/signature).",
                        differences);
                }
            }
        }
    }

    private static void JsonDifferences(JsonElement a, JsonElement b, string path, List<string> differences)
    {
        if (differences.Count >= MaxJsonDifferences) return;
        if (a.ValueKind != b.ValueKind)
        {
            differences.Add($"{path}: {a.ValueKind} in package, {b.ValueKind} in rebuilt");
            return;
        }
        switch (a.ValueKind)
        {
            case JsonValueKind.Object:
                var left = a.EnumerateObject().ToDictionary(p => p.Name, p => p.Value, StringComparer.Ordinal);
                var right = b.EnumerateObject().ToDictionary(p => p.Name, p => p.Value, StringComparer.Ordinal);
                foreach (var name in left.Keys.Union(right.Keys).Order(StringComparer.Ordinal))
                {
                    var child = $"{path}.{name}";
                    var inLeft = left.TryGetValue(name, out var x);
                    var inRight = right.TryGetValue(name, out var y);
                    if (!inLeft) differences.Add($"{child}: only in rebuilt");
                    else if (!inRight) differences.Add($"{child}: only in package");
                    else if (IgnoredDepsJsonFields.Contains(name, StringComparer.Ordinal) &&
                             x.ValueKind == JsonValueKind.String && y.ValueKind == JsonValueKind.String) continue;
                    else JsonDifferences(x, y, child, differences);
                }
                break;
            case JsonValueKind.Array:
                var la = a.EnumerateArray().ToList();
                var ra = b.EnumerateArray().ToList();
                if (la.Count != ra.Count)
                {
                    differences.Add($"{path}: {la.Count} items in package, {ra.Count} in rebuilt");
                    return;
                }
                for (var i = 0; i < la.Count; i++) JsonDifferences(la[i], ra[i], $"{path}[{i}]", differences);
                break;
            default:
                if (!string.Equals(a.GetRawText(), b.GetRawText(), StringComparison.Ordinal))
                {
                    differences.Add($"{path}: {Text.Clean(a.GetRawText(), 80)} in package, {Text.Clean(b.GetRawText(), 80)} in rebuilt");
                }
                break;
        }
    }
}
