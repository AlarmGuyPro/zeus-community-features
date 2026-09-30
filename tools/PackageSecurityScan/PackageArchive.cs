// SPDX-License-Identifier: GPL-2.0-or-later
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;

namespace PackageSecurityScan;

internal sealed record PackageFile(string Path, byte[] Bytes);

/// <summary>
/// The package ZIP read fully into memory as data. Nothing is extracted to disk,
/// so no package file can ever be executed by the act of scanning it.
/// </summary>
internal sealed class PackageArchive
{
    // Same ceilings as tools/validate-package.ps1.
    private const int MaxEntries = 4096;
    private const long MaxExpandedBytes = 1L << 30;

    private PackageArchive(string fileName, string sha256, IReadOnlyList<PackageFile> files)
    {
        FileName = fileName;
        Sha256 = sha256;
        Files = files;
    }

    public string FileName { get; }
    public string Sha256 { get; }
    public IReadOnlyList<PackageFile> Files { get; }

    public static PackageArchive Read(string path)
    {
        var full = Path.GetFullPath(path);
        if (!File.Exists(full)) throw new ToolException($"Package not found: {path}");
        string sha;
        using (var hashStream = File.OpenRead(full)) sha = Text.Hex(SHA256.HashData(hashStream));

        var files = new List<PackageFile>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        long expanded = 0;
        try
        {
            using var zip = ZipFile.OpenRead(full);
            if (zip.Entries.Count > MaxEntries) throw new ToolException($"Package has more than {MaxEntries} entries");
            foreach (var entry in zip.Entries)
            {
                // Directory entries carry no bytes.
                if (entry.FullName.EndsWith('/') && entry.Length == 0) continue;
                var name = entry.FullName;
                if (!seen.Add(name))
                {
                    throw new ToolException($"Package has duplicate or case-colliding entries: {Text.Clean(name)}");
                }
                var remaining = MaxExpandedBytes - expanded;
                var bytes = ReadBounded(entry, remaining);
                expanded += bytes.Length;
                files.Add(new PackageFile(name, bytes));
            }
        }
        catch (InvalidDataException ex)
        {
            throw new ToolException($"Package is not a readable ZIP: {ex.Message}");
        }
        return new PackageArchive(Path.GetFileName(full), sha, files);
    }

    private static byte[] ReadBounded(ZipArchiveEntry entry, long remaining)
    {
        // Never trust the declared length: read at most remaining + 1 bytes.
        using var source = entry.Open();
        using var buffer = new MemoryStream();
        var chunk = new byte[81920];
        int read;
        while ((read = source.Read(chunk, 0, chunk.Length)) > 0)
        {
            if (buffer.Length + read > remaining)
            {
                throw new ToolException("Expanded package exceeds 1 GiB");
            }
            buffer.Write(chunk, 0, read);
        }
        return buffer.ToArray();
    }

    public ManifestInfo ReadManifest()
    {
        var manifest = Files.FirstOrDefault(f => string.Equals(f.Path, "plugin.json", StringComparison.Ordinal))
            ?? throw new ToolException("Package has no top-level plugin.json");
        return ManifestInfo.Parse(manifest.Bytes);
    }
}

/// <summary>The parts of plugin.json the rules depend on.</summary>
internal sealed record ManifestInfo(
    string Id,
    string Version,
    IReadOnlyList<string> Capabilities,
    bool Network,
    bool FileSystemRead,
    bool FileSystemWrite,
    string? AudioFormat,
    string? Homepage,
    string? EntrypointAssembly)
{
    public bool DeclaresCapability(string capability) =>
        Capabilities.Contains(capability, StringComparer.Ordinal);

    public string? HomepageHost =>
        Uri.TryCreate(Homepage, UriKind.Absolute, out var uri) ? uri.IdnHost.ToLowerInvariant() : null;

    public static ManifestInfo Parse(byte[] bytes)
    {
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 64 });
        }
        catch (JsonException ex)
        {
            throw new ToolException($"plugin.json is not valid JSON: {ex.Message}");
        }
        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) throw new ToolException("plugin.json must be a JSON object");
            var capabilities = new List<string>();
            if (root.TryGetProperty("capabilities", out var caps) && caps.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in caps.EnumerateArray())
                {
                    if (item.ValueKind == JsonValueKind.String) capabilities.Add(item.GetString()!);
                }
            }
            bool Permission(string name) =>
                root.TryGetProperty("permissions", out var permissions) &&
                permissions.ValueKind == JsonValueKind.Object &&
                permissions.TryGetProperty(name, out var value) &&
                value.ValueKind == JsonValueKind.True;
            string? NestedString(string parent, string name) =>
                root.TryGetProperty(parent, out var obj) && obj.ValueKind == JsonValueKind.Object &&
                obj.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
                    ? value.GetString()
                    : null;
            string StringOrEmpty(string name) =>
                root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
                    ? value.GetString()!
                    : "";
            return new ManifestInfo(
                StringOrEmpty("id"),
                StringOrEmpty("version"),
                capabilities,
                Permission("network"),
                Permission("fileSystemRead"),
                Permission("fileSystemWrite"),
                NestedString("audio", "format"),
                root.TryGetProperty("homepage", out var home) && home.ValueKind == JsonValueKind.String
                    ? home.GetString()
                    : null,
                NestedString("entrypoint", "assembly"));
        }
    }
}
