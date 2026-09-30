// SPDX-License-Identifier: GPL-2.0-or-later
namespace PackageSecurityScan;

/// <summary>The <c>scan</c> command: package-level rules plus per-assembly and per-module rules.</summary>
internal static class PackageScanner
{
    public static Report Scan(string packagePath, string? allowlistPath)
    {
        var allowlist = allowlistPath is null ? Allowlist.Empty : Allowlist.Load(allowlistPath);
        var package = PackageArchive.Read(packagePath);
        var manifest = package.ReadManifest();
        var findings = new FindingSet();

        findings.Add("manifest-capabilities", Severity.Info, "plugin.json",
            $"Declared capabilities: [{string.Join(", ", manifest.Capabilities)}]; permissions: " +
            $"network={manifest.Network}, fileSystemRead={manifest.FileSystemRead}, " +
            $"fileSystemWrite={manifest.FileSystemWrite}. ABI 1 grants declared capabilities without a prompt and " +
            "does not sandbox the plugin.");

        var nativeAudio = manifest.AudioFormat is "vst3" or "au";
        var assemblies = new List<(PackageFile File, AssemblyModel Model)>();
        foreach (var file in package.Files)
        {
            var bytes = file.Bytes;
            var peKind = FileKinds.ClassifyPe(bytes, out var peReason);
            if (FileKinds.IsElf(bytes) || FileKinds.IsMachO(bytes) || peKind == PeKind.Native)
            {
                var what = FileKinds.IsElf(bytes) ? "ELF executable/shared object"
                    : FileKinds.IsMachO(bytes) ? "Mach-O executable/library (or Java class)"
                    : peReason!;
                if (nativeAudio)
                {
                    findings.Add("native-binary", Severity.Review, file.Path,
                        $"Native code ({what}); allowed for review because audio.format is {manifest.AudioFormat}.");
                }
                else
                {
                    findings.Add("native-binary", Severity.Fail, file.Path,
                        $"Native code ({what}). Community features must be managed-only unless they are VST3/AU audio plugins.");
                }
            }
            else if (peKind == PeKind.Malformed)
            {
                findings.Add("scan-error", Severity.Fail, file.Path, $"Could not analyse the file: {peReason}");
            }
            else if (peKind == PeKind.Managed)
            {
                try
                {
                    assemblies.Add((file, AssemblyModel.Read(bytes)));
                }
                catch (BadImageFormatException ex)
                {
                    findings.Add("scan-error", Severity.Fail, file.Path,
                        $"Could not analyse the assembly metadata: {ex.Message}");
                }
            }
            else if (FileKinds.HasBinaryExtension(file.Path))
            {
                findings.Add("native-binary", Severity.Review, file.Path,
                    "Binary file extension with unrecognised content; confirm what it is.");
            }

            if (FileKinds.HasScriptExtension(file.Path) || FileKinds.IsShebang(bytes))
            {
                findings.Add("script-file", Severity.Review, file.Path,
                    "Ships a shell or interpreter script. Zeus never runs it, but confirm why it is in the package.");
            }
            if (FileKinds.HasArchiveExtension(file.Path) || FileKinds.IsArchiveMagic(bytes))
            {
                findings.Add("nested-archive", Severity.Review, file.Path,
                    "Ships a nested archive whose contents this scan does not inspect.");
            }
            if (FileKinds.IsJavaScript(file.Path))
            {
                JsRules.Evaluate(bytes, file.Path, manifest, findings);
            }
            if (MarkupRules.IsMarkup(file.Path))
            {
                MarkupRules.Evaluate(bytes, file.Path, findings);
            }
            if (file.Path.EndsWith(".wasm", StringComparison.OrdinalIgnoreCase) || FileKinds.IsWasm(bytes))
            {
                findings.Add("wasm-file", Severity.Review, file.Path,
                    "Ships a WebAssembly module (compiled code); loading it from JavaScript is a js-remote-code fail.");
            }
        }

        var bundled = assemblies.Where(a => a.Model.Name is not null)
            .Select(a => a.Model.Name!)
            .ToHashSet(StringComparer.Ordinal);
        foreach (var (file, model) in assemblies)
        {
            ManagedRules.Evaluate(model, file.Path, manifest, bundled, findings);
            var isEntrypoint = string.Equals(file.Path, manifest.EntrypointAssembly, StringComparison.Ordinal);
            if (!isEntrypoint)
            {
                findings.Add("unexpected-assembly-ref", Severity.Review, file.Path,
                    "Bundled managed assembly other than the entrypoint; confirm its origin and licence.",
                    [$"{model.Name ?? "(module)"} {model.Version}"]);
            }
        }

        allowlist.Apply(findings, manifest, package.Sha256);
        return new Report("scan", package.FileName, package.Sha256, manifest, findings);
    }
}
