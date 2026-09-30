// SPDX-License-Identifier: GPL-2.0-or-later
using System.Collections.Immutable;
using System.Reflection.PortableExecutable;

namespace PackageSecurityScan;

internal enum PeKind
{
    NotPe,
    Native,
    Managed,
    Malformed,
}

/// <summary>Content-based (magic byte) file classification. File extensions are never trusted alone.</summary>
internal static class FileKinds
{
    private static readonly string[] ScriptExtensions =
        [".sh", ".bash", ".zsh", ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".vbs", ".vbe", ".wsf", ".py",
         ".rb", ".pl", ".command", ".applescript", ".scpt"];

    private static readonly string[] ArchiveExtensions =
        [".zip", ".nupkg", ".jar", ".tar", ".gz", ".tgz", ".7z", ".rar", ".xz", ".bz2", ".zst", ".cab", ".msi"];

    private static readonly string[] BinaryExtensions =
        [".dll", ".exe", ".so", ".dylib", ".node", ".sys", ".bin", ".o", ".a", ".lib"];

    private static readonly string[] JavaScriptExtensions = [".js", ".mjs", ".cjs"];

    public static bool IsElf(ReadOnlySpan<byte> b) => b.StartsWith((ReadOnlySpan<byte>)[0x7F, 0x45, 0x4C, 0x46]);

    public static bool IsMachO(ReadOnlySpan<byte> b) =>
        b.StartsWith((ReadOnlySpan<byte>)[0xFE, 0xED, 0xFA, 0xCE]) ||
        b.StartsWith((ReadOnlySpan<byte>)[0xFE, 0xED, 0xFA, 0xCF]) ||
        b.StartsWith((ReadOnlySpan<byte>)[0xCE, 0xFA, 0xED, 0xFE]) ||
        b.StartsWith((ReadOnlySpan<byte>)[0xCF, 0xFA, 0xED, 0xFE]) ||
        b.StartsWith((ReadOnlySpan<byte>)[0xCA, 0xFE, 0xBA, 0xBE]) ||
        b.StartsWith((ReadOnlySpan<byte>)[0xCA, 0xFE, 0xBA, 0xBF]);

    public static bool IsMz(ReadOnlySpan<byte> b) => b.StartsWith("MZ"u8);

    public static bool IsZip(ReadOnlySpan<byte> b) =>
        b.StartsWith((ReadOnlySpan<byte>)[0x50, 0x4B, 0x03, 0x04]) ||
        b.StartsWith((ReadOnlySpan<byte>)[0x50, 0x4B, 0x05, 0x06]) ||
        b.StartsWith((ReadOnlySpan<byte>)[0x50, 0x4B, 0x07, 0x08]);

    public static bool IsGzip(ReadOnlySpan<byte> b) => b.StartsWith((ReadOnlySpan<byte>)[0x1F, 0x8B]);

    public static bool Is7z(ReadOnlySpan<byte> b) =>
        b.StartsWith((ReadOnlySpan<byte>)[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]);

    public static bool IsWasm(ReadOnlySpan<byte> b) => b.StartsWith((ReadOnlySpan<byte>)[0x00, 0x61, 0x73, 0x6D]);

    public static bool IsRar(ReadOnlySpan<byte> b) => b.StartsWith("Rar!"u8);

    public static bool IsArchiveMagic(ReadOnlySpan<byte> b) => IsZip(b) || IsGzip(b) || Is7z(b) || IsRar(b);

    /// <summary>Anything a loader would treat as executable native code.</summary>
    public static bool IsExecutableMagic(ReadOnlySpan<byte> b) => IsElf(b) || IsMachO(b) || IsMz(b);

    public static bool IsShebang(ReadOnlySpan<byte> b) =>
        b.StartsWith("#!"u8) || b.StartsWith((ReadOnlySpan<byte>)[0xEF, 0xBB, 0xBF, 0x23, 0x21]);

    public static bool HasScriptExtension(string path) => HasExtension(path, ScriptExtensions);
    public static bool HasArchiveExtension(string path) => HasExtension(path, ArchiveExtensions);
    public static bool HasBinaryExtension(string path) => HasExtension(path, BinaryExtensions);
    public static bool IsJavaScript(string path) => HasExtension(path, JavaScriptExtensions);

    private static bool HasExtension(string path, string[] extensions) =>
        extensions.Any(e => path.EndsWith(e, StringComparison.OrdinalIgnoreCase));

    /// <summary>Classifies a PE image by reading headers only. Never loads it.</summary>
    public static PeKind ClassifyPe(byte[] bytes, out string? reason)
    {
        reason = null;
        if (!IsMz(bytes)) return PeKind.NotPe;
        try
        {
            using var pe = new PEReader(ImmutableArray.Create(bytes));
            var headers = pe.PEHeaders;
            if (headers.CorHeader is null)
            {
                reason = "PE image without a CLI header (native code)";
                return PeKind.Native;
            }
            var flags = headers.CorHeader.Flags;
            if ((flags & CorFlags.ILOnly) == 0)
            {
                reason = "mixed-mode assembly (CLI header without ILOnly: contains native code)";
                return PeKind.Native;
            }
            if ((flags & CorFlags.ILLibrary) != 0 || headers.CorHeader.ManagedNativeHeaderDirectory.Size != 0)
            {
                reason = "ReadyToRun/precompiled assembly: its native code can differ from the IL that was reviewed";
                return PeKind.Native;
            }
            if (!pe.HasMetadata)
            {
                reason = "CLI header without metadata";
                return PeKind.Malformed;
            }
            return PeKind.Managed;
        }
        catch (BadImageFormatException ex)
        {
            reason = "malformed PE image: " + ex.Message;
            return PeKind.Malformed;
        }
    }
}
