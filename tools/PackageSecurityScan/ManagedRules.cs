// SPDX-License-Identifier: GPL-2.0-or-later
namespace PackageSecurityScan;

/// <summary>
/// Rules evaluated against one managed assembly's metadata. Rule ids and
/// severities are documented in tools/package-security-rules.md.
/// </summary>
internal sealed class ManagedRules
{
    private const string InteropNs = "System.Runtime.InteropServices";
    private const string CompilerServicesNs = "System.Runtime.CompilerServices";

    private readonly AssemblyModel _model;
    private readonly string _file;
    private readonly ManifestInfo _manifest;
    private readonly IReadOnlySet<string> _bundledAssemblies;
    private readonly FindingSet _findings;
    private readonly HashSet<string> _referencedTypes;

    private ManagedRules(AssemblyModel model, string file, ManifestInfo manifest,
        IReadOnlySet<string> bundledAssemblies, FindingSet findings)
    {
        _model = model;
        _file = file;
        _manifest = manifest;
        _bundledAssemblies = bundledAssemblies;
        _findings = findings;
        _referencedTypes = new HashSet<string>(
            model.TypeRefs.Select(t => t.FullName)
                .Concat(model.MemberRefs.Select(m => m.ParentType))
                .Concat(model.Attributes.Where(a => a.CtorIsExternal).Select(a => a.CtorType))
                .Where(t => t.Length > 0),
            StringComparer.Ordinal);
    }

    public static void Evaluate(AssemblyModel model, string file, ManifestInfo manifest,
        IReadOnlySet<string> bundledAssemblies, FindingSet findings)
    {
        var rules = new ManagedRules(model, file, manifest, bundledAssemblies, findings);
        rules.PInvoke();
        rules.NativeLibraryLoad();
        rules.ModuleInitializer();
        rules.DynamicCode();
        rules.Process();
        rules.Obfuscation();
        rules.AssemblyReferences();
        rules.Network();
        rules.FileSystem();
        rules.Ipc();
        rules.UnclassifiedIo();
        rules.Registry();
        rules.Environment();
        rules.Reflection();
        rules.HostServices();
        rules.HostData();
        rules.StringRulesForAssembly();
        rules.EmbeddedResources();
        rules.LargeDataBlobs();
        rules.TimeBomb();
    }

    private void Report(string ruleId, Severity severity, string detail, IEnumerable<string> evidence)
    {
        var items = evidence.ToList();
        if (items.Count == 0) return;
        _findings.Add(ruleId, severity, _file, detail, items);
    }

    private static bool IsTypeOrNested(string type, string target) =>
        type == target || type.StartsWith(target + "+", StringComparison.Ordinal);

    private static bool InNamespace(string type, string ns) =>
        type.StartsWith(ns + ".", StringComparison.Ordinal);

    private IEnumerable<string> TypesWhere(Func<string, bool> predicate) =>
        _referencedTypes.Where(predicate).OrderBy(t => t, StringComparer.Ordinal);

    private IEnumerable<MemberRefRecord> Members(Func<string, bool> type, Func<string, bool>? name = null) =>
        _model.MemberRefs.Where(m => type(m.ParentType) && (name is null || name(m.Name)));

    private IEnumerable<MemberRefRecord> Members(string type, params string[] names) =>
        Members(t => IsTypeOrNested(t, type), names.Length == 0 ? null : n => names.Contains(n, StringComparer.Ordinal));

    private IEnumerable<AttributeRecord> AttributesOf(params string[] types) =>
        _model.Attributes.Where(a => types.Contains(a.CtorType, StringComparer.Ordinal));

    private void PInvoke()
    {
        var evidence = _model.Methods.Where(m => m.PInvokeTarget is not null)
            .Select(m => $"{m.DeclaringType}::{m.Name} -> {m.PInvokeTarget}")
            .Concat(AttributesOf($"{InteropNs}.DllImportAttribute", $"{InteropNs}.LibraryImportAttribute")
                .Select(a => $"{a.CtorType} on {a.Parent}"));
        Report("pinvoke", Severity.Fail,
            "Declares platform invoke (native function) imports; native code runs outside every managed check.",
            evidence);
    }

    private void NativeLibraryLoad()
    {
        var evidence = TypesWhere(t => IsTypeOrNested(t, $"{InteropNs}.NativeLibrary"))
            .Concat(Members($"{InteropNs}.Marshal", "GetDelegateForFunctionPointer").Select(m => m.Display))
            .Concat(_model.UnmanagedCalli);
        Report("native-library-load", Severity.Fail,
            "Loads native libraries or calls native function pointers at runtime.", evidence);
    }

    private void ModuleInitializer()
    {
        var evidence = new List<string>();
        if (_model.ModuleHasStaticConstructor) evidence.Add("<Module>::.cctor runs as soon as the assembly is touched");
        evidence.AddRange(AttributesOf($"{CompilerServicesNs}.ModuleInitializerAttribute")
            .Select(a => $"[ModuleInitializer] on {a.Parent}"));
        Report("module-initializer", Severity.Fail,
            "Runs code when the assembly loads, before the plugin is initialized or reviewed at runtime.", evidence);
    }

    private void DynamicCode()
    {
        var evidence = TypesWhere(t =>
                InNamespace(t, "System.Reflection.Emit") ||
                IsTypeOrNested(t, "System.Runtime.Loader.AssemblyLoadContext") ||
                (InNamespace(t, "System.CodeDom.Compiler") && t != "System.CodeDom.Compiler.GeneratedCodeAttribute") ||
                InNamespace(t, "Microsoft.CodeAnalysis"))
            .Concat(Members("System.Reflection.Assembly", "Load", "LoadFrom", "LoadFile", "UnsafeLoadFrom",
                "LoadWithPartialName", "ReflectionOnlyLoad", "ReflectionOnlyLoadFrom").Select(m => m.Display))
            .Concat(Members("System.AppDomain", "Load", "ExecuteAssembly", "ExecuteAssemblyByName")
                .Select(m => m.Display));
        Report("dynamic-code", Severity.Fail,
            "Loads or generates code at runtime, so the code that runs is not the code that was reviewed.",
            evidence);
    }

    private void Process()
    {
        var evidence = TypesWhere(t =>
            IsTypeOrNested(t, "System.Diagnostics.Process") || IsTypeOrNested(t, "System.Diagnostics.ProcessStartInfo"));
        Report("process", Severity.Fail, "Starts or controls operating-system processes.", evidence);
    }

    private static readonly string[] ObfuscatorMarkers =
    [
        "ConfusedByAttribute", "DotfuscatorAttribute", "ObfuscatedByGoliath", "BabelObfuscatorAttribute",
        "BabelAttribute", "CryptoObfuscator", "Xenocode", "NETReactor", "DotNetReactor", "Eziriz",
        "ObfuscatedByAgileDotNetAttribute", "YanoAttribute", "MaxtoCodeAttribute", "NineRays",
    ];

    private void Obfuscation()
    {
        var names = _model.TypeDefs.Select(t => t.FullName).Concat(_referencedTypes).Distinct(StringComparer.Ordinal);
        var evidence = names.Where(n =>
                n.StartsWith("SmartAssembly.", StringComparison.Ordinal) ||
                ObfuscatorMarkers.Any(m => n.Contains(m, StringComparison.Ordinal)))
            .Select(n => "obfuscator marker type " + n)
            .ToList();

        var declared = _model.TypeDefs.Where(t => !t.IsGenerated).Select(t => t.FullName)
            .Concat(_model.Methods.Where(m => !m.IsGenerated).Select(m => m.Name))
            .ToList();
        var unreadable = declared.Count(n => n.Any(c => c > '~' || c < '!'));
        if (declared.Count >= 5 && unreadable > declared.Count * 0.3)
        {
            evidence.Add($"{unreadable} of {declared.Count} type/method names contain non-ASCII or unprintable characters");
        }
        Report("obfuscation", Severity.Fail,
            "The assembly is obfuscated, which defeats review of what it does.", evidence);
    }

    private static readonly string[] AllowedExactReferences =
    [
        "System", "Microsoft.Win32.Primitives", "Microsoft.CSharp", "Microsoft.VisualBasic.Core",
        "netstandard", "mscorlib", "Zeus.Plugins.Contracts",
        // Further shared-framework assemblies (Microsoft.NETCore.App / Microsoft.AspNetCore.App) whose
        // names fall outside the prefixes below. Registry use is still reported by the registry rule.
        "Microsoft.VisualBasic", "Microsoft.Win32.Registry", "WindowsBase", "Microsoft.Net.Http.Headers",
        "Microsoft.JSInterop",
    ];

    private static readonly string[] AllowedReferencePrefixes =
        ["System.", "Microsoft.AspNetCore.", "Microsoft.Extensions."];

    private void AssemblyReferences()
    {
        var hostInternal = new List<string>();
        var unexpected = new List<string>();
        foreach (var (name, version) in _model.AssemblyRefs)
        {
            if (_bundledAssemblies.Contains(name)) continue;
            if (AllowedExactReferences.Contains(name, StringComparer.Ordinal) ||
                AllowedReferencePrefixes.Any(p => name.StartsWith(p, StringComparison.Ordinal)))
            {
                continue;
            }
            if (name.StartsWith("Zeus.", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("Zeus", StringComparison.OrdinalIgnoreCase))
            {
                hostInternal.Add($"{name} {version} (Zeus host internal; only Zeus.Plugins.Contracts is public)");
            }
            else
            {
                unexpected.Add($"{name} {version} (not shipped in the package and not a framework assembly)");
            }
        }
        Report("unexpected-assembly-ref", Severity.Fail,
            "References assemblies outside the public SDK, the shared framework, and the package itself.",
            hostInternal.Concat(unexpected));
    }

    private static readonly string[] NetworkNamespaces =
    [
        "System.Net.Http", "System.Net.Sockets", "System.Net.WebSockets", "System.Net.Mail", "System.Net.Quic",
        "System.Net.NetworkInformation", "System.Net.Security",
    ];

    private static readonly string[] NetworkTypes =
    [
        "System.Net.Dns", "System.Net.WebClient", "System.Net.WebRequest", "System.Net.HttpWebRequest",
        "System.Net.FtpWebRequest", "System.Net.HttpListener",
    ];

    private static bool IsNetworkType(string type) =>
        NetworkNamespaces.Any(ns => InNamespace(type, ns)) || NetworkTypes.Any(n => IsTypeOrNested(type, n));

    [Flags]
    private enum IoUse
    {
        None = 0,
        FileRead = 1,
        FileWrite = 2,
        Network = 4,
        AcceptsUrl = 8,
        Ipc = 16,
    }

    private static readonly string[] FileWritePrefixes =
        ["Write", "Create", "Append", "Delete", "Move", "Copy", "Replace", "Encrypt", "Decrypt", "Set", "set_"];

    private static readonly string[] FileSystemTypes =
    [
        "System.IO.File", "System.IO.FileInfo", "System.IO.FileStream", "System.IO.Directory",
        "System.IO.DirectoryInfo", "System.IO.FileSystemInfo", "System.IO.FileSystemWatcher",
        "System.IO.DriveInfo", "System.IO.RandomAccess", "Microsoft.Win32.SafeHandles.SafeFileHandle",
        "System.Diagnostics.FileVersionInfo",
    ];

    private static bool IsFileSystemType(string type) =>
        FileSystemTypes.Any(t => IsTypeOrNested(type, t)) ||
        InNamespace(type, "System.IO.Enumeration") ||
        type.StartsWith("Microsoft.Extensions.FileProviders.Physical", StringComparison.Ordinal);

    private static bool StringFirst(MemberRefRecord member) =>
        member.Signature.StartsWith("(System.String", StringComparison.Ordinal);

    private static bool IsFileWrite(string type, MemberRefRecord member)
    {
        var name = member.Name;
        switch (type)
        {
            case "System.IO.FileStream":
                return true;
            case "System.IO.FileSystemWatcher":
            case "System.IO.DriveInfo":
            case "Microsoft.Win32.SafeHandles.SafeFileHandle":
            case "System.Diagnostics.FileVersionInfo":
                return false;
            case "System.IO.RandomAccess":
                return name.StartsWith("Write", StringComparison.Ordinal) || name == "SetLength";
            case "System.IO.File":
            case "System.IO.FileInfo":
                return name is "Open" or "OpenWrite" or "OpenHandle" or "MoveTo" or "CopyTo" or "CreateAsSymbolicLink" ||
                    FileWritePrefixes.Any(p => name.StartsWith(p, StringComparison.Ordinal));
            case "System.IO.Directory":
            case "System.IO.DirectoryInfo":
            case "System.IO.FileSystemInfo":
                return name is "Create" or "CreateSubdirectory" or "MoveTo" or "CreateAsSymbolicLink" ||
                    FileWritePrefixes.Any(p => name.StartsWith(p, StringComparison.Ordinal));
            default:
                return false;
        }
    }

    /// <summary>
    /// What one referenced member can do with files, the network, or other processes. APIs that
    /// accept a path string are classified by overload, so XDocument.Load(Stream) is harmless while
    /// XDocument.Load(string) reads a file or fetches a URL.
    /// </summary>
    private static IoUse Classify(MemberRefRecord member)
    {
        var type = member.ParentType;
        var name = member.Name;
        if (IsNetworkType(type)) return IoUse.Network;
        if (IsFileSystemType(type)) return IsFileWrite(type, member) ? IoUse.FileWrite : IoUse.FileRead;
        const IoUse urlRead = IoUse.FileRead | IoUse.Network | IoUse.AcceptsUrl;
        switch (type)
        {
            case "System.IO.Path":
                return name == "GetTempFileName" ? IoUse.FileWrite
                    : name is "GetTempPath" or "Exists" ? IoUse.FileRead : IoUse.None;
            case "System.IO.StreamWriter":
                return name == ".ctor" && StringFirst(member) ? IoUse.FileWrite : IoUse.None;
            case "System.IO.StreamReader":
                return name == ".ctor" && StringFirst(member) ? IoUse.FileRead : IoUse.None;
            case "System.Xml.XmlWriter":
                return name == "Create" && StringFirst(member) ? IoUse.FileWrite : IoUse.None;
            case "System.Xml.XmlTextWriter":
                return name == ".ctor" && StringFirst(member) ? IoUse.FileWrite : IoUse.None;
            case "System.Xml.XmlDocument":
            case "System.Xml.Linq.XDocument":
            case "System.Xml.Linq.XElement":
            case "System.Xml.Linq.XStreamingElement":
                if (!StringFirst(member)) return IoUse.None;
                return name == "Save" ? IoUse.FileWrite : name == "Load" ? urlRead : IoUse.None;
            case "System.Xml.XmlReader":
                return name == "Create" && StringFirst(member) ? urlRead : IoUse.None;
            case "System.Xml.XmlTextReader":
                return name == ".ctor" && StringFirst(member) ? urlRead : IoUse.None;
            case "System.Xml.Xsl.XslCompiledTransform":
                if (!StringFirst(member)) return IoUse.None;
                return name == "Load" ? urlRead : name == "Transform" ? urlRead | IoUse.FileWrite : IoUse.None;
            case "System.Xml.XmlUrlResolver":
            case "System.Xml.XmlSecureResolver":
                return IoUse.Network | IoUse.AcceptsUrl;
            case "System.IO.Compression.ZipFile":
                return name == "OpenRead" ? IoUse.FileRead : IoUse.FileWrite;
            case "System.IO.Compression.ZipFileExtensions":
                return name == "CreateEntryFromFile" ? IoUse.FileRead : IoUse.FileWrite;
            case "System.IO.MemoryMappedFiles.MemoryMappedFile":
                return name switch
                {
                    "CreateFromFile" => IoUse.FileWrite,
                    "OpenExisting" => IoUse.FileRead | IoUse.Ipc,
                    "CreateNew" or "CreateOrOpen" => IoUse.Ipc,
                    _ => IoUse.None,
                };
        }
        return InNamespace(type, "System.IO.Pipes") ? IoUse.Ipc : IoUse.None;
    }

    private IEnumerable<(MemberRefRecord Member, IoUse Use)> ClassifiedMembers() =>
        _model.MemberRefs.Select(m => (m, Classify(m))).Where(x => x.Item2 != IoUse.None);

    private static string DisplayWithSignature(MemberRefRecord member) =>
        member.Name is ".ctor" or "Create" or "Load" or "Save" ? member.Display + member.Signature : member.Display;

    private void Network()
    {
        var evidence = TypesWhere(IsNetworkType)
            .Concat(ClassifiedMembers().Where(x => (x.Use & IoUse.AcceptsUrl) != 0)
                .Select(x => DisplayWithSignature(x.Member) + " (accepts URLs as well as file paths)"))
            .ToList();
        if (evidence.Count == 0) return;
        var declared = _manifest.DeclaresCapability("NetworkAccess") && _manifest.Network;
        if (declared)
        {
            Report("undeclared-network", Severity.Info,
                "Uses networking APIs; the manifest declares NetworkAccess and permissions.network.", evidence);
            return;
        }
        Report("undeclared-network", Severity.Fail,
            $"Uses networking or URL-capable APIs but the manifest does not declare them (capability NetworkAccess: " +
            $"{_manifest.DeclaresCapability("NetworkAccess")}, permissions.network: {_manifest.Network}).",
            evidence);
    }

    private void FileSystem()
    {
        var reads = new List<string>();
        var writes = new List<string>();
        foreach (var (member, use) in ClassifiedMembers())
        {
            if ((use & IoUse.FileWrite) != 0) writes.Add(DisplayWithSignature(member));
            else if ((use & IoUse.FileRead) != 0) reads.Add(DisplayWithSignature(member));
        }
        var typesWithMembers = _model.MemberRefs.Select(m => m.ParentType).ToHashSet(StringComparer.Ordinal);
        foreach (var type in TypesWhere(t => IsFileSystemType(t) && !typesWithMembers.Contains(t)))
        {
            (type == "System.IO.FileStream" ? writes : reads).Add(type);
        }
        ReportFileAccess("read", reads, _manifest.FileSystemRead, "permissions.fileSystemRead");
        ReportFileAccess("write", writes, _manifest.FileSystemWrite, "permissions.fileSystemWrite");
    }

    private void ReportFileAccess(string kind, List<string> evidence, bool declared, string permission)
    {
        if (evidence.Count == 0) return;
        if (declared)
        {
            Report("undeclared-filesystem", Severity.Info, $"Uses file-system {kind} APIs; {permission} is declared.",
                evidence.Select(e => $"{kind}: {e}"));
            return;
        }
        Report("undeclared-filesystem", Severity.Fail,
            $"Uses file-system {kind} APIs but {permission} is not true.", evidence.Select(e => $"{kind}: {e}"));
    }

    private void Ipc()
    {
        var evidence = ClassifiedMembers().Where(x => (x.Use & IoUse.Ipc) != 0).Select(x => x.Member.Display)
            .Concat(TypesWhere(t => InNamespace(t, "System.IO.Pipes")));
        Report("ipc", Severity.Review,
            "Uses named pipes or named shared memory to talk to other processes on the machine.", evidence);
    }

    private static readonly string[] IoSweepNamespaces = ["System.IO", "System.Xml", "System.Net"];

    /// <summary>Types in the swept namespaces that cannot reach files, the network, or other processes.</summary>
    private static readonly HashSet<string> KnownSafeIoTypes = new(StringComparer.Ordinal)
    {
        "System.IO.Stream", "System.IO.MemoryStream", "System.IO.BufferedStream", "System.IO.BinaryReader",
        "System.IO.BinaryWriter", "System.IO.StringReader", "System.IO.StringWriter", "System.IO.TextReader",
        "System.IO.TextWriter", "System.IO.StreamReader", "System.IO.StreamWriter", "System.IO.Path",
        "System.IO.IOException", "System.IO.EndOfStreamException", "System.IO.InvalidDataException",
        "System.IO.FileNotFoundException", "System.IO.DirectoryNotFoundException", "System.IO.PathTooLongException",
        "System.IO.SeekOrigin", "System.IO.FileMode", "System.IO.FileAccess", "System.IO.FileShare",
        "System.IO.FileOptions", "System.IO.SearchOption",
        "System.IO.Compression.DeflateStream", "System.IO.Compression.GZipStream", "System.IO.Compression.BrotliStream",
        "System.IO.Compression.ZLibStream", "System.IO.Compression.ZipArchive", "System.IO.Compression.ZipArchiveEntry",
        "System.IO.Compression.ZipArchiveMode", "System.IO.Compression.CompressionLevel",
        "System.IO.Compression.CompressionMode", "System.IO.Compression.BrotliEncoder",
        "System.IO.Compression.BrotliDecoder",
        "System.Xml.XmlReader", "System.Xml.XmlWriter", "System.Xml.XmlReaderSettings", "System.Xml.XmlWriterSettings",
        "System.Xml.XmlDocument", "System.Xml.XmlNode", "System.Xml.XmlElement", "System.Xml.XmlAttribute",
        "System.Xml.XmlAttributeCollection", "System.Xml.XmlNodeList", "System.Xml.XmlNamespaceManager",
        "System.Xml.XmlConvert", "System.Xml.XmlException", "System.Xml.XmlText", "System.Xml.XmlCDataSection",
        "System.Xml.XmlComment", "System.Xml.XmlDeclaration", "System.Xml.XmlNameTable", "System.Xml.NameTable",
        "System.Xml.XmlLinkedNode", "System.Xml.XmlCharacterData", "System.Xml.XmlNamedNodeMap",
        "System.Xml.XmlDocumentFragment", "System.Xml.XmlQualifiedName", "System.Xml.XmlTextReader",
        "System.Xml.XmlTextWriter", "System.Xml.Xsl.XslCompiledTransform",
        "System.Net.IPAddress", "System.Net.IPEndPoint", "System.Net.EndPoint", "System.Net.DnsEndPoint",
        "System.Net.IPNetwork", "System.Net.WebUtility", "System.Net.HttpStatusCode", "System.Net.HttpVersion",
        "System.Net.DecompressionMethods",
    };

    private static readonly string[] KnownSafeIoNamespaces =
    [
        "System.IO.Pipelines", "System.IO.MemoryMappedFiles", "System.Xml.Linq", "System.Xml.Serialization",
        "System.Xml.XPath", "System.Net.Mime",
    ];

    private static bool IsKnownSafeIoType(string type) =>
        KnownSafeIoTypes.Any(t => IsTypeOrNested(type, t)) || KnownSafeIoNamespaces.Any(ns => InNamespace(type, ns));

    /// <summary>
    /// Deny by default: any I/O, XML, or networking member that no rule classifies and that is not on the
    /// known-safe list is listed for review, so a new or obscure API cannot reach files or the network
    /// unnoticed.
    /// </summary>
    private void UnclassifiedIo()
    {
        var evidence = _model.MemberRefs
            .Where(m => IoSweepNamespaces.Any(ns => InNamespace(m.ParentType, ns)) && Classify(m) == IoUse.None &&
                !IsKnownSafeIoType(m.ParentType))
            .Select(m => m.Display)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal);
        Report("unclassified-io-api", Severity.Review,
            "Uses I/O, XML, or networking APIs that are neither known-safe nor classified by another rule.",
            evidence);
    }

    private void Registry()
    {
        var evidence = TypesWhere(t => t.StartsWith("Microsoft.Win32.Registry", StringComparison.Ordinal));
        Report("registry", Severity.Review, "Reads or writes the Windows registry.", evidence);
    }

    private void Environment()
    {
        var evidence = Members("System.Environment", "GetEnvironmentVariable", "GetEnvironmentVariables",
            "ExpandEnvironmentVariables", "SetEnvironmentVariable").Select(m => m.Display);
        Report("environment", Severity.Review,
            $"Reads or changes environment variables. The Zeus station access token ({StringRules.StationTokenName}) " +
            "lives in the host environment; confirm the plugin does not read it.",
            evidence);
    }

    private static readonly string[] ReflectionLookups =
    [
        "GetType", "InvokeMember", "GetMethod", "GetMethods", "GetField", "GetFields", "GetProperty",
        "GetProperties", "GetMember", "GetMembers", "GetConstructor", "GetConstructors", "GetNestedType",
        "GetNestedTypes", "GetEvent", "GetEvents",
    ];

    private void Reflection()
    {
        var evidence = Members(t => t is "System.Type" or "System.Reflection.TypeInfo" or "System.Reflection.IReflect",
                n => ReflectionLookups.Contains(n, StringComparer.Ordinal))
            .Concat(Members("System.Activator"))
            .Concat(Members(t => t is "System.Reflection.MethodBase" or "System.Reflection.MethodInfo" or
                "System.Reflection.ConstructorInfo", n => n is "Invoke" or "CreateDelegate"))
            .Concat(Members(t => t is "System.Reflection.FieldInfo" or "System.Reflection.PropertyInfo",
                n => n is "GetValue" or "SetValue" or "GetValueDirect" or "SetValueDirect"))
            .Concat(Members("System.Delegate", "CreateDelegate"))
            .Concat(Members("System.Runtime.CompilerServices.Unsafe", "As", "AsRef", "AsPointer")
                .Where(m => !OnlyCalledByCompilerHelpers(m)))
            .Concat(Members(t => IsTypeOrNested(t, $"{InteropNs}.Marshal"), n => n != "GetDelegateForFunctionPointer"))
            .Select(m => m.Display)
            .Concat(TypesWhere(t => t == $"{CompilerServicesNs}.UnsafeAccessorAttribute")
                .Select(t => t + " (accesses private members of other assemblies)"));
        Report("reflection", Severity.Review,
            "Uses reflection, unsafe casts, or marshalling that can reach members the public SDK does not expose.",
            evidence);
    }

    /// <summary>
    /// True when every call site of the member is inside &lt;PrivateImplementationDetails&gt;,
    /// where the C# compiler emits its InlineArray/collection-expression helpers.
    /// </summary>
    private bool OnlyCalledByCompilerHelpers(MemberRefRecord member) =>
        _model.CallersByTarget.TryGetValue(member.Display, out var callers) && callers.Count > 0 &&
        callers.All(c => c.StartsWith("<PrivateImplementationDetails>", StringComparison.Ordinal));

    private void HostServices()
    {
        var evidence = Members("System.IServiceProvider", "GetService")
            .Concat(Members("Microsoft.Extensions.DependencyInjection.ServiceProviderServiceExtensions",
                "GetService", "GetRequiredService", "GetServices", "GetKeyedService", "GetRequiredKeyedService",
                "GetKeyedServices"))
            .Concat(Members("Microsoft.Extensions.DependencyInjection.ActivatorUtilities"))
            .Concat(Members("Microsoft.AspNetCore.Routing.IEndpointRouteBuilder", "get_ServiceProvider"))
            .Concat(Members("Microsoft.AspNetCore.Http.HttpContext", "get_RequestServices"))
            .Concat(Members("Microsoft.AspNetCore.Builder.IApplicationBuilder", "get_ApplicationServices"))
            .Select(m => m.Display)
            .Concat(AttributesOf("Microsoft.AspNetCore.Mvc.FromServicesAttribute",
                    "Microsoft.Extensions.DependencyInjection.FromKeyedServicesAttribute")
                .Select(a => $"{a.CtorType} on {a.Parent}"));
        Report("host-services", Severity.Review,
            "Resolves services from the host's dependency-injection container directly, bypassing the plugin context.",
            evidence);
    }

    private void HostData()
    {
        var evidence = Members("Zeus.Plugins.Contracts.IPluginContext", "get_HostDataDirectory")
            .Select(m => m.Display + " (host data directory: zeus-prefs.db, zeus-logbook.db)")
            .Concat(_model.Strings.Select(s => (s.Value, Marker: StringRules.HostDataMarker(s.Value)))
                .Where(s => s.Marker is not null)
                .Select(s => $"{Text.Quote(s.Value)} mentions {s.Marker}"));
        Report("host-data", Severity.Review,
            "Touches the host's data directory or databases, which hold operator settings and the logbook.",
            evidence);
    }

    private void StringRulesForAssembly()
    {
        var hostApi = new List<string>();
        var publicEndpoints = new List<string>();
        var knownEndpoints = new List<string>();
        var referenceEndpoints = new List<string>();
        var secrets = new List<string>();
        var homepageHost = _manifest.HomepageHost;
        foreach (var s in _model.Strings)
        {
            if (StringRules.IsHostApi(s.Value)) hostApi.Add(Text.Quote(s.Value));
            // Four-part version numbers in attribute arguments look like IPv4 literals.
            foreach (var endpoint in StringRules.Endpoints(s.Value, s.Origin != StringOrigin.AttributeArgument))
            {
                if (!endpoint.IsPublic) continue;
                var item = $"{endpoint.Host} in {Text.Quote(s.Value, 160)}";
                if (homepageHost is not null && endpoint.Host == homepageHost) knownEndpoints.Add(item);
                else if (StringRules.IsReferenceHost(endpoint.Host)) referenceEndpoints.Add(item);
                else publicEndpoints.Add(item);
            }
            secrets.AddRange(StringRules.Secrets(s.Value));
        }
        Report("host-api-string", Severity.Fail,
            "Contains Zeus host API routes, the SignalR hub path, or the station access token name: a backend " +
            "plugin must use the plugin context, never the host HTTP API.", hostApi);
        Report("public-endpoint", Severity.Review, "Contains public network endpoints.", publicEndpoints);
        Report("public-endpoint", Severity.Info, "Contains the manifest homepage host.", knownEndpoints);
        Report("public-endpoint", Severity.Info,
            "Contains standards/documentation URLs (XML namespaces, framework error links); listed, not a finding.",
            referenceEndpoints);
        Report("secret-like", Severity.Review,
            "Contains strings that look like credentials or key material (shown redacted).", secrets);
    }

    private void EmbeddedResources()
    {
        foreach (var resource in _model.Resources)
        {
            if (resource.Bytes is null)
            {
                Report("embedded-resource", Severity.Review, "Declares a linked resource stored outside the assembly.",
                    [$"{resource.Name} -> {resource.LinkedTo}"]);
                continue;
            }
            var bytes = resource.Bytes;
            var executable = FileKinds.IsExecutableMagic(bytes) || FileKinds.IsArchiveMagic(bytes);
            var item = $"{resource.Name} ({bytes.Length} bytes, sha256 {Text.Sha256(bytes)[..16]}…)";
            if (executable)
            {
                Report("embedded-resource", Severity.Fail,
                    "Embeds an executable image or archive as a resource.", [item + " starts with executable/archive magic"]);
            }
            else
            {
                Report("embedded-resource", Severity.Review, "Embeds resources; confirm their content.", [item]);
            }
        }
    }

    private const int LargeBlobBytes = 4096;

    private void LargeDataBlobs()
    {
        var evidence = _model.Fields.Where(f => f.RvaSize > LargeBlobBytes)
            .Select(f => $"{f.DeclaringType}::{f.Name} ({f.RvaSize} bytes of static data)");
        Report("large-data-blob", Severity.Review,
            $"Carries static data blobs larger than {LargeBlobBytes} bytes (possible embedded payload).", evidence);
    }

    private void TimeBomb()
    {
        Report("time-bomb", Severity.Review,
            $"Compares the clock or builds dates from year constants ({IlWalker.MinYear}-{IlWalker.MaxYear}); " +
            "confirm behaviour does not change on a future date.", _model.TimeBombs);
    }
}
