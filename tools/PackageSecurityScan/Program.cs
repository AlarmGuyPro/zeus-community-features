// SPDX-License-Identifier: GPL-2.0-or-later
namespace PackageSecurityScan;

/// <summary>
/// Static security scanner for Zeus community plugin packages.
///
///   scan    --package &lt;zip&gt; [--json &lt;out.json&gt;] [--allowlist &lt;allowlist.json&gt;]
///   compare --package &lt;zip&gt; --rebuilt &lt;dir&gt; [--json &lt;out.json&gt;] [--il-strict]
///
/// Exit codes: 0 clear or review, 2 fail (a hard finding), 1 tool error.
/// Package code is never loaded or executed.
/// </summary>
internal static class Program
{
    // Metadata walks are depth-bounded, but a generous stack keeps a crafted,
    // deeply nested signature from crashing the process before the bound trips.
    private const int WorkerStackBytes = 64 * 1024 * 1024;

    private const string Usage =
        "usage: PackageSecurityScan scan --package <zip> [--json <out.json>] [--allowlist <allowlist.json>]\n" +
        "       PackageSecurityScan compare --package <zip> --rebuilt <dir> [--json <out.json>] [--il-strict]";

    public static int Main(string[] args)
    {
        var exitCode = ExitCodes.ToolError;
        var worker = new Thread(() => exitCode = Run(args), WorkerStackBytes) { Name = "package-security-scan" };
        worker.Start();
        worker.Join();
        return exitCode;
    }

    private static int Run(string[] args)
    {
        try
        {
            var options = ParseArguments(args);
            var report = options.Command switch
            {
                "scan" => PackageScanner.Scan(options.Package, options.Allowlist),
                "compare" => PackageComparer.Compare(options.Package, options.Rebuilt!, options.IlStrict),
                _ => throw new ToolException(Usage),
            };
            report.WriteText(Console.Out);
            if (options.Json is not null) report.WriteJson(options.Json);
            return report.ExitCode;
        }
        catch (ToolException ex)
        {
            Console.Error.WriteLine($"PackageSecurityScan: {ex.Message}");
            return ExitCodes.ToolError;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"PackageSecurityScan: unexpected error: {ex}");
            return ExitCodes.ToolError;
        }
    }

    private sealed record Options(string Command, string Package, string? Json, string? Allowlist, string? Rebuilt,
        bool IlStrict);

    private static Options ParseArguments(string[] args)
    {
        if (args.Length == 0 || args[0] is not ("scan" or "compare")) throw new ToolException(Usage);
        var command = args[0];
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        string[] allowed = command == "scan" ? ["--package", "--json", "--allowlist"] : ["--package", "--rebuilt", "--json"];
        var ilStrict = false;
        for (var i = 1; i < args.Length; i += 2)
        {
            var name = args[i];
            if (command == "compare" && name == "--il-strict")
            {
                if (ilStrict) throw new ToolException("Option --il-strict was given twice");
                ilStrict = true;
                i--;
                continue;
            }
            if (!allowed.Contains(name, StringComparer.Ordinal)) throw new ToolException($"Unknown option {name}\n{Usage}");
            if (i + 1 >= args.Length || string.IsNullOrWhiteSpace(args[i + 1]))
            {
                throw new ToolException($"Option {name} needs a value\n{Usage}");
            }
            if (!values.TryAdd(name, args[i + 1])) throw new ToolException($"Option {name} was given twice");
        }
        if (!values.TryGetValue("--package", out var package)) throw new ToolException($"--package is required\n{Usage}");
        values.TryGetValue("--rebuilt", out var rebuilt);
        if (command == "compare" && rebuilt is null) throw new ToolException($"--rebuilt is required\n{Usage}");
        values.TryGetValue("--json", out var json);
        values.TryGetValue("--allowlist", out var allowlist);
        return new Options(command, package, json, allowlist, rebuilt, ilStrict);
    }
}
