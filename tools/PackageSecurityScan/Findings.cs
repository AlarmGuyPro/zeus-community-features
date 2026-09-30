// SPDX-License-Identifier: GPL-2.0-or-later
using System.Text;

namespace PackageSecurityScan;

/// <summary>Finding severity. Ordered so the worst severity compares greatest.</summary>
internal enum Severity
{
    Info = 0,
    Review = 1,
    Fail = 2,
}

internal static class SeverityExtensions
{
    public static string ToWire(this Severity severity) => severity switch
    {
        Severity.Fail => "fail",
        Severity.Review => "review",
        _ => "info",
    };

    public static string ToDisposition(this Severity severity) => severity switch
    {
        Severity.Fail => "fail",
        Severity.Review => "review",
        _ => "clear",
    };
}

/// <summary>A condition the scanner cannot turn into a verdict (bad arguments, unreadable input).</summary>
internal sealed class ToolException(string message) : Exception(message);

/// <summary>
/// One finding per (rule, file). Repeated hits of the same rule in the same file
/// merge into it: the severity is the worst seen and the evidence accumulates.
/// Keeping the key stable is what lets an allowlist entry name exactly one finding.
/// </summary>
internal sealed class Finding(string ruleId, string file, Severity severity)
{
    public const int MaxEvidence = 40;
    private readonly HashSet<string> _evidenceSeen = new(StringComparer.Ordinal);

    public string RuleId { get; } = ruleId;
    public string File { get; } = file;
    public Severity Severity { get; set; } = severity;
    public List<string> Details { get; } = [];
    public List<string> Evidence { get; } = [];
    public int OmittedEvidence { get; private set; }

    public void AddEvidence(string item)
    {
        var clean = Text.Clean(item, 200);
        if (!_evidenceSeen.Add(clean)) return;
        if (Evidence.Count >= MaxEvidence)
        {
            OmittedEvidence++;
            return;
        }
        Evidence.Add(clean);
    }

    public string DetailText => string.Join(" ", Details);

    public string EvidenceText
    {
        get
        {
            var text = string.Join("; ", Evidence);
            return OmittedEvidence == 0 ? text : $"{text}; (+{OmittedEvidence} more)";
        }
    }
}

internal sealed class FindingSet
{
    private readonly Dictionary<(string RuleId, string File), Finding> _byKey = [];
    private readonly List<Finding> _order = [];

    public IReadOnlyList<Finding> All => _order;

    public Finding Add(string ruleId, Severity severity, string file, string detail,
        IEnumerable<string>? evidence = null)
    {
        var cleanFile = Text.Clean(file, 400);
        if (!_byKey.TryGetValue((ruleId, cleanFile), out var finding))
        {
            finding = new Finding(ruleId, cleanFile, severity);
            _byKey.Add((ruleId, cleanFile), finding);
            _order.Add(finding);
        }
        else if (severity > finding.Severity)
        {
            finding.Severity = severity;
        }
        var cleanDetail = Text.Clean(detail, 600);
        if (!finding.Details.Contains(cleanDetail)) finding.Details.Add(cleanDetail);
        if (evidence is not null)
        {
            foreach (var item in evidence) finding.AddEvidence(item);
        }
        return finding;
    }

    public Severity Worst => _order.Count == 0 ? Severity.Info : _order.Max(f => f.Severity);
}

internal static class Text
{
    /// <summary>
    /// Makes attacker-controlled text safe to print in a CI log or a Markdown
    /// comment: escapes control characters, bidi overrides, zero-width marks, and
    /// unpaired surrogates, then truncates to <paramref name="max"/> characters.
    /// </summary>
    public static string Clean(string value, int max = 200)
    {
        var sb = new StringBuilder(Math.Min(value.Length, max) + 8);
        for (var i = 0; i < value.Length; i++)
        {
            if (sb.Length >= max)
            {
                sb.Append('…');
                break;
            }
            var c = value[i];
            if (char.IsHighSurrogate(c) && i + 1 < value.Length && char.IsLowSurrogate(value[i + 1]))
            {
                sb.Append(c).Append(value[i + 1]);
                i++;
                continue;
            }
            if (char.IsControl(c) || char.IsSurrogate(c) || IsInvisibleFormatting(c))
            {
                sb.Append("\\u").Append(((int)c).ToString("X4", System.Globalization.CultureInfo.InvariantCulture));
                continue;
            }
            sb.Append(c);
        }
        return sb.ToString();
    }

    public static string Quote(string value, int max = 200) => "\"" + Clean(value, max) + "\"";

    private static bool IsInvisibleFormatting(char c) =>
        c is >= '​' and <= '‏' or >= '‪' and <= '‮' or >= '⁦' and <= '⁩'
            or '﻿' or '؜';

    /// <summary>Shannon entropy in bits per character.</summary>
    public static double Entropy(ReadOnlySpan<char> value)
    {
        if (value.IsEmpty) return 0;
        var counts = new Dictionary<char, int>();
        foreach (var c in value) counts[c] = counts.GetValueOrDefault(c) + 1;
        double entropy = 0;
        foreach (var count in counts.Values)
        {
            var p = (double)count / value.Length;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }

    public static string Hex(ReadOnlySpan<byte> bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    public static string Sha256(ReadOnlySpan<byte> bytes) =>
        Hex(System.Security.Cryptography.SHA256.HashData(bytes));
}
