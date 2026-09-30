// SPDX-License-Identifier: GPL-2.0-or-later
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace PackageSecurityScan;

/// <summary>
/// String classifiers shared by the assembly and JavaScript rules. All patterns use
/// the non-backtracking engine so a crafted string cannot stall the scanner.
/// </summary>
internal static class StringRules
{
    private const RegexOptions Options = RegexOptions.NonBacktracking | RegexOptions.CultureInvariant;

    /// <summary>Host HTTP API routes a plugin must never call directly.</summary>
    public static readonly Regex HostApi = new(
        @"/api/(tx|radio|station|dsp|ps|auth|plugins/(install|uninstall|registry))\b",
        Options | RegexOptions.IgnoreCase);

    /// <summary>The host SignalR hub as a path: "/hub", "/hub/…", or "http://host:port/hub".</summary>
    public static readonly Regex HubPath = new(
        @"(^|[\s'""`(=,+]|://[^/\s'""`]*)/hub($|[/?#\s'""`),;+])",
        Options | RegexOptions.IgnoreCase);

    public static readonly Regex Url = new(@"https?://[^\s'""`<>(){}\[\]\\|^]+", Options | RegexOptions.IgnoreCase);

    public static readonly Regex BareIpv4 = new(
        @"(^|[^0-9.])((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3})($|[^0-9.])",
        Options);

    public const string StationTokenName = "ZEUS_STATION_ACCESS_TOKEN";

    public static readonly string[] HostDataMarkers =
        ["zeus-prefs", "zeus-logbook", ".litedb", "litedb", "zeus_station", StationTokenName];

    private static readonly (string Label, Regex Pattern)[] SecretPatterns =
    [
        ("GitHub token", new Regex(@"ghp_[A-Za-z0-9]{36}", Options)),
        ("GitHub fine-grained token", new Regex(@"github_pat_[A-Za-z0-9_]{20,}", Options)),
        ("API secret key", new Regex(@"sk-[A-Za-z0-9_-]{20,}", Options)),
        ("Slack token", new Regex(@"xox[abprs]-[A-Za-z0-9-]{8,}", Options)),
        ("AWS access key", new Regex(@"AKIA[0-9A-Z]{16}", Options)),
        ("private key", new Regex(@"-----BEGIN [A-Z ]*PRIVATE KEY-----", Options)),
        ("JWT", new Regex(@"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.", Options)),
    ];

    private static readonly Regex HighEntropyCandidate = new(@"[A-Za-z0-9+/=_-]{40,}", Options);
    public const double SecretEntropyBits = 4.5;

    /// <summary>
    /// Hosts that appear in standards identifiers (XML namespaces) and framework error
    /// messages. They are content an author cannot control, so they are listed as info.
    /// github.com is deliberately absent: anyone can host a payload there.
    /// </summary>
    private static readonly HashSet<string> ReferenceHosts = new(StringComparer.Ordinal)
    {
        "www.w3.org", "w3.org", "react.dev", "reactjs.org", "legacy.reactjs.org", "developer.mozilla.org",
        "json-schema.org", "schemas.microsoft.com", "schemas.xmlsoap.org", "schemas.openxmlformats.org",
    };

    public static bool IsReferenceHost(string host) => ReferenceHosts.Contains(host);

    public static bool IsHostApi(string value) =>
        HostApi.IsMatch(value) || HubPath.IsMatch(value) ||
        value.Contains(StationTokenName, StringComparison.OrdinalIgnoreCase);

    public static string? HostDataMarker(string value) =>
        HostDataMarkers.FirstOrDefault(m => value.Contains(m, StringComparison.OrdinalIgnoreCase));

    /// <summary>Secret-looking substrings, described without revealing the secret.</summary>
    public static IEnumerable<string> Secrets(string value)
    {
        foreach (var (label, pattern) in SecretPatterns)
        {
            foreach (Match match in pattern.Matches(value)) yield return $"{label}: {Redact(match.Value)}";
        }
        foreach (Match match in HighEntropyCandidate.Matches(value))
        {
            // Paths use the same alphabet as base64 but are separated by many slashes.
            if (match.Value.Count(c => c == '/') > 2) continue;
            // Alphabet tables ("0123456789ABC…xyz") are maximally diverse but not secret.
            if (IsMostlySequential(match.Value)) continue;
            var entropy = Text.Entropy(match.Value);
            if (entropy > SecretEntropyBits)
            {
                yield return $"high-entropy string ({entropy:F2} bits/char): {Redact(match.Value)}";
            }
        }
    }

    private static bool IsMostlySequential(string value)
    {
        var steps = 0;
        for (var i = 1; i < value.Length; i++)
        {
            if (value[i] == value[i - 1] + 1) steps++;
        }
        return steps * 2 >= value.Length - 1;
    }

    /// <summary>The longest run of base64/base64url characters in the value.</summary>
    public static string LongestEncodedRun(string value)
    {
        var best = "";
        foreach (Match match in EncodedRun.Matches(value))
        {
            if (match.Length > best.Length) best = match.Value;
        }
        return best;
    }

    private static readonly Regex EncodedRun = new(@"[A-Za-z0-9+/=_-]{16,}", Options);

    public static string Redact(string secret) =>
        $"{Text.Clean(secret[..Math.Min(12, secret.Length)], 12)}… (length {secret.Length})";

    public sealed record Endpoint(string Host, string Raw, bool IsPublic);

    /// <summary>Every URL host and (optionally) bare IPv4 literal in the string, classified.</summary>
    public static IEnumerable<Endpoint> Endpoints(string value, bool includeBareIps)
    {
        var hosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (Match match in Url.Matches(value))
        {
            if (!Uri.TryCreate(match.Value, UriKind.Absolute, out var uri) || string.IsNullOrEmpty(uri.Host)) continue;
            var host = uri.IdnHost.Trim('[', ']').ToLowerInvariant();
            hosts.Add(host);
            yield return new Endpoint(host, match.Value, IsPublicHost(host));
        }
        if (!includeBareIps) yield break;
        foreach (Match match in BareIpv4.Matches(value))
        {
            var ip = match.Groups[2].Value;
            if (hosts.Contains(ip)) continue;
            yield return new Endpoint(ip, ip, IsPublicHost(ip));
        }
    }

    public static bool IsPublicHost(string host)
    {
        host = host.TrimEnd('.').ToLowerInvariant();
        if (IPAddress.TryParse(host, out var address)) return !IsNonPublicAddress(address);
        if (host == "localhost" || host.EndsWith(".localhost", StringComparison.Ordinal)) return false;
        // mDNS names resolve on the local link only.
        if (host.EndsWith(".local", StringComparison.Ordinal)) return false;
        // RFC 2606 reserved documentation / test names.
        string[] reserved = ["example.com", "example.org", "example.net"];
        if (reserved.Any(r => host == r || host.EndsWith("." + r, StringComparison.Ordinal))) return false;
        string[] reservedTlds = [".example", ".test", ".invalid"];
        return !reservedTlds.Any(t => host.EndsWith(t, StringComparison.Ordinal));
    }

    public static bool IsNonPublicAddress(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = address.GetAddressBytes();
            return b[0] == 0 || b[0] == 10 || b[0] == 127 ||
                (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
                (b[0] == 192 && b[1] == 168) ||
                (b[0] == 169 && b[1] == 254) ||
                (b[0] == 100 && b[1] >= 64 && b[1] <= 127) ||
                b[0] >= 224 ||
                (b[0] == 192 && b[1] == 0 && b[2] == 2) ||
                (b[0] == 198 && b[1] == 51 && b[2] == 100) ||
                (b[0] == 203 && b[1] == 0 && b[2] == 113);
        }
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var b = address.GetAddressBytes();
            var documentation = b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0D && b[3] == 0xB8;
            return IPAddress.IsLoopback(address) || address.Equals(IPAddress.IPv6Any) ||
                address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6Multicast ||
                address.IsIPv6UniqueLocal || documentation;
        }
        return false;
    }
}
