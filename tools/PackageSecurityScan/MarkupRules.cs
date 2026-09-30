// SPDX-License-Identifier: GPL-2.0-or-later
using System.Text;
using System.Text.RegularExpressions;

namespace PackageSecurityScan;

/// <summary>
/// Text rules for HTML and SVG documents in a package. Loaded into a frame, an image, or the
/// page, markup can carry script that runs in the Zeus origin, so active content is a fail.
/// </summary>
internal static class MarkupRules
{
    private const RegexOptions Options =
        RegexOptions.NonBacktracking | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase;

    private static readonly string[] HtmlExtensions = [".html", ".htm", ".xhtml"];
    private static readonly string[] MarkupExtensions = [".html", ".htm", ".xhtml", ".svg"];

    private static readonly Regex[] ActiveContent =
    [
        new(@"<script\b", Options),
        new(@"[\s/""']on[a-z]+\s*=", Options),
        new(@"=\s*['""]?\s*javascript\s*:", Options),
        new(@"url\(\s*['""]?\s*javascript\s*:", Options),
    ];

    private static readonly Regex[] Embeds = [new(@"<(iframe|object|embed|frame|foreignObject)\b", Options)];

    public static bool IsMarkup(string path) =>
        MarkupExtensions.Any(e => path.EndsWith(e, StringComparison.OrdinalIgnoreCase));

    public static void Evaluate(byte[] bytes, string file, FindingSet findings)
    {
        var text = new UTF8Encoding(false, false).GetString(bytes);
        if (HtmlExtensions.Any(e => file.EndsWith(e, StringComparison.OrdinalIgnoreCase)))
        {
            findings.Add("markup-html-file", Severity.Review, file,
                "Ships an HTML document; if the UI frames or navigates to it, it runs in the Zeus origin.");
        }
        Report(text, file, findings, "markup-script", Severity.Fail,
            "Markup contains script, inline event handlers, or javascript: URLs.", ActiveContent);
        Report(text, file, findings, "markup-embed", Severity.Review,
            "Markup embeds frames, objects, or foreignObject content; confirm what they load.", Embeds);
    }

    private static void Report(string text, string file, FindingSet findings, string ruleId, Severity severity,
        string detail, Regex[] patterns)
    {
        var locator = new TextLocator(text);
        var evidence = patterns.SelectMany(p => p.Matches(text)).OrderBy(m => m.Index)
            .Select(m => locator.Locate(m.Index)).ToList();
        if (evidence.Count > 0) findings.Add(ruleId, severity, file, detail, evidence);
    }
}
