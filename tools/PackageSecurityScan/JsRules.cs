// SPDX-License-Identifier: GPL-2.0-or-later
using System.Text;
using System.Text.RegularExpressions;

namespace PackageSecurityScan;

/// <summary>
/// Text rules for JavaScript UI modules. UI modules run in the Zeus SPA origin with no
/// content-security policy, so they can do anything the operator's browser session can.
/// The module is scanned as text; it is never parsed by or run in a JavaScript engine.
/// Comments are scanned too: hiding a pattern in a comment is not a reason to skip it.
/// </summary>
internal sealed class JsRules
{
    private const RegexOptions Options = RegexOptions.NonBacktracking | RegexOptions.CultureInvariant;
    private const int ObfuscatedIdentifierLimit = 20;
    private const int HexEscapeLimit = 200;
    private const int FromCharCodeArgumentLimit = 20;
    private const int EncodedBlobLength = 200;
    private const double EncodedBlobEntropyBits = 5.0;

    private static Regex R(string pattern) => new(pattern, Options);
    private static Regex RI(string pattern) => new(pattern, Options | RegexOptions.IgnoreCase);

    /// <summary>Optional whitespace and comments, allowed between a callee and its '(' (e.g. <c>fetch/**/(</c>).</summary>
    private const string Gap = @"(\s|/\*([^*]|\*+[^*/])*\*+/|//[^\n]*\n)*";

    /// <summary>At least one whitespace character or comment (between <c>new</c> and a constructor name).</summary>
    private const string Gap1 = @"(\s|/\*([^*]|\*+[^*/])*\*+/|//[^\n]*\n)+";

    private const string Quote = @"['""`]";

    /// <summary>A rule: its patterns, plus an optional filter that rejects a match in its context.</summary>
    private sealed record Rule(string Id, Severity Severity, string Detail, Regex[] Patterns,
        Func<string, Match, bool>? Accept = null);

    private static readonly Rule EvalRule = new("js-eval", Severity.Fail,
        "Evaluates strings as code (eval, Function, constructor chains, string timers).",
        [
            // Any reference to eval, not just a direct call: (0,eval)(s), window.eval, window['eval'].
            R(@"\beval\b"),
            // Bare Function(...) and new Function(...), with or without a quoted argument.
            R(@"\bFunction" + Gap + @"\("),
            // [].constructor.constructor(s) and (() => {}).constructor(s) reach Function.
            R(@"\." + Gap + "constructor" + Gap + @"\." + Gap + @"constructor\b"),
            R(@"\." + Gap + "constructor" + Gap + @"\("),
            R(@"\[" + Gap + Quote + "constructor" + Quote + Gap + @"\]"),
            // The global Function through a global receiver (obj.Function stays exempt).
            R(@"\b(window|globalThis|self|top|parent|frames)" + Gap + @"\." + Gap + @"Function\b"),
            R(@"\[" + Gap + Quote + "Function" + Quote + Gap + @"\]"),
            R(@"\bReflect" + Gap + @"\." + Gap + "(construct|apply)" + Gap + @"\(" + Gap + @"(Function|eval)\b"),
            // (async () => {}).constructor, (async function () {}).constructor, (function* () {}).constructor,
            // Object.getPrototypeOf(function () {}).constructor: the (Async|Generator)Function constructors.
            R(@"\}" + Gap + @"\)" + Gap + @"\." + Gap + @"constructor\b"),
            R(@"\bset(Timeout|Interval)" + Gap + @"\(" + Gap + Quote),
        ],
        AcceptEvalMatch);

    private static readonly Rule ConstructorAccessRule = new("js-constructor-access", Severity.Review,
        "Reads .constructor as a value; from a function literal this is the Function constructor (code from strings).",
        [R(@"\." + Gap + @"constructor\b")],
        AcceptConstructorRead);

    private static readonly Rule StringTransformRule = new("js-string-transform", Severity.Review,
        "Builds strings with transforms that defeat text scanning (replace on a literal, fromCharCode); confirm the " +
        "resulting text.",
        [R(@"\bString" + Gap + @"\." + Gap + "fromCharCode" + Gap + @"\("), R(@"\.map" + Gap + @"\([^;]{0,200}fromCharCode")]);

    private static readonly Regex LiteralReplaceTail = R("^" + Gap + @"\." + Gap + "(replace|replaceAll)" + Gap + @"\(");

    private const string SimpleLiteral = @"('[^'\\\r\n]*'|""[^""\\\r\n]*""|`[^`\\]*`)";

    private static readonly Regex SplitReverseJoinTail = R("^" + Gap + @"\." + Gap + "split" + Gap + @"\(" + Gap +
        "(?<split>" + SimpleLiteral + ")" + Gap + @"\)" + Gap + @"\." + Gap + "reverse" + Gap + @"\(" + Gap + @"\)" +
        Gap + @"\." + Gap + "join" + Gap + @"\(" + Gap + "(?<join>" + SimpleLiteral + ")?" + Gap + @"\)");

    private static readonly Regex RemoteImport = R(@"\bimport" + Gap + @"\(" + Gap + Quote + "https?:");

    private static readonly Rule RemoteCodeRule = new("js-remote-code", Severity.Fail,
        "Loads or runs code from outside the reviewed package (remote imports, scripts, workers, WebAssembly).",
        [
            RemoteImport, R(@"\bimportScripts" + Gap + @"\("),
            RI(@"createElement" + Gap + @"\(" + Gap + Quote + "script"),
            R(@"\bnew" + Gap1 + "(Shared)?Worker" + Gap + @"\("),
            R(@"\.src" + Gap + "=" + Gap + Quote + "https?:"),
            R(@"\bWebAssembly" + Gap + @"\." + Gap + "(instantiate|compile)(Streaming)?" + Gap + @"\("),
            // Static ESM imports / re-exports from a remote origin.
            R(@"\b(import|export)\s[^;'""`]{0,200}\bfrom\s*" + Quote + "https?:"),
            R(@"\bimport\s*" + Quote + "https?:"),
        ]);

    private static readonly Regex DynamicImport = R(@"\bimport" + Gap + @"\(");

    private static readonly Rule HostApiRule = new("js-host-api", Severity.Fail,
        "References Zeus host API routes, the SignalR hub, the native bridge, or the station token. UI modules " +
        "must talk to their backend through the host's callBackend.",
        [StringRules.HostApi, StringRules.HubPath, R(@"\bwindow\.__zeus"), R(@"\bwindow\.external\b"), R("ZEUS_STATION")]);

    private static readonly Rule NetworkRule = new("js-network", Severity.Review,
        "Makes network requests directly; plugin UIs should go through the host's callBackend.",
        [
            // Any reference, so an alias (const f = fetch) is still seen.
            R(@"\bfetch\b"), R(@"\bXMLHttpRequest\b"), R(@"\bnew" + Gap1 + "WebSocket" + Gap + @"\("),
            R(@"\bnew" + Gap1 + "EventSource" + Gap + @"\("), R(@"\bsendBeacon" + Gap + @"\("),
        ],
        AcceptKeywordMatch);

    private static readonly Rule StorageRule = new("js-storage", Severity.Review,
        "Uses browser storage shared with the Zeus SPA origin (settings, session data).",
        [
            R(@"\blocalStorage\b"), R(@"\bsessionStorage\b"), R(@"\bindexedDB\b"), R(@"\bdocument\.cookie\b"),
            R(@"\bcaches\.open" + Gap + @"\("),
        ]);

    private static readonly Rule GlobalKeysRule = new("js-global-keys", Severity.Review,
        "Installs a global keyboard listener that can intercept Zeus hotkeys such as Space (transmit).",
        [
            R(@"\b(window|document|globalThis)\.addEventListener" + Gap + @"\(" + Gap + Quote + "key(down|up|press)"),
            R(@"\b(window|document|globalThis)\.onkey(down|up|press)\s*="),
        ]);

    private static readonly Rule CrossWindowRule = new("js-cross-window", Severity.Review,
        "Messages or navigates other windows or the top-level page.",
        [
            R(@"\bpostMessage" + Gap + @"\("), R(@"\bwindow\.(parent|top|opener)\b"),
            R(@"\bwindow\.open" + Gap + @"\("), R(@"\blocation\.(href|assign|replace)\b"),
        ]);

    private static readonly Rule HtmlInjectionRule = new("js-html-injection", Severity.Review,
        "Writes raw HTML into the page (script injection risk into the Zeus origin).",
        [
            R(@"\binnerHTML\b"), R(@"\bouterHTML\b"), R(@"\binsertAdjacentHTML\b"), R(@"\bdangerouslySetInnerHTML\b"),
            R(@"\bdocument\.write(ln)?" + Gap + @"\("),
        ]);

    private static readonly Rule SrcdocRule = new("js-srcdoc", Severity.Fail,
        "Sets iframe srcdoc: the frame runs arbitrary HTML and script in the Zeus origin.", [R(@"\bsrcdoc\b")]);

    private static readonly Rule EmbedRule = new("js-embed", Severity.Review,
        "Creates frames or embedded objects, or points one at a packaged HTML/SVG document; confirm what they load.",
        [
            RI(@"createElement" + Gap + @"\(" + Gap + Quote + "(iframe|object|embed|frame)" + Quote),
            RI(@"\.src" + Gap + "=" + Gap + Quote + @"[^'""`\r\n]*\.(html?|xhtml|svg)" + Quote),
        ],
        AcceptRelativeSrc);

    private static readonly Rule ComputedAccessRule = new("js-computed-access", Severity.Review,
        "Reaches a global or page object through a computed property name built at runtime (a common way to hide " +
        "eval, fetch, or host APIs from text scanning).",
        [R(@"\b(window|globalThis|self|document|top|parent|this)" + Gap + @"\[[^\]]*(\+|\.join" + Gap + @"\(|\$\{)[^\]]*\]")]);

    /// <summary>Names that only appear when split string literals are joined back together.</summary>
    private static readonly Rule SplitNameRule = new("js-split-name", Severity.Fail,
        "Builds a dangerous API name out of split or escaped string literals, which only makes sense to evade review.",
        [
            R(@"\b(eval|Function|constructor|fetch|import|importScripts|XMLHttpRequest|WebSocket|EventSource|" +
              @"sendBeacon|postMessage|localStorage|sessionStorage|indexedDB|cookie|innerHTML|outerHTML|" +
              @"insertAdjacentHTML|srcdoc|WebAssembly|Worker|__zeus|external|ZEUS_STATION|atob|setTimeout|" +
              @"setInterval|window|globalThis|opener)\b"),
            // A host API path that only appears once the pieces are joined or reversed.
            StringRules.HostApi, StringRules.HubPath,
        ]);

    /// <summary>Rules re-run over text reconstructed from split or escaped string literals.</summary>
    private static readonly Rule[] ReconstructedRules =
    [
        EvalRule, RemoteCodeRule, HostApiRule, NetworkRule, StorageRule, CrossWindowRule, HtmlInjectionRule,
        SrcdocRule, SplitNameRule,
    ];

    private static readonly Regex PlusGap = R("^" + Gap + @"\+" + Gap + "$");
    private static readonly Regex CommaGap = R("^" + Gap + "," + Gap + "$");
    private static readonly Regex JoinTail = R("^" + Gap + @"\]" + Gap + @"\." + Gap + "join" + Gap + @"\(" + Gap + @"(\)|['""`])");
    private static readonly Regex CloseParen = R("^" + Gap + @"\)");

    private static readonly Regex ObfuscatedIdentifier = R(@"\b_0x[0-9a-fA-F]{4,}\b");
    private static readonly Regex HexEscape = R(@"\\x[0-9a-fA-F]{2}");
    private static readonly Regex FromCharCode = R(@"String\.fromCharCode\s*\(([^)]*)\)");
    private static readonly Regex[] Decoders = [R(@"\batob\s*\("), R(@"\bunescape\s*\(")];

    private static readonly Regex[] StringLiterals =
    [
        R(@"""(\\.|[^""\\\r\n])*"""), R(@"'(\\.|[^'\\\r\n])*'"), R(@"`(\\.|[^`\\])*`"),
    ];

    private readonly string _text;
    private readonly string _file;
    private readonly ManifestInfo _manifest;
    private readonly FindingSet _findings;
    private readonly TextLocator _locator;

    private JsRules(string text, string file, ManifestInfo manifest, FindingSet findings)
    {
        _text = text;
        _file = file;
        _manifest = manifest;
        _findings = findings;
        _locator = new TextLocator(text);
    }

    public static void Evaluate(byte[] bytes, string file, ManifestInfo manifest, FindingSet findings)
    {
        var text = new UTF8Encoding(false, false).GetString(bytes);
        if (text.Length > 0 && text[0] == '﻿') text = text[1..];
        var rules = new JsRules(text, file, manifest, findings);
        rules.Run();
    }

    private void Run()
    {
        foreach (var rule in new[]
                 {
                     EvalRule, RemoteCodeRule, HostApiRule, NetworkRule, StorageRule, GlobalKeysRule, CrossWindowRule,
                     HtmlInjectionRule, SrcdocRule, EmbedRule, ComputedAccessRule, ConstructorAccessRule,
                     StringTransformRule,
                 })
        {
            Apply(rule);
        }
        var remoteImports = RemoteImport.Matches(_text).Select(m => m.Index).ToHashSet();
        Report("js-dynamic-import", Severity.Review, "Imports modules dynamically; confirm what is loaded.",
            DynamicImport.Matches(_text).Where(m => !remoteImports.Contains(m.Index)).Select(Locate));
        Reconstructed();
        LiteralTransforms();
        Obfuscation();
        PublicEndpoints();
    }

    private void Apply(Rule rule) =>
        Report(rule.Id, rule.Severity, rule.Detail, rule.Patterns.SelectMany(p => p.Matches(_text))
            .Where(m => rule.Accept is null || rule.Accept(_text, m))
            .OrderBy(m => m.Index)
            .Select(Locate));

    private static int PreviousNonSpace(string text, int index)
    {
        for (var i = index - 1; i >= 0; i--)
        {
            if (!char.IsWhiteSpace(text[i])) return i;
        }
        return -1;
    }

    private static int NextNonSpace(string text, int index)
    {
        for (var i = index; i < text.Length; i++)
        {
            if (!char.IsWhiteSpace(text[i])) return i;
        }
        return -1;
    }

    /// <summary>
    /// Rejects a keyword match that is only an object-literal key (<c>{ eval: 1 }</c>) or part of a
    /// hyphenated word inside a string (<c>'unsafe-eval'</c>, <c>eval-source-map</c>).
    /// </summary>
    private static bool AcceptKeywordMatch(string text, Match match)
    {
        var end = match.Index + match.Length;
        var next = NextNonSpace(text, end);
        var nextChar = next < 0 ? '\0' : text[next];
        var previous = PreviousNonSpace(text, match.Index);
        var previousChar = previous < 0 ? '\0' : text[previous];
        if (nextChar == ':' && previousChar is '{' or ',') return false;
        var hyphenated = (match.Index > 0 && text[match.Index - 1] == '-') || (end < text.Length && text[end] == '-');
        return !hyphenated || nextChar == '(';
    }

    private static bool AcceptEvalMatch(string text, Match match)
    {
        if (match.Value.StartsWith("Function", StringComparison.Ordinal))
        {
            // obj.Function(...) is some other method, not the global Function constructor.
            var previous = PreviousNonSpace(text, match.Index);
            return previous < 0 || text[previous] != '.';
        }
        return !match.Value.StartsWith("eval", StringComparison.Ordinal) || AcceptKeywordMatch(text, match);
    }

    /// <summary>
    /// Keeps a .constructor read unless it is plainly benign: this.constructor / X.prototype.constructor,
    /// .constructor.name / .constructor.prototype, an identity comparison, or a form js-eval already fails
    /// (.constructor( and .constructor.constructor).
    /// </summary>
    private static bool AcceptConstructorRead(string text, Match match)
    {
        var end = match.Index + match.Length;
        var next = NextNonSpace(text, end);
        if (next >= 0)
        {
            var rest = text.AsSpan(next, Math.Min(24, text.Length - next));
            if (rest.StartsWith("(") || rest.StartsWith("===") || rest.StartsWith("!==") ||
                rest.StartsWith("==") || rest.StartsWith("!=")) return false;
            if (rest.StartsWith("."))
            {
                var member = rest[1..].TrimStart();
                if (member.StartsWith("name") || member.StartsWith("prototype") || member.StartsWith("constructor"))
                {
                    return false;
                }
            }
        }
        var previous = PreviousNonSpace(text, match.Index);
        var wordEnd = previous + 1;
        var wordStart = wordEnd;
        while (wordStart > 0 && (char.IsLetterOrDigit(text[wordStart - 1]) || text[wordStart - 1] is '_' or '$')) wordStart--;
        var receiver = text[wordStart..wordEnd];
        return receiver is not ("this" or "prototype");
    }

    private static bool AcceptRelativeSrc(string text, Match match) =>
        !match.Value.Contains("http:", StringComparison.OrdinalIgnoreCase) &&
        !match.Value.Contains("https:", StringComparison.OrdinalIgnoreCase);

    private void Report(string ruleId, Severity severity, string detail, IEnumerable<string> evidence)
    {
        var items = evidence.ToList();
        if (items.Count > 0) _findings.Add(ruleId, severity, _file, detail, items);
    }

    private (int Line, int Column) Position(int index) => _locator.Position(index);

    private string Locate(Match match) => Locate(match.Index);

    private string Locate(int index) => _locator.Locate(index);

    private sealed record Literal(int Start, int End, string Raw, string Value);

    private sealed record Reconstruction(int Start, string Text, IReadOnlyList<string> RawPieces);

    /// <summary>
    /// Reassembles strings that were split to dodge a text scan: literals joined with '+', arrays of
    /// literals followed by .join(sep), and single literals written with escapes ('\x65val'). The rules
    /// are re-run on the reconstructed text, and a match counts only when it does not already appear
    /// in one raw literal (those were caught by the direct scan).
    /// </summary>
    private void Reconstructed()
    {
        foreach (var rule in ReconstructedRules)
        {
            var evidence = new List<string>();
            foreach (var candidate in Reconstructions())
            {
                foreach (var match in rule.Patterns.SelectMany(p => p.Matches(candidate.Text)))
                {
                    if (candidate.RawPieces.Any(raw => raw.Contains(match.Value, StringComparison.Ordinal))) continue;
                    if (rule.Accept is not null && !rule.Accept(candidate.Text, match)) continue;
                    var (line, column) = Position(candidate.Start);
                    evidence.Add($"{line}:{column}: reconstructed from split/escaped string literals: " +
                        Text.Quote(candidate.Text, 120));
                }
            }
            Report(rule.Id, rule.Severity, rule.Detail, evidence);
        }
    }

    private List<Reconstruction>? _reconstructions;

    private List<Reconstruction> Reconstructions()
    {
        if (_reconstructions is not null) return _reconstructions;
        var literals = Literals();
        var result = new List<Reconstruction>();
        foreach (var literal in literals)
        {
            if (!string.Equals(literal.Raw, literal.Value, StringComparison.Ordinal))
            {
                result.Add(new Reconstruction(literal.Start, literal.Value, [literal.Raw]));
            }
        }
        // 'lave'.split('').reverse().join('')
        foreach (var literal in literals)
        {
            var tail = SplitReverseJoinTail.Match(_text.Substring(literal.End, Math.Min(256, _text.Length - literal.End)));
            if (!tail.Success) continue;
            var separator = Unescape(tail.Groups["split"].Value[1..^1]);
            var joiner = tail.Groups["join"].Success ? Unescape(tail.Groups["join"].Value[1..^1]) : ",";
            var parts = separator.Length == 0
                ? literal.Value.Select(c => c.ToString()).ToArray()
                : literal.Value.Split(separator);
            Array.Reverse(parts);
            result.Add(new Reconstruction(literal.Start, string.Join(joiner, parts), [literal.Raw]));
        }
        // 'a' + 'b' + 'c'
        for (var i = 0; i < literals.Count; i++)
        {
            var j = i;
            while (j + 1 < literals.Count && PlusGap.IsMatch(Between(literals[j], literals[j + 1]))) j++;
            if (j == i) continue;
            var pieces = literals.GetRange(i, j - i + 1);
            result.Add(new Reconstruction(pieces[0].Start, string.Concat(pieces.Select(p => p.Value)),
                pieces.Select(p => p.Raw).ToList()));
            i = j;
        }
        // ['a', 'b'].join('')
        for (var i = 0; i < literals.Count; i++)
        {
            var open = PreviousNonSpace(_text, literals[i].Start);
            if (open < 0 || _text[open] != '[') continue;
            var j = i;
            while (j + 1 < literals.Count && CommaGap.IsMatch(Between(literals[j], literals[j + 1]))) j++;
            var tailStart = literals[j].End;
            var tail = JoinTail.Match(_text.Substring(tailStart, Math.Min(256, _text.Length - tailStart)));
            if (!tail.Success) continue;
            string separator;
            if (tail.Value.EndsWith(')'))
            {
                separator = ",";
            }
            else
            {
                var separatorStart = tailStart + tail.Length - 1;
                var sepLiteral = literals.Skip(j + 1).FirstOrDefault(l => l.Start == separatorStart);
                if (sepLiteral is null ||
                    !CloseParen.IsMatch(_text.Substring(sepLiteral.End, Math.Min(64, _text.Length - sepLiteral.End))))
                {
                    continue;
                }
                separator = sepLiteral.Value;
            }
            var pieces = literals.GetRange(i, j - i + 1);
            result.Add(new Reconstruction(pieces[0].Start, string.Join(separator, pieces.Select(p => p.Value)),
                pieces.Select(p => p.Raw).ToList()));
            i = j;
        }
        _reconstructions = result;
        return result;
    }

    /// <summary>A string literal immediately transformed with .replace/.replaceAll is flagged for review.</summary>
    private void LiteralTransforms()
    {
        var evidence = new List<string>();
        foreach (var literal in Literals())
        {
            var tail = _text.Substring(literal.End, Math.Min(64, _text.Length - literal.End));
            if (LiteralReplaceTail.IsMatch(tail)) evidence.Add(Locate(literal.Start));
        }
        Report(StringTransformRule.Id, StringTransformRule.Severity, StringTransformRule.Detail, evidence);
    }

    private string Between(Literal left, Literal right) =>
        right.Start - left.End > 256 ? "#" : _text[left.End..right.Start];

    /// <summary>Non-overlapping string literals in source order (approximate: the text is not parsed).</summary>
    private List<Literal>? _literals;

    private List<Literal> Literals()
    {
        if (_literals is not null) return _literals;
        var literals = new List<Literal>();
        var end = 0;
        foreach (var match in StringLiterals.SelectMany(p => p.Matches(_text))
                     .OrderBy(m => m.Index).ThenByDescending(m => m.Length))
        {
            if (match.Index < end) continue;
            var raw = match.Value[1..^1];
            literals.Add(new Literal(match.Index, match.Index + match.Length, raw, Unescape(raw)));
            end = match.Index + match.Length;
        }
        _literals = literals;
        return literals;
    }

    private static string Unescape(string body)
    {
        if (!body.Contains('\\', StringComparison.Ordinal)) return body;
        var sb = new StringBuilder(body.Length);
        for (var i = 0; i < body.Length; i++)
        {
            var c = body[i];
            if (c != '\\' || i + 1 >= body.Length)
            {
                sb.Append(c);
                continue;
            }
            var n = body[++i];
            switch (n)
            {
                case 'n': sb.Append('\n'); break;
                case 't': sb.Append('\t'); break;
                case 'r': sb.Append('\r'); break;
                case 'b': sb.Append('\b'); break;
                case 'f': sb.Append('\f'); break;
                case 'v': sb.Append('\v'); break;
                case '0': sb.Append('\0'); break;
                case '\r' or '\n': break;
                case 'x' when i + 2 < body.Length && IsHex(body, i + 1, 2):
                    sb.Append((char)Convert.ToInt32(body.Substring(i + 1, 2), 16));
                    i += 2;
                    break;
                case 'u' when i + 1 < body.Length && body[i + 1] == '{':
                    var close = body.IndexOf('}', i + 2);
                    if (close > i + 2 && close - i - 2 <= 6 && IsHex(body, i + 2, close - i - 2) &&
                        Convert.ToInt32(body.Substring(i + 2, close - i - 2), 16) is var cp && cp <= 0x10FFFF &&
                        cp is < 0xD800 or > 0xDFFF)
                    {
                        sb.Append(char.ConvertFromUtf32(cp));
                        i = close;
                    }
                    else
                    {
                        sb.Append(n);
                    }
                    break;
                case 'u' when i + 4 < body.Length && IsHex(body, i + 1, 4):
                    sb.Append((char)Convert.ToInt32(body.Substring(i + 1, 4), 16));
                    i += 4;
                    break;
                default: sb.Append(n); break;
            }
        }
        return sb.ToString();
    }

    private static bool IsHex(string value, int start, int length)
    {
        for (var i = start; i < start + length; i++)
        {
            if (!Uri.IsHexDigit(value[i])) return false;
        }
        return true;
    }

    private void Obfuscation()
    {
        var failEvidence = new List<string>();
        var identifiers = ObfuscatedIdentifier.Matches(_text).Select(m => m.Value).Distinct(StringComparer.Ordinal).ToList();
        if (identifiers.Count > ObfuscatedIdentifierLimit)
        {
            failEvidence.Add($"{identifiers.Count} distinct _0x… identifiers (obfuscator output), e.g. " +
                string.Join(", ", identifiers.Take(5)));
        }
        var hexEscapes = HexEscape.Count(_text);
        if (hexEscapes > HexEscapeLimit) failEvidence.Add($"{hexEscapes} \\xNN escape sequences");
        foreach (Match match in FromCharCode.Matches(_text))
        {
            var arguments = match.Groups[1].Value.Count(c => c == ',') + 1;
            if (arguments > FromCharCodeArgumentLimit)
            {
                failEvidence.Add($"String.fromCharCode with {arguments} arguments at {Locate(match)}");
            }
        }
        Report("js-obfuscation", Severity.Fail, "The module is obfuscated, which defeats review of what it does.",
            failEvidence);

        var reviewEvidence = Decoders.SelectMany(p => p.Matches(_text)).OrderBy(m => m.Index).Select(Locate).ToList();
        // An opaque encoded blob is a long unbroken run of base64 characters inside a string
        // literal. Long CSS or template text is not: it is broken up by spaces and punctuation.
        foreach (var literal in StringLiterals.SelectMany(p => p.Matches(_text)))
        {
            if (literal.Length < EncodedBlobLength + 2) continue;
            var run = StringRules.LongestEncodedRun(literal.Value[1..^1]);
            if (run.Length < EncodedBlobLength) continue;
            var entropy = Text.Entropy(run);
            if (entropy > EncodedBlobEntropyBits)
            {
                var (line, column) = Position(literal.Index);
                reviewEvidence.Add($"{line}:{column}: {run.Length}-char encoded run in a string literal, entropy " +
                    $"{entropy:F2} bits/char: {StringRules.Redact(run)}");
            }
        }
        Report("js-obfuscation", Severity.Review, "Decodes or embeds opaque data (atob, unescape, long encoded strings).",
            reviewEvidence);
    }

    /// <summary>
    /// Returns the end of the leading licence/banner comment block (a block comment, or
    /// consecutive line comments, at the very start of the file), or 0 when there is none.
    /// </summary>
    private int BannerEnd()
    {
        var i = 0;
        while (true)
        {
            while (i < _text.Length && char.IsWhiteSpace(_text[i])) i++;
            if (string.CompareOrdinal(_text, i, "/*", 0, 2) == 0)
            {
                var close = _text.IndexOf("*/", i + 2, StringComparison.Ordinal);
                if (close < 0) return _text.Length;
                i = close + 2;
                continue;
            }
            if (string.CompareOrdinal(_text, i, "//", 0, 2) == 0)
            {
                var newline = _text.IndexOf('\n', i);
                if (newline < 0) return _text.Length;
                i = newline + 1;
                continue;
            }
            return i;
        }
    }

    private void PublicEndpoints()
    {
        var bannerEnd = BannerEnd();
        var homepageHost = _manifest.HomepageHost;
        var reviewed = new List<string>();
        var banner = new List<string>();
        var reference = new List<string>();
        foreach (Match match in StringRules.Url.Matches(_text))
        {
            foreach (var endpoint in StringRules.Endpoints(match.Value, includeBareIps: false))
            {
                if (!endpoint.IsPublic) continue;
                var item = $"{endpoint.Host} at {Locate(match)}";
                var trustedBannerHost = endpoint.Host == "github.com" ||
                    (homepageHost is not null && endpoint.Host == homepageHost);
                if (match.Index < bannerEnd && trustedBannerHost) banner.Add(item);
                else if (StringRules.IsReferenceHost(endpoint.Host)) reference.Add(item);
                else reviewed.Add(item);
            }
        }
        Report("js-public-endpoint", Severity.Review, "References public network endpoints.", reviewed);
        Report("js-public-endpoint", Severity.Info,
            "Licence/banner comment links to the feature homepage or GitHub.", banner);
        Report("js-public-endpoint", Severity.Info,
            "Standards/documentation URLs (XML namespaces, framework error links); listed, not a finding.", reference);
    }
}
