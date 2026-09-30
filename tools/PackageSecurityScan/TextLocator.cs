// SPDX-License-Identifier: GPL-2.0-or-later
namespace PackageSecurityScan;

/// <summary>
/// Maps character offsets in a scanned text file to line:column and a short excerpt. The line
/// index is built once and searched by bisection, so locating N matches costs O(N log lines)
/// rather than rescanning the file for every match.
/// </summary>
internal sealed class TextLocator
{
    private const int ExcerptBefore = 40;
    private const int ExcerptLength = 120;
    private readonly string _text;
    private readonly int[] _lineStarts;

    public TextLocator(string text)
    {
        _text = text;
        var starts = new List<int> { 0 };
        for (var i = 0; i < text.Length; i++)
        {
            if (text[i] == '\n') starts.Add(i + 1);
        }
        _lineStarts = [.. starts];
    }

    public (int Line, int Column) Position(int index)
    {
        var line = Array.BinarySearch(_lineStarts, index);
        if (line < 0) line = ~line - 1;
        return (line + 1, index - _lineStarts[line] + 1);
    }

    /// <summary>"line:column: excerpt", with control characters escaped.</summary>
    public string Locate(int index)
    {
        var (line, column) = Position(index);
        var start = Math.Max(0, index - ExcerptBefore);
        var length = Math.Min(ExcerptLength, _text.Length - start);
        var excerpt = _text.Substring(start, length).Replace('\r', ' ').Replace('\n', ' ').Replace('\t', ' ');
        return $"{line}:{column}: {Text.Clean(excerpt, ExcerptLength)}";
    }
}
