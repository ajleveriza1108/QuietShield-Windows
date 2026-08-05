using System.Globalization;

namespace QuietShield.Core.Dns;

public sealed record DomainNormalizationResult(bool IsValid, string? NormalizedValue, string? Error, DnsRuleMatchKind MatchKind);

public static class DomainNormalizer
{
    private static readonly IdnMapping Idn = new() { UseStd3AsciiRules = true };

    public static DomainNormalizationResult NormalizeDomain(string? value) => Normalize(value, false, DnsRuleMatchKind.Exact);

    public static DomainNormalizationResult NormalizeRule(string? value, DnsRuleMatchKind requestedMatchKind) =>
        Normalize(value, true, requestedMatchKind);

    public static bool IsMatch(string normalizedDomain, string normalizedPattern, DnsRuleMatchKind matchKind)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(normalizedDomain);
        ArgumentException.ThrowIfNullOrWhiteSpace(normalizedPattern);
        var basePattern = matchKind == DnsRuleMatchKind.SafeWildcard ? normalizedPattern[2..] : normalizedPattern;
        return matchKind switch
        {
            DnsRuleMatchKind.Exact => normalizedDomain.Equals(basePattern, StringComparison.Ordinal),
            DnsRuleMatchKind.DomainAndSubdomains => normalizedDomain.Equals(basePattern, StringComparison.Ordinal) ||
                                                     normalizedDomain.EndsWith('.' + basePattern, StringComparison.Ordinal),
            DnsRuleMatchKind.SafeWildcard => !normalizedDomain.Equals(basePattern, StringComparison.Ordinal) &&
                                             normalizedDomain.EndsWith('.' + basePattern, StringComparison.Ordinal),
            _ => false
        };
    }

    private static DomainNormalizationResult Normalize(string? value, bool isRule, DnsRuleMatchKind requestedMatchKind)
    {
        if (string.IsNullOrWhiteSpace(value)) return Invalid("A domain is required.", requestedMatchKind);
        if (!value.Equals(value.Trim(), StringComparison.Ordinal)) return Invalid("Leading or trailing whitespace is not allowed.", requestedMatchKind);
        var candidate = value;
        var hasWildcard = candidate.StartsWith("*.", StringComparison.Ordinal);
        if (candidate.Contains('*', StringComparison.Ordinal))
        {
            if (!isRule || !hasWildcard || candidate.Count(static character => character == '*') != 1 || requestedMatchKind != DnsRuleMatchKind.SafeWildcard)
            {
                return Invalid("Only a single leading '*.' wildcard is allowed for a safe wildcard rule.", requestedMatchKind);
            }

            candidate = candidate[2..];
        }
        else if (requestedMatchKind == DnsRuleMatchKind.SafeWildcard)
        {
            return Invalid("A safe wildcard rule must begin with '*.'.", requestedMatchKind);
        }

        if (candidate.EndsWith('.')) candidate = candidate[..^1];
        if (candidate.Length == 0 || candidate.EndsWith('.') || candidate.Contains("..", StringComparison.Ordinal))
        {
            return Invalid("The domain contains an empty label.", requestedMatchKind);
        }

        if (candidate.Any(static character => char.IsWhiteSpace(character)) ||
            candidate.Contains('/') || candidate.Contains('\\') || candidate.Contains(':') || candidate.Contains('@'))
        {
            return Invalid("The value is not a bare domain name.", requestedMatchKind);
        }

        try
        {
            var asciiLabels = candidate.Split('.').Select(static label => Idn.GetAscii(label).ToLowerInvariant()).ToArray();
            if (asciiLabels.Any(static label => label.Length is < 1 or > 63 || label.StartsWith('-') || label.EndsWith('-')))
            {
                return Invalid("A domain label is invalid.", requestedMatchKind);
            }

            var normalized = string.Join('.', asciiLabels);
            if (normalized.Length > 253) return Invalid("The normalized domain exceeds 253 characters.", requestedMatchKind);
            if (hasWildcard) normalized = "*." + normalized;
            return new DomainNormalizationResult(true, normalized, null, requestedMatchKind);
        }
        catch (ArgumentException)
        {
            return Invalid("The domain contains invalid IDN characters.", requestedMatchKind);
        }
    }

    private static DomainNormalizationResult Invalid(string error, DnsRuleMatchKind matchKind) => new(false, null, error, matchKind);
}
