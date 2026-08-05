namespace QuietShield.Core.Dns;

public sealed class DnsPolicyEngine
{
    public static DnsPolicyResult Evaluate(DnsPolicyRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var normalizedDomain = DomainNormalizer.NormalizeDomain(request.Domain);
        if (!normalizedDomain.IsValid || normalizedDomain.NormalizedValue is null)
        {
            return Result(DnsDecision.Indeterminate, null, null, Array.Empty<string>(), normalizedDomain.Error ?? "Domain validation failed.", request.TimestampUtc, null);
        }

        var domain = normalizedDomain.NormalizedValue;
        var matches = BuildMatches(request, domain);
        var selected = SelectByPrecedence(matches, request);
        if (selected is null)
        {
            return Result(DnsDecision.Allow, null, null, Array.Empty<string>(), "No active DNS policy rule matched; the safe default allows this simulation.", request.TimestampUtc, domain);
        }

        var sources = matches.Select(static match => match.Rule.SourceName).Distinct(StringComparer.Ordinal).OrderBy(static source => source, StringComparer.Ordinal).ToArray();
        return Result(
            selected.Rule.Decision,
            selected.Rule.Category,
            selected.Rule.DomainPattern,
            sources,
            CreateReason(selected.Rule),
            request.TimestampUtc,
            domain);
    }

    private static List<NormalizedRuleMatch> BuildMatches(DnsPolicyRequest request, string domain)
    {
        var rules = new List<DnsPolicyRule>();
        rules.AddRange(request.RequiredSafetyExemptions.Select((pattern, index) => new DnsPolicyRule(
            $"safety-{index}", pattern, DnsRuleMatchKind.DomainAndSubdomains, DnsDecision.Allow, DnsCategory.Custom,
            "Required QuietShield safety exemption", DnsRuleSourceKind.RequiredSafetyExemption)));
        rules.AddRange(request.CustomEntries.Select(static entry => entry.ToPolicyRule()));
        if (request.ProtectionList is not null) rules.AddRange(request.ProtectionList.Rules);

        var matches = new List<NormalizedRuleMatch>();
        foreach (var rule in rules)
        {
            var normalized = DomainNormalizer.NormalizeRule(rule.DomainPattern, rule.MatchKind);
            if (normalized.IsValid && normalized.NormalizedValue is not null && DomainNormalizer.IsMatch(domain, normalized.NormalizedValue, rule.MatchKind))
            {
                matches.Add(new NormalizedRuleMatch(rule with { DomainPattern = normalized.NormalizedValue }));
            }
        }

        return matches;
    }

    private static NormalizedRuleMatch? SelectByPrecedence(IReadOnlyList<NormalizedRuleMatch> matches, DnsPolicyRequest request)
    {
        foreach (var sourceKind in new[]
        {
            DnsRuleSourceKind.RequiredSafetyExemption,
            DnsRuleSourceKind.CustomAllowlist,
            DnsRuleSourceKind.ParentProtectedBlock,
            DnsRuleSourceKind.CustomBlocklist,
            DnsRuleSourceKind.Threat
        })
        {
            var match = matches.Where(item => item.Rule.SourceKind == sourceKind).OrderBy(static item => item.Rule.Id, StringComparer.Ordinal).FirstOrDefault();
            if (match is not null) return match;
        }

        return matches
            .Where(item => item.Rule.SourceKind == DnsRuleSourceKind.Category &&
                           DnsModeCategories.IsEnabled(request.ProtectionMode, item.Rule.Category, request.CustomEnabledCategories))
            .OrderBy(static item => item.Rule.Id, StringComparer.Ordinal)
            .FirstOrDefault();
    }

    private static string CreateReason(DnsPolicyRule rule) => rule.SourceKind switch
    {
        DnsRuleSourceKind.RequiredSafetyExemption => "A required QuietShield safety domain is exempt.",
        DnsRuleSourceKind.CustomAllowlist => "An explicit custom allowlist entry matched.",
        DnsRuleSourceKind.ParentProtectedBlock => "A parent-protected custom block entry matched.",
        DnsRuleSourceKind.CustomBlocklist => "An explicit custom blocklist entry matched.",
        DnsRuleSourceKind.Threat => "A threat or malware protection rule matched.",
        DnsRuleSourceKind.Category => $"The active protection mode blocks the {rule.Category} category.",
        _ => "A DNS policy rule matched."
    };

    private static DnsPolicyResult Result(DnsDecision decision, DnsCategory? category, string? matchedRule, IReadOnlyList<string> sources, string reason, DateTimeOffset timestamp, string? normalizedDomain) =>
        new(decision, category, matchedRule, sources, reason, timestamp, normalizedDomain);

    private sealed record NormalizedRuleMatch(DnsPolicyRule Rule);
}
