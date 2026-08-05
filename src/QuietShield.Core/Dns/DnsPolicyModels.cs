namespace QuietShield.Core.Dns;

public enum DnsDecision
{
    Allow,
    Block,
    Indeterminate
}

public enum DnsCategory
{
    Ads,
    Trackers,
    Malware,
    Phishing,
    Scam,
    Cryptomining,
    AdultContent,
    Gambling,
    ViolenceOrChildSafety,
    Custom
}

public enum DnsProtectionMode
{
    Standard,
    High,
    Extreme,
    Custom
}

public enum DnsRuleMatchKind
{
    Exact,
    DomainAndSubdomains,
    SafeWildcard
}

public enum DnsRuleSourceKind
{
    RequiredSafetyExemption,
    CustomAllowlist,
    ParentProtectedBlock,
    CustomBlocklist,
    Threat,
    Category
}

public sealed record DnsPolicyRule(
    string Id,
    string DomainPattern,
    DnsRuleMatchKind MatchKind,
    DnsDecision Decision,
    DnsCategory Category,
    string SourceName,
    DnsRuleSourceKind SourceKind);

public sealed record DnsPolicyRequest(
    string Domain,
    DnsProtectionMode ProtectionMode,
    IReadOnlySet<DnsCategory> CustomEnabledCategories,
    ProtectionListSnapshot? ProtectionList,
    IReadOnlyList<CustomDomainEntry> CustomEntries,
    IReadOnlyList<string> RequiredSafetyExemptions,
    DateTimeOffset TimestampUtc);

public sealed record DnsPolicyResult(
    DnsDecision Decision,
    DnsCategory? Category,
    string? MatchedRule,
    IReadOnlyList<string> SourceList,
    string Reason,
    DateTimeOffset TimestampUtc,
    string? NormalizedDomain);

public static class DnsModeCategories
{
    private static readonly HashSet<DnsCategory> StandardCategories = new()
    {
        DnsCategory.Ads,
        DnsCategory.Trackers,
        DnsCategory.Malware,
        DnsCategory.Phishing,
        DnsCategory.Scam
    };

    private static readonly HashSet<DnsCategory> HighCategories = new(StandardCategories)
    {
        DnsCategory.Cryptomining,
        DnsCategory.Gambling
    };

    private static readonly HashSet<DnsCategory> ExtremeCategories = new(HighCategories)
    {
        DnsCategory.AdultContent,
        DnsCategory.ViolenceOrChildSafety
    };

    public static bool IsEnabled(DnsProtectionMode mode, DnsCategory category, IReadOnlySet<DnsCategory> customCategories) => mode switch
    {
        DnsProtectionMode.Standard => StandardCategories.Contains(category),
        DnsProtectionMode.High => HighCategories.Contains(category),
        DnsProtectionMode.Extreme => ExtremeCategories.Contains(category),
        DnsProtectionMode.Custom => customCategories.Contains(category),
        _ => false
    };
}
