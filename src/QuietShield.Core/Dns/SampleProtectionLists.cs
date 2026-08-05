namespace QuietShield.Core.Dns;

public static class NonProductionSampleProtectionLists
{
    public const string Warning = "NON-PRODUCTION SAMPLE LIST — TEST AND SIMULATION ONLY";

    public static ProtectionListSnapshot Create(DateTimeOffset nowUtc)
    {
        var rules = new[]
        {
            new DnsPolicyRule("sample-ads", "ads.example.test", DnsRuleMatchKind.DomainAndSubdomains, DnsDecision.Block, DnsCategory.Ads, Warning, DnsRuleSourceKind.Category),
            new DnsPolicyRule("sample-tracker", "*.tracker.example.test", DnsRuleMatchKind.SafeWildcard, DnsDecision.Block, DnsCategory.Trackers, Warning, DnsRuleSourceKind.Category),
            new DnsPolicyRule("sample-malware", "malware.example.test", DnsRuleMatchKind.DomainAndSubdomains, DnsDecision.Block, DnsCategory.Malware, Warning, DnsRuleSourceKind.Threat),
            new DnsPolicyRule("sample-phishing", "phishing.example.test", DnsRuleMatchKind.Exact, DnsDecision.Block, DnsCategory.Phishing, Warning, DnsRuleSourceKind.Threat),
            new DnsPolicyRule("sample-adult", "adult.example.test", DnsRuleMatchKind.DomainAndSubdomains, DnsDecision.Block, DnsCategory.AdultContent, Warning, DnsRuleSourceKind.Category)
        };
        var metadata = new ProtectionListMetadata("quietshield-non-production-sample", "sample-1", nowUtc, nowUtc.AddDays(30), string.Empty, NonProductionSampleSignatureVerifier.SampleSignature);
        var unhashed = new ProtectionListSnapshot(metadata, rules);
        return new ProtectionListSnapshot(metadata with { Sha256 = ProtectionListHasher.ComputeSha256(unhashed) }, rules);
    }
}
