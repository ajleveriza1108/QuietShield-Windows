using QuietShield.Core.Dns;

namespace QuietShield.Core.Tests;

[TestClass]
public sealed class DnsPolicyEngineTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 6, 0, 0, 0, TimeSpan.Zero);
    private static readonly string[] SafetyExemptions = { "example.test" };

    [TestMethod]
    public void NormalizationLowercasesAndRemovesTrailingDot()
    {
        var result = DomainNormalizer.NormalizeDomain("Example.COM.");
        Assert.IsTrue(result.IsValid);
        Assert.AreEqual("example.com", result.NormalizedValue);
    }

    [TestMethod]
    public void InternationalDomainIsNormalizedToPunycode()
    {
        var result = DomainNormalizer.NormalizeDomain("bücher.example");
        Assert.IsTrue(result.IsValid);
        Assert.AreEqual("xn--bcher-kva.example", result.NormalizedValue);
    }

    [TestMethod]
    [DataRow("")]
    [DataRow(" example.com")]
    [DataRow("https://example.com")]
    [DataRow("example..com")]
    [DataRow("-example.com")]
    [DataRow("example.com:53")]
    [DataRow("user@example.com")]
    public void InvalidDomainIsRejected(string value) => Assert.IsFalse(DomainNormalizer.NormalizeDomain(value).IsValid);

    [TestMethod]
    [DataRow("*example.com")]
    [DataRow("foo.*.example.com")]
    [DataRow("**.example.com")]
    [DataRow("*.example.com.*")]
    public void MalformedWildcardIsRejected(string value) =>
        Assert.IsFalse(DomainNormalizer.NormalizeRule(value, DnsRuleMatchKind.SafeWildcard).IsValid);

    [TestMethod]
    public void ExactSubdomainAndWildcardMatchingAreDistinct()
    {
        Assert.IsTrue(DomainNormalizer.IsMatch("example.com", "example.com", DnsRuleMatchKind.Exact));
        Assert.IsFalse(DomainNormalizer.IsMatch("www.example.com", "example.com", DnsRuleMatchKind.Exact));
        Assert.IsTrue(DomainNormalizer.IsMatch("www.example.com", "example.com", DnsRuleMatchKind.DomainAndSubdomains));
        Assert.IsTrue(DomainNormalizer.IsMatch("www.example.com", "*.example.com", DnsRuleMatchKind.SafeWildcard));
        Assert.IsFalse(DomainNormalizer.IsMatch("example.com", "*.example.com", DnsRuleMatchKind.SafeWildcard));
        Assert.IsFalse(DomainNormalizer.IsMatch("notexample.com", "*.example.com", DnsRuleMatchKind.SafeWildcard));
    }

    [TestMethod]
    public void RequiredSafetyExemptionOutranksParentProtectedBlock()
    {
        var result = Evaluate(new[] { Custom("example.test", CustomDomainListKind.Blocklist, true) }, SafetyExemptions);
        Assert.AreEqual(DnsDecision.Allow, result.Decision);
        StringAssert.Contains(result.Reason, "safety domain");
    }

    [TestMethod]
    public void ExplicitAllowlistOutranksParentProtectedBlock()
    {
        var result = Evaluate(
            Custom("example.test", CustomDomainListKind.Allowlist),
            Custom("example.test", CustomDomainListKind.Blocklist, true));
        Assert.AreEqual(DnsDecision.Allow, result.Decision);
        StringAssert.Contains(result.Reason, "allowlist");
    }

    [TestMethod]
    public void ParentProtectedBlockOutranksRegularBlockAndThreat()
    {
        var result = EvaluateWithRules(
            new[] { Threat("example.test") },
            Custom("example.test", CustomDomainListKind.Blocklist),
            Custom("example.test", CustomDomainListKind.Blocklist, true));
        Assert.AreEqual(DnsDecision.Block, result.Decision);
        StringAssert.Contains(result.Reason, "parent-protected");
    }

    [TestMethod]
    public void ExplicitBlocklistOutranksThreatRule()
    {
        var result = EvaluateWithRules(new[] { Threat("example.test") }, Custom("example.test", CustomDomainListKind.Blocklist));
        StringAssert.Contains(result.Reason, "explicit custom blocklist");
    }

    [TestMethod]
    public void ThreatRuleOutranksModeCategoryRule()
    {
        var result = EvaluateWithRules(new[] { Threat("example.test"), Category("example.test", DnsCategory.Ads) });
        Assert.AreEqual(DnsCategory.Malware, result.Category);
        StringAssert.Contains(result.Reason, "threat or malware");
    }

    [TestMethod]
    public void ActiveModeCategoryRuleOutranksSafeDefault()
    {
        var result = EvaluateWithRules(new[] { Category("example.test", DnsCategory.Ads) });
        Assert.AreEqual(DnsDecision.Block, result.Decision);
        Assert.AreEqual(DnsCategory.Ads, result.Category);
    }

    [TestMethod]
    public void SafeDefaultAllowsValidUnmatchedDomain()
    {
        var result = Evaluate();
        Assert.AreEqual(DnsDecision.Allow, result.Decision);
        Assert.IsNull(result.MatchedRule);
        StringAssert.Contains(result.Reason, "safe default");
    }

    [TestMethod]
    public void InvalidDomainIsIndeterminate()
    {
        var result = DnsPolicyEngine.Evaluate(Request("https://example.test"));
        Assert.AreEqual(DnsDecision.Indeterminate, result.Decision);
        Assert.IsNull(result.NormalizedDomain);
    }

    [TestMethod]
    public void ProtectionModesEnableDocumentedCategorySets()
    {
        var gambling = Snapshot(Category("example.test", DnsCategory.Gambling));
        Assert.AreEqual(DnsDecision.Allow, DnsPolicyEngine.Evaluate(Request("example.test", DnsProtectionMode.Standard, gambling)).Decision);
        Assert.AreEqual(DnsDecision.Block, DnsPolicyEngine.Evaluate(Request("example.test", DnsProtectionMode.High, gambling)).Decision);
        var adult = Snapshot(Category("example.test", DnsCategory.AdultContent));
        Assert.AreEqual(DnsDecision.Allow, DnsPolicyEngine.Evaluate(Request("example.test", DnsProtectionMode.High, adult)).Decision);
        Assert.AreEqual(DnsDecision.Block, DnsPolicyEngine.Evaluate(Request("example.test", DnsProtectionMode.Extreme, adult)).Decision);
        Assert.AreEqual(DnsDecision.Block, DnsPolicyEngine.Evaluate(Request("example.test", DnsProtectionMode.Custom, adult, new HashSet<DnsCategory> { DnsCategory.AdultContent })).Decision);
    }

    [TestMethod]
    [TestCategory("Phase3Smoke")]
    public void NonProductionSampleListBlocksSampleMalwareOnlyInSimulation()
    {
        var list = NonProductionSampleProtectionLists.Create(Now);
        var result = DnsPolicyEngine.Evaluate(Request("sub.malware.example.test", DnsProtectionMode.Standard, list));
        Assert.AreEqual(DnsDecision.Block, result.Decision);
        Assert.AreEqual(DnsCategory.Malware, result.Category);
        CollectionAssert.Contains(result.SourceList.ToArray(), NonProductionSampleProtectionLists.Warning);
    }

    private static DnsPolicyResult Evaluate(params CustomDomainEntry[] custom) => Evaluate(custom, Array.Empty<string>());

    private static DnsPolicyResult Evaluate(IReadOnlyList<CustomDomainEntry> custom, IReadOnlyList<string> safety) =>
        DnsPolicyEngine.Evaluate(Request("example.test") with { CustomEntries = custom, RequiredSafetyExemptions = safety });

    private static DnsPolicyResult EvaluateWithRules(IReadOnlyList<DnsPolicyRule> rules, params CustomDomainEntry[] custom) =>
        DnsPolicyEngine.Evaluate(Request("example.test", DnsProtectionMode.Standard, Snapshot(rules.ToArray())) with { CustomEntries = custom });

    private static DnsPolicyRequest Request(string domain, DnsProtectionMode mode = DnsProtectionMode.Standard, ProtectionListSnapshot? list = null, IReadOnlySet<DnsCategory>? customCategories = null) =>
        new(domain, mode, customCategories ?? new HashSet<DnsCategory>(), list, Array.Empty<CustomDomainEntry>(), Array.Empty<string>(), Now);

    private static CustomDomainEntry Custom(string pattern, CustomDomainListKind kind, bool parent = false) =>
        new(Guid.NewGuid(), pattern, DnsRuleMatchKind.DomainAndSubdomains, kind, null, Now, parent);

    private static DnsPolicyRule Threat(string pattern) =>
        new("threat", pattern, DnsRuleMatchKind.DomainAndSubdomains, DnsDecision.Block, DnsCategory.Malware, "Threat fixture", DnsRuleSourceKind.Threat);

    private static DnsPolicyRule Category(string pattern, DnsCategory category) =>
        new("category-" + category, pattern, DnsRuleMatchKind.DomainAndSubdomains, DnsDecision.Block, category, "Category fixture", DnsRuleSourceKind.Category);

    private static ProtectionListSnapshot Snapshot(params DnsPolicyRule[] rules) =>
        new(new ProtectionListMetadata("fixture", "1", Now, Now.AddDays(1), "not-activated", "fixture"), rules);
}
