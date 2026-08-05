using QuietShield.Core.Dns;

namespace QuietShield.Core.Tests;

[TestClass]
public sealed class DnsListCacheAndCustomTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 6, 0, 0, 0, TimeSpan.Zero);

    [TestMethod]
    public async Task ValidHashAndSignatureActivateImmutableSnapshot()
    {
        var fixture = CreateActivationFixture();
        var result = await fixture.Activator.ActivateAsync(Signed("1", Rule("one", "example.test")), CancellationToken.None);
        Assert.IsTrue(result.Succeeded);
        Assert.AreEqual("1", fixture.Store.ActiveSnapshot?.Metadata.Version);
        Assert.ThrowsExactly<NotSupportedException>(() => ((IList<DnsPolicyRule>)fixture.Store.ActiveSnapshot!.Rules).Add(Rule("two", "two.test")));
    }

    [TestMethod]
    public async Task InvalidHashDoesNotReplaceActiveList()
    {
        var fixture = CreateActivationFixture();
        await fixture.Activator.ActivateAsync(Signed("1", Rule("one", "one.test")), CancellationToken.None);
        var invalid = Signed("2", Rule("two", "two.test"));
        invalid = new ProtectionListSnapshot(invalid.Metadata with { Sha256 = new string('0', 64) }, invalid.Rules);
        var result = await fixture.Activator.ActivateAsync(invalid, CancellationToken.None);
        Assert.IsFalse(result.Succeeded);
        Assert.AreEqual("1", fixture.Store.ActiveSnapshot?.Metadata.Version);
    }

    [TestMethod]
    public async Task InvalidSignatureDoesNotReplaceActiveList()
    {
        var fixture = CreateActivationFixture();
        var candidate = Signed("1", Rule("one", "one.test"));
        candidate = new ProtectionListSnapshot(candidate.Metadata with { Signature = "invalid" }, candidate.Rules);
        var result = await fixture.Activator.ActivateAsync(candidate, CancellationToken.None);
        Assert.IsFalse(result.Succeeded);
        Assert.IsNull(fixture.Store.ActiveSnapshot);
    }

    [TestMethod]
    public async Task DuplicateRulesAreRemovedAndConflictsReported()
    {
        var fixture = CreateActivationFixture();
        var block = Rule("block-a", "example.test");
        var duplicate = block with { Id = "block-b" };
        var allow = block with { Id = "allow", Decision = DnsDecision.Allow };
        var candidate = Signed("1", block, duplicate, allow);
        var result = await fixture.Activator.ActivateAsync(candidate, CancellationToken.None);
        Assert.IsTrue(result.Succeeded);
        Assert.AreEqual(1, result.DuplicateRulesRemoved);
        Assert.HasCount(1, result.Conflicts);
        Assert.HasCount(2, result.ActiveSnapshot!.Rules);
    }

    [TestMethod]
    public async Task ExplicitRollbackRestoresPreviousSnapshot()
    {
        var fixture = CreateActivationFixture();
        await fixture.Activator.ActivateAsync(Signed("1", Rule("one", "one.test")), CancellationToken.None);
        await fixture.Activator.ActivateAsync(Signed("2", Rule("two", "two.test")), CancellationToken.None);
        Assert.IsTrue(await fixture.Activator.RollbackAsync(CancellationToken.None));
        Assert.AreEqual("1", fixture.Store.ActiveSnapshot?.Metadata.Version);
        Assert.AreEqual("1", fixture.Store.LastKnownGoodSnapshot?.Metadata.Version);
    }

    [TestMethod]
    [TestCategory("Phase3Smoke")]
    public async Task FailedAtomicActivationRollsBackToLastKnownGood()
    {
        var store = new FailingStore(Signed("1", Rule("one", "one.test")));
        var activator = new ProtectionListActivator(new NonProductionSampleSignatureVerifier(), store, new MutableDnsClock(Now));
        var result = await activator.ActivateAsync(Signed("2", Rule("two", "two.test")), CancellationToken.None);
        Assert.IsFalse(result.Succeeded);
        Assert.IsTrue(result.RolledBack);
        Assert.AreEqual("1", store.ActiveSnapshot?.Metadata.Version);
    }

    [TestMethod]
    public async Task CacheEnforcesTtlAndEvictsOldestEntry()
    {
        var clock = new MutableDnsClock(Now);
        var cache = new InMemoryDnsDecisionCache(clock, 2);
        await cache.SetAsync(Key("one.test"), Result("one.test"), DnsCacheEntryKind.Positive, TimeSpan.FromMinutes(1), CancellationToken.None);
        await cache.SetAsync(Key("two.test"), Result("two.test"), DnsCacheEntryKind.Negative, TimeSpan.FromMinutes(2), CancellationToken.None);
        await cache.SetAsync(Key("three.test"), Result("three.test"), DnsCacheEntryKind.Positive, TimeSpan.FromMinutes(2), CancellationToken.None);
        Assert.IsNull(await cache.TryGetAsync(Key("one.test"), CancellationToken.None));
        Assert.AreEqual(2, cache.Count);
        clock.UtcNow = clock.UtcNow.AddMinutes(3);
        Assert.AreEqual(0, cache.Count);
    }

    [TestMethod]
    public async Task CacheSupportsCancellationAndManualClear()
    {
        var cache = new InMemoryDnsDecisionCache(new MutableDnsClock(Now), 2);
        await cache.SetAsync(Key("one.test"), Result("one.test"), DnsCacheEntryKind.Positive, TimeSpan.FromMinutes(1), CancellationToken.None);
        await cache.ClearAsync(CancellationToken.None);
        Assert.AreEqual(0, cache.Count);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAsync<OperationCanceledException>(() => cache.TryGetAsync(Key("one.test"), cancellation.Token));
    }

    [TestMethod]
    public async Task ConcurrentCacheAccessRemainsBounded()
    {
        var cache = new InMemoryDnsDecisionCache(new MutableDnsClock(Now), 20);
        await Task.WhenAll(Enumerable.Range(0, 200).Select(index => cache.SetAsync(
            Key($"{index}.example.test"), Result($"{index}.example.test"), DnsCacheEntryKind.Positive, TimeSpan.FromMinutes(1), CancellationToken.None)));
        Assert.IsLessThanOrEqualTo(20, cache.Count);
    }

    [TestMethod]
    public async Task CustomListSupportsAddEditSearchRemoveAndDuplicateDetection()
    {
        using var service = new InMemoryCustomDomainListService(new MutableDnsClock(Now));
        var added = await service.AddAsync(Draft("Example.TEST", "Initial"), CancellationToken.None);
        Assert.IsTrue(added.Succeeded);
        Assert.AreEqual("example.test", added.Entry?.DomainPattern);
        Assert.IsFalse((await service.AddAsync(Draft("example.test", null), CancellationToken.None)).Succeeded);
        var edited = await service.EditAsync(added.Entry!.Id, Draft("updated.test", "Updated", true), CancellationToken.None);
        Assert.IsTrue(edited.Succeeded);
        Assert.IsTrue(edited.Entry!.ParentProtected);
        Assert.HasCount(1, await service.SearchAsync("Updated", CancellationToken.None));
        Assert.IsTrue((await service.RemoveAsync(added.Entry.Id, CancellationToken.None)).Succeeded);
        Assert.HasCount(0, await service.GetAllAsync(CancellationToken.None));
    }

    [TestMethod]
    public async Task CustomListImportExportIsAtomicAndPrivacyBounded()
    {
        using var source = new InMemoryCustomDomainListService(new MutableDnsClock(Now));
        await source.AddAsync(Draft("example.test", "User-created note", true), CancellationToken.None);
        var json = await source.ExportJsonAsync(CancellationToken.None);
        StringAssert.Contains(json, "schemaVersion");
        Assert.DoesNotContain("commandLine", json, StringComparison.OrdinalIgnoreCase);
        using var destination = new InMemoryCustomDomainListService(new MutableDnsClock(Now));
        Assert.IsTrue((await destination.ImportJsonAsync(json, CancellationToken.None)).Succeeded);
        var imported = await destination.GetAllAsync(CancellationToken.None);
        Assert.HasCount(1, imported);
        Assert.IsTrue(imported[0].ParentProtected);
        var before = await destination.ExportJsonAsync(CancellationToken.None);
        Assert.IsFalse((await destination.ImportJsonAsync("{invalid", CancellationToken.None)).Succeeded);
        Assert.AreEqual(before, await destination.ExportJsonAsync(CancellationToken.None));
    }

    [TestMethod]
    public void DiagnosticLoggingRedactsDomainUnlessExplicitlyEnabled()
    {
        var result = Result("private.example.test");
        Assert.DoesNotContain("private.example.test", DnsDiagnosticRedactor.FormatDecision(result, false), StringComparison.Ordinal);
        StringAssert.Contains(DnsDiagnosticRedactor.FormatDecision(result, true), "private.example.test");
    }

    [TestMethod]
    public void ConcurrentPolicyDecisionsAreDeterministic()
    {
        var list = NonProductionSampleProtectionLists.Create(Now);
        var request = new DnsPolicyRequest("malware.example.test", DnsProtectionMode.Standard, new HashSet<DnsCategory>(), list, Array.Empty<CustomDomainEntry>(), Array.Empty<string>(), Now);
        var decisions = ParallelEnumerable.Range(0, 500).Select(_ => DnsPolicyEngine.Evaluate(request).Decision).ToArray();
        Assert.IsTrue(decisions.All(static decision => decision == DnsDecision.Block));
    }

    private static ActivationFixture CreateActivationFixture()
    {
        var store = new InMemoryProtectionListStore();
        return new ActivationFixture(store, new ProtectionListActivator(new NonProductionSampleSignatureVerifier(), store, new MutableDnsClock(Now)));
    }

    private static ProtectionListSnapshot Signed(string version, params DnsPolicyRule[] rules)
    {
        var metadata = new ProtectionListMetadata("fixture", version, Now, Now.AddDays(1), string.Empty, NonProductionSampleSignatureVerifier.SampleSignature);
        var unhashed = new ProtectionListSnapshot(metadata, rules);
        return new ProtectionListSnapshot(metadata with { Sha256 = ProtectionListHasher.ComputeSha256(unhashed) }, rules);
    }

    private static DnsPolicyRule Rule(string id, string pattern) =>
        new(id, pattern, DnsRuleMatchKind.DomainAndSubdomains, DnsDecision.Block, DnsCategory.Ads, "Fixture", DnsRuleSourceKind.Category);

    private static DnsDecisionCacheKey Key(string domain) => new(domain, DnsProtectionMode.Standard);
    private static DnsPolicyResult Result(string domain) => new(DnsDecision.Allow, null, null, Array.Empty<string>(), "Fixture", Now, domain);
    private static CustomDomainEntryDraft Draft(string domain, string? notes, bool parent = false) =>
        new(domain, DnsRuleMatchKind.DomainAndSubdomains, CustomDomainListKind.Blocklist, notes, parent);

    private sealed record ActivationFixture(InMemoryProtectionListStore Store, ProtectionListActivator Activator);

    private sealed class MutableDnsClock(DateTimeOffset utcNow) : IDnsClock
    {
        public DateTimeOffset UtcNow { get; set; } = utcNow;
    }

    private sealed class FailingStore : IProtectionListStore
    {
        private readonly ProtectionListSnapshot _original;
        public FailingStore(ProtectionListSnapshot original) { _original = original; ActiveSnapshot = original; LastKnownGoodSnapshot = original; }
        public ProtectionListSnapshot? ActiveSnapshot { get; private set; }
        public ProtectionListSnapshot? LastKnownGoodSnapshot { get; private set; }
        public Task ActivateAsync(ProtectionListSnapshot snapshot, CancellationToken cancellationToken)
        {
            ActiveSnapshot = snapshot;
            throw new IOException("Atomic fixture failure.");
        }
        public Task<bool> RollbackAsync(CancellationToken cancellationToken)
        {
            ActiveSnapshot = _original;
            LastKnownGoodSnapshot = _original;
            return Task.FromResult(true);
        }
    }
}
