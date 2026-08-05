using System.Net.NetworkInformation;
using QuietShield.Windows.Diagnostics;
using QuietShield.Windows.Discovery;
using QuietShield.Windows.Discovery.Applications;
using QuietShield.Windows.Integration;
using System.Security.Principal;

namespace QuietShield.Windows.Tests;

[TestClass]
public sealed class Phase2DiscoveryTests
{
    [TestMethod]
    public void Win32EntriesWithSameExecutableAreDeduplicatedAndSourcesAreMerged()
    {
        var executable = Path.Combine(AppContext.BaseDirectory, "fixture.exe");
        var first = Application("one", "Fixture", executable, InstalledApplicationType.Win32, "HKLM-64", false);
        var second = Application("two", "Fixture", executable, InstalledApplicationType.Win32, "HKCU-64", false);
        var result = ApplicationInventoryDeduplicator.Deduplicate(new[] { first, second });
        Assert.HasCount(1, result);
        Assert.HasCount(2, result[0].DiscoverySources);
    }

    [TestMethod]
    public async Task StorePackageIdentityIsReadWithoutInstallCommands()
    {
        const string json = "{\"PackageFamilyName\":\"Fixture_123\",\"PackageFullName\":\"Fixture_1.2.3_x64_123\",\"DisplayName\":\"Fixture\",\"Publisher\":\"CN=Fixture\",\"Version\":\"1.2.3.0\",\"InstallLocation\":\"C:\\\\Program Files\\\\WindowsApps\\\\Fixture\",\"IsFramework\":false,\"IsResourcePackage\":false,\"IsNonRemovable\":false}";
        var source = new PowerShellStorePackageSource(new FakePowerShellRunner(json));
        var packages = await source.ReadAsync(CancellationToken.None);
        Assert.HasCount(1, packages);
        Assert.AreEqual("Fixture_123", packages[0].PackageFamilyName);
    }

    [TestMethod]
    public void MissingExecutableIsPreservedAsUnavailable()
    {
        var result = ApplicationInventoryDeduplicator.Deduplicate(new[]
        {
            Application("missing", "Missing Fixture", @"Z:\does-not-exist\fixture.exe", InstalledApplicationType.Win32, "HKLM-64", false)
        });
        Assert.IsFalse(result[0].ExecutableExists);
        Assert.AreEqual(InstalledApplicationType.Win32, result[0].ApplicationType);
    }

    [TestMethod]
    public void WindowsDirectoryExecutableIsClassifiedAsSystemComponent()
    {
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "notepad.exe");
        Assert.IsTrue(ApplicationInventoryService.IsWindowsSystemPath(path));
        Assert.IsFalse(ApplicationInventoryService.IsWindowsSystemPath("::invalid::"));
    }

    [TestMethod]
    public void NetworkTypeCostAndCategoryMappingsAreDeterministic()
    {
        Assert.AreEqual(DetectedNetworkKind.WiFi, NetworkClassification.MapKind(NetworkInterfaceType.Wireless80211, "Fixture", "Fixture"));
        Assert.AreEqual(DetectedNetworkKind.VpnOrVirtual, NetworkClassification.MapKind(NetworkInterfaceType.Ethernet, "Fixture VPN", "Fixture"));
        Assert.AreEqual(ConnectionCostKind.Metered, NetworkClassification.MapCost("Variable"));
        Assert.AreEqual(ConnectionCostKind.Unmetered, NetworkClassification.MapCost("Unrestricted"));
        Assert.AreEqual(ConnectionCostKind.Unknown, NetworkClassification.MapCost("FutureValue"));
        Assert.AreEqual(NetworkCategoryKind.DomainAuthenticated, NetworkClassification.MapCategory("DomainAuthenticated"));
    }

    [TestMethod]
    public void DnsAndFirewallResultModelsPreserveReadOnlyFacts()
    {
        var dns = new DnsConfigurationSnapshot(
            new[] { new DnsAdapterConfiguration("fixture", "Fixture", DnsConfigurationMode.Automatic, new[] { new DnsServerInfo(DnsAddressFamilyKind.Ipv4, "192.0.2.1") }) },
            EncryptedDnsCapabilityKind.Available, "Not active", DateTimeOffset.UtcNow);
        var firewall = new FirewallStateSnapshot(true,
            new[] { new FirewallProfileState(FirewallProfileKind.Public, true) }, 0, DateTimeOffset.UtcNow);
        Assert.AreEqual(DnsConfigurationMode.Automatic, dns.Adapters[0].Mode);
        Assert.AreEqual("Not active", dns.QuietShieldProtectionState);
        Assert.AreEqual(0, firewall.QuietShieldOwnedRuleCount);
        Assert.IsTrue(firewall.Profiles[0].Enabled);
        Assert.AreEqual(DnsConfigurationMode.Mixed, ReadOnlyDnsConfigurationDiscovery.DetermineMode(true, true));
    }

    [TestMethod]
    public async Task WfpCapabilityCheckIsReadOnlyAndReturnsAnExplicitResult()
    {
        var result = await new ReadOnlyFilteringPlatformCapabilityDiscovery().DiscoverAsync(CancellationToken.None);
        Assert.IsTrue(result.IsSuccess);
        Assert.IsNotNull(result.Value);
        Assert.IsTrue(result.Value.FutureChangesRequireElevation);
        StringAssert.Contains(result.Value.Status, "no WFP object was created", StringComparison.OrdinalIgnoreCase);
    }

    [TestMethod]
    public async Task InventoryDiscoveryHonorsCancellation()
    {
        var service = new ApplicationInventoryService(
            new CancellingUninstallSource(), new EmptyStoreSource(), new EmptyStartMenuSource(), new MemoryCache());
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAsync<OperationCanceledException>(() => service.DiscoverAsync(true, null, cancellation.Token));
    }

    [TestMethod]
    public async Task ApplicationCacheExpiresAtConfiguredAge()
    {
        var directory = Path.Combine(AppContext.BaseDirectory, "cache-fixture-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "applications.json");
        var clock = new MutableClock(new DateTimeOffset(2026, 8, 5, 0, 0, 0, TimeSpan.Zero));
        var cache = new JsonApplicationInventoryCache(path, clock);
        try
        {
            await cache.WriteAsync(new[] { Application("fixture", "Fixture", null, InstalledApplicationType.Unknown, "Fixture", false) }, CancellationToken.None);
            Assert.IsNotNull(await cache.TryReadAsync(TimeSpan.FromMinutes(15), CancellationToken.None));
            clock.UtcNow = clock.UtcNow.AddMinutes(16);
            Assert.IsNull(await cache.TryReadAsync(TimeSpan.FromMinutes(15), CancellationToken.None));
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, true);
        }
    }

    [TestMethod]
    public void DiagnosticRedactionRemovesPrivateIdentifiers()
    {
        var input = $@"C:\Users\{Environment.UserName}\secret 192.0.2.44 2001:db8::10 AA-BB-CC-DD-EE-FF token=abcd";
        var output = PrivacySafeDiagnosticExporter.Redact(input);
        Assert.DoesNotContain(Environment.UserName, output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("192.0.2.44", output, StringComparison.Ordinal);
        Assert.DoesNotContain("2001:db8::10", output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("AA-BB-CC-DD-EE-FF", output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("abcd", output, StringComparison.Ordinal);
    }

    [TestMethod]
    public void DiagnosticSummaryContainsCountsButNoAddressesOrAdapterNames()
    {
        var bundle = new ReadOnlyDiscoveryBundle(
            new[] { Application("fixture", "Private App Name", null, InstalledApplicationType.Win32, "Fixture", false) },
            new NetworkEnvironmentSnapshot(DetectedNetworkKind.Ethernet, ConnectionCostKind.Unmetered, NetworkCategoryKind.Private, true,
                new[] { new NetworkAdapterInfo("secret-id", 1, "Private Adapter Name", "Private Description", DetectedNetworkKind.Ethernet, true, true, true, true, false, ConnectionCostKind.Unmetered, NetworkCategoryKind.Private) },
                "Private summary", DateTimeOffset.UtcNow),
            null, null, null, null, null, Array.Empty<DiscoveryActivity>(), DateTimeOffset.UtcNow, 0, false);
        var summary = new PrivacySafeDiagnosticExporter().CreateSummary(bundle);
        Assert.AreEqual(1, summary.AdapterTypes["Ethernet"]);
        Assert.AreEqual(1, summary.ApplicationTypes["Win32"]);
        var serialized = System.Text.Json.JsonSerializer.Serialize(summary);
        Assert.DoesNotContain("Private Adapter Name", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("Private App Name", serialized, StringComparison.Ordinal);
    }

    [TestMethod]
    [TestCategory("Phase2Smoke")]
    public async Task LiveReadOnlyDiscoveryAndDiagnosticExportSmoke()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        Assert.IsFalse(principal.IsInRole(WindowsBuiltInRole.Administrator), "Phase 2 smoke discovery must run non-elevated.");
        var directory = Path.Combine(AppContext.BaseDirectory, "live-smoke-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var runner = new PowerShellJsonRunner();
            var inventory = new ApplicationInventoryService(
                new RegistryUninstallRegistrationSource(),
                new PowerShellStorePackageSource(runner),
                new StartMenuEntrySource(),
                new JsonApplicationInventoryCache(Path.Combine(directory, "applications.json"), new SystemDiscoveryClock()));
            var coordinator = new ReadOnlyDiscoveryCoordinator(
                inventory,
                new ReadOnlyNetworkEnvironmentDiscovery(runner),
                new ReadOnlyDnsConfigurationDiscovery(runner),
                new ReadOnlyFirewallStateDiscovery(runner),
                new ReadOnlyFilteringPlatformCapabilityDiscovery(),
                new ReadOnlyWindowsServiceStateDiscovery(runner),
                new ReadOnlyPowerStateDiscovery());
            var bundle = await coordinator.RefreshAsync(true, null, CancellationToken.None);
            Assert.IsGreaterThan(0, bundle.Applications.Count);
            Assert.IsNotNull(bundle.Network, string.Join(" | ", bundle.Activity.Select(static item => $"{item.Stage}: {item.Message}")));
            Assert.IsNotNull(bundle.Dns);
            Assert.IsNotNull(bundle.Firewall);
            Assert.IsNotNull(bundle.FilteringPlatform);
            Assert.IsNotNull(bundle.Services);
            Assert.IsNotNull(bundle.Power);
            Assert.AreEqual(0, bundle.Firewall.QuietShieldOwnedRuleCount);
            var exportPath = Path.Combine(directory, "diagnostic.json");
            await new PrivacySafeDiagnosticExporter().ExportAsync(bundle, exportPath, CancellationToken.None);
            var exported = await File.ReadAllTextAsync(exportPath);
            Assert.IsFalse(string.IsNullOrWhiteSpace(exported));
            Assert.DoesNotContain(Environment.UserName, exported, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("ServerAddresses", exported, StringComparison.Ordinal);
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, true);
        }
    }

    private static InstalledApplicationInfo Application(string id, string name, string? executable, InstalledApplicationType type, string source, bool system) =>
        new(id, name, "Fixture Publisher", "1.0", executable is null ? null : Path.GetDirectoryName(executable), executable, type,
            executable is null ? null : new ApplicationIconReference(executable, 0), executable is not null && File.Exists(executable), system, new[] { source });

    private sealed class FakePowerShellRunner(string output) : IPowerShellJsonRunner
    {
        public Task<PowerShellJsonResult> RunAsync(string script, CancellationToken cancellationToken) =>
            Task.FromResult(new PowerShellJsonResult(0, output, string.Empty));
    }

    private sealed class CancellingUninstallSource : IUninstallRegistrationSource
    {
        public Task<IReadOnlyList<UninstallRegistration>> ReadAsync(CancellationToken cancellationToken) =>
            Task.FromCanceled<IReadOnlyList<UninstallRegistration>>(cancellationToken);
    }

    private sealed class EmptyStoreSource : IStorePackageSource
    {
        public Task<IReadOnlyList<StoreApplicationIdentity>> ReadAsync(CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<StoreApplicationIdentity>>(Array.Empty<StoreApplicationIdentity>());
    }

    private sealed class EmptyStartMenuSource : IStartMenuEntrySource
    {
        public Task<IReadOnlyList<StartMenuEntry>> ReadAsync(CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<StartMenuEntry>>(Array.Empty<StartMenuEntry>());
    }

    private sealed class MemoryCache : IApplicationInventoryCache
    {
        public Task<IReadOnlyList<InstalledApplicationInfo>?> TryReadAsync(TimeSpan maximumAge, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<InstalledApplicationInfo>?>(null);
        public Task WriteAsync(IReadOnlyList<InstalledApplicationInfo> applications, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task ClearAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class MutableClock(DateTimeOffset utcNow) : IDiscoveryClock
    {
        public DateTimeOffset UtcNow { get; set; } = utcNow;
    }
}
