using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using QuietShield.Core.Protection;
using QuietShield.Core.ServiceFoundation;
using QuietShield.Service;

namespace QuietShield.Windows.Tests;

[TestClass]
public sealed class Phase12ProductionServiceConfigurationTests
{
    [TestMethod]
    public void ProductionConfigurationValidatesIdentityRootsFilesAndHash()
    {
        using var fixture = new ProductionFixture();
        Assert.IsEmpty(fixture.Configuration.Validate());
        Assert.IsNotEmpty((fixture.Configuration with { Purpose = QuietShieldServiceIdentity.RehearsalPurpose }).Validate());
        Assert.IsNotEmpty((fixture.Configuration with { ApprovedProgramRoots = [fixture.AppRoot, fixture.AppRoot] }).Validate());
        Assert.IsNotEmpty((fixture.Configuration with { PayloadSha256 = new string('A', 64) }).Validate());
    }

    [TestMethod]
    public void ProductionOptionsRequireOneValidatedConfigurationAndUseProductionPipe()
    {
        using var fixture = new ProductionFixture();
        var path = Path.Combine(fixture.Root, "production-config.json");
        File.WriteAllText(path, JsonSerializer.Serialize(fixture.Configuration, ServiceMessageSerializer.Options));
        var options = DiagnosticServiceOptions.Parse(["--service", "--production-config", path, "--state-root", fixture.StateRoot]);
        Assert.IsNull(options.ActivationConfiguration);
        Assert.IsNotNull(options.ProductionConfiguration);
        Assert.AreEqual(QuietShieldServiceProtocol.ProductionPipeName, options.PipeName);
        Assert.AreEqual(fixture.Configuration.InstallationId, options.AuthorizationContext?.AuthorizationId);
        Assert.Throws<ArgumentException>(() => DiagnosticServiceOptions.Parse(["--service", "--production-config", path, "--activation-config", path]));
    }

    [TestMethod]
    public async Task ProductionCoordinatorAcceptsExactInstalledTargetAndRecordsProductionPurpose()
    {
        using var fixture = new ProductionFixture();
        await fixture.Runtime.StartAsync(CancellationToken.None);
        var blocked = await fixture.Coordinator.ChangeAsync(fixture.Request(ProgramConnectionPolicy.Blocked), CancellationToken.None);
        Assert.IsTrue(blocked.ExactRulePresent);
        var transaction = await fixture.Store.ReadValidatedAsync(blocked.TransactionId, CancellationToken.None);
        Assert.AreEqual(QuietShieldServiceIdentity.ProductionPurpose, transaction.Purpose);
        Assert.AreEqual(fixture.Configuration.InstallationId, transaction.ApprovedRehearsalId);
        var allowed = await fixture.Coordinator.ChangeAsync(fixture.Request(ProgramConnectionPolicy.AllowedOnAll), CancellationToken.None);
        Assert.IsFalse(allowed.ExactRulePresent);
        Assert.IsEmpty(fixture.Backend.Rules);
    }

    [TestMethod]
    public async Task ProductionCoordinatorRefusesOutsideChangedQuietShieldAndNetworkSpecificTargets()
    {
        using var fixture = new ProductionFixture();
        await fixture.Runtime.StartAsync(CancellationToken.None);
        var outside = Path.Combine(fixture.Root, "Outside.exe");
        File.WriteAllBytes(outside, [4, 5, 6]);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => fixture.Coordinator.ChangeAsync(fixture.Request(ProgramConnectionPolicy.Blocked, outside), CancellationToken.None));
        var quietShield = Path.Combine(fixture.AppRoot, "QuietShield.Foreign.exe");
        File.WriteAllBytes(quietShield, [7, 8, 9]);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => fixture.Coordinator.ChangeAsync(fixture.Request(ProgramConnectionPolicy.Blocked, quietShield), CancellationToken.None));
        var changed = fixture.Request(ProgramConnectionPolicy.Blocked) with { ExecutableSha256 = new string('A', 64) };
        await Assert.ThrowsAsync<InvalidDataException>(() => fixture.Coordinator.ChangeAsync(changed, CancellationToken.None));
        await Assert.ThrowsAsync<NotSupportedException>(() => fixture.Coordinator.ChangeAsync(fixture.Request(ProgramConnectionPolicy.WiFiOnly), CancellationToken.None));
        Assert.IsEmpty(fixture.Backend.Rules);
    }

    private sealed class ProductionFixture : IDisposable
    {
        public ProductionFixture()
        {
            Root = Path.Combine(Path.GetTempPath(), "QuietShield-Phase12-" + Guid.NewGuid().ToString("N"));
            AppRoot = Path.Combine(Root, "ApprovedPrograms");
            StateRoot = Path.Combine(Root, "State");
            Directory.CreateDirectory(AppRoot);
            Directory.CreateDirectory(StateRoot);
            ExecutablePath = Path.Combine(AppRoot, "CustomerApp.exe");
            ScriptPath = Path.Combine(Root, "Invoke-ServiceFirewallPolicy.ps1");
            File.WriteAllBytes(ExecutablePath, [1, 2, 3]);
            File.WriteAllText(ScriptPath, "# exact production enforcement helper");
            var configuration = new ProductionServiceConfiguration(1, "QuietShield", QuietShieldServiceIdentity.ProductionPurpose,
                QuietShieldServiceIdentity.ServiceName, Guid.NewGuid(), "S-1-5-21-1000", [AppRoot], ScriptPath, Hash(ScriptPath), DateTimeOffset.UtcNow, string.Empty);
            Configuration = configuration with { PayloadSha256 = configuration.ComputePayloadSha256() };
            Options = new(false, true, false, "QuietShield.Service.Phase12." + Guid.NewGuid().ToString("N"), StateRoot, null,
                TimeSpan.Zero, TimeSpan.FromSeconds(2), null, null, null, Configuration);
            Runtime = new(Options, new AtomicJsonStateStore<PersistentServiceState>(1), NullLogger<PersistentServiceRuntime>.Instance);
            Store = new(Options);
            Backend = new();
            Coordinator = new(Configuration.ToAuthorizationContext(), Runtime, Store, Backend);
        }

        public string Root { get; }
        public string AppRoot { get; }
        public string StateRoot { get; }
        public string ExecutablePath { get; }
        public string ScriptPath { get; }
        public ProductionServiceConfiguration Configuration { get; }
        public DiagnosticServiceOptions Options { get; }
        public PersistentServiceRuntime Runtime { get; }
        public PersistentFirewallTransactionStore Store { get; }
        public InMemoryPersistentFirewallBackend Backend { get; }
        public PersistentProgramPolicyCoordinator Coordinator { get; }

        public ProgramRuleChangeRequest Request(ProgramConnectionPolicy policy, string? path = null)
        {
            var target = path ?? ExecutablePath;
            return new(Configuration.InstallationId, "standard", ApprovedProgramTargetIdentity.FromExecutablePath(target), target, Hash(target), policy);
        }

        public void Dispose()
        {
            Coordinator.Dispose();
            Runtime.Dispose();
            if (Directory.Exists(Root)) Directory.Delete(Root, true);
        }

        private static string Hash(string path)
        {
            using var stream = File.OpenRead(path);
            return Convert.ToHexString(SHA256.HashData(stream));
        }
    }
}
