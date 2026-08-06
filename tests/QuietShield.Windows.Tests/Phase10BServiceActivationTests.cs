using System.Security.Cryptography;
using Microsoft.Extensions.Logging.Abstractions;
using QuietShield.Core.ConnectionLock.Transactions;
using QuietShield.Core.Protection;
using QuietShield.Core.ServiceFoundation;
using QuietShield.Service;

namespace QuietShield.Windows.Tests;

[TestClass]
public sealed class Phase10BServiceActivationTests
{
    [TestMethod]
    public void ExactServiceIdentityIsStableAndUnambiguous()
    {
        var serviceName = typeof(QuietShieldServiceIdentity).GetField(nameof(QuietShieldServiceIdentity.ServiceName))?.GetRawConstantValue();
        var displayName = typeof(QuietShieldServiceIdentity).GetField(nameof(QuietShieldServiceIdentity.DisplayName))?.GetRawConstantValue();
        var pipeName = typeof(QuietShieldServiceProtocol).GetField(nameof(QuietShieldServiceProtocol.ProductionPipeName))?.GetRawConstantValue();
        Assert.AreEqual("QuietShieldService", serviceName);
        Assert.AreEqual("QuietShield Protection Service", displayName);
        Assert.AreEqual("QuietShield.Service.v1", pipeName);
    }

    [TestMethod]
    public void ActivationConfigurationRejectsForeignIdentityExpiredWindowAndTampering()
    {
        using var fixture = new CoordinatorFixture();
        Assert.IsEmpty(fixture.Activation.Validate(DateTimeOffset.UtcNow));
        Assert.IsNotEmpty((fixture.Activation with { ServiceName = "ForeignService" }).Validate(DateTimeOffset.UtcNow));
        Assert.IsNotEmpty((fixture.Activation with { ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(-1) }).Validate(DateTimeOffset.UtcNow));
        Assert.IsNotEmpty((fixture.Activation with { PayloadSha256 = new string('A', 64) }).Validate(DateTimeOffset.UtcNow));
    }

    [TestMethod]
    public async Task BlockedCreatesOneExactRuleAndAllowedOnAllRemovesOnlyThatRule()
    {
        using var fixture = new CoordinatorFixture();
        await fixture.StartAsync();
        var blocked = await fixture.Coordinator.ChangeAsync(fixture.Request(ProgramConnectionPolicy.Blocked), CancellationToken.None);
        Assert.IsTrue(blocked.ExactRulePresent);
        Assert.HasCount(1, fixture.Backend.Rules);
        Assert.AreEqual(blocked.ExactRuleName, fixture.Backend.Rules.Single().Name);
        var allowed = await fixture.Coordinator.ChangeAsync(fixture.Request(ProgramConnectionPolicy.AllowedOnAll), CancellationToken.None);
        Assert.IsFalse(allowed.ExactRulePresent);
        Assert.IsEmpty(fixture.Backend.Rules);
        Assert.AreEqual(blocked.ExactRuleName, allowed.ExactRuleName);
    }

    [TestMethod]
    public async Task NetworkSpecificPersistentPoliciesRemainRefused()
    {
        using var fixture = new CoordinatorFixture();
        await fixture.StartAsync();
        await Assert.ThrowsAsync<NotSupportedException>(() => fixture.Coordinator.ChangeAsync(fixture.Request(ProgramConnectionPolicy.WiFiOnly), CancellationToken.None));
        Assert.IsEmpty(fixture.Backend.Rules);
    }

    [TestMethod]
    public async Task UnrelatedRulesRemainByteForByteUnchanged()
    {
        using var fixture = new CoordinatorFixture(includeForeignRule: true);
        await fixture.StartAsync();
        var foreignBefore = fixture.Backend.Rules.Single(static rule => rule.OwnershipMarker == "Foreign");
        await fixture.Coordinator.ChangeAsync(fixture.Request(ProgramConnectionPolicy.Blocked), CancellationToken.None);
        await fixture.Coordinator.ChangeAsync(fixture.Request(ProgramConnectionPolicy.AllowedOnAll), CancellationToken.None);
        var foreignAfter = fixture.Backend.Rules.Single();
        Assert.AreEqual(foreignBefore, foreignAfter);
    }

    [TestMethod]
    public async Task VerificationFailureRollsBackTheExactTransaction()
    {
        using var fixture = new CoordinatorFixture(new VerificationFailureBackend());
        await fixture.StartAsync();
        await Assert.ThrowsAsync<InvalidDataException>(() => fixture.Coordinator.ChangeAsync(fixture.Request(ProgramConnectionPolicy.Blocked), CancellationToken.None));
        var backend = (VerificationFailureBackend)fixture.BackendContract;
        Assert.IsTrue(backend.RestoreCalled);
        Assert.AreEqual(ProgramLockTransactionState.Restored, fixture.Runtime.GetState().TransactionCheckpoint.State);
    }

    [TestMethod]
    public async Task ServiceRestartRecoversInterruptedExactTransactionBeforeActivation()
    {
        using var fixture = new CoordinatorFixture();
        await fixture.StartAsync();
        var blocked = await fixture.Coordinator.ChangeAsync(fixture.Request(ProgramConnectionPolicy.Blocked), CancellationToken.None);
        await fixture.Runtime.UpdateTransactionAsync(new(blocked.TransactionId, ProgramLockTransactionState.ApplyStarted, DateTimeOffset.UtcNow, true, "Simulated process interruption."), CancellationToken.None);
        await fixture.Runtime.StopAsync(CancellationToken.None);
        var restartedRuntime = fixture.CreateRuntime();
        await restartedRuntime.StartAsync(CancellationToken.None);
        Assert.IsTrue(restartedRuntime.GetState().TransactionCheckpoint.IsInterrupted);
        using var restartedCoordinator = new PersistentProgramPolicyCoordinator(fixture.Activation, restartedRuntime,
            new PersistentFirewallTransactionStore(fixture.Options), fixture.BackendContract);
        await restartedCoordinator.RecoverInterruptedAsync(CancellationToken.None);
        Assert.AreEqual(ProgramLockTransactionState.Restored, restartedRuntime.GetState().TransactionCheckpoint.State);
        Assert.IsEmpty(fixture.Backend.Rules);
        restartedRuntime.Dispose();
    }

    [TestMethod]
    public async Task ImmutableTransactionContainsAllVisibleSafetyExemptionsAndPowerShell51ValidatesHash()
    {
        using var fixture = new CoordinatorFixture();
        await fixture.StartAsync();
        var result = await fixture.Coordinator.ChangeAsync(fixture.Request(ProgramConnectionPolicy.Blocked), CancellationToken.None);
        Assert.HasCount(8, result.VisibleSafetyExemptions);
        var transactionPath = new PersistentFirewallTransactionStore(fixture.Options).GetPath(result.TransactionId);
        var script = Path.Combine(FindRepositoryRoot(), "scripts", "Invoke-ServiceFirewallPolicy.ps1");
        var start = new System.Diagnostics.ProcessStartInfo
        {
            FileName = "powershell.exe", UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true
        };
        foreach (var argument in new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script, "-Operation", "Blocked", "-TransactionPath", transactionPath, "-WhatIf" }) start.ArgumentList.Add(argument);
        using var process = System.Diagnostics.Process.Start(start);
        Assert.IsNotNull(process);
        Assert.IsTrue(process.WaitForExit(10_000));
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        Assert.AreEqual(0, process.ExitCode, error);
        StringAssert.Contains(output, "WhatIfPassed");
        StringAssert.Contains(output, "modifyingCommandInvoked");
    }

    [TestMethod]
    public async Task MalformedPersistentTransactionIsRefusedWithoutBackendMutation()
    {
        using var fixture = new CoordinatorFixture();
        await fixture.StartAsync();
        var result = await fixture.Coordinator.ChangeAsync(fixture.Request(ProgramConnectionPolicy.Blocked), CancellationToken.None);
        var store = new PersistentFirewallTransactionStore(fixture.Options);
        await File.WriteAllTextAsync(store.GetPath(result.TransactionId), "{ malformed");
        var ruleBefore = fixture.Backend.Rules.Single();
        await Assert.ThrowsAsync<InvalidDataException>(() => store.ReadValidatedAsync(result.TransactionId, CancellationToken.None));
        Assert.AreEqual(ruleBefore, fixture.Backend.Rules.Single());
    }

    [TestMethod]
    public void ProductionPipeAclIsBoundToSystemAdministratorsAndOneApprovedUser()
    {
        var source = File.ReadAllText(Path.Combine(FindRepositoryRoot(), "src", "QuietShield.Service", "ServiceNamedPipeFactory.cs"));
        foreach (var required in new[] { "LocalSystemSid", "BuiltinAdministratorsSid", "authorizedUserSid", "SetAccessRuleProtection(true, false)", "NamedPipeServerStreamAcl.Create" })
            StringAssert.Contains(source, required);
        Assert.IsFalse(source.Contains("WorldSid", StringComparison.Ordinal));
        Assert.IsFalse(source.Contains("AnonymousSid", StringComparison.Ordinal));
    }

    private sealed class CoordinatorFixture : IDisposable
    {
        private readonly string _root;
        public CoordinatorFixture(bool includeForeignRule = false) : this(includeForeignRule
            ? new InMemoryPersistentFirewallBackend([new("Foreign", 0, "ThirdParty.Rule", "Foreign", Environment.ProcessPath!, true, "Outbound", "Allow", "Any", "Any", "Any", 0)])
            : new InMemoryPersistentFirewallBackend()) { }

        public CoordinatorFixture(IPersistentFirewallBackend backend)
        {
            _root = Path.Combine(Path.GetTempPath(), "QuietShield-Phase10B-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_root);
            ProbePath = Path.Combine(_root, "QuietShield.ConnectionProbe.exe");
            ScriptPath = Path.Combine(_root, "Invoke-ServiceFirewallPolicy.ps1");
            File.WriteAllBytes(ProbePath, [0x51, 0x53, 0x50]);
            File.WriteAllText(ScriptPath, "# test enforcement script");
            var created = DateTimeOffset.UtcNow.AddMinutes(-1);
            var activation = new ServiceActivationConfiguration(1, "QuietShield", "Phase10BControlledServiceRehearsal", "QuietShieldService", Guid.NewGuid(),
                "S-1-5-21-1000", ProbePath, Hash(ProbePath), ScriptPath, Hash(ScriptPath), created, created.AddHours(1), string.Empty);
            Activation = activation with { PayloadSha256 = activation.ComputePayloadSha256() };
            Options = new(false, true, false, "QuietShield.Service.Tests." + Guid.NewGuid().ToString("N"), _root, null, TimeSpan.Zero, TimeSpan.FromSeconds(2), Activation, null, null);
            BackendContract = backend;
            Backend = backend as InMemoryPersistentFirewallBackend ?? new InMemoryPersistentFirewallBackend();
            Runtime = CreateRuntime();
            Coordinator = new(Activation, Runtime, new PersistentFirewallTransactionStore(Options), backend);
        }
        public string ProbePath { get; }
        public string ScriptPath { get; }
        public ServiceActivationConfiguration Activation { get; }
        public DiagnosticServiceOptions Options { get; }
        public PersistentServiceRuntime Runtime { get; private set; }
        public PersistentProgramPolicyCoordinator Coordinator { get; }
        public IPersistentFirewallBackend BackendContract { get; }
        public InMemoryPersistentFirewallBackend Backend { get; }
        public Task StartAsync() => Runtime.StartAsync(CancellationToken.None);
        public ProgramRuleChangeRequest Request(ProgramConnectionPolicy policy) => new(Activation.ApprovedRehearsalId, "phase10b.rehearsal",
            "quietshield.connection-probe", ProbePath, Activation.ProbeSha256, policy);
        public PersistentServiceRuntime CreateRuntime() => new(Options, new AtomicJsonStateStore<PersistentServiceState>(1), NullLogger<PersistentServiceRuntime>.Instance);
        public void Dispose()
        {
            Coordinator.Dispose();
            Runtime.Dispose();
            if (Directory.Exists(_root)) Directory.Delete(_root, true);
        }
        private static string Hash(string path) { using var stream = File.OpenRead(path); return Convert.ToHexString(SHA256.HashData(stream)); }
    }

    private sealed class VerificationFailureBackend : IPersistentFirewallBackend
    {
        public bool IsRealWindowsModifier => false;
        public bool RestoreCalled { get; private set; }
        public Task<PersistentFirewallRuleSnapshot?> GetExactAsync(string ruleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult<PersistentFirewallRuleSnapshot?>(null);
        }
        public Task ApplyBlockedAsync(PersistentFirewallTransaction transaction, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task ApplyAllowedOnAllAsync(PersistentFirewallTransaction transaction, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task RestoreAsync(PersistentFirewallTransaction transaction, CancellationToken cancellationToken) { RestoreCalled = true; return Task.CompletedTask; }
    }

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null) { if (File.Exists(Path.Combine(directory.FullName, "QuietShield.sln"))) return directory.FullName; directory = directory.Parent; }
        throw new DirectoryNotFoundException("QuietShield repository root not found.");
    }
}
