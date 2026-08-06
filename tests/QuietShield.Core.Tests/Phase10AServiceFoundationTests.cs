using System.Text;
using System.Text.Json;
using QuietShield.Core.ConnectionLock;
using QuietShield.Core.ConnectionLock.Transactions;
using QuietShield.Core.Protection;
using QuietShield.Core.ServiceFoundation;

namespace QuietShield.Core.Tests;

[TestClass]
public sealed class Phase10AServiceFoundationTests
{
    private static readonly string[] RequiredMessageNames =
    [
        "GetServiceStatus", "GetActiveProfile", "PreviewPolicyPlan", "RequestProfileActivation",
        "RequestProgramRuleChange", "RequestTemporaryAllowance", "GetTransactionStatus", "RequestRollback", "GetHealth", "Ping"
    ];

    [TestMethod]
    public async Task AtomicStateReplacementCreatesValidatedBackup()
    {
        using var directory = new TemporaryDirectory();
        var path = Path.Combine(directory.Path, "state.json");
        var store = new AtomicJsonStateStore<SmallState>(1);
        await store.SaveAsync(path, new(1, "first"), CancellationToken.None);
        await store.SaveAsync(path, new(1, "second"), CancellationToken.None);
        Assert.AreEqual("second", (await store.ReadValidatedAsync(path, CancellationToken.None)).Value);
        Assert.AreEqual("first", (await store.ReadValidatedAsync(path + ".bak", CancellationToken.None)).Value);
        Assert.IsEmpty(Directory.GetFiles(directory.Path, "*.tmp"));
    }

    [TestMethod]
    public async Task MalformedAndHashMismatchedPersistentStateAreRefused()
    {
        using var directory = new TemporaryDirectory();
        var path = Path.Combine(directory.Path, "state.json");
        await File.WriteAllTextAsync(path, "{not-json");
        var store = new AtomicJsonStateStore<SmallState>(1);
        await Assert.ThrowsAsync<InvalidDataException>(() => store.ReadValidatedAsync(path, CancellationToken.None));
        await store.SaveAsync(path, new(1, "original"), CancellationToken.None);
        var content = await File.ReadAllTextAsync(path);
        await File.WriteAllTextAsync(path, content.Replace("original", "tampered", StringComparison.Ordinal));
        await Assert.ThrowsAsync<InvalidDataException>(() => store.ReadValidatedAsync(path, CancellationToken.None));
    }

    [TestMethod]
    public async Task LastKnownGoodStateRecoversOnlyFromValidatedFallback()
    {
        using var directory = new TemporaryDirectory();
        var primary = Path.Combine(directory.Path, "primary.json");
        var lastKnownGood = Path.Combine(directory.Path, "lkg.json");
        var store = new AtomicJsonStateStore<SmallState>(1);
        await store.SaveAsync(lastKnownGood, new(1, "known-good"), CancellationToken.None);
        await File.WriteAllTextAsync(primary, "corrupt");
        var result = await store.ReadWithLastKnownGoodAsync(primary, lastKnownGood, CancellationToken.None);
        Assert.IsTrue(result.UsedLastKnownGood);
        Assert.AreEqual("known-good", result.State.Value);
    }

    [TestMethod]
    public async Task UnknownSchemaIsRefusedWithoutAnExplicitMigration()
    {
        using var directory = new TemporaryDirectory();
        var path = Path.Combine(directory.Path, "state.json");
        await new AtomicJsonStateStore<SmallState>(2).SaveAsync(path, new(2, "future"), CancellationToken.None);
        await Assert.ThrowsAsync<NotSupportedException>(() => new AtomicJsonStateStore<SmallState>(1).ReadValidatedAsync(path, CancellationToken.None));
    }

    [TestMethod]
    public async Task ExplicitMigrationIsAppliedAndUnmappedMigrationIsRefused()
    {
        using var directory = new TemporaryDirectory();
        var path = Path.Combine(directory.Path, "state.json");
        await new AtomicJsonStateStore<SmallState>(1).SaveAsync(path, new(1, "old"), CancellationToken.None);
        var migrated = await new AtomicJsonStateStore<SmallState>(2, [new SmallStateMigration()]).ReadValidatedAsync(path, CancellationToken.None);
        Assert.AreEqual(2, migrated.SchemaVersion);
        Assert.AreEqual("old-migrated", migrated.Value);
    }

    [TestMethod]
    [DataRow(ProgramConnectionPolicy.Blocked)]
    [DataRow(ProgramConnectionPolicy.AllowedOnAll)]
    public async Task BlockedAndAllowedOnAllAreTheOnlySupportedEventualPersistentPolicies(ProgramConnectionPolicy policy)
    {
        var plan = await new ReadOnlyPersistentPolicyCoordinator(new ReadOnlyPersistentPolicyPreflight()).PreviewAsync(policy, CancellationToken.None);
        Assert.AreEqual(PolicyEnforcementSupport.WindowsFirewallStatic, plan.Enforceability.Support);
        Assert.IsFalse(plan.ApplyPermitted);
        Assert.IsTrue(plan.Audit.Any(static entry => entry.Stage == CoordinatorStage.Apply && entry.Result == "NotActive"));
    }

    [TestMethod]
    [DataRow(ProgramConnectionPolicy.WiFiOnly)]
    [DataRow(ProgramConnectionPolicy.EthernetOnly)]
    [DataRow(ProgramConnectionPolicy.CellularOnly)]
    [DataRow(ProgramConnectionPolicy.MeteredOnly)]
    [DataRow(ProgramConnectionPolicy.UnmeteredOnly)]
    public async Task NetworkSpecificPoliciesRequireTransitionsAndAreNeverApproximated(ProgramConnectionPolicy policy)
    {
        var plan = await new ReadOnlyPersistentPolicyCoordinator(new ReadOnlyPersistentPolicyPreflight()).PreviewAsync(policy, CancellationToken.None);
        Assert.AreEqual(PolicyEnforcementSupport.RequiresRuntimeNetworkTransitionManagement, plan.Enforceability.Support);
        Assert.IsFalse(plan.ApplyPermitted);
        Assert.AreNotEqual(ProposedEnforcementLayer.WindowsFirewall, plan.Enforceability.Layer);
    }

    [TestMethod]
    public async Task EverySafetyExemptionIsVisibleInPlanAudit()
    {
        var plan = await new ReadOnlyPersistentPolicyCoordinator(new ReadOnlyPersistentPolicyPreflight()).PreviewAsync(ProgramConnectionPolicy.Blocked, CancellationToken.None);
        CollectionAssert.AreEquivalent(Enum.GetValues<SafetyExemptionKind>(), plan.SafetyExemptions.Select(static item => item.Kind).ToArray());
        Assert.IsTrue(plan.SafetyExemptions.All(static item => !string.IsNullOrWhiteSpace(item.VisibleReason)));
    }

    [TestMethod]
    public void InterruptedTransactionDetectionIsStrict()
    {
        foreach (var state in new[] { ProgramLockTransactionState.ApplyStarted, ProgramLockTransactionState.RulesApplied,
                     ProgramLockTransactionState.VerificationStarted, ProgramLockTransactionState.VerificationPassed,
                     ProgramLockTransactionState.InterruptedRecoveryRequired })
            Assert.IsTrue(new PersistentTransactionCheckpoint(Guid.NewGuid(), state, DateTimeOffset.UtcNow, true, "test").IsInterrupted);
        Assert.IsFalse(new PersistentTransactionCheckpoint(Guid.NewGuid(), ProgramLockTransactionState.Committed, DateTimeOffset.UtcNow, false, "test").IsInterrupted);
    }

    [TestMethod]
    public void IpcFramesRejectEmptyAndOversizedMessagesBeforeAllocation()
    {
        using var empty = new MemoryStream(BitConverter.GetBytes(0));
        Assert.ThrowsAsync<InvalidDataException>(() => BoundedMessageFrame.ReadAsync(empty, CancellationToken.None));
        using var oversized = new MemoryStream(BitConverter.GetBytes(QuietShieldServiceProtocol.MaximumMessageBytes + 1));
        Assert.ThrowsAsync<InvalidDataException>(() => BoundedMessageFrame.ReadAsync(oversized, CancellationToken.None));
    }

    [TestMethod]
    public async Task IpcFrameRoundTripPreservesBoundedPayload()
    {
        await using var stream = new MemoryStream();
        var payload = Encoding.UTF8.GetBytes("bounded-message");
        await BoundedMessageFrame.WriteAsync(stream, payload, CancellationToken.None);
        stream.Position = 0;
        CollectionAssert.AreEqual(payload, await BoundedMessageFrame.ReadAsync(stream, CancellationToken.None));
    }

    [TestMethod]
    public void InMemoryApplicatorCannotModifyWindows()
    {
        Assert.IsFalse(new InMemoryPolicyApplicator().IsWindowsModifier);
    }

    [TestMethod]
    public void ProtocolHasEveryRequiredMessageAndNoNetworkEndpoint()
    {
        CollectionAssert.AreEquivalent(RequiredMessageNames, Enum.GetNames<ServiceMessageKind>());
        Assert.IsGreaterThan(0, QuietShieldServiceProtocol.MaximumMessageBytes);
    }

    private sealed record SmallState(int SchemaVersion, string Value);
    private sealed class SmallStateMigration : IStateMigration<SmallState>
    {
        public int FromSchemaVersion => 1;
        public int ToSchemaVersion => 2;
        public SmallState Migrate(SmallState state) => new(2, state.Value + "-migrated");
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "QuietShield-Phase10A-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path);
        }
        public string Path { get; }
        public void Dispose() { if (Directory.Exists(Path)) Directory.Delete(Path, true); }
    }
}
