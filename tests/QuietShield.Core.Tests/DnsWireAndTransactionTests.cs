using System.Buffers.Binary;
using QuietShield.Core.Dns;

namespace QuietShield.Core.Tests;

[TestClass]
public sealed class DnsWireAndTransactionTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 6, 0, 0, 0, TimeSpan.Zero);
    private static readonly DnsAdapterIdentity Adapter = new(Guid.Parse("11111111-2222-3333-4444-555555555555"), 17);
    private static readonly string[] OriginalServers = { "1.1.1.1", "2606:4700:4700::1111" };
    private static readonly string[] SingleServer = { "1.1.1.1" };
    private static readonly DnsAdapterOriginalState[] OriginalAdapterStates = { new(Adapter, false, OriginalServers) };
    private static readonly DnsAdapterOriginalState[] SingleAdapterState = { new(Adapter, false, SingleServer) };

    [TestMethod]
    public void WireQueryRoundTripsTransactionQuestionAndArbitraryRecordType()
    {
        var packet = DnsWireProtocol.CreateQuery("MiXeD.Example.Test", 15, 0xBEEF);

        var parsed = DnsWireProtocol.ParseQuery(packet);

        Assert.IsTrue(parsed.Succeeded);
        Assert.AreEqual((ushort)0xBEEF, parsed.Question!.TransactionId);
        Assert.AreEqual("mixed.example.test", parsed.Question.NormalizedDomain);
        Assert.AreEqual((ushort)15, parsed.Question.QueryType);
        Assert.AreEqual((ushort)1, parsed.Question.QueryClass);
    }

    [TestMethod]
    public void BlockedResponsePreservesTransactionAndQuestionMetadata()
    {
        var parsed = DnsWireProtocol.ParseQuery(DnsWireProtocol.CreateQuery("blocked.example.test", 28, 0x1234)).Question!;

        var response = DnsWireProtocol.CreateResponse(parsed, DnsResponseCode.NameError);

        Assert.AreEqual((ushort)0x1234, DnsWireProtocol.GetTransactionId(response));
        Assert.AreEqual(DnsResponseCode.NameError, DnsWireProtocol.GetResponseCode(response));
        Assert.IsTrue(DnsWireProtocol.IsResponse(response));
        Assert.AreEqual((ushort)1, BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(4, 2)));
        CollectionAssert.AreEqual(parsed.Packet[DnsWireProtocol.HeaderLength..parsed.QuestionEndOffset], response[DnsWireProtocol.HeaderLength..]);
    }

    [TestMethod]
    public void ParserRejectsMalformedAndRecursiveCompressionPackets()
    {
        var tooShort = DnsWireProtocol.ParseQuery(new byte[] { 1, 2, 3 });
        var recursive = new byte[18];
        BinaryPrimitives.WriteUInt16BigEndian(recursive.AsSpan(4, 2), 1);
        recursive[12] = 0xC0;
        recursive[13] = 12;

        Assert.IsFalse(tooShort.Succeeded);
        Assert.IsFalse(DnsWireProtocol.ParseQuery(recursive).Succeeded);
    }

    [TestMethod]
    public void FormatErrorPreservesAvailableTransactionIdWithoutEchoingPayload()
    {
        var response = DnsWireProtocol.CreateFormatError(new byte[] { 0xCA, 0xFE, 0x01, 0x00, 99, 88, 77 });

        Assert.HasCount(DnsWireProtocol.HeaderLength, response);
        Assert.AreEqual((ushort)0xCAFE, DnsWireProtocol.GetTransactionId(response));
        Assert.AreEqual(DnsResponseCode.FormatError, DnsWireProtocol.GetResponseCode(response));
    }

    [TestMethod]
    public void BackupRoundTripPreservesExactOriginalValuesAndValidatesHash()
    {
        var backup = CreateBackup();

        var validation = DnsBackupSerializer.DeserializeAndValidate(DnsBackupSerializer.Serialize(backup));

        Assert.IsTrue(validation.Succeeded);
        Assert.AreEqual(backup.BackupId, validation.Document!.BackupId);
        CollectionAssert.AreEqual(OriginalServers, validation.Document.Adapters[0].ServerAddresses.ToArray());
    }

    [TestMethod]
    public void BackupValidationRefusesTamperingUnknownMarkerAndInvalidAddress()
    {
        var backup = CreateBackup();
        Assert.IsFalse(DnsBackupSerializer.Validate(backup with { PayloadSha256 = new string('0', 64) }).Succeeded);
        Assert.IsFalse(DnsBackupSerializer.Validate(backup with { ProductMarker = "Unknown" }).Succeeded);
        var invalid = backup with
        {
            Adapters = new[] { backup.Adapters[0] with { ServerAddresses = new[] { "not-an-address" } } }
        };
        Assert.IsFalse(DnsBackupSerializer.Validate(invalid).Succeeded);
    }

    [TestMethod]
    public void StateMachineAllowsOnlyDocumentedTransitions()
    {
        var machine = new DnsTransactionStateMachine();
        machine.TransitionTo(DnsTransactionState.PreflightPassed);
        machine.TransitionTo(DnsTransactionState.BackupValidated);
        machine.TransitionTo(DnsTransactionState.ReadyForApproval);

        Assert.AreEqual(DnsTransactionState.ReadyForApproval, machine.Current);
        Assert.Throws<InvalidOperationException>(() => machine.TransitionTo(DnsTransactionState.Committed));
    }

    [TestMethod]
    public void ReadinessNamesEveryMissingSafetyRequirement()
    {
        var readiness = DnsTransactionReadinessEvaluator.Evaluate(false, false, false, false, false);

        Assert.IsFalse(readiness.Ready);
        Assert.HasCount(5, readiness.MissingRequirements);
        StringAssert.Contains(readiness.Status, "explicit user approval");
    }

    [TestMethod]
    public void RecoveryPlanRequiresValidatedBackupApprovalAndAdministrator()
    {
        var recovery = DnsRecoveryPlanner.Create(Guid.NewGuid(), DnsRecoveryReason.EmergencyManualRestore, CreateBackup());

        Assert.IsTrue(recovery.RequiresAdministrator);
        Assert.IsTrue(recovery.RequiresExplicitApproval);
        CollectionAssert.AreEqual(new[] { Adapter }, recovery.TargetAdapters.ToArray());
    }

    [TestMethod]
    public void AdapterIdentityRequiresGuidAndIndexMatch()
    {
        Assert.IsTrue(DnsAdapterIdentityMatcher.Matches(Adapter, Adapter));
        Assert.IsFalse(DnsAdapterIdentityMatcher.Matches(Adapter, Adapter with { InterfaceIndex = 18 }));
        Assert.IsFalse(DnsAdapterIdentityMatcher.Matches(Adapter, Adapter with { InterfaceGuid = Guid.NewGuid() }));
    }

    [TestMethod]
    [TestCategory("Phase4Smoke")]
    public async Task TransactionPlanDryRunCapturesValidBackupWithoutInvokingMutator()
    {
        var doubles = new TransactionDoubles();
        var coordinator = doubles.CreateCoordinator();

        var plan = await coordinator.PrepareAsync(new DnsEndpointIdentity("127.0.0.1", 53535, "Loopback preview"), Now, CancellationToken.None);

        Assert.AreEqual(DnsTransactionState.ReadyForApproval, plan.State);
        Assert.IsTrue(DnsBackupSerializer.Validate(plan.OriginalDnsBackup).Succeeded);
        Assert.AreEqual(0, doubles.Mutator.ApplyCount);
        Assert.AreEqual(0, doubles.Mutator.RestoreCount);
    }

    [TestMethod]
    public async Task EveryMissingExecutionGuardPreventsModification()
    {
        var doubles = new TransactionDoubles();
        var coordinator = doubles.CreateCoordinator();
        var plan = await coordinator.PrepareAsync(new DnsEndpointIdentity("127.0.0.1", 53535, "Loopback preview"), Now, CancellationToken.None);
        var authorization = new DnsActivationAuthorization(false, false, false, false, Now.AddMinutes(1));

        var result = await coordinator.ExecuteAsync(plan, authorization, Now, CancellationToken.None);

        Assert.IsFalse(result.Succeeded);
        Assert.AreEqual(0, doubles.Mutator.ApplyCount);
        Assert.AreEqual(0, doubles.Mutator.RestoreCount);
    }

    [TestMethod]
    public async Task VerificationFailureAutomaticallyPlansAndPerformsAbstractRollback()
    {
        var doubles = new TransactionDoubles { ResolverResult = false };
        var coordinator = doubles.CreateCoordinator();
        var plan = await coordinator.PrepareAsync(new DnsEndpointIdentity("127.0.0.1", 53535, "Loopback preview"), Now, CancellationToken.None);
        var authorization = new DnsActivationAuthorization(true, true, true, true, Now.AddMinutes(1));

        var result = await coordinator.ExecuteAsync(plan, authorization, Now, CancellationToken.None);

        Assert.AreEqual(DnsTransactionState.RolledBack, result.State);
        Assert.IsTrue(result.RollbackAttempted);
        Assert.IsTrue(result.RollbackSucceeded);
        Assert.AreEqual(1, doubles.Mutator.ApplyCount);
        Assert.AreEqual(1, doubles.Mutator.RestoreCount);
    }

    [TestMethod]
    public async Task InterruptedTransactionCreatesRecoveryPlanWithoutRestoring()
    {
        var doubles = new TransactionDoubles();
        var coordinator = doubles.CreateCoordinator();
        var plan = await coordinator.PrepareAsync(new DnsEndpointIdentity("127.0.0.1", 53535, "Loopback preview"), Now, CancellationToken.None);
        doubles.Journal.Interrupted = plan with { State = DnsTransactionState.Interrupted };

        var recovery = await coordinator.PlanInterruptedRecoveryAsync(CancellationToken.None);

        Assert.IsNotNull(recovery);
        Assert.AreEqual(DnsRecoveryReason.InterruptedTransaction, recovery.Reason);
        Assert.AreEqual(0, doubles.Mutator.RestoreCount);
    }

    private static DnsBackupDocument CreateBackup() => DnsBackupSerializer.Create(
        OriginalAdapterStates,
        Now,
        Guid.Parse("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"));

    private sealed class TransactionDoubles
    {
        public CountingMutator Mutator { get; } = new();
        public MemoryJournal Journal { get; } = new();
        public bool ResolverResult { get; init; } = true;

        public DnsTransactionCoordinator CreateCoordinator() => new(
            new FixedPreflight(),
            new FixedConfiguration(),
            new MemoryBackupRepository(),
            Journal,
            Mutator,
            new NoOpCacheFlush(),
            new FixedConnectivity(),
            new FixedResolver(ResolverResult));
    }

    private sealed class FixedPreflight : IDnsTransactionPreflight
    {
        public Task<DnsTransactionPreflightResult> RunAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new DnsTransactionPreflightResult(true, new[] { Adapter }, "Passed"));
    }

    private sealed class FixedConfiguration : IDnsOriginalConfigurationSource
    {
        public Task<IReadOnlyList<DnsAdapterOriginalState>> CaptureAsync(IReadOnlyList<DnsAdapterIdentity> adapters, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<DnsAdapterOriginalState>>(SingleAdapterState);
    }

    private sealed class MemoryBackupRepository : IDnsBackupRepository
    {
        private DnsBackupDocument? _backup;
        public Task SaveValidatedAsync(DnsBackupDocument backup, CancellationToken cancellationToken) { _backup = backup; return Task.CompletedTask; }
        public Task<DnsBackupDocument?> LoadLastKnownGoodAsync(CancellationToken cancellationToken) => Task.FromResult(_backup);
    }

    private sealed class MemoryJournal : IDnsTransactionJournal
    {
        public DnsActivationPlan? Interrupted { get; set; }
        public Task SaveAsync(DnsActivationPlan plan, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<DnsActivationPlan?> LoadInterruptedAsync(CancellationToken cancellationToken) => Task.FromResult(Interrupted);
    }

    private sealed class CountingMutator : IDnsConfigurationMutator
    {
        public int ApplyCount { get; private set; }
        public int RestoreCount { get; private set; }
        public Task ApplyAsync(DnsActivationPlan plan, CancellationToken cancellationToken) { ApplyCount++; return Task.CompletedTask; }
        public Task RestoreAsync(DnsRecoveryPlan recoveryPlan, CancellationToken cancellationToken) { RestoreCount++; return Task.CompletedTask; }
    }

    private sealed class NoOpCacheFlush : IDnsCacheFlushOperation
    {
        public Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class FixedConnectivity : IDnsConnectivityVerifier
    {
        public Task<bool> VerifyAsync(DateTimeOffset deadlineUtc, CancellationToken cancellationToken) => Task.FromResult(true);
    }

    private sealed class FixedResolver(bool result) : IQuietShieldResolverVerifier
    {
        public Task<bool> VerifyAsync(DnsEndpointIdentity endpoint, DateTimeOffset deadlineUtc, CancellationToken cancellationToken) => Task.FromResult(result);
    }
}
