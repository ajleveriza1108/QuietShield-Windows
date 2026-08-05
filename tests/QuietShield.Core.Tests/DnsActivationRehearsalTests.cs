using QuietShield.Core.Dns;

namespace QuietShield.Core.Tests;

[TestClass]
public sealed class DnsActivationRehearsalTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 6, 0, 0, 0, TimeSpan.Zero);
    private static readonly DnsAdapterIdentity Identity = new(Guid.Parse("11111111-2222-3333-4444-555555555555"), 7);
    private static readonly string[] Ipv4Servers = { "192.0.2.53", "192.0.2.54", "192.0.2.53" };
    private static readonly string[] Ipv6Servers = { "2001:db8::53", "2001:db8::53" };
    private static readonly string[] ReorderedIpv4Servers = { "192.0.2.53", "192.0.2.53", "192.0.2.54" };
    private static readonly string[] SingleIpv6Server = { "2001:db8::53" };

    [TestMethod]
    [TestCategory("Phase5Smoke")]
    public void WatchdogDeadlineRequiresRollback()
    {
        var decision = DnsWatchdogDecisionEvaluator.Evaluate(Observation(now: Now.AddSeconds(181), deadline: Now.AddSeconds(180)));
        Assert.IsTrue(decision.RestoreRequired);
        Assert.AreEqual(DnsWatchdogTrigger.ApprovedDurationElapsed, decision.Trigger);
    }

    [TestMethod]
    [TestCategory("Phase5Smoke")]
    public void WatchdogHeartbeatLossRequiresRollback()
    {
        var decision = DnsWatchdogDecisionEvaluator.Evaluate(Observation(lastHeartbeat: Now.AddSeconds(-9)));
        Assert.IsTrue(decision.RestoreRequired);
        Assert.AreEqual(DnsWatchdogTrigger.HeartbeatLost, decision.Trigger);
    }

    [TestMethod]
    [TestCategory("Phase5Smoke")]
    public void WatchdogParentProcessLossRequiresRollback()
    {
        var decision = DnsWatchdogDecisionEvaluator.Evaluate(Observation(orchestratorAlive: false));
        Assert.IsTrue(decision.RestoreRequired);
        Assert.AreEqual(DnsWatchdogTrigger.OrchestratorExited, decision.Trigger);
    }

    [TestMethod]
    public void WatchdogConnectivityFailureAndHostExitRequireRollback()
    {
        var connectivity = DnsWatchdogDecisionEvaluator.Evaluate(Observation(connectivityHealthy: false));
        var host = DnsWatchdogDecisionEvaluator.Evaluate(Observation(hostAlive: false));
        Assert.AreEqual(DnsWatchdogTrigger.ConnectivityFailed, connectivity.Trigger);
        Assert.AreEqual(DnsWatchdogTrigger.HostExited, host.Trigger);
    }

    [TestMethod]
    public void MalformedBackupIsRefused()
    {
        var result = DnsRehearsalBackupSerializer.DeserializeAndValidate("{not-json");
        Assert.IsFalse(result.Succeeded);
        Assert.IsNull(result.Document);
    }

    [TestMethod]
    public void BackupRequiresExactAdapterIdentityAndPreservesIpv4AndIpv6RestorationValues()
    {
        var backup = CreateBackup();
        var roundTrip = DnsRehearsalBackupSerializer.DeserializeAndValidate(DnsRehearsalBackupSerializer.Serialize(backup));

        Assert.IsTrue(roundTrip.Succeeded);
        Assert.IsTrue(DnsAdapterIdentityMatcher.Matches(Identity, roundTrip.Document!.Adapter.Identity));
        Assert.IsFalse(DnsAdapterIdentityMatcher.Matches(Identity with { InterfaceIndex = 8 }, roundTrip.Document.Adapter.Identity));
        CollectionAssert.AreEqual(Ipv4Servers, roundTrip.Document.Adapter.Families.Single(static family => family.AddressFamily == DnsRehearsalAddressFamily.IPv4).ServerAddresses.ToArray());
        CollectionAssert.AreEqual(Ipv6Servers, roundTrip.Document.Adapter.Families.Single(static family => family.AddressFamily == DnsRehearsalAddressFamily.IPv6).ServerAddresses.ToArray());
    }

    [TestMethod]
    public void DuplicateAutomaticIpv6EntriesAreAcceptedAndPreservedExactly()
    {
        var validation = DnsRehearsalBackupSerializer.DeserializeAndValidate(DnsRehearsalBackupSerializer.Serialize(CreateBackup()));

        Assert.IsTrue(validation.Succeeded);
        var ipv6 = validation.Document!.Adapter.Families.Single(static family => family.AddressFamily == DnsRehearsalAddressFamily.IPv6);
        Assert.IsTrue(ipv6.Automatic);
        CollectionAssert.AreEqual(Ipv6Servers, ipv6.ServerAddresses.ToArray());
    }

    [TestMethod]
    public void DuplicateValuesAndOrderParticipateInBackupHashValidation()
    {
        var backup = CreateBackup();
        var ipv4 = backup.Adapter.Families.Single(static family => family.AddressFamily == DnsRehearsalAddressFamily.IPv4);
        var reordered = backup with
        {
            Adapter = backup.Adapter with
            {
                Families = new[]
                {
                    ipv4 with { ServerAddresses = ReorderedIpv4Servers },
                    backup.Adapter.Families.Single(static family => family.AddressFamily == DnsRehearsalAddressFamily.IPv6)
                }
            }
        };
        var removedDuplicate = backup with
        {
            Adapter = backup.Adapter with
            {
                Families = backup.Adapter.Families.Select(static family => family.AddressFamily == DnsRehearsalAddressFamily.IPv6
                    ? family with { ServerAddresses = SingleIpv6Server }
                    : family).ToArray()
            }
        };

        Assert.IsFalse(DnsRehearsalBackupSerializer.Validate(reordered).Succeeded);
        Assert.IsFalse(DnsRehearsalBackupSerializer.Validate(removedDuplicate).Succeeded);
    }

    [TestMethod]
    public void RuntimeUpstreamDeduplicationDoesNotAlterStoredBackup()
    {
        var backup = CreateBackup();
        var before = DnsRehearsalBackupSerializer.Serialize(backup);

        var upstreams = DnsRehearsalUpstreamSelector.SelectDistinctForwardingAddresses(backup);

        Assert.HasCount(3, upstreams);
        Assert.AreEqual(before, DnsRehearsalBackupSerializer.Serialize(backup));
        CollectionAssert.AreEqual(Ipv4Servers, backup.Adapter.Families.Single(static family => family.AddressFamily == DnsRehearsalAddressFamily.IPv4).ServerAddresses.ToArray());
        CollectionAssert.AreEqual(Ipv6Servers, backup.Adapter.Families.Single(static family => family.AddressFamily == DnsRehearsalAddressFamily.IPv6).ServerAddresses.ToArray());
    }

    [TestMethod]
    public async Task EmbeddedPolicyLoadsNormalizedBlockAndHandlesTrailingDot()
    {
        var policy = new DnsRehearsalPolicyEvaluator();
        var snapshot = DnsRehearsalPolicyEvaluator.GetSnapshot();
        var decision = await policy.EvaluateAsync("quietshield-blocked.test.", CancellationToken.None);

        Assert.IsTrue(snapshot.Loaded);
        Assert.AreEqual("quietshield-blocked.test", snapshot.NormalizedBlockedTestDomain);
        Assert.AreEqual(DnsDecision.Block, snapshot.TestDecision);
        Assert.AreEqual(DnsDecision.Block, decision.Decision);
        Assert.AreEqual("quietshield-blocked.test", decision.NormalizedDomain);
        Assert.AreEqual("quietshield-blocked.test", decision.MatchedRule);
    }

    [TestMethod]
    public void AdapterSelectionRefusesAmbiguityVpnVirtualAndDisconnectedCandidates()
    {
        var first = Candidate(Identity, DnsRehearsalAdapterKind.WiFi, true, true, false, true);
        var second = Candidate(Identity with { InterfaceIndex = 8 }, DnsRehearsalAdapterKind.Ethernet, true, true, false, true);
        Assert.IsFalse(DnsRehearsalAdapterSelector.SelectExactlyOne(new[] { first, second }).Succeeded);

        var refused = new[]
        {
            Candidate(Identity, DnsRehearsalAdapterKind.Vpn, false, true, true, false),
            Candidate(Identity with { InterfaceIndex = 8 }, DnsRehearsalAdapterKind.Virtual, false, true, true, false),
            Candidate(Identity with { InterfaceIndex = 9 }, DnsRehearsalAdapterKind.Ethernet, true, false, false, true)
        };
        Assert.IsFalse(DnsRehearsalAdapterSelector.SelectExactlyOne(refused).Succeeded);
    }

    [TestMethod]
    public void HostStartupFailureBeforeDnsChangeIsGuarded()
    {
        Assert.IsFalse(DnsRehearsalActivationGuard.CanChangeDns(DnsRehearsalState.WatchdogStarted, false, true, true));
        Assert.IsFalse(DnsRehearsalActivationGuard.CanChangeDns(DnsRehearsalState.ResolverStarted, false, true, true));
        Assert.IsTrue(DnsRehearsalActivationGuard.CanChangeDns(DnsRehearsalState.ResolverStarted, true, true, true));
    }

    [TestMethod]
    [TestCategory("Phase5Smoke")]
    public void FailureAfterDnsChangeTransitionsImmediatelyToRollbackAndCanRecover()
    {
        var machine = new DnsRehearsalStateMachine();
        machine.TransitionTo(DnsRehearsalState.WatchdogStarted);
        machine.TransitionTo(DnsRehearsalState.ResolverStarted);
        machine.TransitionTo(DnsRehearsalState.DnsChanged);
        machine.TransitionTo(DnsRehearsalState.RollbackStarted);
        machine.TransitionTo(DnsRehearsalState.DnsRestored);
        machine.TransitionTo(DnsRehearsalState.PostRestoreVerified);
        machine.TransitionTo(DnsRehearsalState.Completed);
        Assert.AreEqual(DnsRehearsalState.Completed, machine.Current);
    }

    [TestMethod]
    public void DurationEnforcesMaximumAndRepeatedInvocationIsRefused()
    {
        Assert.AreEqual(TimeSpan.FromSeconds(300), DnsRehearsalDuration.Validate(TimeSpan.FromSeconds(300)));
        Assert.Throws<ArgumentOutOfRangeException>(() => DnsRehearsalDuration.Validate(TimeSpan.FromSeconds(301)));
        Assert.IsFalse(DnsRehearsalInvocationGuard.Evaluate(false, true).Allowed);
        Assert.IsFalse(DnsRehearsalInvocationGuard.Evaluate(true, false).Allowed);
        Assert.IsTrue(DnsRehearsalInvocationGuard.Evaluate(false, false).Allowed);
    }

    private static DnsWatchdogObservation Observation(
        DateTimeOffset? now = null,
        DateTimeOffset? deadline = null,
        DateTimeOffset? lastHeartbeat = null,
        bool hostAlive = true,
        bool orchestratorAlive = true,
        bool connectivityHealthy = true) => new(
            true,
            false,
            now ?? Now,
            deadline ?? Now.AddSeconds(180),
            true,
            lastHeartbeat ?? Now,
            TimeSpan.FromSeconds(8),
            true,
            hostAlive,
            orchestratorAlive,
            true,
            connectivityHealthy,
            false);

    private static DnsRehearsalAdapterCandidate Candidate(
        DnsAdapterIdentity identity,
        DnsRehearsalAdapterKind kind,
        bool physical,
        bool active,
        bool virtualAdapter,
        bool supported) => new(identity, kind, physical, active, virtualAdapter, supported);

    private static DnsRehearsalBackupDocument CreateBackup() => DnsRehearsalBackupSerializer.Create(
        Guid.Parse("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"),
        new DnsRehearsalAdapterSnapshot(
            Identity,
            DnsRehearsalAdapterKind.WiFi,
            new[]
            {
                new DnsRehearsalFamilySnapshot(DnsRehearsalAddressFamily.IPv4, true, false, Ipv4Servers),
                new DnsRehearsalFamilySnapshot(DnsRehearsalAddressFamily.IPv6, true, true, Ipv6Servers)
            }),
        Now,
        Guid.Parse("BBBBBBBB-CCCC-DDDD-EEEE-FFFFFFFFFFFF"));
}
