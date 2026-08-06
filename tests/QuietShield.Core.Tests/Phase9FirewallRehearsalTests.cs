using System.Net;
using System.Net.Sockets;
using QuietShield.Core.ConnectionLock.Rehearsal;

namespace QuietShield.Core.Tests;

[TestClass]
public sealed class Phase9FirewallRehearsalTests
{
    private static readonly Guid TransactionId = Guid.Parse("99999999-9999-9999-9999-999999999999");
    private static readonly DateTimeOffset Now = new(2026, 8, 6, 5, 0, 0, TimeSpan.Zero);
    private static readonly string ProbePath = Path.Combine(Path.GetPathRoot(Environment.SystemDirectory)!, "QuietShield-Tests", "QuietShield.ConnectionProbe.exe");

    [TestMethod]
    [TestCategory("Phase9Smoke")]
    public void RehearsalRuleIdentityIsDeterministicAndExact()
    {
        var first = Rule();
        var second = Rule();
        Assert.AreEqual(first, second);
        Assert.AreEqual("QuietShield.ProgramLock.Rehearsal." + TransactionId.ToString("D"), first.RuleName);
        Assert.IsTrue(first.Validate().IsValid);
        Assert.AreEqual("QuietShield rehearsal; schema=1; tx=99999999999999999999999999999999; temporary=1", first.Description);
        Assert.IsTrue(first.Description.All(character => character <= 127));
        Assert.AreEqual(81, first.Description.Length);
    }

    [TestMethod]
    public void DescriptionUsesDeterministicLowercaseTransactionIdFormatting()
    {
        var transactionId = Guid.Parse("ABCDEFAB-CDEF-ABCD-EFAB-CDEFABCDEFAB");
        Assert.AreEqual("QuietShield rehearsal; schema=1; tx=abcdefabcdefabcdefabcdefabcdefab; temporary=1",
            ProgramLockRehearsalRuleIdentity.CreateDescription(transactionId));
    }

    [TestMethod]
    [DataRow("\n")]
    [DataRow("\t")]
    public void DescriptionRejectsNewlineAndTab(string prohibitedCharacter)
    {
        Assert.IsFalse((Rule() with { Description = Rule().Description + prohibitedCharacter }).Validate().IsValid);
    }

    [TestMethod]
    public void DescriptionRejectsNonAsciiPunctuation()
    {
        Assert.IsFalse((Rule() with { Description = Rule().Description.Replace(';', '—') }).Validate().IsValid);
    }

    [TestMethod]
    public void DescriptionEnforcesMaximumLength()
    {
        var result = (Rule() with { Description = new string('A', ProgramLockRehearsalRuleIdentity.MaximumDescriptionLength + 1) }).Validate();
        Assert.IsFalse(result.IsValid);
        Assert.IsTrue(result.Errors.Any(error => error.Contains("160", StringComparison.Ordinal)));
    }

    [TestMethod]
    public void ForeignRuleOwnershipAndNonProbeTargetAreRefused()
    {
        Assert.IsFalse((Rule() with { OwnershipMarker = "Foreign" }).Validate().IsValid);
        Assert.IsFalse((Rule() with { ProgramPath = Path.Combine(Path.GetPathRoot(Environment.SystemDirectory)!, "Windows", "System32", "powershell.exe") }).Validate().IsValid);
    }

    [TestMethod]
    [TestCategory("Phase9Smoke")]
    public void TransactionHashAndMaximumDurationAreValidated()
    {
        var transaction = Transaction();
        Assert.IsTrue(transaction.Validate().IsValid);
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => CreateTransaction(TimeSpan.FromSeconds(121)));
        Assert.IsFalse((transaction with { PayloadSha256 = new string('0', 64) }).Validate().IsValid);
    }

    [TestMethod]
    public void RehearsalStateMachineAllowsOnlyTheExactSequence()
    {
        var machine = new ProgramLockFirewallRehearsalStateMachine(ProgramLockFirewallRehearsalState.Prepared);
        foreach (var state in new[]
                 {
                     ProgramLockFirewallRehearsalState.EndpointVerified, ProgramLockFirewallRehearsalState.BackupCreated,
                     ProgramLockFirewallRehearsalState.WatchdogStarted, ProgramLockFirewallRehearsalState.RuleCreated,
                     ProgramLockFirewallRehearsalState.RuleVerified, ProgramLockFirewallRehearsalState.BlockVerified,
                     ProgramLockFirewallRehearsalState.RehearsalActive, ProgramLockFirewallRehearsalState.RollbackStarted,
                     ProgramLockFirewallRehearsalState.RuleRemoved, ProgramLockFirewallRehearsalState.ConnectivityRestored,
                     ProgramLockFirewallRehearsalState.Completed
                 })
            machine.TransitionTo(state);
        Assert.AreEqual(ProgramLockFirewallRehearsalState.Completed, machine.State);
        Assert.ThrowsExactly<InvalidOperationException>(() => machine.TransitionTo(ProgramLockFirewallRehearsalState.Prepared));
    }

    [TestMethod]
    public void FailureImmediatelyAfterRuleCreationRequestsRollback()
    {
        var machine = new ProgramLockFirewallRehearsalStateMachine(ProgramLockFirewallRehearsalState.RuleCreated);
        machine.Fail();
        Assert.AreEqual(ProgramLockFirewallRehearsalState.RollbackStarted, machine.State);
    }

    [TestMethod]
    [DataRow(ProgramLockWatchdogTrigger.DeadlineExpired)]
    [DataRow(ProgramLockWatchdogTrigger.HeartbeatLost)]
    [DataRow(ProgramLockWatchdogTrigger.ParentProcessLost)]
    [DataRow(ProgramLockWatchdogTrigger.VerificationFailed)]
    [DataRow(ProgramLockWatchdogTrigger.ProbeExitedUnexpectedly)]
    [DataRow(ProgramLockWatchdogTrigger.RollbackRequested)]
    public void WatchdogRequestsCleanupForEveryRequiredTrigger(ProgramLockWatchdogTrigger trigger)
    {
        var result = ProgramLockFirewallWatchdogEvaluator.Evaluate(Observation(trigger));
        Assert.IsTrue(result.CleanupRequired);
        Assert.AreEqual(trigger, result.Trigger);
    }

    [TestMethod]
    [TestCategory("Phase9Smoke")]
    public void ExactCleanupIsIdempotentAndPreservesEveryUnrelatedRule()
    {
        var transaction = Transaction().WithState(ProgramLockFirewallRehearsalState.RollbackStarted);
        var unrelated = new[] { "Microsoft.Rule", "ThirdParty.Rule", "QuietShield.ProgramLock.Other", "QuietShield.ProgramLock.Rehearsal.not-the-transaction" };
        var store = new InMemoryExactProgramLockRehearsalRuleStore(unrelated.Append(transaction.ProposedRule.RuleName));
        Assert.IsTrue(ProgramLockFirewallRehearsalCleanup.RemoveExactValidatedRule(transaction, store));
        Assert.IsFalse(ProgramLockFirewallRehearsalCleanup.RemoveExactValidatedRule(transaction, store));
        CollectionAssert.AreEquivalent(unrelated, store.RuleNames.ToArray());
    }

    [TestMethod]
    public void MalformedAndCompletedTransactionsAreRefusedForCleanup()
    {
        var store = new InMemoryExactProgramLockRehearsalRuleStore(Array.Empty<string>());
        Assert.ThrowsExactly<InvalidDataException>(() => ProgramLockFirewallRehearsalCleanup.RemoveExactValidatedRule(Transaction() with { ProductMarker = "Foreign" }, store));
        var completed = Transaction().WithState(ProgramLockFirewallRehearsalState.Completed, completed: true);
        Assert.ThrowsExactly<InvalidDataException>(() => ProgramLockFirewallRehearsalCleanup.RemoveExactValidatedRule(completed, store));
    }

    [TestMethod]
    public void ConcurrentActiveRehearsalIsRefused()
    {
        Assert.ThrowsExactly<InvalidOperationException>(() => ProgramLockFirewallRehearsalCleanup.RefuseConcurrent(new[] { Transaction() }));
        ProgramLockFirewallRehearsalCleanup.RefuseConcurrent(new[] { Transaction().WithState(ProgramLockFirewallRehearsalState.Completed, completed: true) });
    }

    [TestMethod]
    public async Task ProbeRejectsInvalidArgumentsWithDeterministicExitCode()
    {
        var dnsName = new[] { "example.com", "443", "1000" };
        var invalidPort = new[] { "127.0.0.1", "0", "1000" };
        var invalidTimeout = new[] { "127.0.0.1", "443", "121000" };
        Assert.AreEqual(20, await QuietShield.ConnectionProbe.Program.Main(dnsName));
        Assert.AreEqual(20, await QuietShield.ConnectionProbe.Program.Main(invalidPort));
        Assert.AreEqual(20, await QuietShield.ConnectionProbe.Program.Main(invalidTimeout));
    }

    [TestMethod]
    [TestCategory("Phase9Smoke")]
    public async Task ProbeSucceedsAgainstReachableLiteralIpEndpoint()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var accept = listener.AcceptTcpClientAsync();
            var arguments = new[] { "127.0.0.1", port.ToString(System.Globalization.CultureInfo.InvariantCulture), "2000" };
            Assert.AreEqual(0, await QuietShield.ConnectionProbe.Program.Main(arguments));
            using var accepted = await accept;
            Assert.IsTrue(accepted.Connected);
        }
        finally
        {
            listener.Stop();
        }
    }

    [TestMethod]
    public async Task ProbeReturnsBlockedOrTimedOutForUnreachableLiteralIp()
    {
        var arguments = new[] { "192.0.2.1", "443", "100" };
        Assert.AreEqual(10, await QuietShield.ConnectionProbe.Program.Main(arguments));
    }

    private static ProgramLockRehearsalRuleIdentity Rule() => ProgramLockRehearsalRuleIdentity.Create(
        TransactionId, ProbePath, IPAddress.Parse("93.184.216.34"), 443, Now.AddSeconds(60));

    private static ProgramLockFirewallRehearsalTransaction Transaction() => CreateTransaction(TimeSpan.FromSeconds(60));

    private static ProgramLockFirewallRehearsalTransaction CreateTransaction(TimeSpan duration) => ProgramLockFirewallRehearsalTransaction.Create(
        TransactionId, Now, duration, Rule(), Array.Empty<string>(),
        new[] { new FirewallProfileEvidence("Domain", true, "Block", "Allow") }, true, true);

    private static ProgramLockWatchdogObservation Observation(ProgramLockWatchdogTrigger trigger) => new(
        trigger == ProgramLockWatchdogTrigger.DeadlineExpired ? Now.AddSeconds(61) : Now,
        Now.AddSeconds(60),
        trigger != ProgramLockWatchdogTrigger.ParentProcessLost,
        trigger == ProgramLockWatchdogTrigger.HeartbeatLost,
        trigger == ProgramLockWatchdogTrigger.HeartbeatLost ? Now.AddSeconds(-10) : Now,
        TimeSpan.FromSeconds(5),
        trigger == ProgramLockWatchdogTrigger.VerificationFailed,
        trigger == ProgramLockWatchdogTrigger.ProbeExitedUnexpectedly,
        trigger == ProgramLockWatchdogTrigger.RollbackRequested,
        true,
        false);
}
