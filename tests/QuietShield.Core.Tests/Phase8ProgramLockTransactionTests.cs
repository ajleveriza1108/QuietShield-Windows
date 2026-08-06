using QuietShield.Core.ConnectionLock;
using QuietShield.Core.ConnectionLock.Transactions;
using QuietShield.Core.Protection;
using QuietShield.Core.Simulation;

namespace QuietShield.Core.Tests;

[TestClass]
public sealed class Phase8ProgramLockTransactionTests
{
    private static readonly Guid TransactionOne = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid TransactionTwo = Guid.Parse("22222222-2222-2222-2222-222222222222");
    private static readonly DateTimeOffset Now = new(2026, 8, 6, 4, 0, 0, TimeSpan.Zero);

    [TestMethod]
    public void RuleIdIsDeterministicAndNotBasedOnDisplayNameOrTransaction()
    {
        var first = QuietShieldProgramRuleIdentity.Create(TransactionOne, "profile", Win32(), ProgramConnectionPolicy.Blocked);
        var renamed = Win32() with { DisplayName = "A completely different display name" };
        var second = QuietShieldProgramRuleIdentity.Create(TransactionTwo, "profile", renamed, ProgramConnectionPolicy.Blocked);
        Assert.AreEqual(first.StableRuleId, second.StableRuleId);
        Assert.AreEqual("QuietShield.ProgramLock." + first.StableRuleId, first.RuleName);
        Assert.AreNotEqual(first.CreationTransactionId, second.CreationTransactionId);
    }

    [TestMethod]
    public void StableWin32AndMsixIdentitiesProduceDistinctValidRules()
    {
        var win32 = QuietShieldProgramRuleIdentity.Create(TransactionOne, "profile", Win32(), ProgramConnectionPolicy.Blocked);
        var msix = QuietShieldProgramRuleIdentity.Create(TransactionOne, "profile", Msix(), ProgramConnectionPolicy.Blocked);
        Assert.IsTrue(win32.Validate().IsValid);
        Assert.IsTrue(msix.Validate().IsValid);
        Assert.AreNotEqual(win32.StableRuleId, msix.StableRuleId);
        Assert.IsNotNull(win32.ExecutablePath);
        Assert.IsNotNull(msix.MsixPackageIdentity);
    }

    [TestMethod]
    [DataRow(ProgramConnectionPolicy.Blocked, PolicyEnforcementSupport.WindowsFirewallStatic, ProposedEnforcementLayer.WindowsFirewall)]
    [DataRow(ProgramConnectionPolicy.AllowedOnAll, PolicyEnforcementSupport.WindowsFirewallStatic, ProposedEnforcementLayer.WindowsFirewall)]
    [DataRow(ProgramConnectionPolicy.WiFiOnly, PolicyEnforcementSupport.RequiresRuntimeNetworkTransitionManagement, ProposedEnforcementLayer.WindowsFirewallWithRuntimeTransitions)]
    [DataRow(ProgramConnectionPolicy.EthernetOnly, PolicyEnforcementSupport.RequiresRuntimeNetworkTransitionManagement, ProposedEnforcementLayer.WindowsFirewallWithRuntimeTransitions)]
    [DataRow(ProgramConnectionPolicy.CellularOnly, PolicyEnforcementSupport.RequiresRuntimeNetworkTransitionManagement, ProposedEnforcementLayer.UserModeWindowsFilteringPlatform)]
    [DataRow(ProgramConnectionPolicy.MeteredOnly, PolicyEnforcementSupport.RequiresRuntimeNetworkTransitionManagement, ProposedEnforcementLayer.UserModeWindowsFilteringPlatform)]
    [DataRow(ProgramConnectionPolicy.UnmeteredOnly, PolicyEnforcementSupport.RequiresRuntimeNetworkTransitionManagement, ProposedEnforcementLayer.UserModeWindowsFilteringPlatform)]
    public void EveryPolicyReportsHonestEnforceability(ProgramConnectionPolicy policy, PolicyEnforcementSupport expected, ProposedEnforcementLayer layer)
    {
        var result = PolicyEnforceabilityClassifier.Classify(policy);
        Assert.AreEqual(expected, result.Support);
        Assert.AreEqual(layer, result.Layer);
        Assert.IsFalse(string.IsNullOrWhiteSpace(result.Reason));
    }

    [TestMethod]
    public void MissingAndMovedExecutablesProduceUnsupportedOperations()
    {
        var profile = Profile();
        foreach (var identity in new[] { Win32(false), Win32().MarkMoved(@"D:\Moved\browser.exe") })
        {
            var plan = ProgramLockRulePlanGenerator.Generate(TransactionOne, profile,
                new[] { new ConnectionLockProgramRule(identity, ProgramConnectionPolicy.Blocked) },
                Array.Empty<QuietShieldProgramRuleIdentity>());
            Assert.AreEqual(ProgramLockRuleOperationKind.Unsupported, plan.Operations.Single().Operation);
            Assert.IsFalse(plan.IsValid);
        }
    }

    [TestMethod]
    public void PreflightReturnsEveryExplicitBlockerAndWarning()
    {
        var input = new ProgramLockPreflightInput(
            false, false, false, Profile(), Win32(false), ProgramConnectionPolicy.MeteredOnly, 2, true,
            SimulatedConnectionType.Unknown, false);
        var result = ProgramLockPreflightEvaluator.Evaluate(input);
        Assert.IsFalse(result.Passed);
        foreach (var code in new[]
                 {
                     "AdministratorRequired", "FirewallServiceUnavailable", "BaseFilteringEngineUnavailable",
                     "ExecutableUnavailable", "ConflictingTransaction", "RuntimeTransitionManagementRequired",
                     "EmergencyRecoveryUnavailable"
                 })
            Assert.IsTrue(result.Blockers.Any(finding => finding.Code.Equals(code, StringComparison.Ordinal)), code);
        Assert.IsTrue(result.Warnings.Any(static finding => finding.Code == "ExistingOwnedRules"));
        Assert.IsTrue(result.Warnings.Any(static finding => finding.Code == "ConnectionTypeUnknown"));
    }

    [TestMethod]
    public void ValidFutureContextPassesBlockedPolicyPreflight()
    {
        var result = ProgramLockPreflightEvaluator.Evaluate(new(
            true, true, true, Profile(), Win32(), ProgramConnectionPolicy.Blocked, 0, false,
            SimulatedConnectionType.Ethernet, true));
        Assert.IsTrue(result.Passed, string.Join(Environment.NewLine, result.Blockers.Select(static item => item.Message)));
    }

    [TestMethod]
    public void NewBlockedPolicyProducesDeterministicAddPlan()
    {
        var desired = new[] { Rule(ProgramConnectionPolicy.Blocked) };
        var first = ProgramLockRulePlanGenerator.Generate(TransactionOne, Profile(), desired, Array.Empty<QuietShieldProgramRuleIdentity>());
        var second = ProgramLockRulePlanGenerator.Generate(TransactionOne, Profile(), desired, Array.Empty<QuietShieldProgramRuleIdentity>());
        Assert.AreEqual(first.PlanSha256, second.PlanSha256);
        CollectionAssert.AreEqual(first.Operations.ToArray(), second.Operations.ToArray());
        Assert.AreEqual(ProgramLockRuleOperationKind.Add, first.Operations.Single().Operation);
        Assert.IsFalse(first.CanExecute);
    }

    [TestMethod]
    public async Task HypotheticalSecondApplicationProducesNoChange()
    {
        var desired = new[] { Rule(ProgramConnectionPolicy.Blocked) };
        var first = ProgramLockRulePlanGenerator.Generate(TransactionOne, Profile(), desired, Array.Empty<QuietShieldProgramRuleIdentity>());
        var environment = new InMemoryProgramLockRuleEnvironment();
        await environment.ApplyPlanAsync(first, CancellationToken.None);
        var after = await environment.EnumerateAsync(CancellationToken.None);
        var second = ProgramLockRulePlanGenerator.Generate(TransactionTwo, Profile(), desired, after);
        Assert.AreEqual(ProgramLockRuleOperationKind.NoChange, second.Operations.Single().Operation);
        Assert.IsTrue(second.IsValid);
    }

    [TestMethod]
    public void ChangedPolicyOrProfileProducesReplacement()
    {
        var existing = QuietShieldProgramRuleIdentity.Create(TransactionOne, "old-profile", Win32(), ProgramConnectionPolicy.Blocked);
        var plan = ProgramLockRulePlanGenerator.Generate(TransactionTwo, Profile("new-profile"),
            new[] { Rule(ProgramConnectionPolicy.Blocked) }, new[] { existing });
        var operation = plan.Operations.Single();
        Assert.AreEqual(ProgramLockRuleOperationKind.Replace, operation.Operation);
        Assert.AreEqual(ProgramLockRollbackCounterpart.RestoreReplacedRule, operation.RollbackCounterpart);
    }

    [TestMethod]
    public void AllowedOnAllRemovesOnlyExistingOwnedRestriction()
    {
        var existing = QuietShieldProgramRuleIdentity.Create(TransactionOne, "profile", Win32(), ProgramConnectionPolicy.Blocked);
        var plan = ProgramLockRulePlanGenerator.Generate(TransactionTwo, Profile(),
            new[] { Rule(ProgramConnectionPolicy.AllowedOnAll) }, new[] { existing });
        Assert.AreEqual(ProgramLockRuleOperationKind.Remove, plan.Operations.Single().Operation);
        Assert.AreEqual(existing, plan.Operations.Single().ExistingRule);
    }

    [TestMethod]
    public void DuplicateDesiredRuleAndForeignCollisionAreRefused()
    {
        var duplicated = new[] { Rule(ProgramConnectionPolicy.Blocked), Rule(ProgramConnectionPolicy.Blocked) };
        var duplicatePlan = ProgramLockRulePlanGenerator.Generate(TransactionOne, Profile(), duplicated, Array.Empty<QuietShieldProgramRuleIdentity>());
        Assert.IsTrue(duplicatePlan.Operations.Any(static operation => operation.Operation == ProgramLockRuleOperationKind.Unsupported));
        var proposed = QuietShieldProgramRuleIdentity.Create(TransactionOne, "profile", Win32(), ProgramConnectionPolicy.Blocked);
        var collisions = new[] { new ForeignProgramLockRuleCollision(proposed.RuleName, "Third party") };
        var collisionPlan = ProgramLockRulePlanGenerator.Generate(TransactionOne, Profile(),
            new[] { Rule(ProgramConnectionPolicy.Blocked) }, Array.Empty<QuietShieldProgramRuleIdentity>(), collisions);
        StringAssert.Contains(collisionPlan.Operations.Single().Reason, "foreign rule");
    }

    [TestMethod]
    public void ConnectionSpecificPolicyIsNeverPretendedToBeStatic()
    {
        var plan = ProgramLockRulePlanGenerator.Generate(TransactionOne, Profile(),
            new[] { Rule(ProgramConnectionPolicy.WiFiOnly) }, Array.Empty<QuietShieldProgramRuleIdentity>());
        var operation = plan.Operations.Single();
        Assert.AreEqual(ProgramLockRuleOperationKind.Unsupported, operation.Operation);
        Assert.AreEqual(PolicyEnforcementSupport.RequiresRuntimeNetworkTransitionManagement, operation.Enforceability);
    }

    [TestMethod]
    public void SafetyExemptionProducesAllowedDecisionAndNoBlockingPlan()
    {
        var exempt = ConnectionPolicyDecisionEngine.Evaluate(new(
            Win32(), Profile(), SimulatedConnectionType.WiFi, Now,
            SafetyExemption: SafetyExemption.Create(SafetyExemptionKind.EmergencyRecovery)));
        Assert.AreEqual(SimulatedDecision.Allow, exempt.Decision);
        var plan = ProgramLockRulePlanGenerator.Generate(TransactionOne, Profile(),
            new[] { Rule(ProgramConnectionPolicy.AllowedOnAll) }, Array.Empty<QuietShieldProgramRuleIdentity>());
        Assert.AreEqual(ProgramLockRuleOperationKind.NoChange, plan.Operations.Single().Operation);
    }

    [TestMethod]
    public void BackupHashIncludesOrderedOwnedRulesAndValidates()
    {
        var rules = new[]
        {
            QuietShieldProgramRuleIdentity.Create(TransactionOne, "profile", Win32(), ProgramConnectionPolicy.Blocked),
            QuietShieldProgramRuleIdentity.Create(TransactionOne, "profile", Msix(), ProgramConnectionPolicy.Blocked)
        };
        var backup = Backup(rules);
        Assert.IsTrue(ProgramLockBackupValidator.Validate(backup).IsValid);
        var reversed = backup with { QuietShieldOwnedRules = backup.QuietShieldOwnedRules.Reverse().ToArray() };
        Assert.IsFalse(ProgramLockBackupValidator.Validate(reversed).IsValid);
    }

    [TestMethod]
    public void MalformedHashAndForeignOwnershipAreRefused()
    {
        var backup = Backup();
        Assert.IsFalse(ProgramLockBackupValidator.Validate(backup with { PayloadSha256 = new string('0', 64) }).IsValid);
        Assert.IsFalse(ProgramLockBackupValidator.Validate(backup with { ProductMarker = "Foreign" }).IsValid);
    }

    [TestMethod]
    public async Task MalformedJsonAndMissingCollectionsAreRefusedAsInvalidData()
    {
        var directory = Path.Combine(Path.GetTempPath(), "QuietShield-Phase8-Malformed-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var path = Path.Combine(directory, "backup.json");
            var store = new AtomicJsonProgramLockBackupStore();
            await File.WriteAllTextAsync(path, "{not-json", CancellationToken.None);
            await Assert.ThrowsExactlyAsync<InvalidDataException>(() => store.ReadValidatedAsync(path, CancellationToken.None));
            await File.WriteAllTextAsync(path,
                "{\"schemaVersion\":1,\"productMarker\":\"QuietShield\",\"purpose\":\"ProgramLockTransactionBackup\",\"backupId\":\"33333333-3333-3333-3333-333333333333\",\"transactionId\":\"11111111-1111-1111-1111-111111111111\",\"createdAtUtc\":\"2026-08-06T04:00:00+00:00\",\"activeProfileId\":\"profile\",\"payloadSha256\":\"invalid\"}",
                CancellationToken.None);
            await Assert.ThrowsExactlyAsync<InvalidDataException>(() => store.ReadValidatedAsync(path, CancellationToken.None));
        }
        finally
        {
            Directory.Delete(directory, true);
        }
    }

    [TestMethod]
    public async Task AtomicStoreWritesValidatedBackupLastKnownGoodAndAppendOnlyHistory()
    {
        var directory = Path.Combine(Path.GetTempPath(), "QuietShield-Phase8-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var store = new AtomicJsonProgramLockBackupStore();
            var backup = Backup();
            var backupPath = Path.Combine(directory, "backup.json");
            var lastKnownGood = Path.Combine(directory, "last-known-good.json");
            var history = Path.Combine(directory, "history.jsonl");
            await store.SaveAsync(backup, backupPath, lastKnownGood, history, CancellationToken.None);
            await store.SaveAsync(backup with { BackupId = Guid.Parse("55555555-5555-5555-5555-555555555555") } with
            {
                PayloadSha256 = ProgramLockBackupHash.Compute(backup with { BackupId = Guid.Parse("55555555-5555-5555-5555-555555555555") })
            }, backupPath, lastKnownGood, history, CancellationToken.None);
            Assert.IsTrue(File.Exists(backupPath));
            Assert.IsTrue(File.Exists(lastKnownGood));
            Assert.HasCount(2, File.ReadAllLines(history));
            _ = await store.ReadValidatedAsync(backupPath, CancellationToken.None);
        }
        finally
        {
            Directory.Delete(directory, true);
        }
    }

    [TestMethod]
    public async Task PartialApplyRollbackRestoresExactOwnedRulesAndPreservesForeignNames()
    {
        var original = QuietShieldProgramRuleIdentity.Create(TransactionOne, "profile", Win32(), ProgramConnectionPolicy.Blocked);
        var backup = Backup(new[] { original });
        var partial = QuietShieldProgramRuleIdentity.Create(TransactionTwo, "new-profile", Msix(), ProgramConnectionPolicy.Blocked);
        var partialRules = new[] { partial };
        var foreignRules = new[] { "ThirdParty.Rule" };
        var environment = new FixtureProgramLockRuleEnvironment(partialRules, foreignRules);
        var restored = await ProgramLockRollbackCoordinator.RestoreAsync(backup, environment, CancellationToken.None);
        var rules = await environment.EnumerateAsync(CancellationToken.None);
        Assert.AreEqual(1, restored);
        Assert.AreEqual(original, rules.Single());
        CollectionAssert.Contains(environment.ForeignRuleNames.ToArray(), "ThirdParty.Rule");
    }

    [TestMethod]
    public async Task InterruptedRecoveryRestoresBackupFromEveryInterruptedState()
    {
        var original = QuietShieldProgramRuleIdentity.Create(TransactionOne, "profile", Win32(), ProgramConnectionPolicy.Blocked);
        var backup = Backup(new[] { original });
        foreach (var state in new[]
                 {
                     ProgramLockTransactionState.ApplyStarted, ProgramLockTransactionState.RulesApplied,
                     ProgramLockTransactionState.VerificationStarted, ProgramLockTransactionState.InterruptedRecoveryRequired
                 })
        {
            var environment = new InMemoryProgramLockRuleEnvironment();
            await environment.RecoverInterruptedAsync(backup, state, CancellationToken.None);
            Assert.AreEqual(original, (await environment.EnumerateAsync(CancellationToken.None)).Single());
        }
    }

    [TestMethod]
    public async Task EmergencyRemovalRemovesOnlyOwnedRules()
    {
        var owned = QuietShieldProgramRuleIdentity.Create(TransactionOne, "profile", Win32(), ProgramConnectionPolicy.Blocked);
        var ownedRules = new[] { owned };
        var foreignRules = new[] { "Microsoft.Rule", "ThirdParty.Rule" };
        var environment = new InMemoryProgramLockRuleEnvironment(ownedRules, foreignRules);
        var count = await ProgramLockRollbackCoordinator.EmergencyRemoveOwnedAsync(environment, environment, CancellationToken.None);
        Assert.AreEqual(1, count);
        Assert.HasCount(0, await environment.EnumerateAsync(CancellationToken.None));
        Assert.HasCount(2, environment.ForeignRuleNames);
    }

    [TestMethod]
    public void RecoveryPlannerHandlesRollbackCrashShutdownStaleSwitchMissingAndMalformed()
    {
        var backup = Backup();
        foreach (var scenario in new[]
                 {
                     ProgramLockRecoveryScenario.NormalRollback, ProgramLockRecoveryScenario.PartialApply,
                     ProgramLockRecoveryScenario.ApplicationCrash, ProgramLockRecoveryScenario.SystemShutdown,
                     ProgramLockRecoveryScenario.StaleTransaction, ProgramLockRecoveryScenario.ProfileSwitch,
                     ProgramLockRecoveryScenario.MissingExecutable, ProgramLockRecoveryScenario.EmergencyOwnedRuleRemoval
                 })
        {
            var plan = ProgramLockRecoveryPlanner.Plan(scenario, backup, ProgramLockTransactionState.InterruptedRecoveryRequired,
                Now.AddHours(-1), Now, executableAvailable: scenario != ProgramLockRecoveryScenario.MissingExecutable);
            Assert.IsTrue(plan.CanProceed, scenario.ToString());
            Assert.IsTrue(plan.RemovesOnlyQuietShieldOwnedRules);
        }
        var malformed = backup with { ProductMarker = "Foreign" };
        Assert.IsFalse(ProgramLockRecoveryPlanner.Plan(ProgramLockRecoveryScenario.MalformedBackup, malformed,
            ProgramLockTransactionState.InterruptedRecoveryRequired, Now.AddHours(-1), Now).CanProceed);
        Assert.IsFalse(ProgramLockRecoveryPlanner.Plan(ProgramLockRecoveryScenario.StaleTransaction, backup,
            ProgramLockTransactionState.InterruptedRecoveryRequired, Now.AddMinutes(-1), Now).CanProceed);
    }

    [TestMethod]
    public void TransactionStateMachineSupportsHappyPathWithHashChainedHistory()
    {
        var machine = new ProgramLockTransactionStateMachine(TransactionOne, Now);
        foreach (var state in new[]
                 {
                     ProgramLockTransactionState.PreflightPassed, ProgramLockTransactionState.BackupCreated,
                     ProgramLockTransactionState.PlanValidated, ProgramLockTransactionState.ApplyStarted,
                     ProgramLockTransactionState.RulesApplied, ProgramLockTransactionState.VerificationStarted,
                     ProgramLockTransactionState.VerificationPassed, ProgramLockTransactionState.Committed
                 })
            machine.TransitionTo(state, Now.AddMinutes(machine.History.Count), state.ToString());
        Assert.AreEqual(ProgramLockTransactionState.Committed, machine.State);
        Assert.HasCount(9, machine.History);
        for (var index = 1; index < machine.History.Count; index++)
            Assert.AreEqual(machine.History[index - 1].EntrySha256, machine.History[index].PreviousEntrySha256);
    }

    [TestMethod]
    public void FailureBeforeApplyIsSafeAndFailureAfterApplyRequiresRollback()
    {
        var before = new ProgramLockTransactionStateMachine(TransactionOne, Now);
        before.Fail(Now.AddMinutes(1), "Preflight failed", false);
        Assert.AreEqual(ProgramLockTransactionState.FailedSafely, before.State);

        var after = new ProgramLockTransactionStateMachine(TransactionTwo, Now);
        after.TransitionTo(ProgramLockTransactionState.PreflightPassed, Now.AddMinutes(1), "Preflight");
        after.TransitionTo(ProgramLockTransactionState.BackupCreated, Now.AddMinutes(2), "Backup");
        after.TransitionTo(ProgramLockTransactionState.PlanValidated, Now.AddMinutes(3), "Plan");
        after.TransitionTo(ProgramLockTransactionState.ApplyStarted, Now.AddMinutes(4), "Apply");
        after.Fail(Now.AddMinutes(5), "Failure", false);
        Assert.AreEqual(ProgramLockTransactionState.RollbackStarted, after.State);
    }

    [TestMethod]
    public void InterruptedFailureRequiresRecoveryAndInvalidTransitionsAreRefused()
    {
        var machine = new ProgramLockTransactionStateMachine(TransactionOne, Now);
        Assert.ThrowsExactly<InvalidOperationException>(() => machine.TransitionTo(ProgramLockTransactionState.Committed, Now, "Skip"));
        machine.TransitionTo(ProgramLockTransactionState.PreflightPassed, Now.AddMinutes(1), "Preflight");
        machine.TransitionTo(ProgramLockTransactionState.BackupCreated, Now.AddMinutes(2), "Backup");
        machine.TransitionTo(ProgramLockTransactionState.PlanValidated, Now.AddMinutes(3), "Plan");
        machine.TransitionTo(ProgramLockTransactionState.ApplyStarted, Now.AddMinutes(4), "Apply");
        machine.Fail(Now.AddMinutes(5), "Shutdown", true);
        Assert.AreEqual(ProgramLockTransactionState.InterruptedRecoveryRequired, machine.State);
        Assert.IsTrue(machine.RequiresRollback);
    }

    [TestMethod]
    public void VerificationRequiresExactOwnedRuleSetBackupAndRecovery()
    {
        var desired = new[] { Rule(ProgramConnectionPolicy.Blocked) };
        var plan = ProgramLockRulePlanGenerator.Generate(TransactionOne, Profile(), desired, Array.Empty<QuietShieldProgramRuleIdentity>());
        var expected = new[] { plan.Operations.Single().ProposedRule! };
        var backup = Backup();
        var result = ProgramLockVerificationService.Verify(new(plan, expected, expected, backup, true));
        Assert.IsTrue(result.Passed, string.Join(Environment.NewLine, result.Errors));
        Assert.AreEqual(SimulatedDecision.Block, result.SimulatedOutcomes[Win32().StableId]);
        var failed = ProgramLockVerificationService.Verify(new(plan, expected, Array.Empty<QuietShieldProgramRuleIdentity>(), backup, false));
        Assert.IsFalse(failed.Passed);
    }

    private static ProgramIdentity Win32(bool exists = true) => ProgramIdentity.CreateWin32("inventory:browser", "Browser", @"D:\Apps\Browser\browser.exe", "Contoso", exists);
    private static ProgramIdentity Msix() => ProgramIdentity.CreateMsix("inventory:store", "Store App", "Contoso.App_123", "CN=Contoso");
    private static ConnectionLockProgramRule Rule(ProgramConnectionPolicy policy) => new(Win32(), policy);
    private static ConnectionLockProfile Profile(string id = "profile") => new(id, "Profile", "Fixture", ProgramConnectionPolicy.AllowedOnAll, Array.Empty<ConnectionLockProgramRule>(), false);
    private static ProgramLockBackup Backup(IReadOnlyList<QuietShieldProgramRuleIdentity>? rules = null) => ProgramLockBackup.Create(
        TransactionOne, "profile", new[] { Rule(ProgramConnectionPolicy.Blocked) }, rules ?? Array.Empty<QuietShieldProgramRuleIdentity>(), Now,
        Guid.Parse("33333333-3333-3333-3333-333333333333"));
}
