using QuietShield.Core.ConnectionLock;
using QuietShield.Core.Protection;
using QuietShield.Core.Simulation;

namespace QuietShield.Core.Tests;

[TestClass]
public sealed class Phase7ConnectionLockTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 6, 12, 0, 0, TimeSpan.Zero);
    private static readonly string[] AmbiguousAppPaths = { @"D:\One\app.exe", @"D:\Two\app.exe" };
    private static readonly string[] AmbiguousBrowserPaths = { @"D:\One\browser.exe", @"D:\Two\browser.exe" };
    private static readonly string[] AmbiguousEvidence = { "one", "two" };

    [TestMethod]
    [DataRow(ProgramConnectionPolicy.Blocked, SimulatedConnectionType.WiFi, SimulatedDecision.Block)]
    [DataRow(ProgramConnectionPolicy.WiFiOnly, SimulatedConnectionType.WiFi, SimulatedDecision.Allow)]
    [DataRow(ProgramConnectionPolicy.EthernetOnly, SimulatedConnectionType.Ethernet, SimulatedDecision.Allow)]
    [DataRow(ProgramConnectionPolicy.CellularOnly, SimulatedConnectionType.Cellular, SimulatedDecision.Allow)]
    [DataRow(ProgramConnectionPolicy.MeteredOnly, SimulatedConnectionType.Metered, SimulatedDecision.Allow)]
    [DataRow(ProgramConnectionPolicy.UnmeteredOnly, SimulatedConnectionType.Unmetered, SimulatedDecision.Allow)]
    [DataRow(ProgramConnectionPolicy.AllowedOnAll, SimulatedConnectionType.Unknown, SimulatedDecision.Allow)]
    public void AllConnectionPoliciesAreDeterministic(ProgramConnectionPolicy policy, SimulatedConnectionType connection, SimulatedDecision expected)
    {
        var result = ConnectionPolicyDecisionEngine.Evaluate(CreateInput() with
        {
            ConnectionType = connection,
            Profile = Profile(policy)
        });
        Assert.AreEqual(expected, result.Decision);
        Assert.AreEqual("ProfileDefault", result.MatchedRule);
    }

    [TestMethod]
    public void FixedBlockAllCannotBeDeletedOrEdited()
    {
        var catalog = new ProtectionProfileCatalog();
        Assert.AreSame(ConnectionLockProfile.BlockAll, catalog.SelectedProfile);
        Assert.ThrowsExactly<InvalidOperationException>(() => catalog.Delete(ConnectionLockProfile.BlockAllId));
        Assert.ThrowsExactly<InvalidOperationException>(() => catalog.Update(ConnectionLockProfile.BlockAll with { Name = "Changed" }));
    }

    [TestMethod]
    public void CatalogAllowsAtMostFiveEditableProfiles()
    {
        var catalog = new ProtectionProfileCatalog();
        for (var index = 0; index < 5; index++) catalog.Add(Profile(ProgramConnectionPolicy.AllowedOnAll, $"p{index}", $"Profile {index}"));
        Assert.HasCount(6, catalog.Profiles);
        Assert.ThrowsExactly<InvalidOperationException>(() => catalog.Add(Profile(ProgramConnectionPolicy.Blocked, "p6", "Profile 6")));
    }

    [TestMethod]
    public void DuplicateProfileNamesAreRejectedCaseInsensitively()
    {
        var catalog = new ProtectionProfileCatalog(new[] { Profile(ProgramConnectionPolicy.AllowedOnAll, "one", "Study") });
        Assert.ThrowsExactly<ArgumentException>(() => catalog.Add(Profile(ProgramConnectionPolicy.Blocked, "two", "STUDY")));
    }

    [TestMethod]
    public void ProfileValidationRejectsMalformedAndUnsupportedRules()
    {
        var ambiguous = ProgramIdentity.Ambiguous("Same name", AmbiguousAppPaths);
        var profile = Profile(ProgramConnectionPolicy.AllowedOnAll) with
        {
            ProgramOverrides = new[] { new ConnectionLockProgramRule(ambiguous, (ProgramConnectionPolicy)999) }
        };
        Assert.IsFalse(profile.Validate().IsValid);
    }

    [TestMethod]
    public void Win32IdentityRemainsStableWhenExecutableMoves()
    {
        var identity = Win32(exists: true);
        var moved = identity.MarkMoved(@"D:\Moved\browser.exe");
        Assert.AreEqual(identity.StableId, moved.StableId);
        Assert.AreEqual(ProgramPathStatus.Moved, moved.PathStatus);
        Assert.AreNotEqual(identity.ExecutablePath, moved.ExecutablePath);
    }

    [TestMethod]
    public void MissingWin32IdentityIsRepresentedWithoutDisplayNameMatching()
    {
        var identity = Win32(exists: false);
        Assert.AreEqual(ProgramPathStatus.Missing, identity.PathStatus);
        Assert.IsTrue(identity.Validate().IsValid);
        Assert.AreNotEqual(identity.DisplayName, identity.StableId);
    }

    [TestMethod]
    public void MsixIdentityRequiresPackageFamilyName()
    {
        var identity = ProgramIdentity.CreateMsix("inventory:store", "Store App", "Contoso.App_123", "CN=Contoso");
        Assert.AreEqual(ProgramIdentityKind.MicrosoftStoreOrMsix, identity.Kind);
        Assert.AreEqual(ProgramPathStatus.PackageManaged, identity.PathStatus);
        Assert.IsTrue(identity.Validate().IsValid);
    }

    [TestMethod]
    public void AmbiguousIdentityIsRefused()
    {
        var identity = ProgramIdentity.Ambiguous("Browser", AmbiguousBrowserPaths);
        var result = ConnectionPolicyDecisionEngine.Evaluate(CreateInput(identity) with { Profile = Profile(ProgramConnectionPolicy.Blocked) });
        Assert.AreEqual(SimulatedDecision.Unsupported, result.Decision);
        Assert.AreEqual("UnsupportedOrAmbiguousIdentity", result.MatchedRule);
    }

    [TestMethod]
    public void EmergencyRecoveryOutranksRequiredComponent()
    {
        var result = Evaluate(SafetyExemption.Create(SafetyExemptionKind.EmergencyRecovery), parent: true);
        Assert.AreEqual("EmergencyRecoveryExemption", result.MatchedRule);
    }

    [TestMethod]
    public void RequiredComponentOutranksParentRestriction()
    {
        var result = Evaluate(SafetyExemption.Create(SafetyExemptionKind.RequiredDnsOperations), parent: true);
        Assert.AreEqual("RequiredQuietShieldComponentExemption", result.MatchedRule);
    }

    [TestMethod]
    public void ParentRestrictionOutranksTemporaryAllowance()
    {
        var input = CreateInput() with { IsParentProtected = true, TemporaryAllowance = TimedAllowance() };
        Assert.AreEqual("ParentProtectedRestriction", ConnectionPolicyDecisionEngine.Evaluate(input).MatchedRule);
    }

    [TestMethod]
    public void TemporaryAllowanceOutranksCompatibility()
    {
        var input = CreateInput() with { TemporaryAllowance = TimedAllowance(), CompatibilityExclusion = ProgramExclusion() };
        Assert.AreEqual("ActiveTemporaryAllowance", ConnectionPolicyDecisionEngine.Evaluate(input).MatchedRule);
    }

    [TestMethod]
    public void CompatibilityOutranksSchedule()
    {
        var input = CreateInput() with { CompatibilityExclusion = ProgramExclusion(), Schedule = ActiveSchedule(ProgramConnectionPolicy.Blocked) };
        Assert.AreEqual("ActiveCompatibilityExclusion", ConnectionPolicyDecisionEngine.Evaluate(input).MatchedRule);
    }

    [TestMethod]
    public void ScheduleOutranksExplicitRule()
    {
        var input = CreateInput() with { Schedule = ActiveSchedule(ProgramConnectionPolicy.Blocked), ExplicitRule = Rule(ProgramConnectionPolicy.AllowedOnAll) };
        Assert.AreEqual("ActiveSchedule", ConnectionPolicyDecisionEngine.Evaluate(input).MatchedRule);
    }

    [TestMethod]
    public void ExplicitRuleOutranksProfileDefault()
    {
        var input = CreateInput() with { ExplicitRule = Rule(ProgramConnectionPolicy.Blocked), Profile = Profile(ProgramConnectionPolicy.AllowedOnAll) };
        Assert.AreEqual("ExplicitProgramRule", ConnectionPolicyDecisionEngine.Evaluate(input).MatchedRule);
    }

    [TestMethod]
    public void ProfileDefaultReturnsFullDecisionEvidence()
    {
        var result = ConnectionPolicyDecisionEngine.Evaluate(CreateInput());
        Assert.AreEqual("ProfileDefault", result.MatchedRule);
        Assert.AreEqual("Fixture", result.ActiveProfile);
        Assert.AreEqual(SimulatedConnectionType.WiFi, result.ConnectionType);
        Assert.AreEqual("Not configured", result.ScheduleResult);
        Assert.AreEqual("Not configured", result.CompatibilityResult);
        Assert.AreEqual("No exemption matched", result.SafetyExemptionResult);
    }

    [TestMethod]
    [DataRow(SafetyExemptionKind.QuietShieldDesktopApp)]
    [DataRow(SafetyExemptionKind.FutureQuietShieldService)]
    [DataRow(SafetyExemptionKind.LicensingRefresh)]
    [DataRow(SafetyExemptionKind.Updater)]
    [DataRow(SafetyExemptionKind.Dhcp)]
    [DataRow(SafetyExemptionKind.RequiredDnsOperations)]
    [DataRow(SafetyExemptionKind.WindowsNetworking)]
    [DataRow(SafetyExemptionKind.EmergencyRecovery)]
    public void EverySafetyExemptionHasVisibleReason(SafetyExemptionKind kind)
    {
        var exemption = SafetyExemption.Create(kind);
        Assert.IsFalse(string.IsNullOrWhiteSpace(exemption.VisibleReason));
        Assert.AreEqual(SimulatedDecision.Allow, ConnectionPolicyDecisionEngine.Evaluate(CreateInput() with { SafetyExemption = exemption }).Decision);
    }

    [TestMethod]
    public void TemporaryAllowanceExpiresAndRestoresPriorPolicy()
    {
        var allowance = TimedAllowance();
        Assert.IsTrue(allowance.IsActiveAt(Now.AddMinutes(4), true));
        Assert.IsFalse(allowance.IsActiveAt(Now.AddMinutes(5), true));
        Assert.AreEqual(ProgramConnectionPolicy.Blocked, allowance.PriorPolicy);
    }

    [TestMethod]
    public void UntilCloseAllowanceEndsWhenProgramClosesAndCleanupReturnsIt()
    {
        var store = new TemporaryAllowanceStore();
        var allowance = ProgramTemporaryAllowance.CreateTimed("inventory:browser", TemporaryAllowanceKind.UntilProgramCloses, Now, ProgramConnectionPolicy.Blocked);
        store.Add(allowance);
        Assert.IsTrue(allowance.IsActiveAt(Now.AddDays(1), true));
        var expired = store.CleanupExpired(Now.AddDays(1), _ => false);
        Assert.HasCount(1, expired);
        Assert.HasCount(0, store.Items);
    }

    [TestMethod]
    public void OvernightScheduleHonorsStartAndEndBoundaries()
    {
        var schedule = new ConnectionPolicySchedule("night", "Night", new HashSet<DayOfWeek> { DayOfWeek.Thursday }, new TimeOnly(22, 0), new TimeOnly(7, 0), TimeZoneInfo.Utc.Id, ProgramConnectionPolicy.Blocked, ConnectionSchedulePreset.Custom, 10, true);
        Assert.IsTrue(ConnectionScheduleEvaluator.IsActive(schedule, new DateTimeOffset(2026, 8, 6, 22, 0, 0, TimeSpan.Zero)));
        Assert.IsTrue(ConnectionScheduleEvaluator.IsActive(schedule, new DateTimeOffset(2026, 8, 7, 6, 59, 0, TimeSpan.Zero)));
        Assert.IsFalse(ConnectionScheduleEvaluator.IsActive(schedule, new DateTimeOffset(2026, 8, 7, 7, 0, 0, TimeSpan.Zero)));
    }

    [TestMethod]
    public void ScheduleEvaluationIsTimeZoneSafeAndReconcilesSleepWake()
    {
        var schedule = new ConnectionPolicySchedule("study", "Study", new HashSet<DayOfWeek> { DayOfWeek.Thursday }, new TimeOnly(12, 0), new TimeOnly(13, 0), TimeZoneInfo.Utc.Id, ProgramConnectionPolicy.Blocked, ConnectionSchedulePreset.Study, 10, true);
        var result = ConnectionScheduleEvaluator.Evaluate(new[] { schedule }, Now.AddMinutes(30), Now.AddMinutes(-30));
        Assert.IsTrue(result.IsActive);
        Assert.IsTrue(result.ReconciledAfterSleepOrWake);
    }

    [TestMethod]
    public void ScheduleConflictResolutionIsDeterministic()
    {
        var permissive = Schedule("z", ProgramConnectionPolicy.AllowedOnAll, 100);
        var restrictive = Schedule("a", ProgramConnectionPolicy.Blocked, 100);
        var first = ConnectionScheduleEvaluator.Evaluate(new[] { permissive, restrictive }, Now);
        var second = ConnectionScheduleEvaluator.Evaluate(new[] { restrictive, permissive }, Now);
        Assert.AreEqual("a", first.MatchedSchedule?.Id);
        Assert.AreEqual(first.MatchedSchedule, second.MatchedSchedule);
    }

    [TestMethod]
    [DataRow(CompatibilityExclusionKind.Program, "inventory:browser")]
    [DataRow(CompatibilityExclusionKind.Domain, "example.com")]
    [DataRow(CompatibilityExclusionKind.TemporaryBypass, "inventory:browser")]
    public void CompatibilityExclusionsExplainExactRelaxation(CompatibilityExclusionKind kind, string target)
    {
        var exclusion = new ConnectionCompatibilityExclusion(kind, target, "Allow only this exact target for compatibility testing.", Now.AddMinutes(15));
        exclusion.EnsureSafe();
        var result = ConnectionPolicyDecisionEngine.Evaluate(CreateInput() with { CompatibilityExclusion = exclusion });
        StringAssert.Contains(result.Reason, exclusion.Relaxation);
    }

    [TestMethod]
    public void CompatibilityGuardRefusesGlobalSilentDisable()
    {
        var exclusion = new ConnectionCompatibilityExclusion(CompatibilityExclusionKind.Domain, "*", "Disable everything");
        Assert.ThrowsExactly<ArgumentException>(exclusion.EnsureSafe);
    }

    [TestMethod]
    public void CompatibilityDomainUsesExactTrailingDotNormalization()
    {
        var exclusion = ConnectionCompatibilityExclusion.CreateDomain("Example.COM.", "Relax only this exact domain.");
        Assert.AreEqual("example.com", exclusion.Target);
        exclusion.EnsureSafe();
    }

    [TestMethod]
    public void UnknownConnectionUsesIndeterminateSafeFallbackWithoutSilentAllow()
    {
        var result = ConnectionPolicyDecisionEngine.Evaluate(CreateInput() with
        {
            ConnectionType = SimulatedConnectionType.Unknown,
            Profile = Profile(ProgramConnectionPolicy.WiFiOnly)
        });
        Assert.AreEqual(SimulatedDecision.Indeterminate, result.Decision);
        Assert.AreEqual("ProfileDefault", result.MatchedRule);
        StringAssert.Contains(result.Reason, "refuses to guess");
    }

    [TestMethod]
    public void PlannerIsDeterministicAndAlwaysIncludesRollback()
    {
        var planner = new ReadOnlyProgramEnforcementPlanner();
        var first = planner.Plan(Rule(ProgramConnectionPolicy.WiFiOnly));
        var second = planner.Plan(Rule(ProgramConnectionPolicy.WiFiOnly));
        Assert.AreEqual(first, second);
        Assert.IsGreaterThanOrEqualTo(first.RollbackSteps.Count, 3);
        Assert.AreEqual(ProposedEnforcementStrategy.ConnectionAwarePolicy, first.Strategy);
        Assert.IsFalse(first.CanExecute);
    }

    [TestMethod]
    public void PlannerRefusesMissingMovedAndAmbiguousTargets()
    {
        var planner = new ReadOnlyProgramEnforcementPlanner();
        foreach (var identity in new[] { Win32(false), Win32(true).MarkMoved(@"D:\Moved\browser.exe"), ProgramIdentity.Ambiguous("Browser", AmbiguousEvidence) })
        {
            var plan = planner.Plan(new ConnectionLockProgramRule(identity, ProgramConnectionPolicy.Blocked));
            Assert.AreEqual(ProposedEnforcementStrategy.Unsupported, plan.Strategy);
            Assert.IsNotNull(plan.UnsupportedOrAmbiguousReason);
            Assert.IsFalse(plan.CanExecute);
        }
    }

    [TestMethod]
    public void PrivacySafeJsonRoundTripPersistsSelectionWithoutPaths()
    {
        var identity = Win32(true);
        var profile = Profile(ProgramConnectionPolicy.Blocked, "focus", "Focus") with { ProgramOverrides = new[] { new ConnectionLockProgramRule(identity, ProgramConnectionPolicy.WiFiOnly) } };
        var catalog = new ProtectionProfileCatalog(new[] { profile }, "focus");
        var json = PrivacySafeProfileJson.Export(catalog.Snapshot());
        Assert.IsFalse(json.Contains(identity.ExecutablePath!, StringComparison.OrdinalIgnoreCase));
        var imported = PrivacySafeProfileJson.Import(json, new Dictionary<string, ProgramIdentity>(StringComparer.OrdinalIgnoreCase) { [identity.StableId] = identity });
        Assert.AreEqual("focus", imported.SelectedProfileId);
        Assert.AreEqual(ProgramConnectionPolicy.WiFiOnly, imported.SelectedProfile.ProgramOverrides[0].Policy);
    }

    [TestMethod]
    public void JsonImportRejectsMalformedUnsupportedAndUnknownIdentityDocuments()
    {
        Assert.ThrowsExactly<FormatException>(() => PrivacySafeProfileJson.Import("{", new Dictionary<string, ProgramIdentity>()));
        Assert.ThrowsExactly<NotSupportedException>(() => PrivacySafeProfileJson.Import("{\"schemaVersion\":99,\"selectedProfileId\":\"x\",\"profiles\":[]}", new Dictionary<string, ProgramIdentity>()));
        var json = "{\"schemaVersion\":1,\"selectedProfileId\":\"p\",\"profiles\":[{\"id\":\"p\",\"name\":\"P\",\"description\":\"D\",\"defaultPolicy\":\"Blocked\",\"parentProtected\":false,\"rules\":[{\"stableApplicationId\":\"missing\",\"kind\":\"Win32Executable\",\"policy\":\"Blocked\",\"isEnabled\":true}]}]}";
        Assert.ThrowsExactly<FormatException>(() => PrivacySafeProfileJson.Import(json, new Dictionary<string, ProgramIdentity>()));
    }

    private static ConnectionDecisionResult Evaluate(SafetyExemption? exemption = null, bool parent = false) =>
        ConnectionPolicyDecisionEngine.Evaluate(CreateInput() with { SafetyExemption = exemption, IsParentProtected = parent });

    private static ConnectionDecisionInput CreateInput(ProgramIdentity? identity = null) => new(
        identity ?? Win32(true), Profile(ProgramConnectionPolicy.AllowedOnAll), SimulatedConnectionType.WiFi, Now);

    private static ProgramIdentity Win32(bool exists) => ProgramIdentity.CreateWin32("inventory:browser", "Browser", @"D:\Apps\Browser\browser.exe", "Contoso", exists);
    private static ConnectionLockProgramRule Rule(ProgramConnectionPolicy policy) => new(Win32(true), policy);
    private static ConnectionLockProfile Profile(ProgramConnectionPolicy policy, string id = "fixture", string name = "Fixture") => new(id, name, "Fixture profile", policy, Array.Empty<ConnectionLockProgramRule>(), false);
    private static ProgramTemporaryAllowance TimedAllowance() => ProgramTemporaryAllowance.CreateTimed("inventory:browser", TemporaryAllowanceKind.FiveMinutes, Now, ProgramConnectionPolicy.Blocked);
    private static ConnectionCompatibilityExclusion ProgramExclusion() => new(CompatibilityExclusionKind.Program, "inventory:browser", "Allow only the selected program.", Now.AddMinutes(10));
    private static ScheduleEvaluation ActiveSchedule(ProgramConnectionPolicy policy) => new(true, Schedule("schedule", policy, 10), "Active fixture schedule", false);
    private static ConnectionPolicySchedule Schedule(string id, ProgramConnectionPolicy policy, int priority) => new(id, id, new HashSet<DayOfWeek> { Now.DayOfWeek }, new TimeOnly(11, 0), new TimeOnly(13, 0), TimeZoneInfo.Utc.Id, policy, ConnectionSchedulePreset.Custom, priority, true);
}
