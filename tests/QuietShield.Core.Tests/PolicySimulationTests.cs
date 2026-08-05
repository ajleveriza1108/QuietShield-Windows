using QuietShield.Core.Protection;
using QuietShield.Core.Scheduling;
using QuietShield.Core.Simulation;

namespace QuietShield.Core.Tests;

[TestClass]
public sealed class PolicySimulationTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 5, 12, 0, 0, TimeSpan.Zero);

    [TestMethod]
    public void SafetyRecoveryOutranksEveryRestriction()
    {
        var input = CreateInput() with { IsSafetyRecoveryExempt = true, IsRequiredQuietShieldComponent = true, IsParentProtected = true };
        var result = PolicySimulator.Simulate(input);
        Assert.AreEqual(SimulatedDecision.Allow, result.Decision);
        Assert.AreEqual("SafetyRecoveryExemption", result.ResponsibleRule);
    }

    [TestMethod]
    public void RequiredComponentOutranksParentProtection()
    {
        var result = PolicySimulator.Simulate(CreateInput() with { IsRequiredQuietShieldComponent = true, IsParentProtected = true });
        Assert.AreEqual(SimulatedDecision.Allow, result.Decision);
        Assert.AreEqual("RequiredQuietShieldComponentExemption", result.ResponsibleRule);
    }

    [TestMethod]
    public void ParentProtectionOutranksTemporaryAllowance()
    {
        var result = PolicySimulator.Simulate(CreateInput() with
        {
            IsParentProtected = true,
            TemporaryAllowance = new TemporaryAllowance(Now.AddHours(1), "Fixture")
        });
        Assert.AreEqual(SimulatedDecision.RequireParentApproval, result.Decision);
    }

    [TestMethod]
    public void TemporaryAllowanceOutranksCompatibilityExclusion()
    {
        var result = PolicySimulator.Simulate(CreateInput() with
        {
            TemporaryAllowance = new TemporaryAllowance(Now.AddMinutes(1), "Fixture"),
            CompatibilityExclusion = new CompatibilityExclusion("app", "Fixture exclusion"),
            IsCompatibilityExclusionActive = true
        });
        Assert.AreEqual(SimulatedDecision.AllowTemporarily, result.Decision);
        Assert.AreEqual("ActiveTemporaryAllowance", result.ResponsibleRule);
    }

    [TestMethod]
    public void CompatibilityExclusionOutranksActiveSchedule()
    {
        var result = PolicySimulator.Simulate(CreateInput() with
        {
            CompatibilityExclusion = new CompatibilityExclusion("app", "Fixture exclusion"),
            IsCompatibilityExclusionActive = true,
            Schedule = CreateActiveSchedule(ProgramConnectionPolicy.Blocked)
        });
        Assert.AreEqual(SimulatedDecision.Allow, result.Decision);
        Assert.AreEqual("ActiveCompatibilityExclusion", result.ResponsibleRule);
    }

    [TestMethod]
    public void ActiveScheduleOutranksExplicitRule()
    {
        var result = PolicySimulator.Simulate(CreateInput() with
        {
            Schedule = CreateActiveSchedule(ProgramConnectionPolicy.Blocked),
            ExplicitProgramRule = new ProgramRule("app", "Fixture", ProgramConnectionPolicy.AllowedOnAll)
        });
        Assert.AreEqual(SimulatedDecision.Block, result.Decision);
        Assert.AreEqual("ActiveSchedule", result.ResponsibleRule);
    }

    [TestMethod]
    public void ExplicitRuleOutranksProfileDefault()
    {
        var result = PolicySimulator.Simulate(CreateInput() with
        {
            ExplicitProgramRule = new ProgramRule("app", "Fixture", ProgramConnectionPolicy.Blocked),
            ProfileDefaultPolicy = ProgramConnectionPolicy.AllowedOnAll
        });
        Assert.AreEqual(SimulatedDecision.Block, result.Decision);
        Assert.AreEqual("ExplicitProgramRule", result.ResponsibleRule);
    }

    [TestMethod]
    public void ProfileDefaultIsUsedWhenNoHigherRuleMatches()
    {
        var result = PolicySimulator.Simulate(CreateInput() with { ProfileDefaultPolicy = ProgramConnectionPolicy.AllowedOnAll });
        Assert.AreEqual(SimulatedDecision.Allow, result.Decision);
        Assert.AreEqual("ProfileDefault", result.ResponsibleRule);
    }

    [TestMethod]
    [TestCategory("Phase2Smoke")]
    public void NoRuleFallsBackToIndeterminate()
    {
        var result = PolicySimulator.Simulate(CreateInput());
        Assert.AreEqual(SimulatedDecision.Indeterminate, result.Decision);
        Assert.AreEqual("SafeFallback", result.ResponsibleRule);
        Assert.AreEqual(PolicySimulationResult.SimulationOnlyLabel, result.EnforcementLabel);
    }

    [TestMethod]
    public void UnknownConnectionNeverSilentlyResolvesConnectionSpecificRule()
    {
        var result = PolicySimulator.Simulate(CreateInput() with
        {
            ConnectionType = SimulatedConnectionType.Unknown,
            ExplicitProgramRule = new ProgramRule("app", "Fixture", ProgramConnectionPolicy.WiFiOnly)
        });
        Assert.AreEqual(SimulatedDecision.Indeterminate, result.Decision);
        Assert.IsNotNull(result.Warning);
    }

    [TestMethod]
    public void ExpiredTemporaryAllowanceDoesNotOverrideExplicitRule()
    {
        var result = PolicySimulator.Simulate(CreateInput() with
        {
            TemporaryAllowance = new TemporaryAllowance(Now, "Expired fixture"),
            ExplicitProgramRule = new ProgramRule("app", "Fixture", ProgramConnectionPolicy.Blocked)
        });
        Assert.AreEqual(SimulatedDecision.Block, result.Decision);
    }

    [TestMethod]
    public void ScheduleStartIsInclusiveAndEndIsExclusive()
    {
        var schedule = new ProtectionSchedule("schedule", "Boundary", new HashSet<DayOfWeek> { DayOfWeek.Wednesday }, new TimeOnly(12, 0), new TimeOnly(13, 0), "profile", true);
        Assert.IsTrue(PolicySimulator.IsScheduleActive(schedule, Now));
        Assert.IsFalse(PolicySimulator.IsScheduleActive(schedule, Now.AddHours(1)));
    }

    [TestMethod]
    public void OvernightScheduleUsesPreviousDayBeforeEndBoundary()
    {
        var schedule = new ProtectionSchedule("schedule", "Overnight", new HashSet<DayOfWeek> { DayOfWeek.Tuesday }, new TimeOnly(22, 0), new TimeOnly(2, 0), "profile", true);
        Assert.IsTrue(PolicySimulator.IsScheduleActive(schedule, new DateTimeOffset(2026, 8, 5, 1, 59, 0, TimeSpan.Zero)));
        Assert.IsFalse(PolicySimulator.IsScheduleActive(schedule, new DateTimeOffset(2026, 8, 5, 2, 0, 0, TimeSpan.Zero)));
    }

    private static PolicySimulationInput CreateInput() => new(
        "app", SimulatedConnectionType.WiFi, CreateProfile(), null, null, Now, null, null, false, false, null, false, false);

    private static ProtectionProfile CreateProfile() => new(
        "profile", "Fixture", ProtectionMode.Standard, Array.Empty<ProgramRule>(), Array.Empty<CompatibilityExclusion>(), NotificationPriority.Normal, false);

    private static SimulationSchedule CreateActiveSchedule(ProgramConnectionPolicy policy) => new(
        new ProtectionSchedule("schedule", "Active", new HashSet<DayOfWeek> { Now.DayOfWeek }, new TimeOnly(11, 0), new TimeOnly(13, 0), "profile", true), policy);
}
