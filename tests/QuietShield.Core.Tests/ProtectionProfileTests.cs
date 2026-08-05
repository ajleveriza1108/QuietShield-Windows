using QuietShield.Core.Protection;

namespace QuietShield.Core.Tests;

[TestClass]
public sealed class ProtectionProfileTests
{
    [TestMethod]
    public void StandardProfileWithoutProgramRulesIsValid()
    {
        var profile = CreateProfile(ProtectionMode.Standard, Array.Empty<ProgramRule>());

        var result = profile.Validate();

        Assert.IsTrue(result.IsValid, string.Join(Environment.NewLine, result.Errors));
    }

    [TestMethod]
    public void CustomProfileRequiresAtLeastOneProgramRule()
    {
        var profile = CreateProfile(ProtectionMode.Custom, Array.Empty<ProgramRule>());

        var result = profile.Validate();

        Assert.IsFalse(result.IsValid);
        CollectionAssert.Contains(result.Errors.ToArray(), "A custom profile must contain at least one program rule.");
    }

    [TestMethod]
    public void DuplicateProgramRulesAreRejectedCaseInsensitively()
    {
        var rules = new[]
        {
            new ProgramRule("browser.exe", "Browser", ProgramConnectionPolicy.AllowedOnAll),
            new ProgramRule("BROWSER.EXE", "Browser duplicate", ProgramConnectionPolicy.Blocked)
        };
        var profile = CreateProfile(ProtectionMode.Custom, rules);

        var result = profile.Validate();

        Assert.IsFalse(result.IsValid);
        Assert.IsTrue(result.Errors.Any(static error => error.Contains("more than once", StringComparison.Ordinal)));
    }

    [TestMethod]
    [DataRow(ProgramConnectionPolicy.Blocked)]
    [DataRow(ProgramConnectionPolicy.WiFiOnly)]
    [DataRow(ProgramConnectionPolicy.EthernetOnly)]
    [DataRow(ProgramConnectionPolicy.CellularOnly)]
    [DataRow(ProgramConnectionPolicy.UnmeteredOnly)]
    [DataRow(ProgramConnectionPolicy.AllowedOnAll)]
    public void EveryDefinedProgramConnectionPolicyIsValid(ProgramConnectionPolicy policy)
    {
        var rule = new ProgramRule("sample.exe", "Sample", policy);

        Assert.IsTrue(rule.Validate().IsValid);
    }

    [TestMethod]
    public void ProgramRuleRequiresStableIdentifierAndDisplayName()
    {
        var rule = new ProgramRule("", "", ProgramConnectionPolicy.Blocked);

        var result = rule.Validate();

        Assert.IsFalse(result.IsValid);
        Assert.HasCount(2, result.Errors);
    }

    private static ProtectionProfile CreateProfile(ProtectionMode mode, IReadOnlyList<ProgramRule> rules) =>
        new(
            "default",
            "Default",
            mode,
            rules,
            Array.Empty<CompatibilityExclusion>(),
            NotificationPriority.Quiet,
            false);
}
