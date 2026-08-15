// QuietShield Backend Integration 05 R1
using Microsoft.VisualStudio.TestTools.UnitTesting;
using QuietShield.Core.IntegrationWave;

namespace QuietShield.Core.Tests;

[TestClass]
public sealed class BackendIntegration05Tests
{
    [TestMethod]
    public void UnknownSystemComponentIsProtected()
    {
        var decision = CompatibilityGuardEngine.Evaluate(
            new(
                "windows:unknown",
                "Unknown Windows Component",
                true,
                DateTimeOffset.UtcNow),
            Array.Empty<CompatibilityRule>());

        Assert.AreEqual(CompatibilityTier.CriticalSystem, decision.Tier);
        Assert.IsFalse(decision.MayBeRestricted);
    }

    [TestMethod]
    public void BatterySaverSlowsWatchCadence()
    {
        var normal = AdaptiveProgramWatchCadence.GetNextDelay(false, true, false);
        var saver = AdaptiveProgramWatchCadence.GetNextDelay(true, false, false);

        Assert.IsGreaterThan(normal, saver);
    }
}
