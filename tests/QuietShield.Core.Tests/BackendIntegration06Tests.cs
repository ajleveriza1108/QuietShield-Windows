// QuietShield Backend Integration 06 R1
using Microsoft.VisualStudio.TestTools.UnitTesting;
using QuietShield.Core.FinalBackends;
using QuietShield.Core.IntegrationWave;

namespace QuietShield.Core.Tests;

[TestClass]
public sealed class BackendIntegration06Tests
{
    [TestMethod]
    public void ChildBlockedApplicationIsDenied()
    {
        var coordinator = new ParentChildRuntimeCoordinator(
            ParentChildRuntimeCoordinator.CreateIntegrityKey());

        coordinator.SetPolicy(new(
            "child-1",
            "Child",
            true,
            ["app:blocked"],
            Array.Empty<string>(),
            Array.Empty<string>(),
            Array.Empty<DailyAccessWindow>(),
            false,
            true));

        var result = coordinator.Evaluate(new(
            FamilyRole.Child,
            DateTimeOffset.Now,
            "app:blocked",
            null));

        Assert.IsFalse(result.Allowed);
    }

    [TestMethod]
    public void ProtectedPolicyRoundTrips()
    {
        var key = ParentChildRuntimeCoordinator.CreateIntegrityKey();
        var source = new ParentChildRuntimeCoordinator(key);
        source.SetPolicy(new(
            "child-1",
            "Child",
            true,
            Array.Empty<string>(),
            Array.Empty<string>(),
            Array.Empty<string>(),
            Array.Empty<DailyAccessWindow>(),
            false,
            true));

        var envelope = source.ExportProtectedPolicy();
        var restored = new ParentChildRuntimeCoordinator(key);
        restored.ImportProtectedPolicy(envelope);

        Assert.IsTrue(restored.HasPolicy);
    }
}
