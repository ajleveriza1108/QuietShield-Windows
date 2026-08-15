// QuietShield Backend Integration 03 R1
using Microsoft.VisualStudio.TestTools.UnitTesting;
using QuietShield.Core.IntegrationWave;

namespace QuietShield.Core.Tests;

[TestClass]
public sealed class BackendIntegration03Tests
{
    [TestMethod]
    public void KnownBlockerKeepsSystemDnsActivationGated()
    {
        var result = DnsActivationSafetyGate.Evaluate(
            new(
                KnownPhase5BlockerCleared: false,
                LocalProxyHealthy: true,
                AdapterSnapshotCaptured: true,
                RollbackValidated: true,
                ExplicitAdministratorApproval: true,
                ConflictingDnsProductDetected: false));

        Assert.IsFalse(result.EligibleForExplicitActivation);
        Assert.IsFalse(result.AdapterMutationPerformed);
    }

    [TestMethod]
    public void ReadyStateStillDoesNotMutateAdapters()
    {
        var result = DnsActivationSafetyGate.Evaluate(
            new(true, true, true, true, true, false));

        Assert.IsTrue(result.EligibleForExplicitActivation);
        Assert.IsFalse(result.AdapterMutationPerformed);
    }
}
