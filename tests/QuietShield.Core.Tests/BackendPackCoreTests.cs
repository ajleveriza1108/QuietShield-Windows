// QuietShield Backend Pack 1-4 R1
using QuietShield.Core.Backends;

namespace QuietShield.Core.Tests;

[TestClass]
public sealed class BackendPackCoreTests
{
    [TestMethod]
    public void DnsPolicyExplicitAllowWithHigherPriorityWins()
    {
        var engine = new DnsPolicyEngine(new[]
        {
            new DnsPolicyRule("example.test", DnsPolicyAction.Block, true, 10),
            new DnsPolicyRule("safe.example.test", DnsPolicyAction.Allow, true, 20)
        });

        Assert.AreEqual(
            DnsPolicyAction.Allow,
            engine.Evaluate("safe.example.test").Action);

        Assert.AreEqual(
            DnsPolicyAction.Block,
            engine.Evaluate("ads.example.test").Action);
    }

    [TestMethod]
    public void AutomationRespectsServiceAndDnsActivationGate()
    {
        var plan = ProtectionAutomationEngine.Evaluate(new(
            BackendProtectionLevel.High,
            ScheduleAllowsProtection: true,
            ServiceAvailable: true,
            DnsProxyHealthy: true,
            DnsSystemActivationReady: false,
            IsMetered: false,
            BatterySaverActive: false,
            AggressiveWatchRequested: false,
            NetworkTelemetryAvailable: true));

        Assert.IsTrue(plan.ProgramConnectionLockEnabled);
        Assert.IsTrue(plan.DnsProxyEnabled);
        Assert.IsFalse(plan.DnsSystemActivationRequested);
        Assert.IsTrue(plan.NetworkTelemetryEnabled);
        Assert.IsTrue(plan.AggressiveProgramWatchEnabled);
    }

    [TestMethod]
    public void HealthSupervisorUsesBoundedRecoveryBackoff()
    {
        var now = DateTimeOffset.UtcNow;
        var supervisor = new BackendHealthSupervisor(
            TimeSpan.FromMinutes(1),
            failureThreshold: 2,
            baseRecoveryDelay: TimeSpan.FromSeconds(1));

        supervisor.RecordFailure("service", TimeSpan.FromMilliseconds(5), "failure-1", now);
        supervisor.RecordFailure("service", TimeSpan.FromMilliseconds(6), "failure-2", now);

        Assert.AreEqual(
            BackendHealthState.Failed,
            supervisor.Snapshot(now).State);

        Assert.IsTrue(
            supervisor.ShouldAttemptRecovery(now.AddSeconds(2)));

        supervisor.MarkRecoveryAttempt(now.AddSeconds(2));

        Assert.AreEqual(
            BackendHealthState.Recovering,
            supervisor.Snapshot(now.AddSeconds(2)).State);
    }

    [TestMethod]
    public void TelemetryAccumulatorComputesNonNegativeDeltas()
    {
        var accumulator = new NetworkTelemetryAccumulator(4);
        var now = DateTimeOffset.UtcNow;

        accumulator.Add(new(
            now,
            Array.Empty<NetworkConnectionSample>(),
            new[]
            {
                new NetworkInterfaceSample(
                    "id",
                    "adapter",
                    "adapter",
                    "Ethernet",
                    "Up",
                    100,
                    200,
                    1,
                    1)
            }));

        accumulator.Add(new(
            now.AddSeconds(2),
            Array.Empty<NetworkConnectionSample>(),
            new[]
            {
                new NetworkInterfaceSample(
                    "id",
                    "adapter",
                    "adapter",
                    "Ethernet",
                    "Up",
                    160,
                    280,
                    2,
                    2)
            }));

        var summary = accumulator.Snapshot();
        Assert.AreEqual(60L, summary.ReceivedDelta);
        Assert.AreEqual(80L, summary.SentDelta);
    }
}
