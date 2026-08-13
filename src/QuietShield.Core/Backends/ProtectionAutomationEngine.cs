// QuietShield Backend Pack 1-4 R1
namespace QuietShield.Core.Backends;

public enum BackendProtectionLevel
{
    Standard = 0,
    High = 1,
    Extreme = 2,
    Custom = 3
}

public sealed record ProtectionAutomationInput(
    BackendProtectionLevel Level,
    bool ScheduleAllowsProtection,
    bool ServiceAvailable,
    bool DnsProxyHealthy,
    bool DnsSystemActivationReady,
    bool IsMetered,
    bool BatterySaverActive,
    bool AggressiveWatchRequested,
    bool NetworkTelemetryAvailable);

public sealed record ProtectionAutomationPlan(
    bool ProtectionActive,
    bool ProgramConnectionLockEnabled,
    bool DnsProxyEnabled,
    bool DnsSystemActivationRequested,
    bool NetworkTelemetryEnabled,
    bool CompatibilityGuardEnabled,
    bool AggressiveProgramWatchEnabled,
    bool ReduceBackgroundSampling,
    IReadOnlyList<string> Reasons,
    IReadOnlyList<string> Warnings);

public static class ProtectionAutomationEngine
{
    public static ProtectionAutomationPlan Evaluate(ProtectionAutomationInput input)
    {
        var reasons = new List<string>();
        var warnings = new List<string>();

        if (!input.ScheduleAllowsProtection)
        {
            reasons.Add("Protection is outside the active schedule window.");
            return new(
                false,
                false,
                false,
                false,
                input.NetworkTelemetryAvailable,
                true,
                false,
                true,
                reasons,
                warnings);
        }

        var programLock = input.ServiceAvailable;
        if (!programLock)
        {
            warnings.Add("Persistent Program Connection Lock is unavailable until QuietShieldService is running.");
        }

        var dnsProxy = input.DnsProxyHealthy;
        if (!dnsProxy)
        {
            warnings.Add("The local DNS filtering proxy is not healthy.");
        }

        // Backend Pack R1 never bypasses the known system-DNS activation gate.
        var requestSystemDns = dnsProxy && input.DnsSystemActivationReady;
        if (dnsProxy && !input.DnsSystemActivationReady)
        {
            warnings.Add("DNS filtering backend is live, but Windows adapter DNS activation remains safety-gated.");
        }

        var aggressive =
            input.AggressiveWatchRequested ||
            input.Level is BackendProtectionLevel.High or BackendProtectionLevel.Extreme;

        if (input.BatterySaverActive && input.Level != BackendProtectionLevel.Extreme)
        {
            aggressive = false;
            reasons.Add("Aggressive Program Watch is reduced while Battery Saver is active.");
        }

        var reduceSampling = input.BatterySaverActive || input.IsMetered;
        if (input.IsMetered)
        {
            reasons.Add("Background sampling is reduced on a metered connection.");
        }

        if (input.Level == BackendProtectionLevel.Extreme)
        {
            reasons.Add("Extreme mode keeps aggressive watch enabled unless the active schedule disables protection.");
            aggressive = true;
        }

        reasons.Add("Protection automation plan was computed without broad or implicit system mutation.");

        return new(
            true,
            programLock,
            dnsProxy,
            requestSystemDns,
            input.NetworkTelemetryAvailable,
            true,
            aggressive,
            reduceSampling,
            reasons,
            warnings);
    }
}
