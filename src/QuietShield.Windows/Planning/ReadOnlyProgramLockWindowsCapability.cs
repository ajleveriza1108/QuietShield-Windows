using QuietShield.Core.ConnectionLock.Transactions;
using QuietShield.Core.Protection;
using QuietShield.Windows.Integration;

namespace QuietShield.Windows.Planning;

public sealed record ProgramLockWindowsCapabilitySnapshot(
    bool WindowsFirewallServiceAvailable,
    bool BaseFilteringEngineAvailable,
    int ExistingQuietShieldOwnedRuleCount,
    bool FutureChangesRequireAdministrator,
    bool ModifyingImplementationRegistered,
    string Status);

public interface IReadOnlyProgramLockWindowsCapability
{
    ProgramLockWindowsCapabilitySnapshot Inspect(FirewallStateSnapshot firewall, ServiceStateSnapshot services);
    IReadOnlyList<PolicyEnforceability> GetPolicySupportMatrix();
}

public sealed class ReadOnlyProgramLockWindowsCapability : IReadOnlyProgramLockWindowsCapability
{
    public ProgramLockWindowsCapabilitySnapshot Inspect(FirewallStateSnapshot firewall, ServiceStateSnapshot services)
    {
        ArgumentNullException.ThrowIfNull(firewall);
        ArgumentNullException.ThrowIfNull(services);
        return new(
            firewall.ServiceAvailable && services.WindowsFirewall.Registered,
            services.BaseFilteringEngine.Registered && services.BaseFilteringEngine.Running,
            firewall.QuietShieldOwnedRuleCount,
            true,
            false,
            "Read-only Windows Firewall/BFE capability inspection completed; no rule API was opened for modification.");
    }

    public IReadOnlyList<PolicyEnforceability> GetPolicySupportMatrix() =>
        Enum.GetValues<ProgramConnectionPolicy>().Select(PolicyEnforceabilityClassifier.Classify).ToArray();
}
