namespace QuietShield.App.ViewModels;

public sealed partial class MainViewModel
{
    private string _firewallRehearsalCapability = "Read-only Firewall capability discovery pending.";

    public string FirewallRehearsalCapability { get => _firewallRehearsalCapability; private set => SetField(ref _firewallRehearsalCapability, value); }
    public string RehearsalTestExecutableReadiness { get; } = "Dedicated .NET 10 probe defined; build output is validated before any rehearsal.";
    public string RehearsalEndpointReadiness { get; } = "Resolved once and TCP-tested only during preflight; no endpoint is selected yet.";
    public string RehearsalBackupReadiness { get; } = "Exact rehearsal-only rule, profile, service, endpoint, and SHA-256 transaction backup modeled.";
    public string RehearsalWatchdogReadiness { get; } = "Independent deadline, heartbeat, parent-loss, verification-failure, and rollback monitoring modeled.";
    public string LastFirewallRehearsalResult { get; } = "Not run — dry validation only.";
    public string LastFirewallRollbackResult { get; } = "Not run — no rehearsal rule has been created.";
    public string PermanentFirewallEnforcementStatus { get; } = "Not active";

    private void UpdateProgramLockFirewallRehearsalReadiness()
    {
        FirewallRehearsalCapability = _bundle?.Firewall is { ServiceAvailable: true }
            ? $"Available for separately approved rehearsal; profiles discovered: {_bundle.Firewall.Profiles.Count}; QuietShield-owned rules: {_bundle.Firewall.QuietShieldOwnedRuleCount}."
            : "Unavailable or not yet verified; rehearsal must stop without changes.";
    }
}
