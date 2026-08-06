using System.Security.Cryptography;
using System.Text;
using QuietShield.Core.Protection;
using QuietShield.Core.Validation;

namespace QuietShield.Core.ConnectionLock.Transactions;

public enum ProgramLockRuleDirection
{
    Outbound,
    Inbound
}

public enum ProgramLockProtocolScope
{
    Any,
    Tcp,
    Udp
}

public enum ProgramLockNetworkScope
{
    All,
    WiFi,
    Ethernet,
    Cellular,
    Metered,
    Unmetered
}

public enum PolicyEnforcementSupport
{
    WindowsFirewallStatic,
    RequiresRuntimeNetworkTransitionManagement,
    Unsupported
}

public enum ProposedEnforcementLayer
{
    WindowsFirewall,
    WindowsFirewallWithRuntimeTransitions,
    UserModeWindowsFilteringPlatform,
    None
}

public sealed record QuietShieldProgramRuleIdentity(
    string OwnershipMarker,
    int SchemaVersion,
    string StableRuleId,
    string ProfileId,
    string StableApplicationIdentity,
    string? ExecutablePath,
    string? MsixPackageIdentity,
    ProgramConnectionPolicy ConnectionPolicy,
    ProgramLockRuleDirection Direction,
    ProgramLockProtocolScope ProtocolScope,
    ProgramLockNetworkScope NetworkScope,
    Guid CreationTransactionId,
    string DisplayName,
    string Description)
{
    public const string Owner = "QuietShield";
    public const int CurrentSchemaVersion = 1;
    public const string RuleNamePrefix = "QuietShield.ProgramLock.";

    public string RuleName => RuleNamePrefix + StableRuleId;

    public ValidationResult Validate()
    {
        var errors = new List<string>();
        if (!string.Equals(OwnershipMarker, Owner, StringComparison.Ordinal)) errors.Add("The rule ownership marker is foreign.");
        if (SchemaVersion != CurrentSchemaVersion) errors.Add("The rule schema version is unsupported.");
        if (string.IsNullOrWhiteSpace(StableRuleId) || StableRuleId.Length != 32 || StableRuleId.Any(static value => !Uri.IsHexDigit(value))) errors.Add("The stable rule ID is invalid.");
        if (string.IsNullOrWhiteSpace(ProfileId)) errors.Add("A profile ID is required.");
        if (string.IsNullOrWhiteSpace(StableApplicationIdentity)) errors.Add("A stable application identity is required.");
        if (string.IsNullOrWhiteSpace(ExecutablePath) == string.IsNullOrWhiteSpace(MsixPackageIdentity)) errors.Add("Exactly one executable path or MSIX package identity is required.");
        if (!Enum.IsDefined(ConnectionPolicy) || !Enum.IsDefined(Direction) || !Enum.IsDefined(ProtocolScope) || !Enum.IsDefined(NetworkScope)) errors.Add("The rule contains an unsupported policy or scope.");
        if (CreationTransactionId == Guid.Empty) errors.Add("A creation transaction ID is required.");
        if (string.IsNullOrWhiteSpace(DisplayName) || string.IsNullOrWhiteSpace(Description)) errors.Add("A rule display name and description are required.");
        if (!RuleName.StartsWith(RuleNamePrefix, StringComparison.Ordinal)) errors.Add("The rule name is outside the QuietShield Program Lock namespace.");
        return errors.Count == 0 ? ValidationResult.Valid : new ValidationResult(errors);
    }

    public static QuietShieldProgramRuleIdentity Create(
        Guid transactionId,
        string profileId,
        ProgramIdentity application,
        ProgramConnectionPolicy policy,
        ProgramLockRuleDirection direction = ProgramLockRuleDirection.Outbound,
        ProgramLockProtocolScope protocol = ProgramLockProtocolScope.Any)
    {
        ArgumentNullException.ThrowIfNull(application);
        var applicationValidation = application.Validate();
        if (!applicationValidation.IsValid) throw new ArgumentException(string.Join(" ", applicationValidation.Errors), nameof(application));
        if (transactionId == Guid.Empty) throw new ArgumentException("A transaction ID is required.", nameof(transactionId));
        var networkScope = PolicyEnforceabilityClassifier.GetNetworkScope(policy);
        var canonical = string.Join("|", CurrentSchemaVersion, profileId.Trim(), application.StableId.Trim(), policy, direction, protocol, networkScope);
        var stableRuleId = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)))[..32];
        return new(
            Owner,
            CurrentSchemaVersion,
            stableRuleId,
            profileId.Trim(),
            application.StableId,
            application.Kind == ProgramIdentityKind.Win32Executable ? application.ExecutablePath : null,
            application.Kind == ProgramIdentityKind.MicrosoftStoreOrMsix ? application.PackageFamilyName : null,
            policy,
            direction,
            protocol,
            networkScope,
            transactionId,
            $"QuietShield Program Lock — {application.DisplayName}",
            $"QuietShield-owned {policy} proposal for stable application {application.StableId}.");
    }

    public string ComputePayloadSha256()
    {
        var canonical = string.Join("|", OwnershipMarker, SchemaVersion, StableRuleId, ProfileId, StableApplicationIdentity,
            ExecutablePath ?? string.Empty, MsixPackageIdentity ?? string.Empty, ConnectionPolicy, Direction, ProtocolScope,
            NetworkScope, CreationTransactionId.ToString("D"), DisplayName, Description);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }
}

public sealed record PolicyEnforceability(
    ProgramConnectionPolicy Policy,
    PolicyEnforcementSupport Support,
    ProposedEnforcementLayer Layer,
    string Reason);

public static class PolicyEnforceabilityClassifier
{
    public static PolicyEnforceability Classify(ProgramConnectionPolicy policy) => policy switch
    {
        ProgramConnectionPolicy.Blocked => new(policy, PolicyEnforcementSupport.WindowsFirewallStatic, ProposedEnforcementLayer.WindowsFirewall,
            "A deterministic outbound block can be represented by an application-specific Windows Firewall rule."),
        ProgramConnectionPolicy.AllowedOnAll => new(policy, PolicyEnforcementSupport.WindowsFirewallStatic, ProposedEnforcementLayer.WindowsFirewall,
            "Allowed on All is represented by the verified absence of QuietShield-owned blocking rules for the application."),
        ProgramConnectionPolicy.WiFiOnly or ProgramConnectionPolicy.EthernetOnly => new(policy,
            PolicyEnforcementSupport.RequiresRuntimeNetworkTransitionManagement,
            ProposedEnforcementLayer.WindowsFirewallWithRuntimeTransitions,
            "Static rules cannot safely express every simultaneous, virtual, and changing adapter topology; runtime network-transition management would be required."),
        ProgramConnectionPolicy.CellularOnly or ProgramConnectionPolicy.MeteredOnly or ProgramConnectionPolicy.UnmeteredOnly => new(policy,
            PolicyEnforcementSupport.RequiresRuntimeNetworkTransitionManagement,
            ProposedEnforcementLayer.UserModeWindowsFilteringPlatform,
            "Windows Firewall does not expose a reliable static scope for this policy; a separately approved user-mode WFP and runtime-transition design would be required."),
        _ => new(policy, PolicyEnforcementSupport.Unsupported, ProposedEnforcementLayer.None, "The policy is unknown and cannot be planned safely.")
    };

    public static ProgramLockNetworkScope GetNetworkScope(ProgramConnectionPolicy policy) => policy switch
    {
        ProgramConnectionPolicy.WiFiOnly => ProgramLockNetworkScope.WiFi,
        ProgramConnectionPolicy.EthernetOnly => ProgramLockNetworkScope.Ethernet,
        ProgramConnectionPolicy.CellularOnly => ProgramLockNetworkScope.Cellular,
        ProgramConnectionPolicy.MeteredOnly => ProgramLockNetworkScope.Metered,
        ProgramConnectionPolicy.UnmeteredOnly => ProgramLockNetworkScope.Unmetered,
        _ => ProgramLockNetworkScope.All
    };
}
