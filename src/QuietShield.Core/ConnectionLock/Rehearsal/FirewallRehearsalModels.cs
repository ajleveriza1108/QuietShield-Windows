using System.Net;
using System.Security.Cryptography;
using System.Text;
using QuietShield.Core.Validation;

namespace QuietShield.Core.ConnectionLock.Rehearsal;

public enum ProgramLockFirewallRehearsalState
{
    Prepared,
    EndpointVerified,
    BackupCreated,
    WatchdogStarted,
    RuleCreated,
    RuleVerified,
    BlockVerified,
    RehearsalActive,
    RollbackStarted,
    RuleRemoved,
    ConnectivityRestored,
    Completed
}

public sealed record ProgramLockRehearsalRuleIdentity(
    string OwnershipMarker,
    int SchemaVersion,
    Guid TransactionId,
    string RuleName,
    string Description,
    string ProgramPath,
    string RemoteAddress,
    int RemotePort,
    DateTimeOffset ExpiresAtUtc)
{
    public const string Owner = "QuietShield";
    public const int CurrentSchemaVersion = 1;
    public const string Prefix = "QuietShield.ProgramLock.Rehearsal.";
    public const int MaximumDescriptionLength = 160;
    private const string DescriptionPrefix = "QuietShield rehearsal; schema=1; tx=";
    private const string DescriptionSuffix = "; temporary=1";

    public static ProgramLockRehearsalRuleIdentity Create(
        Guid transactionId,
        string programPath,
        IPAddress remoteAddress,
        int remotePort,
        DateTimeOffset expiresAtUtc)
    {
        if (transactionId == Guid.Empty) throw new ArgumentException("A transaction ID is required.", nameof(transactionId));
        ArgumentException.ThrowIfNullOrWhiteSpace(programPath);
        ArgumentNullException.ThrowIfNull(remoteAddress);
        if (remotePort != 443) throw new ArgumentOutOfRangeException(nameof(remotePort), "The rehearsal endpoint must use TCP port 443.");
        var name = Prefix + transactionId.ToString("D");
        var expiration = expiresAtUtc.ToUniversalTime();
        var description = CreateDescription(transactionId);
        return new(Owner, CurrentSchemaVersion, transactionId, name, description, Path.GetFullPath(programPath), remoteAddress.ToString(), remotePort, expiration);
    }

    public static string CreateDescription(Guid transactionId)
    {
        if (transactionId == Guid.Empty) throw new ArgumentException("A transaction ID is required.", nameof(transactionId));
        var description = DescriptionPrefix + transactionId.ToString("N") + DescriptionSuffix;
        var validation = ValidateDescription(description, transactionId);
        if (!validation.IsValid) throw new InvalidOperationException(string.Join(" ", validation.Errors));
        return description;
    }

    public static ValidationResult ValidateDescription(string? description, Guid transactionId)
    {
        var errors = new List<string>();
        if (string.IsNullOrEmpty(description)) errors.Add("The Firewall description is required.");
        else
        {
            if (description.Length > MaximumDescriptionLength) errors.Add("The Firewall description exceeds 160 characters.");
            if (description.Any(character => character is < ' ' or > '~')) errors.Add("The Firewall description must contain printable ASCII characters only.");
            var expected = DescriptionPrefix + transactionId.ToString("N") + DescriptionSuffix;
            if (!string.Equals(description, expected, StringComparison.Ordinal)) errors.Add("The Firewall description does not match the deterministic transaction format.");
        }
        return errors.Count == 0 ? ValidationResult.Valid : new ValidationResult(errors);
    }

    public ValidationResult Validate()
    {
        var errors = new List<string>();
        if (!string.Equals(OwnershipMarker, Owner, StringComparison.Ordinal)) errors.Add("The rehearsal rule ownership marker is foreign.");
        if (SchemaVersion != CurrentSchemaVersion) errors.Add("The rehearsal rule schema is unsupported.");
        if (TransactionId == Guid.Empty || !string.Equals(RuleName, Prefix + TransactionId.ToString("D"), StringComparison.Ordinal))
            errors.Add("The rehearsal rule identity is not the exact deterministic transaction identity.");
        if (string.IsNullOrWhiteSpace(ProgramPath) || !Path.IsPathFullyQualified(ProgramPath) ||
            !Path.GetFileName(ProgramPath).Equals("QuietShield.ConnectionProbe.exe", StringComparison.OrdinalIgnoreCase))
            errors.Add("The rehearsal rule target is not the exact dedicated probe executable.");
        if (!IPAddress.TryParse(RemoteAddress, out _) || RemotePort != 443) errors.Add("The rehearsal endpoint is invalid.");
        var descriptionValidation = ValidateDescription(Description, TransactionId);
        if (!descriptionValidation.IsValid) errors.AddRange(descriptionValidation.Errors);
        return errors.Count == 0 ? ValidationResult.Valid : new ValidationResult(errors);
    }
}

public sealed record FirewallProfileEvidence(string Name, bool Enabled, string DefaultInboundAction, string DefaultOutboundAction);

public sealed record ProgramLockFirewallRehearsalTransaction(
    int SchemaVersion,
    string ProductMarker,
    string Purpose,
    Guid TransactionId,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset ExpiresAtUtc,
    ProgramLockFirewallRehearsalState State,
    ProgramLockRehearsalRuleIdentity ProposedRule,
    IReadOnlyList<string> ExistingOwnedRehearsalRuleNames,
    IReadOnlyList<FirewallProfileEvidence> FirewallProfiles,
    bool FirewallServiceHealthy,
    bool BaseFilteringEngineHealthy,
    bool Completed,
    string PayloadSha256)
{
    public const int CurrentSchemaVersion = 1;
    public const string ExpectedProductMarker = "QuietShield";
    public const string ExpectedPurpose = "ProgramLockFirewallRehearsal";
    public static readonly TimeSpan DefaultDuration = TimeSpan.FromSeconds(60);
    public static readonly TimeSpan MaximumDuration = TimeSpan.FromSeconds(120);

    public static ProgramLockFirewallRehearsalTransaction Create(
        Guid transactionId,
        DateTimeOffset createdAtUtc,
        TimeSpan duration,
        ProgramLockRehearsalRuleIdentity proposedRule,
        IReadOnlyList<string> existingOwnedRuleNames,
        IReadOnlyList<FirewallProfileEvidence> profiles,
        bool firewallHealthy,
        bool bfeHealthy)
    {
        if (duration <= TimeSpan.Zero || duration > MaximumDuration) throw new ArgumentOutOfRangeException(nameof(duration));
        ArgumentNullException.ThrowIfNull(proposedRule);
        var withoutHash = new ProgramLockFirewallRehearsalTransaction(
            CurrentSchemaVersion, ExpectedProductMarker, ExpectedPurpose, transactionId, createdAtUtc.ToUniversalTime(),
            createdAtUtc.ToUniversalTime().Add(duration), ProgramLockFirewallRehearsalState.Prepared, proposedRule,
            existingOwnedRuleNames.ToArray(), profiles.ToArray(), firewallHealthy, bfeHealthy, false, string.Empty);
        return withoutHash with { PayloadSha256 = ComputePayloadSha256(withoutHash) };
    }

    public ProgramLockFirewallRehearsalTransaction WithState(ProgramLockFirewallRehearsalState state, bool completed = false)
    {
        var updated = this with { State = state, Completed = completed, PayloadSha256 = string.Empty };
        return updated with { PayloadSha256 = ComputePayloadSha256(updated) };
    }

    public ValidationResult Validate(bool allowCompleted = true)
    {
        var errors = new List<string>();
        if (SchemaVersion != CurrentSchemaVersion || !string.Equals(ProductMarker, ExpectedProductMarker, StringComparison.Ordinal) ||
            !string.Equals(Purpose, ExpectedPurpose, StringComparison.Ordinal)) errors.Add("The rehearsal transaction schema, ownership, or purpose is foreign.");
        if (TransactionId == Guid.Empty || ProposedRule is null || TransactionId != ProposedRule.TransactionId) errors.Add("The rehearsal transaction identity is invalid.");
        else
        {
            var ruleValidation = ProposedRule.Validate();
            if (!ruleValidation.IsValid) errors.AddRange(ruleValidation.Errors);
        }
        var duration = ExpiresAtUtc - CreatedAtUtc;
        if (duration <= TimeSpan.Zero || duration > MaximumDuration) errors.Add("The rehearsal duration exceeds its safety limit.");
        if (!FirewallServiceHealthy || !BaseFilteringEngineHealthy) errors.Add("The required filtering services are not healthy.");
        if (ExistingOwnedRehearsalRuleNames is null || FirewallProfiles is null) errors.Add("The rehearsal evidence collections are missing.");
        if (!allowCompleted && (Completed || State == ProgramLockFirewallRehearsalState.Completed)) errors.Add("Completed rehearsal transactions cannot be restored.");
        if (!string.Equals(PayloadSha256, ComputePayloadSha256(this), StringComparison.Ordinal)) errors.Add("The rehearsal transaction SHA-256 payload verification failed.");
        return errors.Count == 0 ? ValidationResult.Valid : new ValidationResult(errors);
    }

    public static string ComputePayloadSha256(ProgramLockFirewallRehearsalTransaction transaction)
    {
        var builder = new StringBuilder();
        builder.Append(transaction.SchemaVersion).Append('|').Append(transaction.ProductMarker).Append('|').Append(transaction.Purpose).Append('|')
            .Append(transaction.TransactionId.ToString("D")).Append('|').Append(transaction.CreatedAtUtc.ToUniversalTime().ToString("O")).Append('|')
            .Append(transaction.ExpiresAtUtc.ToUniversalTime().ToString("O")).Append('|').Append(transaction.State).Append('|')
            .Append(transaction.Completed).Append('|').Append(transaction.FirewallServiceHealthy).Append('|').Append(transaction.BaseFilteringEngineHealthy).Append('\n');
        if (transaction.ProposedRule is not null)
            builder.Append("R|").Append(transaction.ProposedRule.RuleName).Append('|').Append(transaction.ProposedRule.Description).Append('|')
                .Append(transaction.ProposedRule.ProgramPath).Append('|').Append(transaction.ProposedRule.RemoteAddress).Append('|')
                .Append(transaction.ProposedRule.RemotePort).Append('|').Append(transaction.ProposedRule.ExpiresAtUtc.ToUniversalTime().ToString("O")).Append('\n');
        foreach (var name in transaction.ExistingOwnedRehearsalRuleNames ?? Array.Empty<string>()) builder.Append("E|").Append(name).Append('\n');
        foreach (var profile in transaction.FirewallProfiles ?? Array.Empty<FirewallProfileEvidence>())
            builder.Append("F|").Append(profile.Name).Append('|').Append(profile.Enabled).Append('|').Append(profile.DefaultInboundAction).Append('|').Append(profile.DefaultOutboundAction).Append('\n');
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(builder.ToString())));
    }
}
