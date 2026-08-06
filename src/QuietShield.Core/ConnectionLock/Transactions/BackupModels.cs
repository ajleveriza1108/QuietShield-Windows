using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using QuietShield.Core.Protection;
using QuietShield.Core.Validation;

namespace QuietShield.Core.ConnectionLock.Transactions;

public sealed record ProgramPolicyBackupEntry(string StableApplicationIdentity, ProgramConnectionPolicy Policy);

public sealed record ProgramIdentityBackupEntry(
    string StableApplicationIdentity,
    ProgramIdentityKind Kind,
    string? ExecutablePath,
    string? MsixPackageIdentity,
    ProgramPathStatus PathStatus,
    bool IsSystemComponent);

public sealed record ProgramRuleBackupEntry(
    int OriginalOrder,
    QuietShieldProgramRuleIdentity Rule,
    string RulePayloadSha256);

public sealed record ProgramLockBackup(
    int SchemaVersion,
    string ProductMarker,
    string Purpose,
    Guid BackupId,
    Guid TransactionId,
    DateTimeOffset CreatedAtUtc,
    string ActiveProfileId,
    IReadOnlyList<ProgramPolicyBackupEntry> ProgramPolicies,
    IReadOnlyList<ProgramIdentityBackupEntry> ApplicationIdentities,
    IReadOnlyList<ProgramRuleBackupEntry> QuietShieldOwnedRules,
    string PayloadSha256)
{
    public const int CurrentSchemaVersion = 1;
    public const string ExpectedProductMarker = "QuietShield";
    public const string ExpectedPurpose = "ProgramLockTransactionBackup";

    public static ProgramLockBackup Create(
        Guid transactionId,
        string activeProfileId,
        IReadOnlyList<ConnectionLockProgramRule> policies,
        IReadOnlyList<QuietShieldProgramRuleIdentity> existingQuietShieldRules,
        DateTimeOffset createdAtUtc,
        Guid? backupId = null)
    {
        if (transactionId == Guid.Empty) throw new ArgumentException("A transaction ID is required.", nameof(transactionId));
        ArgumentException.ThrowIfNullOrWhiteSpace(activeProfileId);
        ArgumentNullException.ThrowIfNull(policies);
        ArgumentNullException.ThrowIfNull(existingQuietShieldRules);
        var policyEntries = policies.Select(static rule => new ProgramPolicyBackupEntry(rule.Identity.StableId, rule.Policy)).ToArray();
        var identities = policies.Select(static rule => new ProgramIdentityBackupEntry(
            rule.Identity.StableId,
            rule.Identity.Kind,
            rule.Identity.ExecutablePath,
            rule.Identity.PackageFamilyName,
            rule.Identity.PathStatus,
            rule.Identity.IsSystemComponent)).ToArray();
        var ruleEntries = existingQuietShieldRules.Select(static (rule, index) => new ProgramRuleBackupEntry(index, rule, rule.ComputePayloadSha256())).ToArray();
        var withoutHash = new ProgramLockBackup(
            CurrentSchemaVersion,
            ExpectedProductMarker,
            ExpectedPurpose,
            backupId ?? Guid.NewGuid(),
            transactionId,
            createdAtUtc.ToUniversalTime(),
            activeProfileId.Trim(),
            policyEntries,
            identities,
            ruleEntries,
            string.Empty);
        return withoutHash with { PayloadSha256 = ProgramLockBackupHash.Compute(withoutHash) };
    }
}

public static class ProgramLockBackupHash
{
    public static string Compute(ProgramLockBackup backup)
    {
        ArgumentNullException.ThrowIfNull(backup);
        var builder = new StringBuilder();
        builder.Append(backup.SchemaVersion).Append('|').Append(backup.ProductMarker).Append('|').Append(backup.Purpose).Append('|')
            .Append(backup.BackupId.ToString("D")).Append('|').Append(backup.TransactionId.ToString("D")).Append('|')
            .Append(backup.CreatedAtUtc.ToUniversalTime().ToString("O")).Append('|').Append(backup.ActiveProfileId).Append('\n');
        foreach (var policy in backup.ProgramPolicies)
            builder.Append("P|").Append(policy.StableApplicationIdentity).Append('|').Append(policy.Policy).Append('\n');
        foreach (var identity in backup.ApplicationIdentities)
            builder.Append("I|").Append(identity.StableApplicationIdentity).Append('|').Append(identity.Kind).Append('|')
                .Append(identity.ExecutablePath ?? string.Empty).Append('|').Append(identity.MsixPackageIdentity ?? string.Empty).Append('|')
                .Append(identity.PathStatus).Append('|').Append(identity.IsSystemComponent).Append('\n');
        foreach (var entry in backup.QuietShieldOwnedRules)
            builder.Append("R|").Append(entry.OriginalOrder).Append('|').Append(entry.RulePayloadSha256).Append('\n');
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(builder.ToString())));
    }
}

public static class ProgramLockBackupValidator
{
    public static ValidationResult Validate(ProgramLockBackup backup)
    {
        ArgumentNullException.ThrowIfNull(backup);
        var errors = new List<string>();
        if (backup.SchemaVersion != ProgramLockBackup.CurrentSchemaVersion) errors.Add("The backup schema version is unsupported.");
        if (!string.Equals(backup.ProductMarker, ProgramLockBackup.ExpectedProductMarker, StringComparison.Ordinal) ||
            !string.Equals(backup.Purpose, ProgramLockBackup.ExpectedPurpose, StringComparison.Ordinal)) errors.Add("The backup ownership or purpose is foreign.");
        if (backup.BackupId == Guid.Empty || backup.TransactionId == Guid.Empty) errors.Add("The backup or transaction identity is invalid.");
        if (string.IsNullOrWhiteSpace(backup.ActiveProfileId)) errors.Add("The backup active profile is missing.");
        if (backup.ProgramPolicies is null || backup.ApplicationIdentities is null || backup.QuietShieldOwnedRules is null)
        {
            errors.Add("The backup is missing one or more required collections.");
            return new ValidationResult(errors);
        }
        if (backup.ProgramPolicies.Count != backup.ApplicationIdentities.Count) errors.Add("The backup policy and application identity counts differ.");
        if (backup.ApplicationIdentities.Any(static item => item is null || string.IsNullOrWhiteSpace(item.StableApplicationIdentity)))
            errors.Add("The backup contains an invalid application identity entry.");
        if (backup.ApplicationIdentities.Where(static item => item is not null).GroupBy(static item => item.StableApplicationIdentity, StringComparer.OrdinalIgnoreCase).Any(static group => group.Count() > 1))
            errors.Add("The backup contains duplicate application identities.");
        for (var index = 0; index < backup.QuietShieldOwnedRules.Count; index++)
        {
            var entry = backup.QuietShieldOwnedRules[index];
            if (entry is null || entry.Rule is null)
            {
                errors.Add("The backup contains an invalid rule entry.");
                continue;
            }
            if (entry.OriginalOrder != index) errors.Add("The original QuietShield rule order is malformed.");
            var ruleValidation = entry.Rule.Validate();
            if (!ruleValidation.IsValid) errors.AddRange(ruleValidation.Errors);
            if (!string.Equals(entry.RulePayloadSha256, entry.Rule.ComputePayloadSha256(), StringComparison.Ordinal)) errors.Add("A backed-up rule hash is invalid.");
        }
        if (!string.Equals(backup.PayloadSha256, ProgramLockBackupHash.Compute(backup), StringComparison.Ordinal)) errors.Add("The backup SHA-256 payload verification failed.");
        return errors.Count == 0 ? ValidationResult.Valid : new ValidationResult(errors);
    }
}

public interface IProgramLockBackupStore
{
    Task SaveAsync(ProgramLockBackup backup, string backupPath, string lastKnownGoodPath, string historyPath, CancellationToken cancellationToken);
    Task<ProgramLockBackup> ReadValidatedAsync(string backupPath, CancellationToken cancellationToken);
}

public sealed class AtomicJsonProgramLockBackupStore : IProgramLockBackupStore
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    private static readonly JsonSerializerOptions HistoryOptions = new(Options)
    {
        WriteIndented = false
    };

    public async Task SaveAsync(ProgramLockBackup backup, string backupPath, string lastKnownGoodPath, string historyPath, CancellationToken cancellationToken)
    {
        var validation = ProgramLockBackupValidator.Validate(backup);
        if (!validation.IsValid) throw new InvalidDataException(string.Join(" ", validation.Errors));
        var json = JsonSerializer.Serialize(backup, Options);
        await WriteAtomicAsync(backupPath, json, cancellationToken).ConfigureAwait(false);
        await WriteAtomicAsync(lastKnownGoodPath, json, cancellationToken).ConfigureAwait(false);
        var historyDirectory = Path.GetDirectoryName(Path.GetFullPath(historyPath)) ?? throw new InvalidOperationException("History path has no directory.");
        Directory.CreateDirectory(historyDirectory);
        var historyEntry = JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            productMarker = ProgramLockBackup.ExpectedProductMarker,
            purpose = "ProgramLockTransactionHistory",
            backup.BackupId,
            backup.TransactionId,
            backup.CreatedAtUtc,
            backup.PayloadSha256
        }, HistoryOptions);
        await File.AppendAllTextAsync(historyPath, historyEntry + Environment.NewLine, Encoding.UTF8, cancellationToken).ConfigureAwait(false);
    }

    public async Task<ProgramLockBackup> ReadValidatedAsync(string backupPath, CancellationToken cancellationToken)
    {
        var resolved = Path.GetFullPath(backupPath);
        if (!File.Exists(resolved)) throw new FileNotFoundException("The Program Lock backup was not found.", resolved);
        ProgramLockBackup backup;
        try
        {
            await using var stream = File.OpenRead(resolved);
            backup = await JsonSerializer.DeserializeAsync<ProgramLockBackup>(stream, Options, cancellationToken).ConfigureAwait(false)
                ?? throw new InvalidDataException("The Program Lock backup is empty.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("The Program Lock backup JSON is malformed.", exception);
        }
        var validation = ProgramLockBackupValidator.Validate(backup);
        if (!validation.IsValid) throw new InvalidDataException(string.Join(" ", validation.Errors));
        return backup;
    }

    private static async Task WriteAtomicAsync(string path, string content, CancellationToken cancellationToken)
    {
        var resolved = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(resolved) ?? throw new InvalidOperationException("Backup path has no directory.");
        Directory.CreateDirectory(directory);
        var temporary = resolved + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            await File.WriteAllTextAsync(temporary, content, Encoding.UTF8, cancellationToken).ConfigureAwait(false);
            File.Move(temporary, resolved, true);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }
}
