using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using QuietShield.Core.ConnectionLock;
using QuietShield.Core.ServiceFoundation;

namespace QuietShield.Service;

public sealed class PersistentFirewallTransactionStore
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly string _directory;

    public PersistentFirewallTransactionStore(DiagnosticServiceOptions options) =>
        _directory = Path.Combine(options.StateRoot, "transactions");

    public string GetPath(Guid transactionId) => Path.Combine(_directory, transactionId.ToString("D") + ".json");

    public async Task SaveImmutableAsync(PersistentFirewallTransaction transaction, CancellationToken cancellationToken)
    {
        var errors = Validate(transaction);
        if (errors.Count != 0) throw new InvalidDataException(string.Join(" ", errors));
        Directory.CreateDirectory(_directory);
        var path = GetPath(transaction.TransactionId);
        if (File.Exists(path)) throw new InvalidOperationException("The immutable transaction record already exists.");
        var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            await File.WriteAllTextAsync(temporary, JsonSerializer.Serialize(transaction, Options), cancellationToken).ConfigureAwait(false);
            File.Move(temporary, path);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    public async Task<PersistentFirewallTransaction> ReadValidatedAsync(Guid transactionId, CancellationToken cancellationToken)
    {
        var path = GetPath(transactionId);
        try
        {
            await using var stream = File.OpenRead(path);
            var transaction = await JsonSerializer.DeserializeAsync<PersistentFirewallTransaction>(stream, Options, cancellationToken).ConfigureAwait(false)
                              ?? throw new InvalidDataException("The persistent Firewall transaction is empty.");
            var errors = Validate(transaction);
            if (errors.Count != 0) throw new InvalidDataException(string.Join(" ", errors));
            return transaction;
        }
        catch (JsonException exception) { throw new InvalidDataException("The persistent Firewall transaction JSON is malformed.", exception); }
    }

    public static IReadOnlyList<string> Validate(PersistentFirewallTransaction transaction)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        var errors = new List<string>();
        if (transaction.SchemaVersion != PersistentFirewallTransaction.CurrentSchemaVersion) errors.Add("The transaction schema is unsupported.");
        if (!transaction.ProductMarker.Equals(QuietShieldServiceIdentity.ProductMarker, StringComparison.Ordinal) ||
            transaction.Purpose is not (QuietShieldServiceIdentity.RehearsalPurpose or QuietShieldServiceIdentity.ProductionPurpose)) errors.Add("The transaction owner or purpose is foreign.");
        if (transaction.TransactionId == Guid.Empty || transaction.ApprovedRehearsalId == Guid.Empty) errors.Add("The transaction identity is invalid.");
        if (transaction.Policy is not (Core.Protection.ProgramConnectionPolicy.Blocked or Core.Protection.ProgramConnectionPolicy.AllowedOnAll)) errors.Add("Only Blocked and AllowedOnAll are supported.");
        if (string.IsNullOrWhiteSpace(transaction.ProfileId) || string.IsNullOrWhiteSpace(transaction.StableApplicationIdentity)) errors.Add("The profile or application identity is missing.");
        if (!Path.IsPathFullyQualified(transaction.ProgramPath) || !File.Exists(transaction.ProgramPath)) errors.Add("The exact program path is unavailable.");
        if (!IsHash(transaction.ProgramSha256) || File.Exists(transaction.ProgramPath) && !FileHash(transaction.ProgramPath).Equals(transaction.ProgramSha256, StringComparison.OrdinalIgnoreCase)) errors.Add("The exact program hash is invalid.");
        if (string.IsNullOrWhiteSpace(transaction.StableRuleId) || transaction.StableRuleId.Length != 32 || transaction.StableRuleId.Any(static item => !Uri.IsHexDigit(item)) || transaction.StableRuleId.Any(char.IsUpper)) errors.Add("The deterministic rule ID is invalid.");
        if (string.IsNullOrWhiteSpace(transaction.RuleName) || !transaction.RuleName.Equals("QuietShield.ProgramLock." + transaction.StableRuleId, StringComparison.Ordinal)) errors.Add("The exact deterministic rule name is invalid.");
        if (string.IsNullOrWhiteSpace(transaction.Description) || transaction.Description.Length > 160 || transaction.Description.Any(static item => item > 0x7f || item is '\r' or '\n' or '\t')) errors.Add("The rule description must be short ASCII.");
        if (transaction.BackupRule is not null && (!transaction.BackupRule.OwnershipMarker.Equals("QuietShield", StringComparison.Ordinal) || !transaction.BackupRule.Name.Equals(transaction.RuleName, StringComparison.Ordinal))) errors.Add("The backup rule is foreign or does not match exactly.");
        var requiredExemptions = Enum.GetValues<SafetyExemptionKind>();
        if (transaction.SafetyExemptions.Count != requiredExemptions.Length || requiredExemptions.Any(kind => transaction.SafetyExemptions.Count(item => item.Kind == kind) != 1)) errors.Add("The required safety exemptions are incomplete.");
        if (!IsHash(transaction.PayloadSha256) || !CryptographicOperations.FixedTimeEquals(Convert.FromHexString(transaction.ComputePayloadSha256()), Convert.FromHexString(transaction.PayloadSha256))) errors.Add("The transaction SHA-256 is invalid.");
        return errors;
    }

    private static bool IsHash(string value) => !string.IsNullOrWhiteSpace(value) && value.Length == 64 && value.All(Uri.IsHexDigit);
    private static string FileHash(string path) { using var stream = File.OpenRead(path); return Convert.ToHexString(SHA256.HashData(stream)); }
}
