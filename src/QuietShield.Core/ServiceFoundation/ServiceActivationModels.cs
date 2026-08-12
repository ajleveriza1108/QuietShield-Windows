using System.Security.Cryptography;
using System.Text;
using QuietShield.Core.ConnectionLock;
using QuietShield.Core.Protection;

namespace QuietShield.Core.ServiceFoundation;

public static class QuietShieldServiceIdentity
{
    public const string ServiceName = "QuietShieldService";
    public const string DisplayName = "QuietShield Protection Service";
    public const string ProductMarker = "QuietShield";
    public const string RehearsalPurpose = "Phase10BControlledServiceRehearsal";
    public const string ProductionPurpose = "QuietShieldProductionService";
}

public static class ApprovedProgramTargetIdentity
{
    public const string Prefix = "windows-exe:";

    public static string FromExecutablePath(string executablePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        var canonicalPath = Path.GetFullPath(executablePath).Trim().ToUpperInvariant();
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonicalPath)));
        return Prefix + hash[..32].ToLowerInvariant();
    }
}

public sealed record ServiceActivationConfiguration(
    int SchemaVersion,
    string ProductMarker,
    string Purpose,
    string ServiceName,
    Guid ApprovedRehearsalId,
    string AuthorizedUserSid,
    string ProbePath,
    string ProbeSha256,
    string EnforcementScriptPath,
    string EnforcementScriptSha256,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset ExpiresAtUtc,
    string PayloadSha256)
{
    public const int CurrentSchemaVersion = 1;

    public string ComputePayloadSha256()
    {
        var canonical = string.Join("|", SchemaVersion, ProductMarker, Purpose, ServiceName,
            ApprovedRehearsalId.ToString("D"), AuthorizedUserSid, Path.GetFullPath(ProbePath), ProbeSha256.ToUpperInvariant(),
            Path.GetFullPath(EnforcementScriptPath), EnforcementScriptSha256.ToUpperInvariant(),
            CreatedAtUtc.ToUniversalTime().ToString("O"), ExpiresAtUtc.ToUniversalTime().ToString("O"));
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    public IReadOnlyList<string> Validate(DateTimeOffset nowUtc)
    {
        var errors = new List<string>();
        if (SchemaVersion != CurrentSchemaVersion) errors.Add("The service activation schema is unsupported.");
        if (!ProductMarker.Equals(QuietShieldServiceIdentity.ProductMarker, StringComparison.Ordinal)) errors.Add("The service activation owner is foreign.");
        if (!Purpose.Equals(QuietShieldServiceIdentity.RehearsalPurpose, StringComparison.Ordinal)) errors.Add("The service activation purpose is unsupported.");
        if (!ServiceName.Equals(QuietShieldServiceIdentity.ServiceName, StringComparison.Ordinal)) errors.Add("The service identity is incorrect.");
        if (ApprovedRehearsalId == Guid.Empty) errors.Add("An approved rehearsal ID is required.");
        if (string.IsNullOrWhiteSpace(AuthorizedUserSid) || !AuthorizedUserSid.StartsWith("S-1-", StringComparison.Ordinal)) errors.Add("An authorized Windows SID is required.");
        ValidateFile(ProbePath, ProbeSha256, "probe", errors);
        ValidateFile(EnforcementScriptPath, EnforcementScriptSha256, "enforcement script", errors);
        if (ExpiresAtUtc <= CreatedAtUtc || ExpiresAtUtc - CreatedAtUtc > TimeSpan.FromHours(4)) errors.Add("The activation validity window is invalid.");
        if (nowUtc < CreatedAtUtc.AddMinutes(-5) || nowUtc >= ExpiresAtUtc) errors.Add("The approved service activation has expired or is not yet valid.");
        if (!IsHash(PayloadSha256) || !CryptographicOperations.FixedTimeEquals(Convert.FromHexString(ComputePayloadSha256()), Convert.FromHexString(PayloadSha256)))
            errors.Add("The activation payload SHA-256 is invalid.");
        return errors;
    }

    private static void ValidateFile(string path, string expectedHash, string label, List<string> errors)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path) || !File.Exists(path)) { errors.Add($"The approved {label} path is unavailable."); return; }
        if (!IsHash(expectedHash)) { errors.Add($"The approved {label} SHA-256 is malformed."); return; }
        using var stream = File.OpenRead(path);
        var actual = Convert.ToHexString(SHA256.HashData(stream));
        if (!CryptographicOperations.FixedTimeEquals(Convert.FromHexString(actual), Convert.FromHexString(expectedHash))) errors.Add($"The approved {label} SHA-256 does not match.");
    }

    private static bool IsHash(string value) => !string.IsNullOrWhiteSpace(value) && value.Length == 64 && value.All(Uri.IsHexDigit);

    public ProgramPolicyAuthorizationContext ToAuthorizationContext() => new(
        ApprovedRehearsalId,
        Purpose,
        AuthorizedUserSid,
        EnforcementScriptPath,
        [Path.GetDirectoryName(Path.GetFullPath(ProbePath))!],
        Path.GetFullPath(ProbePath),
        ProbeSha256.ToUpperInvariant());
}

public sealed record ProductionServiceConfiguration(
    int SchemaVersion,
    string ProductMarker,
    string Purpose,
    string ServiceName,
    Guid InstallationId,
    string AuthorizedUserSid,
    IReadOnlyList<string> ApprovedProgramRoots,
    string EnforcementScriptPath,
    string EnforcementScriptSha256,
    DateTimeOffset CreatedAtUtc,
    string PayloadSha256)
{
    public const int CurrentSchemaVersion = 1;

    public string ComputePayloadSha256()
    {
        var roots = string.Join("~", ApprovedProgramRoots.Select(NormalizeRoot).OrderBy(static value => value, StringComparer.OrdinalIgnoreCase));
        var canonical = string.Join("|", SchemaVersion, ProductMarker, Purpose, ServiceName,
            InstallationId.ToString("D"), AuthorizedUserSid, roots, Path.GetFullPath(EnforcementScriptPath),
            EnforcementScriptSha256.ToUpperInvariant(), CreatedAtUtc.ToUniversalTime().ToString("O"));
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();
        if (SchemaVersion != CurrentSchemaVersion) errors.Add("The production service schema is unsupported.");
        if (!ProductMarker.Equals(QuietShieldServiceIdentity.ProductMarker, StringComparison.Ordinal)) errors.Add("The production service owner is foreign.");
        if (!Purpose.Equals(QuietShieldServiceIdentity.ProductionPurpose, StringComparison.Ordinal)) errors.Add("The production service purpose is unsupported.");
        if (!ServiceName.Equals(QuietShieldServiceIdentity.ServiceName, StringComparison.Ordinal)) errors.Add("The service identity is incorrect.");
        if (InstallationId == Guid.Empty) errors.Add("A production installation ID is required.");
        if (string.IsNullOrWhiteSpace(AuthorizedUserSid) || !AuthorizedUserSid.StartsWith("S-1-", StringComparison.Ordinal)) errors.Add("An authorized Windows SID is required.");
        if (ApprovedProgramRoots.Count is < 1 or > 8 || ApprovedProgramRoots.Any(static value => string.IsNullOrWhiteSpace(value) || !Path.IsPathFullyQualified(value)))
            errors.Add("One to eight absolute approved application roots are required.");
        else if (ApprovedProgramRoots.Select(NormalizeRoot).Distinct(StringComparer.OrdinalIgnoreCase).Count() != ApprovedProgramRoots.Count)
            errors.Add("Approved application roots must be unique.");
        ValidateFile(EnforcementScriptPath, EnforcementScriptSha256, errors);
        if (!IsHash(PayloadSha256) || !CryptographicOperations.FixedTimeEquals(Convert.FromHexString(ComputePayloadSha256()), Convert.FromHexString(PayloadSha256)))
            errors.Add("The production service payload SHA-256 is invalid.");
        return errors;
    }

    public ProgramPolicyAuthorizationContext ToAuthorizationContext() => new(
        InstallationId,
        Purpose,
        AuthorizedUserSid,
        Path.GetFullPath(EnforcementScriptPath),
        ApprovedProgramRoots.Select(NormalizeRoot).Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
        null,
        null);

    private static string NormalizeRoot(string value) => Path.GetFullPath(value).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
    private static bool IsHash(string value) => !string.IsNullOrWhiteSpace(value) && value.Length == 64 && value.All(Uri.IsHexDigit);
    private static void ValidateFile(string path, string expectedHash, List<string> errors)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path) || !File.Exists(path)) { errors.Add("The production enforcement script is unavailable."); return; }
        if (!IsHash(expectedHash)) { errors.Add("The production enforcement script SHA-256 is malformed."); return; }
        using var stream = File.OpenRead(path);
        var actual = Convert.ToHexString(SHA256.HashData(stream));
        if (!CryptographicOperations.FixedTimeEquals(Convert.FromHexString(actual), Convert.FromHexString(expectedHash))) errors.Add("The production enforcement script SHA-256 does not match.");
    }
}

public sealed record ProgramPolicyAuthorizationContext(
    Guid AuthorizationId,
    string Purpose,
    string AuthorizedUserSid,
    string EnforcementScriptPath,
    IReadOnlyList<string> ApprovedProgramRoots,
    string? FixedProgramPath,
    string? FixedProgramSha256)
{
    public bool IsProduction => Purpose.Equals(QuietShieldServiceIdentity.ProductionPurpose, StringComparison.Ordinal);
}

public sealed record PersistentFirewallRuleSnapshot(
    string OwnershipMarker,
    int SchemaVersion,
    string Name,
    string Description,
    string ProgramPath,
    bool Enabled,
    string Direction,
    string Action,
    string Profile,
    string Protocol,
    string RemoteAddress,
    int RemotePort);

public sealed record PersistentFirewallTransaction(
    int SchemaVersion,
    string ProductMarker,
    string Purpose,
    Guid TransactionId,
    Guid ApprovedRehearsalId,
    DateTimeOffset CreatedAtUtc,
    string Stage,
    string ProfileId,
    string StableApplicationIdentity,
    string ProgramPath,
    string ProgramSha256,
    ProgramConnectionPolicy Policy,
    string StableRuleId,
    string RuleName,
    string Description,
    PersistentFirewallRuleSnapshot? BackupRule,
    IReadOnlyList<SafetyExemption> SafetyExemptions,
    string PayloadSha256)
{
    public const int CurrentSchemaVersion = 1;

    public string ComputePayloadSha256()
    {
        var backup = BackupRule is null ? "absent" : string.Join("~", BackupRule.OwnershipMarker, BackupRule.SchemaVersion,
            BackupRule.Name, BackupRule.Description, Path.GetFullPath(BackupRule.ProgramPath), BackupRule.Enabled,
            BackupRule.Direction, BackupRule.Action, BackupRule.Profile, BackupRule.Protocol, BackupRule.RemoteAddress, BackupRule.RemotePort);
        var exemptions = string.Join("~", SafetyExemptions.OrderBy(static item => item.Kind).Select(static item => $"{item.Kind}:{item.VisibleReason}"));
        var canonical = string.Join("|", SchemaVersion, ProductMarker, Purpose, TransactionId.ToString("D"), ApprovedRehearsalId.ToString("D"),
            CreatedAtUtc.ToUniversalTime().ToString("O"), Stage, ProfileId, StableApplicationIdentity, Path.GetFullPath(ProgramPath),
            ProgramSha256.ToUpperInvariant(), Policy, StableRuleId.ToLowerInvariant(), RuleName, Description, backup, exemptions);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }
}

public interface IPersistentFirewallBackend
{
    bool IsRealWindowsModifier { get; }
    Task<PersistentFirewallRuleSnapshot?> GetExactAsync(string ruleName, CancellationToken cancellationToken);
    Task ApplyBlockedAsync(PersistentFirewallTransaction transaction, CancellationToken cancellationToken);
    Task ApplyAllowedOnAllAsync(PersistentFirewallTransaction transaction, CancellationToken cancellationToken);
    Task RestoreAsync(PersistentFirewallTransaction transaction, CancellationToken cancellationToken);
}

public interface IServiceProgramPolicyCoordinator
{
    bool PersistentEnforcementAvailable { get; }
    Task<ProgramRuleChangeResponse> ChangeAsync(ProgramRuleChangeRequest request, CancellationToken cancellationToken);
    Task RecoverInterruptedAsync(CancellationToken cancellationToken);
}
