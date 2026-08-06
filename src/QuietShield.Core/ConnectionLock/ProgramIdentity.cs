using System.Security.Cryptography;
using System.Text;
using QuietShield.Core.Validation;

namespace QuietShield.Core.ConnectionLock;

public enum ProgramIdentityKind
{
    Win32Executable,
    MicrosoftStoreOrMsix
}

public enum ProgramPathStatus
{
    Present,
    Missing,
    Moved,
    PackageManaged,
    Ambiguous
}

public sealed record ProgramIdentity(
    string StableId,
    ProgramIdentityKind Kind,
    string DisplayName,
    string? Publisher,
    string? ExecutablePath,
    string? PackageFamilyName,
    bool IsSystemComponent,
    ProgramPathStatus PathStatus,
    string IdentityEvidence)
{
    public ValidationResult Validate()
    {
        var errors = new List<string>();
        if (string.IsNullOrWhiteSpace(StableId)) errors.Add("A stable application identifier is required.");
        if (string.IsNullOrWhiteSpace(DisplayName)) errors.Add("An application display name is required for presentation.");
        if (string.IsNullOrWhiteSpace(IdentityEvidence)) errors.Add("Identity evidence is required; display name alone is never sufficient.");

        if (Kind == ProgramIdentityKind.Win32Executable && string.IsNullOrWhiteSpace(ExecutablePath))
        {
            errors.Add("A Win32 identity requires an executable path, including when the path is missing or moved.");
        }
        if (Kind == ProgramIdentityKind.MicrosoftStoreOrMsix && string.IsNullOrWhiteSpace(PackageFamilyName))
        {
            errors.Add("An MSIX identity requires a package family name.");
        }
        if (PathStatus == ProgramPathStatus.Ambiguous)
        {
            errors.Add("Ambiguous application identities cannot receive a simulated rule.");
        }
        return errors.Count == 0 ? ValidationResult.Valid : new ValidationResult(errors);
    }

    public ProgramIdentity MarkMoved(string currentExecutablePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(currentExecutablePath);
        if (Kind != ProgramIdentityKind.Win32Executable) throw new InvalidOperationException("Only a Win32 identity can be moved.");
        return this with { ExecutablePath = NormalizePath(currentExecutablePath), PathStatus = ProgramPathStatus.Moved };
    }

    public static ProgramIdentity CreateWin32(
        string inventoryStableId,
        string displayName,
        string executablePath,
        string? publisher,
        bool exists,
        bool isSystemComponent = false) =>
        new(
            RequireStableInventoryId(inventoryStableId),
            ProgramIdentityKind.Win32Executable,
            displayName,
            publisher,
            NormalizePath(executablePath),
            null,
            isSystemComponent,
            exists ? ProgramPathStatus.Present : ProgramPathStatus.Missing,
            "Read-only inventory stable ID plus canonical executable path");

    public static ProgramIdentity CreateMsix(
        string inventoryStableId,
        string displayName,
        string packageFamilyName,
        string? publisher,
        bool isSystemComponent = false) =>
        new(
            RequireStableInventoryId(inventoryStableId),
            ProgramIdentityKind.MicrosoftStoreOrMsix,
            displayName,
            publisher,
            null,
            packageFamilyName.Trim(),
            isSystemComponent,
            ProgramPathStatus.PackageManaged,
            "Read-only inventory stable ID plus package family name");

    public static ProgramIdentity Ambiguous(string displayName, IReadOnlyList<string> candidateEvidence)
    {
        ArgumentNullException.ThrowIfNull(candidateEvidence);
        var evidence = string.Join("|", candidateEvidence.Order(StringComparer.OrdinalIgnoreCase));
        var digest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(evidence)));
        return new($"ambiguous:{digest}", ProgramIdentityKind.Win32Executable, displayName, null,
            candidateEvidence.Count > 0 ? candidateEvidence[0] : "[unresolved]", null, false, ProgramPathStatus.Ambiguous,
            $"{candidateEvidence.Count} non-display-name candidates require disambiguation");
    }

    private static string RequireStableInventoryId(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return value.Trim();
    }

    private static string NormalizePath(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return Path.GetFullPath(value).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
    }
}
