using System.Text.Json;
using System.Text.Json.Serialization;
using QuietShield.Core.Protection;
using QuietShield.Core.Validation;

namespace QuietShield.Core.ConnectionLock;

public sealed record ConnectionLockProgramRule(
    ProgramIdentity Identity,
    ProgramConnectionPolicy Policy,
    bool IsEnabled = true)
{
    public ValidationResult Validate()
    {
        var errors = Identity.Validate().Errors.ToList();
        if (!Enum.IsDefined(Policy)) errors.Add("The connection policy is unsupported.");
        return errors.Count == 0 ? ValidationResult.Valid : new ValidationResult(errors);
    }
}

public sealed record ConnectionLockProfile(
    string Id,
    string Name,
    string Description,
    ProgramConnectionPolicy DefaultPolicy,
    IReadOnlyList<ConnectionLockProgramRule> ProgramOverrides,
    bool IsFixed,
    bool ParentProtected = false)
{
    public const string BlockAllId = "quietshield.fixed.block-all";

    public static ConnectionLockProfile BlockAll { get; } = new(
        BlockAllId,
        "Block All",
        "Fixed safety profile that simulates blocking every non-exempt connection.",
        ProgramConnectionPolicy.Blocked,
        Array.Empty<ConnectionLockProgramRule>(),
        true);

    public ValidationResult Validate()
    {
        var errors = new List<string>();
        if (string.IsNullOrWhiteSpace(Id)) errors.Add("A profile identifier is required.");
        if (string.IsNullOrWhiteSpace(Name)) errors.Add("A profile name is required.");
        if (Name.Length > 80) errors.Add("Profile names cannot exceed 80 characters.");
        if (Description is null) errors.Add("A profile description is required.");
        else if (Description.Length > 500) errors.Add("Profile descriptions cannot exceed 500 characters.");
        if (!Enum.IsDefined(DefaultPolicy)) errors.Add("The profile default policy is unsupported.");
        if (IsFixed && (!Id.Equals(BlockAllId, StringComparison.Ordinal) || DefaultPolicy != ProgramConnectionPolicy.Blocked))
        {
            errors.Add("Only the canonical Block All profile may be fixed.");
        }

        foreach (var duplicate in ProgramOverrides.GroupBy(static rule => rule.Identity.StableId, StringComparer.OrdinalIgnoreCase).Where(static group => group.Count() > 1))
        {
            errors.Add($"Program identity '{duplicate.Key}' has duplicate overrides.");
        }
        foreach (var rule in ProgramOverrides) errors.AddRange(rule.Validate().Errors);
        return errors.Count == 0 ? ValidationResult.Valid : new ValidationResult(errors);
    }
}

public sealed record ProfileCatalogSnapshot(string SelectedProfileId, IReadOnlyList<ConnectionLockProfile> Profiles);

public sealed class ProtectionProfileCatalog
{
    public const int MaximumEditableProfiles = 5;
    private readonly List<ConnectionLockProfile> _profiles;

    public ProtectionProfileCatalog(IEnumerable<ConnectionLockProfile>? profiles = null, string? selectedProfileId = null)
    {
        _profiles = new List<ConnectionLockProfile> { ConnectionLockProfile.BlockAll };
        foreach (var profile in profiles ?? Array.Empty<ConnectionLockProfile>())
        {
            if (!profile.IsFixed) Add(profile);
        }
        SelectedProfileId = SelectExistingOrBlockAll(selectedProfileId);
    }

    public IReadOnlyList<ConnectionLockProfile> Profiles => _profiles.AsReadOnly();
    public string SelectedProfileId { get; private set; }
    public ConnectionLockProfile SelectedProfile => _profiles.Single(profile => profile.Id.Equals(SelectedProfileId, StringComparison.Ordinal));

    public void Add(ConnectionLockProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        if (profile.IsFixed) throw new InvalidOperationException("The fixed Block All profile is supplied by QuietShield and cannot be added or replaced.");
        EnsureValid(profile, null);
        if (_profiles.Count(static item => !item.IsFixed) >= MaximumEditableProfiles) throw new InvalidOperationException("At most five editable profiles are permitted.");
        _profiles.Add(profile);
    }

    public void Update(ConnectionLockProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        var index = _profiles.FindIndex(item => item.Id.Equals(profile.Id, StringComparison.Ordinal));
        if (index < 0) throw new KeyNotFoundException("The profile does not exist.");
        if (_profiles[index].IsFixed || profile.IsFixed) throw new InvalidOperationException("The fixed Block All profile cannot be edited.");
        EnsureValid(profile, profile.Id);
        _profiles[index] = profile;
    }

    public void Delete(string profileId)
    {
        var profile = _profiles.SingleOrDefault(item => item.Id.Equals(profileId, StringComparison.Ordinal))
            ?? throw new KeyNotFoundException("The profile does not exist.");
        if (profile.IsFixed) throw new InvalidOperationException("The fixed Block All profile cannot be deleted.");
        _profiles.Remove(profile);
        if (SelectedProfileId.Equals(profileId, StringComparison.Ordinal)) SelectedProfileId = ConnectionLockProfile.BlockAllId;
    }

    public void Select(string profileId)
    {
        if (!_profiles.Any(item => item.Id.Equals(profileId, StringComparison.Ordinal))) throw new KeyNotFoundException("The selected profile does not exist.");
        SelectedProfileId = profileId;
    }

    public ProfileCatalogSnapshot Snapshot() => new(SelectedProfileId, _profiles.ToArray());

    private void EnsureValid(ConnectionLockProfile profile, string? replacingId)
    {
        var validation = profile.Validate();
        if (!validation.IsValid) throw new ArgumentException(string.Join(" ", validation.Errors), nameof(profile));
        if (_profiles.Any(item => !item.Id.Equals(replacingId, StringComparison.Ordinal) && item.Id.Equals(profile.Id, StringComparison.OrdinalIgnoreCase)))
            throw new ArgumentException("A profile with this identifier already exists.", nameof(profile));
        if (_profiles.Any(item => !item.Id.Equals(replacingId, StringComparison.Ordinal) && item.Name.Equals(profile.Name, StringComparison.OrdinalIgnoreCase)))
            throw new ArgumentException("A profile with this name already exists.", nameof(profile));
    }

    private string SelectExistingOrBlockAll(string? selectedProfileId) =>
        _profiles.Any(item => item.Id.Equals(selectedProfileId, StringComparison.Ordinal))
            ? selectedProfileId!
            : ConnectionLockProfile.BlockAllId;
}

public static class PrivacySafeProfileJson
{
    private const int SchemaVersion = 1;
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public static string Export(ProfileCatalogSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        var document = new PortableCatalog(
            SchemaVersion,
            snapshot.SelectedProfileId,
            snapshot.Profiles.Where(static profile => !profile.IsFixed).Select(static profile => new PortableProfile(
                profile.Id,
                profile.Name,
                profile.Description,
                profile.DefaultPolicy,
                profile.ParentProtected,
                profile.ProgramOverrides.Select(static rule => new PortableRule(
                    rule.Identity.StableId,
                    rule.Identity.Kind,
                    rule.Policy,
                    rule.IsEnabled)).ToArray())).ToArray());
        return JsonSerializer.Serialize(document, Options);
    }

    public static ProtectionProfileCatalog Import(string json, IReadOnlyDictionary<string, ProgramIdentity> knownIdentities)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);
        ArgumentNullException.ThrowIfNull(knownIdentities);
        PortableCatalog document;
        try
        {
            document = JsonSerializer.Deserialize<PortableCatalog>(json, Options)
                ?? throw new FormatException("The profile document is empty.");
        }
        catch (JsonException exception)
        {
            throw new FormatException("The profile document is malformed JSON.", exception);
        }
        if (document.SchemaVersion != SchemaVersion) throw new NotSupportedException($"Profile schema {document.SchemaVersion} is unsupported.");
        if (document.Profiles is null) throw new FormatException("The profile collection is missing.");
        if (document.Profiles.Count > ProtectionProfileCatalog.MaximumEditableProfiles) throw new FormatException("The document exceeds the five-profile maximum.");

        var profiles = document.Profiles.Select(profile => new ConnectionLockProfile(
            string.IsNullOrWhiteSpace(profile.Id) ? throw new FormatException("A profile identifier is required.") : profile.Id,
            string.IsNullOrWhiteSpace(profile.Name) ? throw new FormatException("A profile name is required.") : profile.Name,
            profile.Description ?? throw new FormatException("A profile description is required."),
            profile.DefaultPolicy,
            (profile.Rules ?? throw new FormatException("A profile rule collection is required.")).Select(rule => new ConnectionLockProgramRule(
                ResolveIdentity(rule, knownIdentities),
                rule.Policy,
                rule.IsEnabled)).ToArray(),
            false,
            profile.ParentProtected)).ToArray();
        try
        {
            return new ProtectionProfileCatalog(profiles, document.SelectedProfileId);
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
        {
            throw new FormatException("The profile document contains an invalid or unsupported profile rule.", exception);
        }
    }

    private static ProgramIdentity ResolveIdentity(PortableRule rule, IReadOnlyDictionary<string, ProgramIdentity> knownIdentities)
    {
        if (!Enum.IsDefined(rule.Kind)) throw new FormatException("A program identity kind is unsupported.");
        if (!Enum.IsDefined(rule.Policy)) throw new FormatException("A program connection policy is unsupported.");
        if (!knownIdentities.TryGetValue(rule.StableApplicationId, out var identity))
            throw new FormatException($"Program identity '{rule.StableApplicationId}' is unavailable or moved without a verified identity match.");
        if (identity.Kind != rule.Kind) throw new FormatException($"Program identity '{rule.StableApplicationId}' has a mismatched identity kind.");
        return identity;
    }

    private sealed record PortableCatalog(int SchemaVersion, string SelectedProfileId, IReadOnlyList<PortableProfile> Profiles);
    private sealed record PortableProfile(string Id, string Name, string? Description, ProgramConnectionPolicy DefaultPolicy, bool ParentProtected, IReadOnlyList<PortableRule>? Rules);
    private sealed record PortableRule(string StableApplicationId, ProgramIdentityKind Kind, ProgramConnectionPolicy Policy, bool IsEnabled);
}
