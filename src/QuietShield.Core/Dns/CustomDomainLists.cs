using System.Text.Json;

namespace QuietShield.Core.Dns;

public enum CustomDomainListKind
{
    Allowlist,
    Blocklist
}

public sealed record CustomDomainEntry(
    Guid Id,
    string DomainPattern,
    DnsRuleMatchKind MatchKind,
    CustomDomainListKind ListKind,
    string? Notes,
    DateTimeOffset CreatedAtUtc,
    bool ParentProtected)
{
    public DnsPolicyRule ToPolicyRule()
    {
        var sourceKind = ListKind == CustomDomainListKind.Allowlist
            ? DnsRuleSourceKind.CustomAllowlist
            : ParentProtected ? DnsRuleSourceKind.ParentProtectedBlock : DnsRuleSourceKind.CustomBlocklist;
        return new DnsPolicyRule(
            Id.ToString("D"),
            DomainPattern,
            MatchKind,
            ListKind == CustomDomainListKind.Allowlist ? DnsDecision.Allow : DnsDecision.Block,
            DnsCategory.Custom,
            ListKind == CustomDomainListKind.Allowlist ? "Custom allowlist" : ParentProtected ? "Parent-protected custom blocklist" : "Custom blocklist",
            sourceKind);
    }
}

public sealed record CustomDomainEntryDraft(
    string DomainPattern,
    DnsRuleMatchKind MatchKind,
    CustomDomainListKind ListKind,
    string? Notes,
    bool ParentProtected);

public sealed record CustomDomainListOperation(bool Succeeded, string Status, CustomDomainEntry? Entry);

public interface ICustomDomainListService
{
    Task<IReadOnlyList<CustomDomainEntry>> GetAllAsync(CancellationToken cancellationToken);
    Task<IReadOnlyList<CustomDomainEntry>> SearchAsync(string? query, CancellationToken cancellationToken);
    Task<CustomDomainListOperation> AddAsync(CustomDomainEntryDraft draft, CancellationToken cancellationToken);
    Task<CustomDomainListOperation> EditAsync(Guid id, CustomDomainEntryDraft draft, CancellationToken cancellationToken);
    Task<CustomDomainListOperation> RemoveAsync(Guid id, CancellationToken cancellationToken);
    Task<string> ExportJsonAsync(CancellationToken cancellationToken);
    Task<CustomDomainListOperation> ImportJsonAsync(string json, CancellationToken cancellationToken);
}

public sealed class InMemoryCustomDomainListService : ICustomDomainListService, IDisposable
{
    private const int MaximumNotesLength = 500;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    private readonly ReaderWriterLockSlim _lock = new(LockRecursionPolicy.NoRecursion);
    private readonly IDnsClock _clock;
    private List<CustomDomainEntry> _entries = new();

    public InMemoryCustomDomainListService(IDnsClock clock) => _clock = clock;

    public Task<IReadOnlyList<CustomDomainEntry>> GetAllAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _lock.EnterReadLock();
        try { return Task.FromResult<IReadOnlyList<CustomDomainEntry>>(_entries.OrderBy(static entry => entry.DomainPattern, StringComparer.Ordinal).ToArray()); }
        finally { _lock.ExitReadLock(); }
    }

    public async Task<IReadOnlyList<CustomDomainEntry>> SearchAsync(string? query, CancellationToken cancellationToken)
    {
        var all = await GetAllAsync(cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(query)) return all;
        return all.Where(entry => entry.DomainPattern.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                                  (entry.Notes?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false)).ToArray();
    }

    public Task<CustomDomainListOperation> AddAsync(CustomDomainEntryDraft draft, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var validation = Validate(draft);
        if (!validation.Succeeded) return Task.FromResult(validation);
        var normalizedDraft = Normalize(draft, validation.Entry!.DomainPattern);
        _lock.EnterWriteLock();
        try
        {
            if (HasDuplicate(_entries, normalizedDraft, null)) return Task.FromResult(Failure("A matching entry already exists in this list."));
            var entry = new CustomDomainEntry(Guid.NewGuid(), normalizedDraft.DomainPattern, normalizedDraft.MatchKind, normalizedDraft.ListKind, normalizedDraft.Notes, _clock.UtcNow, normalizedDraft.ParentProtected);
            _entries.Add(entry);
            return Task.FromResult(new CustomDomainListOperation(true, "The custom DNS entry was added to the in-memory simulation list.", entry));
        }
        finally { _lock.ExitWriteLock(); }
    }

    public Task<CustomDomainListOperation> EditAsync(Guid id, CustomDomainEntryDraft draft, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var validation = Validate(draft);
        if (!validation.Succeeded) return Task.FromResult(validation);
        var normalizedDraft = Normalize(draft, validation.Entry!.DomainPattern);
        _lock.EnterWriteLock();
        try
        {
            var index = _entries.FindIndex(entry => entry.Id == id);
            if (index < 0) return Task.FromResult(Failure("The custom DNS entry was not found."));
            if (HasDuplicate(_entries, normalizedDraft, id)) return Task.FromResult(Failure("A matching entry already exists in this list."));
            var updated = _entries[index] with
            {
                DomainPattern = normalizedDraft.DomainPattern,
                MatchKind = normalizedDraft.MatchKind,
                ListKind = normalizedDraft.ListKind,
                Notes = normalizedDraft.Notes,
                ParentProtected = normalizedDraft.ParentProtected
            };
            _entries[index] = updated;
            return Task.FromResult(new CustomDomainListOperation(true, "The custom DNS entry was updated.", updated));
        }
        finally { _lock.ExitWriteLock(); }
    }

    public Task<CustomDomainListOperation> RemoveAsync(Guid id, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _lock.EnterWriteLock();
        try
        {
            var entry = _entries.FirstOrDefault(item => item.Id == id);
            if (entry is null) return Task.FromResult(Failure("The custom DNS entry was not found."));
            _entries.Remove(entry);
            return Task.FromResult(new CustomDomainListOperation(true, "The custom DNS entry was removed.", entry));
        }
        finally { _lock.ExitWriteLock(); }
    }

    public async Task<string> ExportJsonAsync(CancellationToken cancellationToken)
    {
        var entries = await GetAllAsync(cancellationToken).ConfigureAwait(false);
        return JsonSerializer.Serialize(new CustomDomainListDocument(1, "QuietShield custom DNS simulation entries", entries), JsonOptions);
    }

    public Task<CustomDomainListOperation> ImportJsonAsync(string json, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (string.IsNullOrWhiteSpace(json)) return Task.FromResult(Failure("Import JSON is empty."));
        CustomDomainListDocument? document;
        try { document = JsonSerializer.Deserialize<CustomDomainListDocument>(json, JsonOptions); }
        catch (JsonException exception) { return Task.FromResult(Failure($"Import JSON is invalid: {exception.Message}")); }
        if (document is null || document.SchemaVersion != 1 || document.Entries is null) return Task.FromResult(Failure("The custom DNS list schema is unsupported."));

        var validated = new List<CustomDomainEntry>();
        foreach (var entry in document.Entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var draft = new CustomDomainEntryDraft(entry.DomainPattern, entry.MatchKind, entry.ListKind, entry.Notes, entry.ParentProtected);
            var validation = Validate(draft);
            if (!validation.Succeeded) return Task.FromResult(validation with { Status = $"Entry '{entry.Id}' is invalid: {validation.Status}" });
            var normalized = Normalize(draft, validation.Entry!.DomainPattern);
            if (entry.Id == Guid.Empty) return Task.FromResult(Failure("Imported entries require non-empty IDs."));
            var normalizedEntry = entry with
            {
                DomainPattern = normalized.DomainPattern,
                Notes = normalized.Notes,
                CreatedAtUtc = entry.CreatedAtUtc == default ? _clock.UtcNow : entry.CreatedAtUtc
            };
            if (validated.Any(item => item.Id == normalizedEntry.Id) || HasDuplicate(validated, normalized, null))
            {
                return Task.FromResult(Failure("The imported document contains duplicate entries."));
            }

            validated.Add(normalizedEntry);
        }

        _lock.EnterWriteLock();
        try { _entries = validated; }
        finally { _lock.ExitWriteLock(); }
        return Task.FromResult(new CustomDomainListOperation(true, $"Imported {validated.Count} custom DNS simulation entries atomically.", null));
    }

    public void Dispose()
    {
        _lock.Dispose();
        GC.SuppressFinalize(this);
    }

    private static CustomDomainListOperation Validate(CustomDomainEntryDraft draft)
    {
        ArgumentNullException.ThrowIfNull(draft);
        var normalization = DomainNormalizer.NormalizeRule(draft.DomainPattern, draft.MatchKind);
        if (!normalization.IsValid || normalization.NormalizedValue is null) return Failure(normalization.Error ?? "The domain pattern is invalid.");
        if (draft.Notes?.Length > MaximumNotesLength) return Failure($"Notes cannot exceed {MaximumNotesLength} characters.");
        var placeholder = new CustomDomainEntry(Guid.Empty, normalization.NormalizedValue, draft.MatchKind, draft.ListKind, NormalizeNotes(draft.Notes), default, draft.ParentProtected);
        return new CustomDomainListOperation(true, "Valid", placeholder);
    }

    private static CustomDomainEntryDraft Normalize(CustomDomainEntryDraft draft, string normalizedPattern) =>
        draft with { DomainPattern = normalizedPattern, Notes = NormalizeNotes(draft.Notes) };

    private static string? NormalizeNotes(string? notes) => string.IsNullOrWhiteSpace(notes) ? null : notes.Trim();

    private static bool HasDuplicate(IEnumerable<CustomDomainEntry> entries, CustomDomainEntryDraft draft, Guid? excludedId) =>
        entries.Any(entry => entry.Id != excludedId && entry.ListKind == draft.ListKind && entry.MatchKind == draft.MatchKind &&
                             entry.DomainPattern.Equals(draft.DomainPattern, StringComparison.Ordinal));

    private static CustomDomainListOperation Failure(string status) => new(false, status, null);

    private sealed record CustomDomainListDocument(int SchemaVersion, string Description, IReadOnlyList<CustomDomainEntry>? Entries);
}
