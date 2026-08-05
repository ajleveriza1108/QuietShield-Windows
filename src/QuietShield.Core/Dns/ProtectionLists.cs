using System.Security.Cryptography;
using System.Text;

namespace QuietShield.Core.Dns;

public sealed record ProtectionListMetadata(
    string ListId,
    string Version,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset ExpiresAtUtc,
    string Sha256,
    string Signature);

public sealed class ProtectionListSnapshot
{
    public ProtectionListSnapshot(ProtectionListMetadata metadata, IEnumerable<DnsPolicyRule> rules)
    {
        Metadata = metadata;
        Rules = Array.AsReadOnly(rules.ToArray());
    }

    public ProtectionListMetadata Metadata { get; }
    public IReadOnlyList<DnsPolicyRule> Rules { get; }
}

public sealed record ProtectionListConflict(string NormalizedPattern, DnsRuleMatchKind MatchKind, IReadOnlyList<string> RuleIds, string Description);

public sealed record ProtectionListActivationResult(
    bool Succeeded,
    string Status,
    ProtectionListSnapshot? ActiveSnapshot,
    int DuplicateRulesRemoved,
    IReadOnlyList<ProtectionListConflict> Conflicts,
    bool RolledBack);

public interface IProtectionListSignatureVerifier
{
    Task<bool> VerifyAsync(string sha256, string signature, CancellationToken cancellationToken);
}

public interface IProtectionListStore
{
    ProtectionListSnapshot? ActiveSnapshot { get; }
    ProtectionListSnapshot? LastKnownGoodSnapshot { get; }
    Task ActivateAsync(ProtectionListSnapshot snapshot, CancellationToken cancellationToken);
    Task<bool> RollbackAsync(CancellationToken cancellationToken);
}

public interface IProtectionListDifferentialUpdater
{
    Task<ProtectionListSnapshot> ApplyAsync(ProtectionListSnapshot baseline, Stream differentialPayload, CancellationToken cancellationToken);
}

public sealed class InMemoryProtectionListStore : IProtectionListStore
{
    private readonly object _sync = new();
    private ProtectionListSnapshot? _active;
    private ProtectionListSnapshot? _lastKnownGood;
    private ProtectionListSnapshot? _rollback;

    public ProtectionListSnapshot? ActiveSnapshot { get { lock (_sync) return _active; } }
    public ProtectionListSnapshot? LastKnownGoodSnapshot { get { lock (_sync) return _lastKnownGood; } }

    public Task ActivateAsync(ProtectionListSnapshot snapshot, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_sync)
        {
            _rollback = _active;
            _active = snapshot;
            _lastKnownGood = snapshot;
        }

        return Task.CompletedTask;
    }

    public Task<bool> RollbackAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_sync)
        {
            if (_rollback is null) return Task.FromResult(false);
            _active = _rollback;
            _lastKnownGood = _rollback;
            _rollback = null;
            return Task.FromResult(true);
        }
    }
}

public sealed class ProtectionListActivator
{
    private readonly IProtectionListSignatureVerifier _signatureVerifier;
    private readonly IProtectionListStore _store;
    private readonly IDnsClock _clock;

    public ProtectionListActivator(IProtectionListSignatureVerifier signatureVerifier, IProtectionListStore store, IDnsClock clock)
    {
        _signatureVerifier = signatureVerifier;
        _store = store;
        _clock = clock;
    }

    public async Task<ProtectionListActivationResult> ActivateAsync(ProtectionListSnapshot candidate, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        cancellationToken.ThrowIfCancellationRequested();
        if (candidate.Metadata.ExpiresAtUtc <= candidate.Metadata.CreatedAtUtc || candidate.Metadata.ExpiresAtUtc <= _clock.UtcNow)
        {
            return Failed("The protection list is expired or has invalid timestamps.");
        }

        var normalization = NormalizeRules(candidate.Rules);
        if (!normalization.Succeeded)
        {
            return new ProtectionListActivationResult(false, normalization.Error!, _store.ActiveSnapshot, normalization.Duplicates, normalization.Conflicts, false);
        }

        var canonicalPayload = new ProtectionListSnapshot(candidate.Metadata, normalization.CanonicalRules);
        var normalizedSnapshot = new ProtectionListSnapshot(candidate.Metadata, normalization.Rules);
        var computedHash = ProtectionListHasher.ComputeSha256(canonicalPayload);
        if (!ProtectionListHasher.FixedTimeEquals(computedHash, candidate.Metadata.Sha256))
        {
            return new ProtectionListActivationResult(false, "SHA-256 verification failed; the previous active list remains unchanged.", _store.ActiveSnapshot, normalization.Duplicates, normalization.Conflicts, false);
        }

        if (!await _signatureVerifier.VerifyAsync(computedHash, candidate.Metadata.Signature, cancellationToken).ConfigureAwait(false))
        {
            return new ProtectionListActivationResult(false, "Signature verification failed; the previous active list remains unchanged.", _store.ActiveSnapshot, normalization.Duplicates, normalization.Conflicts, false);
        }

        try
        {
            await _store.ActivateAsync(normalizedSnapshot, cancellationToken).ConfigureAwait(false);
            return new ProtectionListActivationResult(true, "The verified protection list was activated atomically.", normalizedSnapshot, normalization.Duplicates, normalization.Conflicts, false);
        }
        catch (Exception exception) when (exception is IOException or InvalidOperationException)
        {
            var rolledBack = await _store.RollbackAsync(CancellationToken.None).ConfigureAwait(false);
            return new ProtectionListActivationResult(false, $"Activation failed: {exception.Message}", _store.ActiveSnapshot, normalization.Duplicates, normalization.Conflicts, rolledBack);
        }
    }

    public Task<bool> RollbackAsync(CancellationToken cancellationToken) => _store.RollbackAsync(cancellationToken);

    private ProtectionListActivationResult Failed(string status) => new(false, status, _store.ActiveSnapshot, 0, Array.Empty<ProtectionListConflict>(), false);

    private static RuleNormalizationResult NormalizeRules(IReadOnlyList<DnsPolicyRule> rules)
    {
        var normalized = new List<DnsPolicyRule>();
        foreach (var rule in rules)
        {
            var pattern = DomainNormalizer.NormalizeRule(rule.DomainPattern, rule.MatchKind);
            if (!pattern.IsValid || pattern.NormalizedValue is null)
            {
                return RuleNormalizationResult.Failure($"Rule '{rule.Id}' is invalid: {pattern.Error}");
            }

            if (rule.Decision == DnsDecision.Indeterminate)
            {
                return RuleNormalizationResult.Failure($"Rule '{rule.Id}' cannot use an Indeterminate list decision.");
            }

            normalized.Add(rule with { DomainPattern = pattern.NormalizedValue });
        }

        var distinct = normalized.GroupBy(static rule => string.Join('|', rule.DomainPattern, rule.MatchKind, rule.Decision, rule.Category, rule.SourceKind), StringComparer.Ordinal)
            .Select(static group => group.OrderBy(static rule => rule.Id, StringComparer.Ordinal).First()).ToArray();
        var conflicts = distinct.GroupBy(static rule => (rule.DomainPattern, rule.MatchKind))
            .Where(static group => group.Select(static rule => rule.Decision).Distinct().Count() > 1)
            .Select(static group => new ProtectionListConflict(
                group.Key.DomainPattern,
                group.Key.MatchKind,
                group.Select(static rule => rule.Id).OrderBy(static id => id, StringComparer.Ordinal).ToArray(),
                "Allow and block rules target the same normalized pattern."))
            .ToArray();
        return RuleNormalizationResult.Success(normalized, distinct, normalized.Count - distinct.Length, conflicts);
    }

    private sealed record RuleNormalizationResult(bool Succeeded, IReadOnlyList<DnsPolicyRule> CanonicalRules, IReadOnlyList<DnsPolicyRule> Rules, int Duplicates, IReadOnlyList<ProtectionListConflict> Conflicts, string? Error)
    {
        public static RuleNormalizationResult Success(IReadOnlyList<DnsPolicyRule> canonicalRules, IReadOnlyList<DnsPolicyRule> rules, int duplicates, IReadOnlyList<ProtectionListConflict> conflicts) => new(true, canonicalRules, rules, duplicates, conflicts, null);
        public static RuleNormalizationResult Failure(string error) => new(false, Array.Empty<DnsPolicyRule>(), Array.Empty<DnsPolicyRule>(), 0, Array.Empty<ProtectionListConflict>(), error);
    }
}

public static class ProtectionListHasher
{
    public static string ComputeSha256(ProtectionListSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        var content = new StringBuilder()
            .Append(snapshot.Metadata.ListId).Append('\n')
            .Append(snapshot.Metadata.Version).Append('\n')
            .Append(snapshot.Metadata.CreatedAtUtc.ToUniversalTime().ToString("O", System.Globalization.CultureInfo.InvariantCulture)).Append('\n')
            .Append(snapshot.Metadata.ExpiresAtUtc.ToUniversalTime().ToString("O", System.Globalization.CultureInfo.InvariantCulture)).Append('\n');
        foreach (var rule in snapshot.Rules.OrderBy(static rule => rule.Id, StringComparer.Ordinal))
        {
            content.Append(rule.Id).Append('|').Append(rule.DomainPattern).Append('|').Append(rule.MatchKind).Append('|')
                .Append(rule.Decision).Append('|').Append(rule.Category).Append('|').Append(rule.SourceName).Append('|')
                .Append(rule.SourceKind).Append('\n');
        }

        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(content.ToString())));
    }

    public static bool FixedTimeEquals(string first, string second)
    {
        if (first.Length != second.Length) return false;
        return CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(first), Encoding.ASCII.GetBytes(second));
    }
}

public sealed class NonProductionSampleSignatureVerifier : IProtectionListSignatureVerifier
{
    public const string SampleSignature = "NON-PRODUCTION-SAMPLE-SIGNATURE";

    public Task<bool> VerifyAsync(string sha256, string signature, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(signature.Equals(SampleSignature, StringComparison.Ordinal));
    }
}
