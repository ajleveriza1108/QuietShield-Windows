namespace QuietShield.Core.Dns;

public interface IDnsClock
{
    DateTimeOffset UtcNow { get; }
}

public sealed class SystemDnsClock : IDnsClock
{
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}

public enum DnsCacheEntryKind
{
    Positive,
    Negative
}

public sealed record DnsDecisionCacheKey(string NormalizedDomain, DnsProtectionMode ProtectionMode);

public sealed record DnsDecisionCacheValue(DnsPolicyResult Result, DnsCacheEntryKind Kind, DateTimeOffset ExpiresAtUtc);

public interface IDnsDecisionCache
{
    Task<DnsDecisionCacheValue?> TryGetAsync(DnsDecisionCacheKey key, CancellationToken cancellationToken);
    Task SetAsync(DnsDecisionCacheKey key, DnsPolicyResult result, DnsCacheEntryKind kind, TimeSpan ttl, CancellationToken cancellationToken);
    Task ClearAsync(CancellationToken cancellationToken);
    int Count { get; }
}

public sealed class InMemoryDnsDecisionCache : IDnsDecisionCache
{
    private readonly object _sync = new();
    private readonly Dictionary<DnsDecisionCacheKey, CacheEntry> _entries = new();
    private readonly IDnsClock _clock;
    private readonly int _maximumSize;
    private long _sequence;

    public InMemoryDnsDecisionCache(IDnsClock clock, int maximumSize)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumSize);
        _clock = clock;
        _maximumSize = maximumSize;
    }

    public int Count { get { lock (_sync) { RemoveExpired(); return _entries.Count; } } }

    public Task<DnsDecisionCacheValue?> TryGetAsync(DnsDecisionCacheKey key, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(key);
        cancellationToken.ThrowIfCancellationRequested();
        lock (_sync)
        {
            RemoveExpired();
            return Task.FromResult(_entries.TryGetValue(key, out var entry)
                ? new DnsDecisionCacheValue(entry.Result, entry.Kind, entry.ExpiresAtUtc)
                : null);
        }
    }

    public Task SetAsync(DnsDecisionCacheKey key, DnsPolicyResult result, DnsCacheEntryKind kind, TimeSpan ttl, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(result);
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(ttl, TimeSpan.Zero);
        lock (_sync)
        {
            RemoveExpired();
            if (!_entries.ContainsKey(key) && _entries.Count >= _maximumSize)
            {
                var oldest = _entries.OrderBy(static pair => pair.Value.Sequence).First().Key;
                _entries.Remove(oldest);
            }

            _entries[key] = new CacheEntry(result, kind, _clock.UtcNow.Add(ttl), ++_sequence);
        }

        return Task.CompletedTask;
    }

    public Task ClearAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_sync) _entries.Clear();
        return Task.CompletedTask;
    }

    private void RemoveExpired()
    {
        var now = _clock.UtcNow;
        foreach (var key in _entries.Where(pair => pair.Value.ExpiresAtUtc <= now).Select(static pair => pair.Key).ToArray())
        {
            _entries.Remove(key);
        }
    }

    private sealed record CacheEntry(DnsPolicyResult Result, DnsCacheEntryKind Kind, DateTimeOffset ExpiresAtUtc, long Sequence);
}
