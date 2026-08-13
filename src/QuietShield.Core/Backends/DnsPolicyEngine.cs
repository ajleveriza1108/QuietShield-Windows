// QuietShield Backend Pack 1-4 R1
using System.Globalization;
using System.Net;

namespace QuietShield.Core.Backends;

public enum DnsPolicyAction
{
    Allow = 0,
    Block = 1
}

public sealed record DnsPolicyRule(
    string Pattern,
    DnsPolicyAction Action,
    bool IncludeSubdomains = true,
    int Priority = 0);

public sealed record DnsPolicyDecision(
    string Host,
    DnsPolicyAction Action,
    string MatchedPattern,
    int Priority,
    bool Matched);

public sealed record DnsProxyConfiguration(
    IPAddress UpstreamAddress,
    int UpstreamPort = 53,
    int ListenPort = 0,
    TimeSpan? QueryTimeout = null)
{
    public TimeSpan EffectiveQueryTimeout => QueryTimeout ?? TimeSpan.FromSeconds(3);
}

public sealed class DnsPolicyEngine
{
    private readonly object _sync = new();
    private IReadOnlyList<DnsPolicyRule> _rules = Array.Empty<DnsPolicyRule>();
    private readonly IdnMapping _idn = new();

    public DnsPolicyEngine(IEnumerable<DnsPolicyRule>? rules = null)
    {
        ReplaceRules(rules ?? Array.Empty<DnsPolicyRule>());
    }

    public void ReplaceRules(IEnumerable<DnsPolicyRule> rules)
    {
        ArgumentNullException.ThrowIfNull(rules);

        var normalized = rules
            .Select(rule => rule with { Pattern = NormalizePattern(rule.Pattern) })
            .Where(rule => !string.IsNullOrWhiteSpace(rule.Pattern))
            .OrderByDescending(rule => rule.Priority)
            .ThenBy(rule => rule.Action == DnsPolicyAction.Allow ? 0 : 1)
            .ThenByDescending(rule => rule.Pattern.Length)
            .ToArray();

        lock (_sync)
        {
            _rules = normalized;
        }
    }

    public DnsPolicyDecision Evaluate(string host)
    {
        var normalizedHost = NormalizeHost(host);
        IReadOnlyList<DnsPolicyRule> snapshot;
        lock (_sync)
        {
            snapshot = _rules;
        }

        foreach (var rule in snapshot)
        {
            if (Matches(normalizedHost, rule))
            {
                return new(
                    normalizedHost,
                    rule.Action,
                    rule.Pattern,
                    rule.Priority,
                    true);
            }
        }

        return new(
            normalizedHost,
            DnsPolicyAction.Allow,
            string.Empty,
            0,
            false);
    }

    public static string NormalizeHost(string host)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        var trimmed = host.Trim().TrimEnd('.').ToLowerInvariant();
        if (trimmed.Length == 0)
        {
            throw new ArgumentException("DNS host cannot be empty.", nameof(host));
        }

        return new IdnMapping().GetAscii(trimmed).ToLowerInvariant();
    }

    private string NormalizePattern(string pattern)
    {
        if (string.IsNullOrWhiteSpace(pattern))
        {
            return string.Empty;
        }

        var trimmed = pattern.Trim().ToLowerInvariant();
        if (trimmed.StartsWith("*.", StringComparison.Ordinal))
        {
            return "*." + _idn.GetAscii(trimmed[2..].TrimEnd('.')).ToLowerInvariant();
        }

        return _idn.GetAscii(trimmed.TrimEnd('.')).ToLowerInvariant();
    }

    private static bool Matches(string host, DnsPolicyRule rule)
    {
        if (rule.Pattern.StartsWith("*.", StringComparison.Ordinal))
        {
            var suffix = rule.Pattern[2..];
            return host.EndsWith("." + suffix, StringComparison.Ordinal);
        }

        if (host.Equals(rule.Pattern, StringComparison.Ordinal))
        {
            return true;
        }

        return rule.IncludeSubdomains &&
               host.EndsWith("." + rule.Pattern, StringComparison.Ordinal);
    }
}
