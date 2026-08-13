// QuietShield Backend Pack 5-8 R1
using System.Security.Cryptography;
using System.Text.Json;

namespace QuietShield.Core.FinalBackends;

public enum FamilyRole
{
    Parent = 0,
    Child = 1,
    PrivateAdministrator = 2
}

public sealed record DailyAccessWindow(
    DayOfWeek Day,
    TimeOnly StartInclusive,
    TimeOnly EndExclusive)
{
    public bool Contains(DateTimeOffset localTime)
    {
        if (localTime.DayOfWeek != Day)
        {
            return false;
        }

        var value = TimeOnly.FromDateTime(localTime.DateTime);
        return StartInclusive <= value && value < EndExclusive;
    }
}

public sealed record ChildProtectionPolicy(
    string PolicyId,
    string DisplayName,
    bool Enabled,
    IReadOnlyList<string> BlockedApplicationIdentities,
    IReadOnlyList<string> AllowedApplicationIdentities,
    IReadOnlyList<string> BlockedHosts,
    IReadOnlyList<DailyAccessWindow> AllowedWindows,
    bool BlockUnknownApplications,
    bool RequireHttpsForChildBrowsing);

public sealed record ChildAccessRequest(
    FamilyRole Role,
    DateTimeOffset LocalTime,
    string StableApplicationIdentity,
    Uri? Destination);

public sealed record ChildAccessDecision(
    bool Allowed,
    string Reason,
    bool ScheduleMatched,
    bool ApplicationMatched,
    bool WebsiteMatched);

public static class ParentChildPolicyEngine
{
    public static ChildAccessDecision Evaluate(
        ChildProtectionPolicy policy,
        ChildAccessRequest request)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(request);

        if (request.Role is FamilyRole.Parent or FamilyRole.PrivateAdministrator)
        {
            return new(true, "Parent/administrator role is not restricted by the child policy.", true, true, true);
        }

        if (!policy.Enabled)
        {
            return new(true, "Child policy is disabled.", true, true, true);
        }

        var scheduleMatched =
            policy.AllowedWindows.Count == 0 ||
            policy.AllowedWindows.Any(window => window.Contains(request.LocalTime));

        if (!scheduleMatched)
        {
            return new(false, "Current time is outside the child's allowed schedule.", false, false, false);
        }

        var appIdentity = (request.StableApplicationIdentity ?? string.Empty).Trim();
        var explicitlyAllowed = policy.AllowedApplicationIdentities.Contains(appIdentity, StringComparer.Ordinal);
        var explicitlyBlocked = policy.BlockedApplicationIdentities.Contains(appIdentity, StringComparer.Ordinal);

        if (explicitlyBlocked)
        {
            return new(false, "Application is explicitly blocked by the child policy.", true, true, false);
        }

        if (policy.BlockUnknownApplications &&
            !explicitlyAllowed &&
            policy.AllowedApplicationIdentities.Count > 0)
        {
            return new(false, "Application is not on the child's allowlist.", true, false, false);
        }

        if (request.Destination is null)
        {
            return new(true, "Application access is allowed by the child policy.", true, true, true);
        }

        if (policy.RequireHttpsForChildBrowsing &&
            !request.Destination.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            return new(false, "Child browsing policy requires HTTPS.", true, true, true);
        }

        var host = NormalizeHost(request.Destination.Host);
        var blockedHost = policy.BlockedHosts.Any(pattern => HostMatches(host, pattern));
        if (blockedHost)
        {
            return new(false, "Destination is blocked by the child website policy.", true, true, true);
        }

        return new(true, "Child access is allowed.", true, true, false);
    }

    private static string NormalizeHost(string host) =>
        host.Trim().TrimEnd('.').ToLowerInvariant();

    private static bool HostMatches(string host, string pattern)
    {
        var normalized = pattern.Trim().TrimEnd('.').ToLowerInvariant();
        if (normalized.StartsWith("*.", StringComparison.Ordinal))
        {
            var suffix = normalized[2..];
            return host.EndsWith("." + suffix, StringComparison.Ordinal);
        }

        return host.Equals(normalized, StringComparison.Ordinal) ||
               host.EndsWith("." + normalized, StringComparison.Ordinal);
    }
}

public sealed record ParentPinCredential(
    string SaltBase64,
    string HashBase64,
    int Iterations)
{
    private const int SaltLength = 16;
    private const int HashLength = 32;
    private const int DefaultIterations = 150_000;

    public static ParentPinCredential Create(string pin, int iterations = DefaultIterations)
    {
        ValidatePin(pin);
        if (iterations < 100_000)
        {
            throw new ArgumentOutOfRangeException(nameof(iterations), "PIN derivation iterations are below the minimum.");
        }

        var salt = RandomNumberGenerator.GetBytes(SaltLength);
        var hash = Rfc2898DeriveBytes.Pbkdf2(
            pin,
            salt,
            iterations,
            HashAlgorithmName.SHA256,
            HashLength);

        return new(
            Convert.ToBase64String(salt),
            Convert.ToBase64String(hash),
            iterations);
    }

    public bool Verify(string pin)
    {
        ValidatePin(pin);

        var salt = Convert.FromBase64String(SaltBase64);
        var expected = Convert.FromBase64String(HashBase64);
        var actual = Rfc2898DeriveBytes.Pbkdf2(
            pin,
            salt,
            Iterations,
            HashAlgorithmName.SHA256,
            expected.Length);

        return CryptographicOperations.FixedTimeEquals(expected, actual);
    }

    private static void ValidatePin(string pin)
    {
        if (string.IsNullOrWhiteSpace(pin) ||
            pin.Length < 6 ||
            pin.Length > 64)
        {
            throw new ArgumentException("Parent PIN must contain 6 to 64 characters.", nameof(pin));
        }
    }
}

public sealed record SignedChildPolicyEnvelope(
    string PayloadBase64,
    string MacBase64);

public static class ChildPolicyIntegrity
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public static SignedChildPolicyEnvelope Protect(
        ChildProtectionPolicy policy,
        ReadOnlySpan<byte> integrityKey)
    {
        ArgumentNullException.ThrowIfNull(policy);
        if (integrityKey.Length < 32)
        {
            throw new ArgumentException("Child policy integrity key must be at least 256 bits.", nameof(integrityKey));
        }

        var payload = JsonSerializer.SerializeToUtf8Bytes(policy, JsonOptions);
        var mac = HMACSHA256.HashData(integrityKey, payload);

        return new(
            Convert.ToBase64String(payload),
            Convert.ToBase64String(mac));
    }

    public static ChildProtectionPolicy Unprotect(
        SignedChildPolicyEnvelope envelope,
        ReadOnlySpan<byte> integrityKey)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        if (integrityKey.Length < 32)
        {
            throw new ArgumentException("Child policy integrity key must be at least 256 bits.", nameof(integrityKey));
        }

        var payload = Convert.FromBase64String(envelope.PayloadBase64);
        var expectedMac = Convert.FromBase64String(envelope.MacBase64);
        var actualMac = HMACSHA256.HashData(integrityKey, payload);

        if (!CryptographicOperations.FixedTimeEquals(expectedMac, actualMac))
        {
            throw new CryptographicException("Child policy integrity validation failed.");
        }

        return JsonSerializer.Deserialize<ChildProtectionPolicy>(payload, JsonOptions)
               ?? throw new InvalidDataException("Child policy payload is invalid.");
    }
}
