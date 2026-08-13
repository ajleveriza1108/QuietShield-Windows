// QuietShield Backend Pack 5-8 R1
using System.Security.Cryptography;
using System.Text.Json;

namespace QuietShield.Licensing;

public sealed record SignedLicensePayload(
    string LicenseId,
    LicenseState State,
    DateTimeOffset IssuedAtUtc,
    DateTimeOffset ExpiresAtUtc,
    string OpaqueDeviceId,
    IReadOnlyList<LicensedDevice> Devices,
    TrialState? Trial,
    bool IsPrivateAdministratorLicense,
    string PolicyVersion);

public sealed record SignedLicenseEnvelope(
    string PayloadBase64,
    string SignatureBase64);

public static class SignedLicenseBackend
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public static SignedLicenseEnvelope SignForTesting(
        SignedLicensePayload payload,
        ECDsa privateKey)
    {
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentNullException.ThrowIfNull(privateKey);

        var bytes = JsonSerializer.SerializeToUtf8Bytes(payload, JsonOptions);
        var signature = privateKey.SignData(bytes, HashAlgorithmName.SHA256);

        return new(
            Convert.ToBase64String(bytes),
            Convert.ToBase64String(signature));
    }

    public static SignedLicensePayload Verify(
        SignedLicenseEnvelope envelope,
        ReadOnlySpan<byte> subjectPublicKeyInfo,
        string expectedOpaqueDeviceId,
        DateTimeOffset trustedNowUtc)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedOpaqueDeviceId);

        var payloadBytes = Convert.FromBase64String(envelope.PayloadBase64);
        var signature = Convert.FromBase64String(envelope.SignatureBase64);

        using var publicKey = ECDsa.Create();
        publicKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo, out var consumed);
        if (consumed != subjectPublicKeyInfo.Length)
        {
            throw new CryptographicException("License public key contained trailing data.");
        }

        if (!publicKey.VerifyData(payloadBytes, signature, HashAlgorithmName.SHA256))
        {
            throw new CryptographicException("License signature validation failed.");
        }

        var payload = JsonSerializer.Deserialize<SignedLicensePayload>(payloadBytes, JsonOptions)
                      ?? throw new InvalidDataException("Signed license payload is invalid.");

        if (!payload.OpaqueDeviceId.Equals(expectedOpaqueDeviceId, StringComparison.Ordinal))
        {
            throw new UnauthorizedAccessException("Signed license is bound to a different opaque device.");
        }

        if (payload.ExpiresAtUtc <= trustedNowUtc &&
            payload.State is not LicenseState.PrivateAdministratorUnlimited)
        {
            throw new InvalidDataException("Signed license payload has expired.");
        }

        ValidatePolicy(payload);
        return payload;
    }

    public static LicenseSnapshot ToSnapshot(
        SignedLicensePayload payload,
        DateTimeOffset trustedNowUtc)
    {
        ArgumentNullException.ThrowIfNull(payload);

        var devicePool = new DevicePoolState(
            payload.Devices,
            payload.IsPrivateAdministratorLicense);

        var state = payload.State;
        var display = state switch
        {
            LicenseState.Licensed => "Licensed",
            LicenseState.ServerControlledTrial => "7-day full-feature trial",
            LicenseState.PrivateAdministratorUnlimited => "Private administrator unlimited",
            LicenseState.TemporaryOfflineGrace => "Temporary offline grace",
            LicenseState.Expired => "Expired",
            LicenseState.DeviceLimitReached => "Device limit reached",
            _ => state.ToString()
        };

        if (payload.Trial is not null &&
            payload.State == LicenseState.ServerControlledTrial &&
            !payload.Trial.IsActiveAt(trustedNowUtc))
        {
            state = LicenseState.Expired;
            display = "Trial expired";
        }

        return new(
            state,
            display,
            devicePool,
            payload.Trial,
            null);
    }

    private static void ValidatePolicy(SignedLicensePayload payload)
    {
        var policy = UniversalLicensePolicy.Default;
        var pool = new DevicePoolState(payload.Devices, payload.IsPrivateAdministratorLicense);

        if (!payload.IsPrivateAdministratorLicense &&
            pool.ActiveDeviceCount > policy.MaximumActiveDevices)
        {
            throw new InvalidDataException("Signed license exceeds the universal three-device limit.");
        }

        if (payload.Trial is not null &&
            !payload.Trial.MatchesPolicy(policy))
        {
            throw new InvalidDataException("Signed trial does not match the universal seven-day server-controlled policy.");
        }
    }
}

public static class TrustedLicenseClock
{
    public static DateTimeOffset ClampForwardOnly(
        DateTimeOffset serverObservedAtUtc,
        DateTimeOffset currentUtc,
        DateTimeOffset lastTrustedUtc)
    {
        var trusted = currentUtc;

        if (trusted < serverObservedAtUtc)
        {
            trusted = serverObservedAtUtc;
        }

        if (trusted < lastTrustedUtc)
        {
            trusted = lastTrustedUtc;
        }

        return trusted;
    }
}
