// QuietShield Backend Pack 5-8 R1
using System.Security.Cryptography;
using System.Text.Json;

namespace QuietShield.Core.FinalBackends;

public sealed record SignedUpdatePayload(
    string Version,
    string PackageName,
    string PackageSha256,
    long PackageLength,
    Uri DownloadUri,
    DateTimeOffset ReleasedAtUtc,
    string MinimumSupportedVersion);

public sealed record SignedUpdateEnvelope(
    string PayloadBase64,
    string SignatureBase64);

public static class SecureUpdateManifest
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public static SignedUpdateEnvelope SignForTesting(
        SignedUpdatePayload payload,
        ECDsa privateKey)
    {
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentNullException.ThrowIfNull(privateKey);

        ValidatePayload(payload);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(payload, JsonOptions);
        var signature = privateKey.SignData(bytes, HashAlgorithmName.SHA256);

        return new(
            Convert.ToBase64String(bytes),
            Convert.ToBase64String(signature));
    }

    public static SignedUpdatePayload Verify(
        SignedUpdateEnvelope envelope,
        ReadOnlySpan<byte> subjectPublicKeyInfo)
    {
        ArgumentNullException.ThrowIfNull(envelope);

        var payloadBytes = Convert.FromBase64String(envelope.PayloadBase64);
        var signature = Convert.FromBase64String(envelope.SignatureBase64);

        using var publicKey = ECDsa.Create();
        publicKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo, out var consumed);
        if (consumed != subjectPublicKeyInfo.Length)
        {
            throw new CryptographicException("Update public key contained trailing data.");
        }

        if (!publicKey.VerifyData(payloadBytes, signature, HashAlgorithmName.SHA256))
        {
            throw new CryptographicException("Update manifest signature validation failed.");
        }

        var payload = JsonSerializer.Deserialize<SignedUpdatePayload>(payloadBytes, JsonOptions)
                      ?? throw new InvalidDataException("Signed update payload is invalid.");

        ValidatePayload(payload);
        return payload;
    }

    public static bool IsNewerVersion(string currentVersion, string candidateVersion)
    {
        var current = ParseVersion(currentVersion);
        var candidate = ParseVersion(candidateVersion);
        return candidate.CompareTo(current) > 0;
    }

    private static Version ParseVersion(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);

        var core = value.Split('-', 2, StringSplitOptions.TrimEntries)[0];
        return Version.TryParse(core, out var version)
            ? version
            : throw new FormatException("Update version is invalid.");
    }

    private static void ValidatePayload(SignedUpdatePayload payload)
    {
        if (!payload.DownloadUri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Update package URI must use HTTPS.");
        }

        if (payload.PackageSha256.Length != 64 ||
            !payload.PackageSha256.All(Uri.IsHexDigit))
        {
            throw new InvalidDataException("Update package SHA-256 is invalid.");
        }

        if (payload.PackageLength <= 0)
        {
            throw new InvalidDataException("Update package length must be positive.");
        }

        _ = ParseVersion(payload.Version);
        _ = ParseVersion(payload.MinimumSupportedVersion);
    }
}

public sealed record FinalBackendInvariantInput(
    bool ParentChildPolicyValidated,
    bool PrivateBrowserPolicyValidated,
    bool FileSafetyValidated,
    bool LicensingSignatureValidated,
    bool UpdateSignatureValidated,
    bool SystemDnsActivationStillGated,
    bool BroadFirewallMutationDetected,
    bool UnsignedUpdateAccepted,
    bool ChildPolicyTamperAccepted);

public sealed record FinalBackendInvariantReport(
    bool Passed,
    IReadOnlyList<string> Failures);

public static class FinalBackendInvariantAuditor
{
    public static FinalBackendInvariantReport Audit(FinalBackendInvariantInput input)
    {
        var failures = new List<string>();

        if (!input.ParentChildPolicyValidated)
        {
            failures.Add("Parent/Child policy backend is not validated.");
        }

        if (!input.PrivateBrowserPolicyValidated)
        {
            failures.Add("Private Browser policy backend is not validated.");
        }

        if (!input.FileSafetyValidated)
        {
            failures.Add("File Safety backend is not validated.");
        }

        if (!input.LicensingSignatureValidated)
        {
            failures.Add("Signed licensing backend is not validated.");
        }

        if (!input.UpdateSignatureValidated)
        {
            failures.Add("Signed update manifest backend is not validated.");
        }

        if (!input.SystemDnsActivationStillGated)
        {
            failures.Add("Known DNS activation safety gate was unexpectedly removed.");
        }

        if (input.BroadFirewallMutationDetected)
        {
            failures.Add("Broad Firewall mutation was detected.");
        }

        if (input.UnsignedUpdateAccepted)
        {
            failures.Add("Unsigned/tampered update was accepted.");
        }

        if (input.ChildPolicyTamperAccepted)
        {
            failures.Add("Tampered child policy was accepted.");
        }

        return new(failures.Count == 0, failures);
    }
}
