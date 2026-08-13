// QuietShield Backend Pack 5-8 R1
using System.Security.Cryptography;
using QuietShield.Core.FinalBackends;

namespace QuietShield.Windows.FinalBackends;

public sealed record UpdatePackageVerification(
    bool Passed,
    string ActualSha256,
    long ActualLength,
    string Message);

public static class WindowsUpdatePackageVerifier
{
    public static async Task<UpdatePackageVerification> VerifyAsync(
        string packagePath,
        SignedUpdatePayload manifest,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(packagePath);
        ArgumentNullException.ThrowIfNull(manifest);

        var fullPath = Path.GetFullPath(packagePath);
        var info = new FileInfo(fullPath);

        if (!info.Exists)
        {
            return new(false, string.Empty, 0, "Update package file is missing.");
        }

        string actualHash;

        await using (var stream = new FileStream(
            fullPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 128 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan))
        {
            var hash = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
            actualHash = Convert.ToHexString(hash);
        }

        var lengthMatches = info.Length == manifest.PackageLength;
        var hashMatches = actualHash.Equals(
            manifest.PackageSha256,
            StringComparison.OrdinalIgnoreCase);

        var passed = lengthMatches && hashMatches;
        var message = passed
            ? "Update package hash and length match the signed manifest."
            : "Update package failed signed-manifest hash/length verification.";

        return new(passed, actualHash, info.Length, message);
    }
}
