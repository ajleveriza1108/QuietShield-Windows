// QuietShield Backend Integration 10 R1
using QuietShield.Core.FinalBackends;
using QuietShield.Windows.FinalBackends;

namespace QuietShield.Windows.IntegrationWave;

public sealed record UpdateStageResult(
    bool Downloaded,
    bool Verified,
    string? StagedPath,
    string Message);

public static class SecureUpdateStagingClient
{
    public static async Task<UpdateStageResult> DownloadAndStageAsync(
        SignedUpdatePayload payload,
        string stagingRoot,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentException.ThrowIfNullOrWhiteSpace(stagingRoot);

        if (!payload.DownloadUri.Scheme.Equals(
                Uri.UriSchemeHttps,
                StringComparison.OrdinalIgnoreCase))
        {
            return new(false, false, null, "Only HTTPS update downloads are allowed.");
        }

        Directory.CreateDirectory(stagingRoot);

        var safeName = Path.GetFileName(payload.PackageName);
        if (string.IsNullOrWhiteSpace(safeName))
            return new(false, false, null, "Update package name is invalid.");

        var finalPath = Path.Combine(stagingRoot, safeName);
        var temporaryPath = finalPath + "." + Guid.NewGuid().ToString("N") + ".partial";

        try
        {
            using var client = new HttpClient
            {
                Timeout = TimeSpan.FromMinutes(5)
            };

            using var response = await client.GetAsync(
                payload.DownloadUri,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken).ConfigureAwait(false);

            response.EnsureSuccessStatusCode();

            var advertised = response.Content.Headers.ContentLength;
            if (advertised is > 0 && advertised.Value != payload.PackageLength)
            {
                return new(
                    false,
                    false,
                    null,
                    "Server Content-Length does not match the signed manifest.");
            }

            await using (var input = await response.Content
                .ReadAsStreamAsync(cancellationToken)
                .ConfigureAwait(false))
            await using (var output = new FileStream(
                temporaryPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                128 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                await input.CopyToAsync(output, cancellationToken)
                    .ConfigureAwait(false);
            }

            var verification = await WindowsUpdatePackageVerifier
                .VerifyAsync(temporaryPath, payload, cancellationToken)
                .ConfigureAwait(false);

            if (!verification.Passed)
            {
                return new(
                    true,
                    false,
                    null,
                    verification.Message);
            }

            File.Move(temporaryPath, finalPath, overwrite: true);
            return new(
                true,
                true,
                finalPath,
                "Update package was downloaded and staged after signed-manifest verification. Installation was not started.");
        }
        finally
        {
            if (File.Exists(temporaryPath))
                File.Delete(temporaryPath);
        }
    }
}
