// QuietShield Backend Integration 10 R1
using Microsoft.VisualStudio.TestTools.UnitTesting;
using QuietShield.Core.FinalBackends;
using QuietShield.Windows.FinalBackends;

namespace QuietShield.Windows.Tests;

[TestClass]
public sealed class BackendIntegration10Tests
{
    [TestMethod]
    public async Task ExistingVerifierAcceptsMatchingPackage()
    {
        var path = Path.Combine(
            Path.GetTempPath(),
            "qs-update-" + Guid.NewGuid().ToString("N") + ".bin");

        try
        {
            var bytes = System.Text.Encoding.UTF8.GetBytes("QuietShield update test");
            await File.WriteAllBytesAsync(path, bytes);
            var hash = Convert.ToHexString(
                System.Security.Cryptography.SHA256.HashData(bytes));

            var payload = new SignedUpdatePayload(
                "1.2.3",
                Path.GetFileName(path),
                hash,
                bytes.LongLength,
                new Uri("https://example.invalid/quietshield.bin"),
                DateTimeOffset.UtcNow,
                "1.0.0");

            var result = await WindowsUpdatePackageVerifier.VerifyAsync(path, payload);
            Assert.IsTrue(result.Passed);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
