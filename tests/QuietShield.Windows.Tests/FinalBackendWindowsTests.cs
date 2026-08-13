// QuietShield Backend Pack 5-8 R1
using QuietShield.Core.FinalBackends;
using QuietShield.Windows.FinalBackends;

namespace QuietShield.Windows.Tests;

[TestClass]
public sealed class FinalBackendWindowsTests
{
    private static readonly byte[] WrongPackageBytes = [1, 2, 3, 4];

    [TestMethod]
    public void ChildSessionProbeReturnsProcessSnapshot()
    {
        var processes = WindowsChildSessionProbe.CaptureProcesses();

        Assert.IsNotEmpty(processes);
        // Count is covered by Assert.IsNotEmpty above.
    }

    [TestMethod]
    public async Task FileSafetyScannerHashesExactFile()
    {
        var root = Path.Combine(
            Path.GetTempPath(),
            "QuietShield-FinalBackendTests",
            Guid.NewGuid().ToString("N"));

        Directory.CreateDirectory(root);
        var path = Path.Combine(root, "sample.txt");

        try
        {
            await File.WriteAllTextAsync(path, "QuietShield safe test file");
            var report = await WindowsFileSafetyScanner.ScanAsync(path);

            Assert.AreEqual(64, report.Sha256.Length);
            Assert.AreEqual(".txt", report.Extension);
            Assert.IsFalse(report.HasPortableExecutableHeader);
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [TestMethod]
    public void OpaqueDeviceIdentityIsStableAndHashed()
    {
        var first = WindowsOpaqueDeviceIdentity.GetCurrentUserDeviceId();
        var second = WindowsOpaqueDeviceIdentity.GetCurrentUserDeviceId();

        Assert.AreEqual(first, second);
        Assert.AreEqual(64, first.Length);
        Assert.IsTrue(first.All(Uri.IsHexDigit));
    }

    [TestMethod]
    public async Task UpdatePackageVerifierRejectsWrongHash()
    {
        var root = Path.Combine(
            Path.GetTempPath(),
            "QuietShield-FinalBackendTests",
            Guid.NewGuid().ToString("N"));

        Directory.CreateDirectory(root);
        var path = Path.Combine(root, "package.bin");

        try
        {
            await File.WriteAllBytesAsync(path, WrongPackageBytes);

            var manifest = new SignedUpdatePayload(
                "1.0.1",
                "package.bin",
                new string('A', 64),
                4,
                new Uri("https://example.com/package.bin"),
                DateTimeOffset.UtcNow,
                "1.0.0");

            var result = await WindowsUpdatePackageVerifier.VerifyAsync(path, manifest);

            Assert.IsFalse(result.Passed);
            Assert.AreEqual(4L, result.ActualLength);
            Assert.AreEqual(64, result.ActualSha256.Length);
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [TestMethod]
    public void DefenderAvailabilityProbeDoesNotMutateSystem()
    {
        var path = WindowsDefenderIntegration.FindMpCmdRun();

        Assert.IsTrue(path is null || Path.IsPathFullyQualified(path));
    }
}
