// QuietShield Backend Integration 08 R1
using Microsoft.VisualStudio.TestTools.UnitTesting;
using QuietShield.Windows.IntegrationWave;

namespace QuietShield.Windows.Tests;

[TestClass]
public sealed class BackendIntegration08Tests
{
    [TestMethod]
    public async Task PlainTextFileScansWithoutRemediation()
    {
        var path = Path.Combine(
            Path.GetTempPath(),
            "qs-file-safety-" + Guid.NewGuid().ToString("N") + ".txt");

        try
        {
            await File.WriteAllTextAsync(path, "QuietShield test content");
            var result = await FileSafetyPipeline.InspectAsync(
                path,
                runDefenderForHighRisk: false);

            Assert.IsNotNull(result.StaticReport.Sha256);
            Assert.IsNull(result.Defender);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
