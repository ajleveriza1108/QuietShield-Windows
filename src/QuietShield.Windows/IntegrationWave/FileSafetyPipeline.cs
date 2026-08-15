// QuietShield Backend Integration 08 R1
using QuietShield.Windows.FinalBackends;

namespace QuietShield.Windows.IntegrationWave;

public sealed record FileSafetyPipelineResult(
    FileSafetyReport StaticReport,
    DefenderScanResult? Defender,
    bool UserActionRequired,
    string Summary);

public static class FileSafetyPipeline
{
    public static async Task<FileSafetyPipelineResult> InspectAsync(
        string path,
        bool runDefenderForHighRisk,
        CancellationToken cancellationToken = default)
    {
        var report = await WindowsFileSafetyScanner
            .ScanAsync(path, cancellationToken)
            .ConfigureAwait(false);

        DefenderScanResult? defender = null;
        if (runDefenderForHighRisk && report.Risk == FileRiskLevel.High)
        {
            defender = await WindowsDefenderIntegration
                .ScanExactFileAsync(path, cancellationToken)
                .ConfigureAwait(false);
        }

        var actionRequired =
            report.Risk != FileRiskLevel.Low ||
            (defender is { ScanStarted: true, ExitCode: not 0 });

        var summary = report.Risk switch
        {
            FileRiskLevel.Low => "No high-risk static signal was detected.",
            FileRiskLevel.Caution => "Caution signals were detected; user review is recommended.",
            FileRiskLevel.High => "High-risk executable/script signals were detected.",
            _ => "File safety result is unknown."
        };

        return new(report, defender, actionRequired, summary);
    }
}
