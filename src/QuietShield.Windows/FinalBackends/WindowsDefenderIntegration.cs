// QuietShield Backend Pack 5-8 R1
using System.Diagnostics;

namespace QuietShield.Windows.FinalBackends;

public sealed record DefenderScanResult(
    bool Available,
    bool ScanStarted,
    int? ExitCode,
    string Message);

public static class WindowsDefenderIntegration
{
    public static string? FindMpCmdRun()
    {
        var platformRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Microsoft",
            "Windows Defender",
            "Platform");

        if (Directory.Exists(platformRoot))
        {
            var first = Directory
                .EnumerateDirectories(platformRoot)
                .OrderByDescending(static value => value, StringComparer.OrdinalIgnoreCase)
                .Select(static directory => Path.Combine(directory, "MpCmdRun.exe"))
                .FirstOrDefault(File.Exists);

            if (!string.IsNullOrWhiteSpace(first))
            {
                return first;
            }
        }

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var legacy = Path.Combine(programFiles, "Windows Defender", "MpCmdRun.exe");
        return File.Exists(legacy) ? legacy : null;
    }

    public static async Task<DefenderScanResult> ScanExactFileAsync(
        string path,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var fullPath = Path.GetFullPath(path);

        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException("Windows Defender scan target does not exist.", fullPath);
        }

        var executable = FindMpCmdRun();
        if (executable is null)
        {
            return new(false, false, null, "Microsoft Defender command-line scanner is unavailable.");
        }

        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = executable,
                Arguments = "-Scan -ScanType 3 -File " + Quote(fullPath) + " -DisableRemediation",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            }
        };

        if (!process.Start())
        {
            return new(true, false, null, "Microsoft Defender scanner could not be started.");
        }

        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        var standardOutput = await process.StandardOutput.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
        var standardError = await process.StandardError.ReadToEndAsync(cancellationToken).ConfigureAwait(false);

        var message = string.Join(
            " ",
            new[] { standardOutput.Trim(), standardError.Trim() }
                .Where(static value => !string.IsNullOrWhiteSpace(value)));

        return new(
            true,
            true,
            process.ExitCode,
            string.IsNullOrWhiteSpace(message) ? "Microsoft Defender scan completed." : message);
    }

    private static string Quote(string value) =>
        "\"" + value.Replace("\"", "\\\"", StringComparison.Ordinal) + "\"";
}
