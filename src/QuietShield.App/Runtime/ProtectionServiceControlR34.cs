using System.Diagnostics;
using System.IO;
using System.Globalization;
using System.Text;

namespace QuietShield.App.Runtime;

internal enum QuietShieldWindowsServiceState
{
    NotInstalled,
    Stopped,
    StartPending,
    StopPending,
    Running,
    Paused,
    Unknown
}

internal sealed record QuietShieldWindowsServiceProbe(
    QuietShieldWindowsServiceState State,
    int QueryExitCode,
    string StatusText,
    string BinaryPath)
{
    internal bool IsInstalled =>
        State != QuietShieldWindowsServiceState.NotInstalled;
}

internal static class ProtectionServiceControlR34
{
    private const string ServiceName = "QuietShieldService";

    internal static async Task<QuietShieldWindowsServiceProbe> QueryAsync(
        CancellationToken cancellationToken)
    {
        var query = await RunCapturedAsync(
                "query",
                cancellationToken)
            .ConfigureAwait(false);

        if (query.ExitCode == 1060 ||
            query.Output.Contains(
                "does not exist as an installed service",
                StringComparison.OrdinalIgnoreCase))
        {
            return new(
                QuietShieldWindowsServiceState.NotInstalled,
                query.ExitCode,
                "QuietShieldService is not installed.",
                string.Empty);
        }

        var state = ParseState(query.Output);

        var qc = await RunCapturedAsync(
                "qc",
                cancellationToken)
            .ConfigureAwait(false);

        var binaryPath = ParseBinaryPath(qc.Output);

        var statusText =
            state switch
            {
                QuietShieldWindowsServiceState.Running =>
                    "QuietShieldService is running.",

                QuietShieldWindowsServiceState.Stopped =>
                    "QuietShieldService is installed but stopped.",

                QuietShieldWindowsServiceState.StartPending =>
                    "QuietShieldService is starting.",

                QuietShieldWindowsServiceState.StopPending =>
                    "QuietShieldService is stopping.",

                QuietShieldWindowsServiceState.Paused =>
                    "QuietShieldService is paused.",

                _ =>
                    query.ExitCode == 0
                        ? "QuietShieldService returned an unrecognized Windows state."
                        : "QuietShieldService query failed with Windows service exit code " +
                          query.ExitCode.ToString(CultureInfo.InvariantCulture) +
                          "."
            };

        return new(
            state,
            query.ExitCode,
            statusText,
            binaryPath);
    }

    private static void WriteMasterControlDiagnosticR3545(
        string message)
    {
        try
        {
            var directory =
                Path.Combine(
                    Environment.GetFolderPath(
                        Environment.SpecialFolder.LocalApplicationData),
                    "QuietShield",
                    "Diagnostics");

            Directory.CreateDirectory(directory);

            var path =
                Path.Combine(
                    directory,
                    "protection-master-control.log");

            var line =
                DateTimeOffset.Now.ToString(
                    "yyyy-MM-dd HH:mm:ss.fff zzz",
                    CultureInfo.InvariantCulture) +
                " | " +
                message +
                Environment.NewLine;

            File.AppendAllText(
                path,
                line);
        }
        catch
        {
            // Diagnostics must never prevent service control.
        }
    }
    internal static async Task<int> RunElevatedAsync(
        string action,
        CancellationToken cancellationToken)
    {
        if (!string.Equals(
                action,
                "start",
                StringComparison.Ordinal) &&
            !string.Equals(
                action,
                "stop",
                StringComparison.Ordinal))
        {
            throw new ArgumentOutOfRangeException(nameof(action));
        }

        var before =
            await QueryAsync(cancellationToken)
                .ConfigureAwait(false);

        WriteMasterControlDiagnosticR3545(
            "REQUEST " +
            action +
            " | Before=" +
            before.State +
            " | Exit=" +
            before.StatusText +
            " | Path=" +
            before.BinaryPath);

        if (!before.IsInstalled)
        {
            throw new InvalidOperationException(
                "QuietShield Protection Service is not installed. " +
                "No UAC service-control request was sent.");
        }

        var expected =
            string.Equals(
                action,
                "start",
                StringComparison.Ordinal)
                ? QuietShieldWindowsServiceState.Running
                : QuietShieldWindowsServiceState.Stopped;

        if (before.State == expected)
        {
            WriteMasterControlDiagnosticR3545(
                "NOOP " +
                action +
                " | Already=" +
                expected);

            return 0;
        }

        var serviceControlExe =
            Path.Combine(
                Environment.SystemDirectory,
                "sc.exe");

        if (!File.Exists(serviceControlExe))
        {
            throw new FileNotFoundException(
                "Windows Service Control Manager utility was not found.",
                serviceControlExe);
        }

        var startInfo =
            new ProcessStartInfo
            {
                FileName = serviceControlExe,
                Arguments =
                    action +
                    " " +
                    ServiceName,
                Verb = "runas",
                UseShellExecute = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                WorkingDirectory =
                    Environment.SystemDirectory
            };

        WriteMasterControlDiagnosticR3545(
            "UAC REQUEST | Executable=" +
            serviceControlExe +
            " | Arguments=" +
            startInfo.Arguments);

        using var process =
            Process.Start(startInfo) ??
            throw new InvalidOperationException(
                "Windows did not create the elevated QuietShield service-control request.");

        await process.WaitForExitAsync(cancellationToken)
            .ConfigureAwait(false);

        var serviceControlExitCode =
            process.ExitCode;

        WriteMasterControlDiagnosticR3545(
            "SC EXIT | Action=" +
            action +
            " | Exit=" +
            serviceControlExitCode.ToString(
                CultureInfo.InvariantCulture));

        if (serviceControlExitCode != 0 &&
            serviceControlExitCode != 1056 &&
            serviceControlExitCode != 1062)
        {
            var afterFailure =
                await QueryAsync(CancellationToken.None)
                    .ConfigureAwait(false);

            WriteMasterControlDiagnosticR3545(
                "SC FAILURE | State=" +
                afterFailure.State +
                " | " +
                afterFailure.StatusText);

            throw new InvalidOperationException(
                "Windows could not " +
                action +
                " QuietShieldService. " +
                "sc.exe exit code: " +
                serviceControlExitCode.ToString(
                    CultureInfo.InvariantCulture) +
                ". Current state: " +
                afterFailure.StatusText +
                FormatPath(afterFailure.BinaryPath) +
                " Diagnostic log: %LocalAppData%\\QuietShield\\Diagnostics\\protection-master-control.log");
        }

        QuietShieldWindowsServiceProbe? reachedExpected =
            null;

        for (var attempt = 0; attempt < 40; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var current =
                await QueryAsync(cancellationToken)
                    .ConfigureAwait(false);

            WriteMasterControlDiagnosticR3545(
                "POLL " +
                (attempt + 1).ToString(
                    CultureInfo.InvariantCulture) +
                " | State=" +
                current.State +
                " | QueryExit=" +
                current.StatusText);

            if (current.State == expected)
            {
                reachedExpected = current;
                break;
            }

            await Task.Delay(
                    TimeSpan.FromMilliseconds(500),
                    cancellationToken)
                .ConfigureAwait(false);
        }

        if (reachedExpected is null)
        {
            var timedOut =
                await QueryAsync(CancellationToken.None)
                    .ConfigureAwait(false);

            WriteMasterControlDiagnosticR3545(
                "TIMEOUT | Expected=" +
                expected +
                " | Actual=" +
                timedOut.State +
                " | " +
                timedOut.StatusText);

            throw new TimeoutException(
                "Windows accepted the QuietShieldService " +
                action +
                " request, but the service did not reach " +
                expected +
                ". " +
                timedOut.StatusText +
                FormatPath(timedOut.BinaryPath) +
                " Diagnostic log: %LocalAppData%\\QuietShield\\Diagnostics\\protection-master-control.log");
        }

        // Start must be stable, not merely momentarily observed as Running.
        if (expected == QuietShieldWindowsServiceState.Running)
        {
            await Task.Delay(
                    TimeSpan.FromSeconds(2),
                    cancellationToken)
                .ConfigureAwait(false);

            var stable =
                await QueryAsync(CancellationToken.None)
                    .ConfigureAwait(false);

            WriteMasterControlDiagnosticR3545(
                "STABILITY | State=" +
                stable.State +
                " | " +
                stable.StatusText);

            if (stable.State != QuietShieldWindowsServiceState.Running)
            {
                throw new InvalidOperationException(
                    "QuietShieldService reached Running after UAC but did not remain Running during verification. " +
                    stable.StatusText +
                    FormatPath(stable.BinaryPath) +
                    " Diagnostic log: %LocalAppData%\\QuietShield\\Diagnostics\\protection-master-control.log");
            }
        }

        WriteMasterControlDiagnosticR3545(
            "SUCCESS " +
            action +
            " | State=" +
            expected);

        return 0;
    }

    private static async Task<(int ExitCode, string Output)> RunCapturedAsync(
        string verb,
        CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "sc.exe",
            Arguments = verb + " " + ServiceName,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WorkingDirectory = Environment.SystemDirectory
        };

        using var process = Process.Start(startInfo) ??
            throw new InvalidOperationException(
                "Windows did not start the read-only QuietShield service query.");

        var outputTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var errorTask = process.StandardError.ReadToEndAsync(cancellationToken);

        await process.WaitForExitAsync(cancellationToken)
            .ConfigureAwait(false);

        var output = await outputTask.ConfigureAwait(false);
        var error = await errorTask.ConfigureAwait(false);

        var combined = new StringBuilder();

        if (!string.IsNullOrWhiteSpace(output))
        {
            combined.AppendLine(output.Trim());
        }

        if (!string.IsNullOrWhiteSpace(error))
        {
            combined.AppendLine(error.Trim());
        }

        return (
            process.ExitCode,
            combined.ToString());
    }

    private static QuietShieldWindowsServiceState ParseState(string text)
    {
        using var reader = new StringReader(text);

        while (reader.ReadLine() is { } line)
        {
            if (!line.Contains(
                    "STATE",
                    StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var colon = line.IndexOf(':');

            if (colon < 0)
            {
                continue;
            }

            var tail = line[(colon + 1)..].Trim();
            var parts = tail.Split(
                ' ',
                StringSplitOptions.RemoveEmptyEntries);

            if (parts.Length == 0 ||
                !int.TryParse(
                    parts[0],
                    NumberStyles.Integer,
                    CultureInfo.InvariantCulture,
                    out var numericState))
            {
                continue;
            }

            return numericState switch
            {
                1 => QuietShieldWindowsServiceState.Stopped,
                2 => QuietShieldWindowsServiceState.StartPending,
                3 => QuietShieldWindowsServiceState.StopPending,
                4 => QuietShieldWindowsServiceState.Running,
                7 => QuietShieldWindowsServiceState.Paused,
                _ => QuietShieldWindowsServiceState.Unknown
            };
        }

        return QuietShieldWindowsServiceState.Unknown;
    }

    private static string ParseBinaryPath(string text)
    {
        using var reader = new StringReader(text);

        while (reader.ReadLine() is { } line)
        {
            if (!line.Contains(
                    "BINARY_PATH_NAME",
                    StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var colon = line.IndexOf(':');

            return colon < 0
                ? string.Empty
                : line[(colon + 1)..].Trim();
        }

        return string.Empty;
    }

    private static string FormatPath(string binaryPath) =>
        string.IsNullOrWhiteSpace(binaryPath)
            ? string.Empty
            : " Service path: " + binaryPath;
}
