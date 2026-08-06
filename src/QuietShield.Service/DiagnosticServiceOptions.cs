namespace QuietShield.Service;

public sealed record DiagnosticServiceOptions(
    bool DiagnosticMode,
    bool RunClientSmoke,
    string PipeName,
    string StateRoot,
    string? OutputPath,
    TimeSpan Duration,
    TimeSpan RequestTimeout)
{
    public static DiagnosticServiceOptions Parse(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);
        var diagnostic = args.Contains("--diagnostic", StringComparer.OrdinalIgnoreCase);
        var smoke = args.Contains("--ipc-smoke", StringComparer.OrdinalIgnoreCase);
        var pipe = Value(args, "--pipe-name") ?? Core.ServiceFoundation.QuietShieldServiceProtocol.DefaultPipeName;
        var stateRoot = Value(args, "--state-root") ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "QuietShield", "Service");
        var output = Value(args, "--output");
        var durationText = Value(args, "--duration-seconds");
        var durationSeconds = durationText is null ? 0 : int.Parse(durationText, System.Globalization.CultureInfo.InvariantCulture);
        if (durationSeconds is < 0 or > 3600) throw new ArgumentOutOfRangeException(nameof(args), "Diagnostic duration must be between 0 and 3600 seconds.");
        if (string.IsNullOrWhiteSpace(pipe) || pipe.Length > 200 || pipe.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
            throw new ArgumentException("The local pipe name is invalid.", nameof(args));
        return new(diagnostic, smoke, pipe, Path.GetFullPath(stateRoot), output is null ? null : Path.GetFullPath(output),
            TimeSpan.FromSeconds(durationSeconds), TimeSpan.FromSeconds(5));
    }

    private static string? Value(string[] args, string name)
    {
        for (var index = 0; index < args.Length - 1; index++)
            if (args[index].Equals(name, StringComparison.OrdinalIgnoreCase)) return args[index + 1];
        return null;
    }
}
