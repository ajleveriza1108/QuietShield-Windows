namespace QuietShield.Service;

public sealed record DiagnosticServiceOptions(
    bool DiagnosticMode,
    bool ServiceMode,
    bool RunClientSmoke,
    string PipeName,
    string StateRoot,
    string? OutputPath,
    TimeSpan Duration,
    TimeSpan RequestTimeout,
    Core.ServiceFoundation.ServiceActivationConfiguration? ActivationConfiguration,
    string? ControlRequestPath,
    string? ControlOutputPath,
    Core.ServiceFoundation.ProductionServiceConfiguration? ProductionConfiguration = null)
{
    public Core.ServiceFoundation.ProgramPolicyAuthorizationContext? AuthorizationContext =>
        ProductionConfiguration?.ToAuthorizationContext() ?? ActivationConfiguration?.ToAuthorizationContext();

    public static DiagnosticServiceOptions Parse(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);
        var diagnostic = args.Contains("--diagnostic", StringComparer.OrdinalIgnoreCase);
        var serviceMode = args.Contains("--service", StringComparer.OrdinalIgnoreCase);
        var smoke = args.Contains("--ipc-smoke", StringComparer.OrdinalIgnoreCase);
        if (diagnostic && serviceMode) throw new ArgumentException("Diagnostic and service modes are mutually exclusive.", nameof(args));
        var pipe = Value(args, "--pipe-name") ?? (serviceMode
            ? Core.ServiceFoundation.QuietShieldServiceProtocol.ProductionPipeName
            : Core.ServiceFoundation.QuietShieldServiceProtocol.DefaultPipeName);
        var stateRoot = Value(args, "--state-root") ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "QuietShield", "Service");
        var output = Value(args, "--output");
        var durationText = Value(args, "--duration-seconds");
        var durationSeconds = durationText is null ? 0 : int.Parse(durationText, System.Globalization.CultureInfo.InvariantCulture);
        if (durationSeconds is < 0 or > 3600) throw new ArgumentOutOfRangeException(nameof(args), "Diagnostic duration must be between 0 and 3600 seconds.");
        if (string.IsNullOrWhiteSpace(pipe) || pipe.Length > 200 || pipe.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
            throw new ArgumentException("The local pipe name is invalid.", nameof(args));
        Core.ServiceFoundation.ServiceActivationConfiguration? activation = null;
        var activationPath = Value(args, "--activation-config");
        Core.ServiceFoundation.ProductionServiceConfiguration? production = null;
        var productionPath = Value(args, "--production-config");
        if (activationPath is not null && productionPath is not null)
            throw new ArgumentException("Controlled rehearsal and production service configurations are mutually exclusive.", nameof(args));
        if (activationPath is not null)
        {
            using var stream = File.OpenRead(Path.GetFullPath(activationPath));
            activation = System.Text.Json.JsonSerializer.Deserialize<Core.ServiceFoundation.ServiceActivationConfiguration>(
                stream, Core.ServiceFoundation.ServiceMessageSerializer.Options)
                ?? throw new InvalidDataException("The service activation configuration is empty.");
            var errors = activation.Validate(DateTimeOffset.UtcNow);
            if (errors.Count != 0) throw new InvalidDataException(string.Join(" ", errors));
        }
        if (productionPath is not null)
        {
            using var stream = File.OpenRead(Path.GetFullPath(productionPath));
            production = System.Text.Json.JsonSerializer.Deserialize<Core.ServiceFoundation.ProductionServiceConfiguration>(
                stream, Core.ServiceFoundation.ServiceMessageSerializer.Options)
                ?? throw new InvalidDataException("The production service configuration is empty.");
            var errors = production.Validate();
            if (errors.Count != 0) throw new InvalidDataException(string.Join(" ", errors));
        }
        if (serviceMode && activation is null && production is null) throw new InvalidDataException("Service mode requires a validated controlled-activation or production configuration.");
        var controlRequest = Value(args, "--control-request");
        var controlOutput = Value(args, "--control-output");
        if ((controlRequest is null) != (controlOutput is null)) throw new ArgumentException("Control request and output paths must be supplied together.", nameof(args));
        var requestTimeout = serviceMode || controlRequest is not null
            ? TimeSpan.FromSeconds(150)
            : TimeSpan.FromSeconds(5);
        return new(diagnostic, serviceMode, smoke, pipe, Path.GetFullPath(stateRoot), output is null ? null : Path.GetFullPath(output),
            TimeSpan.FromSeconds(durationSeconds), requestTimeout, activation,
            controlRequest is null ? null : Path.GetFullPath(controlRequest), controlOutput is null ? null : Path.GetFullPath(controlOutput), production);
    }

    private static string? Value(string[] args, string name)
    {
        for (var index = 0; index < args.Length - 1; index++)
            if (args[index].Equals(name, StringComparison.OrdinalIgnoreCase)) return args[index + 1];
        return null;
    }
}
