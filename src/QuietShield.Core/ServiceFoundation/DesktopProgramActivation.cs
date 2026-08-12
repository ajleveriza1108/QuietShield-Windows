using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using QuietShield.Core.Protection;

namespace QuietShield.Core.ServiceFoundation;

public enum DesktopActivationState { Unavailable, Ready, Pending, Applying, Applied, Recovering, SimulationOnly, Failed }

public enum DesktopActivationIssue
{
    None,
    ServiceUnavailable,
    ServiceStopped,
    IpcFailure,
    TargetExecutableMissing,
    TargetHashChanged,
    UnsupportedTarget,
    UnsupportedPersistentPolicy,
    TargetNotAuthorized,
    TransactionRolledBack,
    RecoverySucceeded,
    AdministrativeActionRequired,
    PersistentProtectionTemporarilyUnavailable,
    DesktopConfigurationUnavailable,
    InvalidServiceResponse
}

public sealed record DesktopServiceObservation(bool Registered, bool Running);
public sealed record DesktopProgramTargetCandidate(string DisplayName, string? ExecutablePath, string? PackageFamilyName, bool IsWindowsSystemComponent);

public sealed record DesktopProgramPolicyConfiguration(
    int SchemaVersion,
    string ProfileId,
    string DisplayName,
    string StableApplicationIdentity,
    string ExecutablePath,
    string ExecutableSha256,
    ProgramConnectionPolicy Policy,
    DateTimeOffset RequestedAtUtc)
{
    public const int CurrentSchemaVersion = 1;

    public string ComputePayloadSha256()
    {
        var canonical = string.Join("|", SchemaVersion, ProfileId, DisplayName, StableApplicationIdentity,
            Path.GetFullPath(ExecutablePath), ExecutableSha256.ToUpperInvariant(), Policy,
            RequestedAtUtc.ToUniversalTime().ToString("O"));
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }
}

public sealed record DesktopTargetValidation(bool IsValid, DesktopActivationIssue Issue, string CustomerMessage, DesktopProgramPolicyConfiguration? Configuration);
public sealed record DesktopProgramActivationSnapshot(DesktopActivationState State, DesktopActivationIssue Issue, string CustomerMessage,
    DesktopProgramPolicyConfiguration? SavedConfiguration, Guid? TransactionId = null);

public interface IDesktopProgramPolicyStore
{
    Task<DesktopProgramPolicyConfiguration?> LoadAsync(CancellationToken cancellationToken);
    Task SaveAsync(DesktopProgramPolicyConfiguration configuration, CancellationToken cancellationToken);
}

public sealed class JsonDesktopProgramPolicyStore : IDesktopProgramPolicyStore
{
    private static readonly JsonSerializerOptions Options = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = true };
    private readonly string _path;

    public JsonDesktopProgramPolicyStore(string path) => _path = Path.GetFullPath(path ?? throw new ArgumentNullException(nameof(path)));

    public async Task<DesktopProgramPolicyConfiguration?> LoadAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_path)) return null;
        try
        {
            await using var stream = new FileStream(_path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.Asynchronous);
            var envelope = await JsonSerializer.DeserializeAsync<DesktopPolicyEnvelope>(stream, Options, cancellationToken).ConfigureAwait(false)
                           ?? throw new InvalidDataException("The saved desktop policy is empty.");
            if (envelope.Configuration.SchemaVersion != DesktopProgramPolicyConfiguration.CurrentSchemaVersion ||
                envelope.PayloadSha256.Length != 64 || envelope.PayloadSha256.Any(static value => !Uri.IsHexDigit(value)) ||
                !CryptographicOperations.FixedTimeEquals(Convert.FromHexString(envelope.Configuration.ComputePayloadSha256()), Convert.FromHexString(envelope.PayloadSha256)))
                throw new InvalidDataException("The saved desktop policy failed integrity validation.");
            return envelope.Configuration;
        }
        catch (JsonException exception) { throw new InvalidDataException("The saved desktop policy is malformed.", exception); }
    }

    public async Task SaveAsync(DesktopProgramPolicyConfiguration configuration, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        var directory = Path.GetDirectoryName(_path) ?? throw new InvalidOperationException("The desktop policy store has no directory.");
        Directory.CreateDirectory(directory);
        var temporary = _path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            await using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough | FileOptions.Asynchronous))
            {
                await JsonSerializer.SerializeAsync(stream, new DesktopPolicyEnvelope(configuration, configuration.ComputePayloadSha256()), Options, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            if (File.Exists(_path)) File.Replace(temporary, _path, null, true);
            else File.Move(temporary, _path);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    private sealed record DesktopPolicyEnvelope(DesktopProgramPolicyConfiguration Configuration, string PayloadSha256);
}

public sealed class WindowsInstalledProgramTargetValidator
{
    private readonly IReadOnlyList<string> _allowedRoots;

    public WindowsInstalledProgramTargetValidator(IEnumerable<string>? allowedRoots = null)
    {
        _allowedRoots = (allowedRoots ?? DefaultAllowedRoots())
            .Where(static root => !string.IsNullOrWhiteSpace(root))
            .Select(static root => Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public async Task<DesktopTargetValidation> CaptureAsync(DesktopProgramTargetCandidate candidate, string profileId,
        ProgramConnectionPolicy policy, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        if (policy is not (ProgramConnectionPolicy.Blocked or ProgramConnectionPolicy.AllowedOnAll))
            return Failure(DesktopActivationIssue.UnsupportedPersistentPolicy, "This network-specific policy remains simulation-only.");
        if (!string.IsNullOrWhiteSpace(candidate.PackageFamilyName) || string.IsNullOrWhiteSpace(candidate.ExecutablePath))
            return Failure(DesktopActivationIssue.UnsupportedTarget, "Persistent protection currently requires an exact installed Win32 executable.");
        var path = ValidatePath(candidate.ExecutablePath, candidate.IsWindowsSystemComponent);
        if (path.Issue != DesktopActivationIssue.None) return Failure(path.Issue, path.Message);
        var resolvedPath = path.Path!;
        await using var stream = new FileStream(resolvedPath, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.Asynchronous | FileOptions.SequentialScan);
        var hash = Convert.ToHexString(await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false));
        var configuration = new DesktopProgramPolicyConfiguration(1, string.IsNullOrWhiteSpace(profileId) ? "desktop.default" : profileId.Trim(),
            candidate.DisplayName.Trim(), ApprovedProgramTargetIdentity.FromExecutablePath(resolvedPath), resolvedPath, hash, policy, DateTimeOffset.UtcNow);
        return new(true, DesktopActivationIssue.None, "The exact installed application identity is ready.", configuration);
    }

    public async Task<DesktopTargetValidation> RevalidateAsync(DesktopProgramPolicyConfiguration configuration, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        if (configuration.SchemaVersion != 1 || configuration.Policy is not (ProgramConnectionPolicy.Blocked or ProgramConnectionPolicy.AllowedOnAll))
            return Failure(DesktopActivationIssue.UnsupportedPersistentPolicy, "The saved policy is not eligible for persistent protection.");
        var path = ValidatePath(configuration.ExecutablePath, false);
        if (path.Issue != DesktopActivationIssue.None) return Failure(path.Issue, path.Message);
        var resolvedPath = path.Path!;
        if (!ApprovedProgramTargetIdentity.FromExecutablePath(resolvedPath).Equals(configuration.StableApplicationIdentity, StringComparison.Ordinal))
            return Failure(DesktopActivationIssue.UnsupportedTarget, "The saved application identity no longer matches its executable path.");
        await using var stream = new FileStream(resolvedPath, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.Asynchronous | FileOptions.SequentialScan);
        var actualHash = Convert.ToHexString(await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false));
        if (!actualHash.Equals(configuration.ExecutableSha256, StringComparison.OrdinalIgnoreCase))
            return Failure(DesktopActivationIssue.TargetHashChanged, "The application changed after it was selected. Select it again before saving protection.");
        return new(true, DesktopActivationIssue.None, "The exact installed application identity is still valid.", configuration);
    }

    private (DesktopActivationIssue Issue, string Message, string? Path) ValidatePath(string path, bool isWindowsSystemComponent)
    {
        if (isWindowsSystemComponent)
            return (DesktopActivationIssue.UnsupportedTarget, "Windows and system components cannot be selected for persistent Program Connection Lock.", null);
        string resolved;
        try { resolved = Path.GetFullPath(path); }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        { return (DesktopActivationIssue.UnsupportedTarget, "The selected application path is invalid.", null); }
        if (!File.Exists(resolved)) return (DesktopActivationIssue.TargetExecutableMissing, "The selected application executable is missing or moved.", null);
        if (!Path.GetExtension(resolved).Equals(".exe", StringComparison.OrdinalIgnoreCase) || Path.GetFileName(resolved).StartsWith("QuietShield.", StringComparison.OrdinalIgnoreCase))
            return (DesktopActivationIssue.UnsupportedTarget, "This executable is not an eligible customer application target.", null);
        var matchingRoot = _allowedRoots.FirstOrDefault(root => resolved.StartsWith(root, StringComparison.OrdinalIgnoreCase));
        if (matchingRoot is null) return (DesktopActivationIssue.UnsupportedTarget, "The executable is outside an approved installed-application location.", null);
        if (ContainsReparsePoint(resolved, matchingRoot)) return (DesktopActivationIssue.UnsupportedTarget, "Reparse-point application targets are not supported.", null);
        return (DesktopActivationIssue.None, "The installed executable path is eligible.", resolved);
    }

    private static bool ContainsReparsePoint(string path, string root)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) return true;
        var directory = Directory.GetParent(path);
        var canonicalRoot = root.TrimEnd(Path.DirectorySeparatorChar);
        while (directory is not null && directory.FullName.StartsWith(canonicalRoot, StringComparison.OrdinalIgnoreCase))
        {
            if ((directory.Attributes & FileAttributes.ReparsePoint) != 0) return true;
            directory = directory.Parent;
        }
        return false;
    }

    private static IEnumerable<string> DefaultAllowedRoots()
    {
        yield return Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        yield return Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        yield return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs");
    }

    private static DesktopTargetValidation Failure(DesktopActivationIssue issue, string message) => new(false, issue, message, null);
}

public sealed class DesktopProgramActivationWorkflow
{
    private readonly IQuietShieldServiceClient _serviceClient;
    private readonly IDesktopProgramPolicyStore _store;
    private readonly WindowsInstalledProgramTargetValidator _targetValidator;

    public DesktopProgramActivationWorkflow(IQuietShieldServiceClient serviceClient, IDesktopProgramPolicyStore store, WindowsInstalledProgramTargetValidator targetValidator)
    { _serviceClient = serviceClient; _store = store; _targetValidator = targetValidator; }

    public DesktopProgramPolicyConfiguration? SavedConfiguration { get; private set; }

    public Task<DesktopTargetValidation> CaptureAsync(DesktopProgramTargetCandidate candidate, string profileId,
        ProgramConnectionPolicy policy, CancellationToken cancellationToken) =>
        _targetValidator.CaptureAsync(candidate, profileId, policy, cancellationToken);

    public async Task<DesktopProgramActivationSnapshot> LoadAsync(CancellationToken cancellationToken)
    {
        try
        {
            SavedConfiguration = await _store.LoadAsync(cancellationToken).ConfigureAwait(false);
            return Snapshot(DesktopActivationState.Ready, DesktopActivationIssue.None,
                SavedConfiguration is null ? "Choose an installed application and policy." : "Saved desktop policy loaded for reconciliation.");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            SavedConfiguration = null;
            return Snapshot(DesktopActivationState.Failed, DesktopActivationIssue.DesktopConfigurationUnavailable,
                "Saved policy could not be validated. No policy was sent to the service.");
        }
    }

    public DesktopProgramActivationSnapshot Reconcile(DesktopServiceObservation observation, ServiceStatusSnapshot? status, bool ipcFailed)
    {
        if (!observation.Registered) return Snapshot(DesktopActivationState.Unavailable, DesktopActivationIssue.ServiceUnavailable, "Persistent protection is unavailable because QuietShield Protection Service is not installed.");
        if (!observation.Running) return Snapshot(DesktopActivationState.Unavailable, DesktopActivationIssue.ServiceStopped, "QuietShield Protection Service is installed but stopped.");
        if (ipcFailed || status is null) return Snapshot(DesktopActivationState.Unavailable, DesktopActivationIssue.IpcFailure, "The service is running, but its secure local connection failed.");
        if (status.TransactionStatus.Contains("Interrupted", StringComparison.OrdinalIgnoreCase) || status.RecoveryReadiness.Contains("rollback", StringComparison.OrdinalIgnoreCase))
            return Snapshot(DesktopActivationState.Recovering, DesktopActivationIssue.TransactionRolledBack, "Protection recovery is in progress. Saved desktop state will not overwrite service recovery.");
        if (!status.PersistentEnforcementAvailable || status.ProgramChangeAuthorizationId is null)
            return Snapshot(DesktopActivationState.Unavailable, DesktopActivationIssue.PersistentProtectionTemporarilyUnavailable, "Persistent protection is temporarily unavailable.");
        if (SavedConfiguration is null) return Snapshot(DesktopActivationState.Ready, DesktopActivationIssue.None, "Choose an installed application and save Blocked or Allowed on All.");
        var active = (status.ProgramPolicies ?? Array.Empty<PersistentProgramPolicy>()).FirstOrDefault(policy => policy.Enabled && policy.StableApplicationIdentity.Equals(SavedConfiguration.StableApplicationIdentity, StringComparison.Ordinal));
        if (status.LastKnownGoodPolicyStatus.Contains("Recovered", StringComparison.OrdinalIgnoreCase) && active is not null)
            return Snapshot(DesktopActivationState.Applied, DesktopActivationIssue.RecoverySucceeded, "Service recovery succeeded from validated last-known-good state.");
        if (active is not null && active.Policy == SavedConfiguration.Policy && status.LastKnownGoodPolicyStatus.Contains("Validated", StringComparison.OrdinalIgnoreCase))
            return Snapshot(DesktopActivationState.Applied, DesktopActivationIssue.None, "Saved desktop policy matches the service and its validated last-known-good state.");
        return Snapshot(DesktopActivationState.Pending, DesktopActivationIssue.None, "The saved desktop request differs from service state. Review it before saving again.");
    }

    public async Task<DesktopProgramActivationSnapshot> ApplyAsync(DesktopProgramPolicyConfiguration configuration,
        DesktopServiceObservation observation, CancellationToken cancellationToken)
    {
        if (!observation.Registered) return Snapshot(DesktopActivationState.Unavailable, DesktopActivationIssue.ServiceUnavailable, "Persistent protection requires QuietShield Protection Service.");
        if (!observation.Running) return Snapshot(DesktopActivationState.Unavailable, DesktopActivationIssue.ServiceStopped, "QuietShield Protection Service is stopped. Use the approved lifecycle recovery path.");
        var validation = await _targetValidator.RevalidateAsync(configuration, cancellationToken).ConfigureAwait(false);
        if (!validation.IsValid) return Snapshot(DesktopActivationState.Failed, validation.Issue, validation.CustomerMessage);

        ServiceStatusSnapshot status;
        try
        {
            var statusResponse = await _serviceClient.SendAsync(ServiceMessageKind.GetServiceStatus, null, cancellationToken).ConfigureAwait(false);
            if (statusResponse.Status != ServiceResponseStatus.Ok || statusResponse.Payload.Deserialize<ServiceStatusSnapshot>(ServiceMessageSerializer.Options) is not { } parsed)
                return Snapshot(DesktopActivationState.Unavailable, DesktopActivationIssue.InvalidServiceResponse, "The service returned an invalid status response.");
            status = parsed;
        }
        catch (Exception exception) when (exception is IOException or TimeoutException or InvalidDataException)
        { return Snapshot(DesktopActivationState.Unavailable, DesktopActivationIssue.IpcFailure, "The secure local service connection failed. No policy was saved."); }

        if (!status.ServiceInstalled) return Snapshot(DesktopActivationState.Unavailable, DesktopActivationIssue.ServiceUnavailable, "QuietShield Protection Service is not installed.");
        if (!status.ServiceRunning) return Snapshot(DesktopActivationState.Unavailable, DesktopActivationIssue.ServiceStopped, "QuietShield Protection Service is stopped.");
        if (!status.IpcConnected) return Snapshot(DesktopActivationState.Unavailable, DesktopActivationIssue.IpcFailure, "The secure local service connection is unavailable.");
        if (!status.PersistentEnforcementAvailable || status.ProgramChangeAuthorizationId is null)
            return Snapshot(DesktopActivationState.Unavailable, DesktopActivationIssue.PersistentProtectionTemporarilyUnavailable, "Persistent protection is temporarily unavailable.");
        if (status.TransactionStatus.Contains("Interrupted", StringComparison.OrdinalIgnoreCase))
            return Snapshot(DesktopActivationState.Recovering, DesktopActivationIssue.TransactionRolledBack, "Service recovery must finish before another policy is saved.");

        ServiceResponse response;
        try
        {
            response = await _serviceClient.SendAsync(ServiceMessageKind.RequestProgramRuleChange,
                new ProgramRuleChangeRequest(status.ProgramChangeAuthorizationId.Value, configuration.ProfileId, configuration.StableApplicationIdentity,
                    configuration.ExecutablePath, configuration.ExecutableSha256, configuration.Policy), cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is IOException or TimeoutException or InvalidDataException)
        { return Snapshot(DesktopActivationState.Failed, DesktopActivationIssue.IpcFailure, "The policy request did not complete over the secure local connection."); }
        if (response.Status != ServiceResponseStatus.Ok) return MapRefusal(response);
        var result = response.Payload.Deserialize<ProgramRuleChangeResponse>(ServiceMessageSerializer.Options);
        var expectedPresent = configuration.Policy == ProgramConnectionPolicy.Blocked;
        if (result is null || result.Policy != configuration.Policy || !result.TransactionStatus.Equals("Committed", StringComparison.Ordinal) || result.ExactRulePresent != expectedPresent)
            return Snapshot(DesktopActivationState.Failed, DesktopActivationIssue.InvalidServiceResponse, "The service did not return verified policy-commit evidence.");
        try
        {
            await _store.SaveAsync(configuration, cancellationToken).ConfigureAwait(false);
            SavedConfiguration = configuration;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return new(DesktopActivationState.Applied, DesktopActivationIssue.DesktopConfigurationUnavailable,
                "Protection was applied, but the desktop could not save its local reconciliation record.", SavedConfiguration, result.TransactionId);
        }
        return new(DesktopActivationState.Applied, DesktopActivationIssue.None,
            configuration.Policy == ProgramConnectionPolicy.Blocked ? "This application is blocked on all connections." : "QuietShield blocking is removed for this application on all connections.",
            SavedConfiguration, result.TransactionId);
    }

    private DesktopProgramActivationSnapshot MapRefusal(ServiceResponse response)
    {
        if (response.Status == ServiceResponseStatus.NotActive) return Snapshot(DesktopActivationState.Unavailable, DesktopActivationIssue.PersistentProtectionTemporarilyUnavailable, "Persistent protection is temporarily unavailable.");
        if (response.Message.Contains("hash", StringComparison.OrdinalIgnoreCase)) return Snapshot(DesktopActivationState.Failed, DesktopActivationIssue.TargetHashChanged, "The application changed after it was selected. Select it again.");
        if (response.Message.Contains("approved program target", StringComparison.OrdinalIgnoreCase) || response.Message.Contains("stable application identity", StringComparison.OrdinalIgnoreCase))
            return Snapshot(DesktopActivationState.Failed, DesktopActivationIssue.TargetNotAuthorized, "The service is not authorized for this exact application target.");
        if (response.Message.Contains("Network-specific", StringComparison.OrdinalIgnoreCase)) return Snapshot(DesktopActivationState.SimulationOnly, DesktopActivationIssue.UnsupportedPersistentPolicy, "This network-specific policy remains simulation-only.");
        if (response.Message.Contains("rollback", StringComparison.OrdinalIgnoreCase) || response.Message.Contains("restored", StringComparison.OrdinalIgnoreCase))
            return Snapshot(DesktopActivationState.Recovering, DesktopActivationIssue.TransactionRolledBack, "The policy transaction was rolled back safely.");
        if (response.Message.Contains("Administrator", StringComparison.OrdinalIgnoreCase)) return Snapshot(DesktopActivationState.Failed, DesktopActivationIssue.AdministrativeActionRequired, "An approved administrative lifecycle action is required outside the desktop app.");
        return Snapshot(DesktopActivationState.Failed, DesktopActivationIssue.InvalidServiceResponse, "The service refused the policy request. No unverified state was saved.");
    }

    private DesktopProgramActivationSnapshot Snapshot(DesktopActivationState state, DesktopActivationIssue issue, string message) => new(state, issue, message, SavedConfiguration);
}
