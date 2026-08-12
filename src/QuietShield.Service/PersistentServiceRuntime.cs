using Microsoft.Extensions.Logging;
using QuietShield.Core.ConnectionLock;
using QuietShield.Core.ConnectionLock.Transactions;
using QuietShield.Core.ServiceFoundation;

namespace QuietShield.Service;

public sealed partial class PersistentServiceRuntime : IDisposable
{
    public const int CurrentSchemaVersion = 1;
    private readonly object _sync = new();
    private readonly DiagnosticServiceOptions _options;
    private readonly AtomicJsonStateStore<PersistentServiceState> _store;
    private readonly ILogger<PersistentServiceRuntime> _logger;
    private readonly SemaphoreSlim _stateMutationGate = new(1, 1);
    private PersistentServiceState _state = CreateDefault();
    private ServiceHealthSnapshot _health = new("Stopped", 0, null, "Not run", true, false, "Service host is stopped.");
    private bool _usedLastKnownGood;
    private bool _stateIntegrityValid = true;
    private bool _persistentEnforcementAvailable;

    public PersistentServiceRuntime(
        DiagnosticServiceOptions options,
        AtomicJsonStateStore<PersistentServiceState> store,
        ILogger<PersistentServiceRuntime> logger)
    {
        _options = options;
        _store = store;
        _logger = logger;
    }

    public string StatePath => Path.Combine(_options.StateRoot, "service-state.json");
    public string LastKnownGoodPath => Path.Combine(_options.StateRoot, "last-known-good-state.json");

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        SetHealth("Starting", "Read-only startup preflight is running.", true, false);
        Directory.CreateDirectory(_options.StateRoot);
        var primaryExists = File.Exists(StatePath);
        var lastKnownGoodExists = File.Exists(LastKnownGoodPath);
        if (!primaryExists && !lastKnownGoodExists)
        {
            _state = CreateDefault();
            await _store.SaveAsync(StatePath, _state, cancellationToken).ConfigureAwait(false);
            await _store.SaveAsync(LastKnownGoodPath, _state, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            try
            {
                var loaded = await _store.ReadWithLastKnownGoodAsync(StatePath, LastKnownGoodPath, cancellationToken).ConfigureAwait(false);
                _state = loaded.State;
                _usedLastKnownGood = loaded.UsedLastKnownGood;
            }
            catch (Exception exception) when (exception is IOException or InvalidDataException or NotSupportedException or UnauthorizedAccessException)
            {
                _stateIntegrityValid = false;
                SetHealth("InvalidState", "Persistent state validation failed; automatic enforcement is prohibited.", false, false);
                LogInvalidState(_logger, exception.GetType().Name);
                return;
            }
        }

        var interrupted = _state.TransactionCheckpoint.IsInterrupted;
        var detail = interrupted
            ? "Interrupted transaction detected; enforcement remains inactive pending explicit rollback."
            : _usedLastKnownGood
                ? "Primary state was refused; validated last-known-good state loaded without enforcement."
                : "Startup preflight and persistent-state integrity validation passed; enforcement remains inactive.";
        SetHealth(interrupted ? "RecoveryRequired" : _options.ServiceMode ? "HealthyService" : "HealthyDiagnostic", detail, true, interrupted);
        await PersistHealthAsync("Running", "Unclean until graceful stop completes.", null, cancellationToken).ConfigureAwait(false);
        LogStarted(_logger, _options.PipeName);
    }

    public async Task RecordHeartbeatAsync(CancellationToken cancellationToken)
    {
        ServiceHealthSnapshot next;
        lock (_sync)
        {
            next = _health with { HeartbeatSequence = _health.HeartbeatSequence + 1, LastHeartbeatUtc = DateTimeOffset.UtcNow };
            _health = next;
        }
        if (_stateIntegrityValid)
            await PersistHealthAsync(next.State, "Unclean until graceful stop completes.", null, cancellationToken).ConfigureAwait(false);
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        SetHealth("Stopping", "Graceful shutdown is persisting clean state.", _stateIntegrityValid, _state.TransactionCheckpoint.IsInterrupted);
        if (_stateIntegrityValid)
            await PersistHealthAsync("Stopped", "Clean", null, cancellationToken).ConfigureAwait(false);
        SetHealth("Stopped", _stateIntegrityValid ? "Service host stopped cleanly." : "Service host stopped without altering invalid persistent state.",
            _stateIntegrityValid, _state.TransactionCheckpoint.IsInterrupted);
        LogStopped(_logger);
    }

    public ServiceHealthSnapshot GetHealth() { lock (_sync) return _health; }

    public ServiceStatusSnapshot GetStatus()
    {
        var health = GetHealth();
        lock (_sync)
        {
            return new(
                _options.ServiceMode ? "Installed" : "Not installed",
                _options.ServiceMode ? "Service IPC" : _options.DiagnosticMode ? "Diagnostic mode" : "Console-safe mode",
                _persistentEnforcementAvailable ? "Available for authorized program target" : "Not active",
                _state.ActiveProfileId,
                _usedLastKnownGood ? "Recovered from validated last-known-good policy" : _state.LastKnownGoodPolicy.Validated ? "Validated" : "Not validated",
                _state.TransactionCheckpoint.IsInterrupted ? "Interrupted transaction requires explicit recovery" : _state.TransactionCheckpoint.State?.ToString() ?? "No transaction",
                _state.TransactionCheckpoint.IsInterrupted ? "Explicit rollback required" : "Ready; exact transaction rollback validated",
                health.LastHeartbeatUtc ?? DateTimeOffset.UtcNow,
                _options.ServiceMode,
                _options.ServiceMode && health.State is not ("Stopped" or "Stopping" or "InvalidState"),
                true,
                _persistentEnforcementAvailable,
                _state.ProgramPolicies,
                _options.ServiceMode ? _options.AuthorizationContext?.AuthorizationId : null);
        }
    }

    public PersistentServiceState GetState() { lock (_sync) return _state; }

    public void SetPersistentEnforcementAvailable(bool available) => _persistentEnforcementAvailable = available && _stateIntegrityValid;

    public async Task UpdateTransactionAsync(PersistentTransactionCheckpoint checkpoint, CancellationToken cancellationToken)
    {
        await _stateMutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            PersistentServiceState updated;
            lock (_sync) { updated = _state with { TransactionCheckpoint = checkpoint }; _state = updated; }
            await _store.SaveAsync(StatePath, updated, cancellationToken).ConfigureAwait(false);
        }
        finally { _stateMutationGate.Release(); }
    }

    public async Task CommitPolicyAsync(string profileId, PersistentProgramPolicy policy, string policySha256, CancellationToken cancellationToken)
    {
        await _stateMutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            PersistentServiceState updated;
            lock (_sync)
            {
                var policies = _state.ProgramPolicies.Where(item => !item.StableApplicationIdentity.Equals(policy.StableApplicationIdentity, StringComparison.OrdinalIgnoreCase)).Append(policy).ToArray();
                updated = _state with
                {
                    ActiveProfileId = profileId,
                    ProgramPolicies = policies,
                    LastKnownGoodPolicy = new(profileId, policySha256, DateTimeOffset.UtcNow, true),
                    TransactionCheckpoint = new(null, ProgramLockTransactionState.Committed, DateTimeOffset.UtcNow, false, "Exact Program Lock policy transaction committed and verified.")
                };
                _state = updated;
            }
            await _store.SaveAsync(StatePath, updated, cancellationToken).ConfigureAwait(false);
            await _store.SaveAsync(LastKnownGoodPath, updated, cancellationToken).ConfigureAwait(false);
        }
        finally { _stateMutationGate.Release(); }
    }

    private async Task PersistHealthAsync(string state, string shutdown, string? failure, CancellationToken cancellationToken)
    {
        await _stateMutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
        PersistentServiceState updated;
        lock (_sync)
        {
            updated = _state with
            {
                Health = new(state, _health.HeartbeatSequence, _health.LastHeartbeatUtc, shutdown, failure)
            };
            _state = updated;
        }
        await _store.SaveAsync(StatePath, updated, cancellationToken).ConfigureAwait(false);
        if (updated.LastKnownGoodPolicy.Validated && !updated.TransactionCheckpoint.IsInterrupted)
            await _store.SaveAsync(LastKnownGoodPath, updated, cancellationToken).ConfigureAwait(false);
        }
        finally { _stateMutationGate.Release(); }
    }

    private void SetHealth(string state, string detail, bool integrity, bool interrupted)
    {
        lock (_sync) _health = _health with { State = state, PreflightStatus = detail, StateIntegrityValid = integrity, InterruptedTransactionDetected = interrupted, Detail = detail };
    }

    private static PersistentServiceState CreateDefault()
    {
        var policyHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(ConnectionLockProfile.BlockAllId)));
        return new(
            CurrentSchemaVersion,
            ConnectionLockProfile.BlockAllId,
            Array.Empty<PersistentProgramPolicy>(),
            Array.Empty<ProgramTemporaryAllowance>(),
            Array.Empty<ConnectionPolicySchedule>(),
            Array.Empty<ConnectionCompatibilityExclusion>(),
            new(null, null, DateTimeOffset.UtcNow, false, "No persistent transaction has started."),
            new(ConnectionLockProfile.BlockAllId, policyHash, DateTimeOffset.UtcNow, true),
            new("Created", 0, null, "Clean", null));
    }

    public void Dispose()
    {
        _stateMutationGate.Dispose();
        GC.SuppressFinalize(this);
    }

    [LoggerMessage(EventId = 10101, Level = LogLevel.Information, Message = "QuietShield service diagnostic foundation started on local named pipe {PipeName}; persistent enforcement remains inactive.")]
    private static partial void LogStarted(ILogger logger, string pipeName);
    [LoggerMessage(EventId = 10102, Level = LogLevel.Information, Message = "QuietShield service diagnostic foundation stopped gracefully.")]
    private static partial void LogStopped(ILogger logger);
    [LoggerMessage(EventId = 10103, Level = LogLevel.Error, Message = "QuietShield persistent state was refused ({FailureType}); automatic enforcement remains prohibited.")]
    private static partial void LogInvalidState(ILogger logger, string failureType);
}
