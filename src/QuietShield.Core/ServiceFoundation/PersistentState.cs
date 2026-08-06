using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using QuietShield.Core.ConnectionLock;
using QuietShield.Core.ConnectionLock.Transactions;
using QuietShield.Core.Protection;

namespace QuietShield.Core.ServiceFoundation;

public sealed record PersistentProgramPolicy(string StableApplicationIdentity, ProgramConnectionPolicy Policy, bool Enabled);

public sealed record PersistentServiceState(
    int SchemaVersion,
    string ActiveProfileId,
    IReadOnlyList<PersistentProgramPolicy> ProgramPolicies,
    IReadOnlyList<ProgramTemporaryAllowance> TemporaryAllowances,
    IReadOnlyList<ConnectionPolicySchedule> Schedules,
    IReadOnlyList<ConnectionCompatibilityExclusion> CompatibilityExclusions,
    PersistentTransactionCheckpoint TransactionCheckpoint,
    LastKnownGoodPolicy LastKnownGoodPolicy,
    PersistentHealthState Health);

public sealed record PersistentTransactionCheckpoint(
    Guid? TransactionId,
    ProgramLockTransactionState? State,
    DateTimeOffset UpdatedAtUtc,
    bool RollbackEligible,
    string Detail)
{
    public bool IsInterrupted => State is ProgramLockTransactionState.ApplyStarted or
        ProgramLockTransactionState.RulesApplied or ProgramLockTransactionState.VerificationStarted or
        ProgramLockTransactionState.VerificationPassed or ProgramLockTransactionState.InterruptedRecoveryRequired;
}

public sealed record LastKnownGoodPolicy(
    string ProfileId,
    string PolicySha256,
    DateTimeOffset CapturedAtUtc,
    bool Validated);

public sealed record PersistentHealthState(
    string State,
    long HeartbeatSequence,
    DateTimeOffset? LastHeartbeatUtc,
    string LastShutdown,
    string? LastFailure);

public sealed record StateLoadResult<T>(T State, bool UsedLastKnownGood, string SourcePath);

public sealed record AtomicStateEnvelope<T>(int SchemaVersion, string PayloadSha256, T Payload);

public interface IStateMigration<T>
{
    int FromSchemaVersion { get; }
    int ToSchemaVersion { get; }
    T Migrate(T state);
}

public interface IAtomicStateStore<T>
{
    Task SaveAsync(string path, T state, CancellationToken cancellationToken);
    Task<T> ReadValidatedAsync(string path, CancellationToken cancellationToken);
    Task<StateLoadResult<T>> ReadWithLastKnownGoodAsync(string primaryPath, string lastKnownGoodPath, CancellationToken cancellationToken);
}

public sealed class AtomicJsonStateStore<T> : IAtomicStateStore<T>
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly int _currentSchemaVersion;
    private readonly Dictionary<int, IStateMigration<T>> _migrations;

    public AtomicJsonStateStore(int currentSchemaVersion, IEnumerable<IStateMigration<T>>? migrations = null)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(currentSchemaVersion);
        _currentSchemaVersion = currentSchemaVersion;
        _migrations = (migrations ?? Array.Empty<IStateMigration<T>>()).ToDictionary(static migration => migration.FromSchemaVersion);
    }

    public async Task SaveAsync(string path, T state, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(state);
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath) ?? throw new ArgumentException("A state directory is required.", nameof(path));
        Directory.CreateDirectory(directory);
        var payloadBytes = JsonSerializer.SerializeToUtf8Bytes(state, Options);
        var envelope = new AtomicStateEnvelope<T>(_currentSchemaVersion, Convert.ToHexString(SHA256.HashData(payloadBytes)), state);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(envelope, Options);
        var temporaryPath = fullPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        var backupPath = fullPath + ".bak";

        try
        {
            await using (var stream = new FileStream(temporaryPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough | FileOptions.Asynchronous))
            {
                await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }

            if (File.Exists(fullPath)) File.Replace(temporaryPath, fullPath, backupPath, true);
            else File.Move(temporaryPath, fullPath);
        }
        finally
        {
            if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
        }
    }

    public async Task<T> ReadValidatedAsync(string path, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        AtomicStateEnvelope<T> envelope;
        try
        {
            await using var stream = new FileStream(Path.GetFullPath(path), FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.Asynchronous);
            envelope = await JsonSerializer.DeserializeAsync<AtomicStateEnvelope<T>>(stream, Options, cancellationToken).ConfigureAwait(false)
                ?? throw new InvalidDataException("The persistent state envelope is empty.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("The persistent state is malformed JSON.", exception);
        }

        if (envelope.Payload is null) throw new InvalidDataException("The persistent state payload is missing.");
        var payloadHash = Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(envelope.Payload, Options)));
        if (!CryptographicOperations.FixedTimeEquals(Convert.FromHexString(payloadHash), ParseHash(envelope.PayloadSha256)))
            throw new InvalidDataException("The persistent state SHA-256 integrity check failed.");

        var schema = envelope.SchemaVersion;
        var state = envelope.Payload;
        while (schema != _currentSchemaVersion)
        {
            if (schema > _currentSchemaVersion || !_migrations.TryGetValue(schema, out var migration) || migration.ToSchemaVersion <= schema)
                throw new NotSupportedException($"Persistent state schema {schema} cannot be migrated to {_currentSchemaVersion}.");
            state = migration.Migrate(state);
            schema = migration.ToSchemaVersion;
        }
        return state;
    }

    public async Task<StateLoadResult<T>> ReadWithLastKnownGoodAsync(
        string primaryPath,
        string lastKnownGoodPath,
        CancellationToken cancellationToken)
    {
        try
        {
            return new(await ReadValidatedAsync(primaryPath, cancellationToken).ConfigureAwait(false), false, Path.GetFullPath(primaryPath));
        }
        catch (Exception exception) when (exception is IOException or InvalidDataException or NotSupportedException or UnauthorizedAccessException)
        {
            var state = await ReadValidatedAsync(lastKnownGoodPath, cancellationToken).ConfigureAwait(false);
            return new(state, true, Path.GetFullPath(lastKnownGoodPath));
        }
    }

    private static byte[] ParseHash(string hash)
    {
        if (string.IsNullOrWhiteSpace(hash) || hash.Length != 64 || hash.Any(static value => !Uri.IsHexDigit(value)))
            throw new InvalidDataException("The persistent state SHA-256 value is malformed.");
        return Convert.FromHexString(hash);
    }
}
