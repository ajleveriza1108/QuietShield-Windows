// QuietShield Backend Integration 09 R1
using System.Security.Cryptography;
using System.Text.Json;
using QuietShield.Licensing;
using QuietShield.LicenseServer;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSingleton<DevelopmentSigningKeyStore>();
builder.Services.AddSingleton<DevelopmentTrialStore>();

var app = builder.Build();

app.MapGet("/health", () => Results.Ok(new
{
    status = "ok",
    utc = DateTimeOffset.UtcNow,
    policy = "3 devices / 7-day server-controlled trial"
}));

app.MapGet("/v1/public-key", (DevelopmentSigningKeyStore keys) =>
    Results.Ok(new
    {
        algorithm = "ECDSA_P256_SHA256",
        subjectPublicKeyInfoBase64 =
            Convert.ToBase64String(keys.ExportPublicKey())
    }));

app.MapPost(
    "/v1/trial/issue",
    async (
        LicenseIssueRequest request,
        DevelopmentSigningKeyStore keys,
        DevelopmentTrialStore trials,
        CancellationToken cancellationToken) =>
    {
        if (string.IsNullOrWhiteSpace(request.OpaqueDeviceId))
            return Results.BadRequest("Opaque device ID is required.");

        var now = DateTimeOffset.UtcNow;
        var trial = await trials.GetOrCreateAsync(
            request.OpaqueDeviceId.Trim(),
            now,
            cancellationToken);

        var device = new LicensedDevice(
            request.OpaqueDeviceId.Trim(),
            string.IsNullOrWhiteSpace(request.DisplayName)
                ? "Windows device"
                : request.DisplayName.Trim(),
            QuietShieldPlatform.Windows,
            trial.ServerStartedAtUtc,
            now,
            true);

        var payload = new SignedLicensePayload(
            "trial-" + request.OpaqueDeviceId.Trim(),
            LicenseState.ServerControlledTrial,
            now,
            trial.ServerExpiresAtUtc,
            request.OpaqueDeviceId.Trim(),
            [device],
            trial,
            false,
            "dev-1");

        var envelope = SignedLicenseBackend.SignForTesting(
            payload,
            keys.PrivateKey);

        return Results.Ok(
            new LicenseIssueResponse(envelope, now));
    });

app.MapPost(
    "/v1/license/refresh",
    async (
        LicenseIssueRequest request,
        DevelopmentSigningKeyStore keys,
        DevelopmentTrialStore trials,
        CancellationToken cancellationToken) =>
    {
        if (string.IsNullOrWhiteSpace(request.OpaqueDeviceId))
            return Results.BadRequest("Opaque device ID is required.");

        var now = DateTimeOffset.UtcNow;
        var trial = await trials.GetOrCreateAsync(
            request.OpaqueDeviceId.Trim(),
            now,
            cancellationToken);

        var state = trial.IsActiveAt(now)
            ? LicenseState.ServerControlledTrial
            : LicenseState.Expired;

        var device = new LicensedDevice(
            request.OpaqueDeviceId.Trim(),
            string.IsNullOrWhiteSpace(request.DisplayName)
                ? "Windows device"
                : request.DisplayName.Trim(),
            QuietShieldPlatform.Windows,
            trial.ServerStartedAtUtc,
            now,
            true);

        var payload = new SignedLicensePayload(
            "trial-" + request.OpaqueDeviceId.Trim(),
            state,
            now,
            state == LicenseState.Expired ? now.AddMinutes(5) : trial.ServerExpiresAtUtc,
            request.OpaqueDeviceId.Trim(),
            [device],
            trial,
            false,
            "dev-1");

        var envelope = SignedLicenseBackend.SignForTesting(
            payload,
            keys.PrivateKey);

        return Results.Ok(
            new LicenseIssueResponse(envelope, now));
    });

app.Run();

namespace QuietShield.LicenseServer
{
public sealed record LicenseIssueRequest(
    string OpaqueDeviceId,
    string? DisplayName);

public sealed record LicenseIssueResponse(
    SignedLicenseEnvelope Envelope,
    DateTimeOffset ServerObservedAtUtc);

public sealed class DevelopmentSigningKeyStore : IDisposable
{
    private readonly string _keyPath;
    public ECDsa PrivateKey { get; }

    public DevelopmentSigningKeyStore()
    {
        var root = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "QuietShield",
            "LicenseServerDev");

        Directory.CreateDirectory(root);
        _keyPath = Path.Combine(root, "ecdsa-p256-private.pkcs8");

        PrivateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        if (File.Exists(_keyPath))
        {
            var bytes = Convert.FromBase64String(File.ReadAllText(_keyPath));
            PrivateKey.ImportPkcs8PrivateKey(bytes, out _);
        }
        else
        {
            File.WriteAllText(
                _keyPath,
                Convert.ToBase64String(PrivateKey.ExportPkcs8PrivateKey()));
        }
    }

    public byte[] ExportPublicKey() =>
        PrivateKey.ExportSubjectPublicKeyInfo();

    public void Dispose()
    {
        PrivateKey.Dispose();
        GC.SuppressFinalize(this);
    }
}

public sealed class DevelopmentTrialStore : IDisposable
{
    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly string _path;

    public DevelopmentTrialStore()
    {
        var root = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "QuietShield",
            "LicenseServerDev");

        Directory.CreateDirectory(root);
        _path = Path.Combine(root, "trials.json");
    }

    public void Dispose()
    {
        _gate.Dispose();
        GC.SuppressFinalize(this);
    }

    public async Task<TrialState> GetOrCreateAsync(
        string opaqueDeviceId,
        DateTimeOffset nowUtc,
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            Dictionary<string, TrialState> state;

            if (File.Exists(_path))
            {
                try
                {
                    var json = await File.ReadAllTextAsync(
                        _path,
                        cancellationToken).ConfigureAwait(false);

                    state = JsonSerializer.Deserialize<Dictionary<string, TrialState>>(
                                json,
                                Options)
                            ?? new(StringComparer.Ordinal);
                }
                catch (JsonException)
                {
                    state = new(StringComparer.Ordinal);
                }
            }
            else
            {
                state = new(StringComparer.Ordinal);
            }

            if (state.TryGetValue(opaqueDeviceId, out var existing))
                return existing;

            var policy = UniversalLicensePolicy.Default;
            var trial = new TrialState(
                nowUtc,
                nowUtc + policy.FullFeatureTrialDuration,
                nowUtc,
                policy.TrialIsServerControlled);

            state[opaqueDeviceId] = trial;

            await File.WriteAllTextAsync(
                _path,
                JsonSerializer.Serialize(state, Options),
                cancellationToken).ConfigureAwait(false);

            return trial;
        }
        finally
        {
            _gate.Release();
        }
    }
}
}
