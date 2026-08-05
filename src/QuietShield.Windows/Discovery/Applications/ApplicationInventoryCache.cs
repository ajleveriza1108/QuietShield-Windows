using System.Text.Json;
using QuietShield.Windows.Integration;

namespace QuietShield.Windows.Discovery.Applications;

public interface IDiscoveryClock
{
    DateTimeOffset UtcNow { get; }
}

public sealed class SystemDiscoveryClock : IDiscoveryClock
{
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}

public interface IApplicationInventoryCache
{
    Task<IReadOnlyList<InstalledApplicationInfo>?> TryReadAsync(TimeSpan maximumAge, CancellationToken cancellationToken);

    Task WriteAsync(IReadOnlyList<InstalledApplicationInfo> applications, CancellationToken cancellationToken);

    Task ClearAsync(CancellationToken cancellationToken);
}

public sealed class JsonApplicationInventoryCache : IApplicationInventoryCache
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.General)
    {
        WriteIndented = false
    };
    private readonly string _cachePath;
    private readonly IDiscoveryClock _clock;

    public JsonApplicationInventoryCache(string cachePath, IDiscoveryClock clock)
    {
        _cachePath = cachePath;
        _clock = clock;
    }

    public async Task<IReadOnlyList<InstalledApplicationInfo>?> TryReadAsync(
        TimeSpan maximumAge,
        CancellationToken cancellationToken)
    {
        if (!File.Exists(_cachePath))
        {
            return null;
        }

        try
        {
            await using var stream = File.OpenRead(_cachePath);
            var document = await JsonSerializer.DeserializeAsync<ApplicationInventoryCacheDocument>(
                stream,
                SerializerOptions,
                cancellationToken).ConfigureAwait(false);
            if (document is null || _clock.UtcNow - document.CreatedAtUtc > maximumAge)
            {
                return null;
            }

            return document.Applications;
        }
        catch (JsonException)
        {
            return null;
        }
        catch (IOException)
        {
            return null;
        }
    }

    public async Task WriteAsync(
        IReadOnlyList<InstalledApplicationInfo> applications,
        CancellationToken cancellationToken)
    {
        var directory = Path.GetDirectoryName(_cachePath);
        if (string.IsNullOrWhiteSpace(directory))
        {
            throw new InvalidOperationException("The discovery cache path has no parent directory.");
        }

        Directory.CreateDirectory(directory);
        var temporaryPath = _cachePath + ".tmp";
        await using (var stream = new FileStream(
                         temporaryPath,
                         FileMode.Create,
                         FileAccess.Write,
                         FileShare.None,
                         81920,
                         FileOptions.Asynchronous))
        {
            await JsonSerializer.SerializeAsync(
                stream,
                new ApplicationInventoryCacheDocument(_clock.UtcNow, applications),
                SerializerOptions,
                cancellationToken).ConfigureAwait(false);
        }

        File.Move(temporaryPath, _cachePath, true);
    }

    public Task ClearAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (File.Exists(_cachePath))
        {
            File.Delete(_cachePath);
        }

        return Task.CompletedTask;
    }

    private sealed record ApplicationInventoryCacheDocument(
        DateTimeOffset CreatedAtUtc,
        IReadOnlyList<InstalledApplicationInfo> Applications);
}
