using System.IO;
using System.Text.Json;
using QuietShield.Core.DataSaving;

namespace QuietShield.App.DataSaving;

public sealed class JsonOperatingModeStore : IOperatingModeStore
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    private readonly string _path;

    public JsonOperatingModeStore(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("A mode-store path is required.", nameof(path));
        }

        _path = Path.GetFullPath(path);
    }

    public async Task<OperatingModeState> LoadAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_path))
        {
            return OperatingModeState.Default;
        }

        try
        {
            var json = await File.ReadAllTextAsync(_path, cancellationToken).ConfigureAwait(false);
            var state = JsonSerializer.Deserialize<OperatingModeState>(json, SerializerOptions);
            return state?.Normalize() ?? OperatingModeState.Default;
        }
        catch (JsonException)
        {
            return OperatingModeState.Default;
        }
        catch (IOException)
        {
            return OperatingModeState.Default;
        }
        catch (UnauthorizedAccessException)
        {
            return OperatingModeState.Default;
        }
    }

    public async Task SaveAsync(OperatingModeState state, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(state);

        var normalized = state.Normalize();
        var directory = Path.GetDirectoryName(_path);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var temporaryPath = _path + "." + Guid.NewGuid().ToString("N") + ".tmp";

        try
        {
            var json = JsonSerializer.Serialize(normalized, SerializerOptions);
            await File.WriteAllTextAsync(temporaryPath, json, cancellationToken).ConfigureAwait(false);
            File.Move(temporaryPath, _path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }
}
