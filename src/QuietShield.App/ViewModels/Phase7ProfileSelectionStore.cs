using System.IO;
using System.Text.Json;

namespace QuietShield.App.ViewModels;

public interface IProfileSelectionStore
{
    string? LoadSelectedProfileId();
    void SaveSelectedProfileId(string profileId);
}

public sealed class JsonProfileSelectionStore : IProfileSelectionStore
{
    private static readonly JsonSerializerOptions Options = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = true };
    private readonly string _path;

    public JsonProfileSelectionStore(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _path = path;
    }

    public string? LoadSelectedProfileId()
    {
        if (!File.Exists(_path)) return null;
        try
        {
            return JsonSerializer.Deserialize<SelectionDocument>(File.ReadAllText(_path), Options)?.SelectedProfileId;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            return null;
        }
    }

    public void SaveSelectedProfileId(string profileId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(profileId);
        var directory = Path.GetDirectoryName(_path) ?? throw new InvalidOperationException("The selection store path has no directory.");
        Directory.CreateDirectory(directory);
        var temporaryPath = _path + ".tmp";
        File.WriteAllText(temporaryPath, JsonSerializer.Serialize(new SelectionDocument(1, profileId), Options));
        File.Move(temporaryPath, _path, true);
    }

    private sealed record SelectionDocument(int SchemaVersion, string SelectedProfileId);
}
