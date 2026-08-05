using System.Text.Json;
using QuietShield.Windows.Integration;

namespace QuietShield.Windows.Discovery.Applications;

public sealed class PowerShellStorePackageSource : IStorePackageSource
{
    private const string DiscoveryScript = "Get-AppxPackage | ForEach-Object { [pscustomobject]@{ PackageFamilyName=$_.PackageFamilyName; PackageFullName=$_.PackageFullName; DisplayName=$_.Name; Publisher=$_.Publisher; Version=$_.Version.ToString(); InstallLocation=$_.InstallLocation; IsFramework=[bool]$_.IsFramework; IsResourcePackage=[bool]$_.IsResourcePackage; IsNonRemovable=[bool]$_.NonRemovable } } | ConvertTo-Json -Depth 3 -Compress";
    private readonly Discovery.IPowerShellJsonRunner _runner;

    public PowerShellStorePackageSource(Discovery.IPowerShellJsonRunner runner)
    {
        _runner = runner;
    }

    public async Task<IReadOnlyList<StoreApplicationIdentity>> ReadAsync(CancellationToken cancellationToken)
    {
        var result = await _runner.RunAsync(DiscoveryScript, cancellationToken).ConfigureAwait(false);
        if (result.ExitCode != 0 || string.IsNullOrWhiteSpace(result.StandardOutput))
        {
            return Array.Empty<StoreApplicationIdentity>();
        }

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(result.StandardOutput);
        }
        catch (JsonException)
        {
            return Array.Empty<StoreApplicationIdentity>();
        }

        using (document)
        {
        var elements = document.RootElement.ValueKind == JsonValueKind.Array
            ? document.RootElement.EnumerateArray().ToArray()
            : new[] { document.RootElement };
        var packages = new List<StoreApplicationIdentity>(elements.Length);

        foreach (var element in elements)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var familyName = GetString(element, "PackageFamilyName");
            var fullName = GetString(element, "PackageFullName");
            var displayName = GetString(element, "DisplayName");
            if (string.IsNullOrWhiteSpace(familyName) || string.IsNullOrWhiteSpace(fullName) || string.IsNullOrWhiteSpace(displayName))
            {
                continue;
            }

            packages.Add(new StoreApplicationIdentity(
                familyName,
                fullName,
                displayName,
                GetString(element, "Publisher"),
                GetString(element, "Version"),
                GetString(element, "InstallLocation"),
                GetBoolean(element, "IsFramework"),
                GetBoolean(element, "IsResourcePackage"),
                GetBoolean(element, "IsNonRemovable")));
        }

            return packages;
        }
    }

    private static string? GetString(JsonElement element, string propertyName) =>
        element.TryGetProperty(propertyName, out var property) && property.ValueKind == JsonValueKind.String
            ? property.GetString()
            : null;

    private static bool GetBoolean(JsonElement element, string propertyName) =>
        element.TryGetProperty(propertyName, out var property) &&
        property.ValueKind is JsonValueKind.True or JsonValueKind.False &&
        property.GetBoolean();
}
