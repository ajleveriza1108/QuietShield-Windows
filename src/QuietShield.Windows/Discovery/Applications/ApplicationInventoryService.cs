using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using QuietShield.Core.Results;
using QuietShield.Windows.Integration;

namespace QuietShield.Windows.Discovery.Applications;

public sealed class ApplicationInventoryService : IApplicationInventoryService, IInstalledApplicationDiscovery
{
    private static readonly TimeSpan CacheLifetime = TimeSpan.FromMinutes(15);
    private static readonly string[] StoreDiscoverySources = { "Microsoft Store/MSIX package identity" };
    private readonly IUninstallRegistrationSource _uninstallSource;
    private readonly IStorePackageSource _storeSource;
    private readonly IStartMenuEntrySource _startMenuSource;
    private readonly IApplicationInventoryCache _cache;

    public ApplicationInventoryService(
        IUninstallRegistrationSource uninstallSource,
        IStorePackageSource storeSource,
        IStartMenuEntrySource startMenuSource,
        IApplicationInventoryCache cache)
    {
        _uninstallSource = uninstallSource;
        _storeSource = storeSource;
        _startMenuSource = startMenuSource;
        _cache = cache;
    }

    public bool LastResultUsedCache { get; private set; }

    public Task<OperationResult<IReadOnlyList<InstalledApplicationInfo>>> DiscoverAsync(CancellationToken cancellationToken) =>
        DiscoverAsync(false, null, cancellationToken);

    public async Task<OperationResult<IReadOnlyList<InstalledApplicationInfo>>> DiscoverAsync(
        bool forceRefresh,
        IProgress<DiscoveryProgress>? progress,
        CancellationToken cancellationToken)
    {
        LastResultUsedCache = false;
        if (!forceRefresh)
        {
            var cached = await _cache.TryReadAsync(CacheLifetime, cancellationToken).ConfigureAwait(false);
            if (cached is not null)
            {
                LastResultUsedCache = true;
                progress?.Report(new DiscoveryProgress("Applications", 1, 1, $"Loaded {cached.Count} applications from the safe local cache."));
                return OperationResult.Success(cached, "Application inventory loaded from the safe local cache.");
            }
        }

        progress?.Report(new DiscoveryProgress("Applications", 0, 3, "Reading Win32 uninstall registrations."));
        var uninstallTask = _uninstallSource.ReadAsync(cancellationToken);
        var storeTask = _storeSource.ReadAsync(cancellationToken);
        var startMenuTask = _startMenuSource.ReadAsync(cancellationToken);
        await Task.WhenAll(uninstallTask, storeTask, startMenuTask).ConfigureAwait(false);

        cancellationToken.ThrowIfCancellationRequested();
        progress?.Report(new DiscoveryProgress("Applications", 1, 3, "Normalizing Win32 application metadata."));
        var candidates = new List<InstalledApplicationInfo>();
        candidates.AddRange(uninstallTask.Result.Select(CreateFromUninstallRegistration));

        progress?.Report(new DiscoveryProgress("Applications", 2, 3, "Normalizing Store identities and Start menu entries."));
        candidates.AddRange(storeTask.Result.Select(CreateFromStoreIdentity));
        candidates.AddRange(startMenuTask.Result.Select(CreateFromStartMenuEntry));

        cancellationToken.ThrowIfCancellationRequested();
        var applications = ApplicationInventoryDeduplicator.Deduplicate(candidates);
        await _cache.WriteAsync(applications, cancellationToken).ConfigureAwait(false);
        progress?.Report(new DiscoveryProgress("Applications", 3, 3, $"Discovered {applications.Count} deduplicated applications."));
        return OperationResult.Success(applications, "Read-only application inventory completed.");
    }

    public Task ClearCacheAsync(CancellationToken cancellationToken) => _cache.ClearAsync(cancellationToken);

    private static InstalledApplicationInfo CreateFromUninstallRegistration(UninstallRegistration registration)
    {
        var executable = ResolveExecutable(registration.DisplayName, registration.DisplayIcon, registration.InstallLocation);
        var systemComponent = registration.IsSystemComponent || IsWindowsSystemPath(executable);
        var icon = ParseIconReference(registration.DisplayIcon, executable);
        var publisher = registration.Publisher;
        var version = registration.Version;

        if (executable is not null && File.Exists(executable))
        {
            try
            {
                var metadata = FileVersionInfo.GetVersionInfo(executable);
                publisher ??= Normalize(metadata.CompanyName);
                version ??= Normalize(metadata.FileVersion);
            }
            catch (Exception exception) when (exception is FileNotFoundException or IOException or UnauthorizedAccessException or ArgumentException)
            {
                // The file can disappear between existence and metadata checks.
            }
        }

        var type = systemComponent ? InstalledApplicationType.SystemComponent : InstalledApplicationType.Win32;
        var identity = string.Join('|', new[]
        {
            registration.DisplayName,
            publisher ?? string.Empty,
            version ?? string.Empty,
            registration.InstallLocation ?? string.Empty,
            executable ?? string.Empty
        });

        return new InstalledApplicationInfo(
            CreateStableId(type, identity),
            registration.DisplayName,
            publisher,
            version,
            registration.InstallLocation,
            executable,
            type,
            icon,
            executable is not null && File.Exists(executable),
            systemComponent,
            new[] { registration.Source });
    }

    private static InstalledApplicationInfo CreateFromStoreIdentity(StoreApplicationIdentity package)
    {
        var systemComponent = package.IsFramework || package.IsResourcePackage || package.IsNonRemovable ||
                              IsWindowsSystemPath(package.InstallLocation);
        var type = systemComponent
            ? InstalledApplicationType.SystemComponent
            : InstalledApplicationType.MicrosoftStoreOrMsix;
        return new InstalledApplicationInfo(
            CreateStableId(type, package.PackageFamilyName),
            package.DisplayName,
            package.Publisher,
            package.Version,
            package.InstallLocation,
            null,
            type,
            null,
            false,
            systemComponent,
            StoreDiscoverySources)
        {
            PackageFamilyName = package.PackageFamilyName
        };
    }

    private static InstalledApplicationInfo CreateFromStartMenuEntry(StartMenuEntry entry)
    {
        var executable = string.Equals(Path.GetExtension(entry.TargetPath), ".exe", StringComparison.OrdinalIgnoreCase)
            ? entry.TargetPath
            : null;
        var systemComponent = IsWindowsSystemPath(executable);
        var type = systemComponent ? InstalledApplicationType.SystemComponent : InstalledApplicationType.Unknown;
        return new InstalledApplicationInfo(
            CreateStableId(type, executable ?? entry.ShortcutPath),
            entry.DisplayName,
            null,
            null,
            executable is null ? null : Path.GetDirectoryName(executable),
            executable,
            type,
            executable is null ? null : new ApplicationIconReference(executable, 0),
            executable is not null && File.Exists(executable),
            systemComponent,
            new[] { entry.Source });
    }

    private static string? ResolveExecutable(string displayName, string? displayIcon, string? installLocation)
    {
        var icon = ParseIconPath(displayIcon);
        if (icon is not null && string.Equals(Path.GetExtension(icon), ".exe", StringComparison.OrdinalIgnoreCase))
        {
            return icon;
        }

        if (string.IsNullOrWhiteSpace(installLocation) || !Directory.Exists(installLocation))
        {
            return null;
        }

        try
        {
            var executables = Directory.EnumerateFiles(installLocation, "*.exe", SearchOption.TopDirectoryOnly)
                .Take(200)
                .ToArray();
            if (executables.Length == 1)
            {
                return executables[0];
            }

            var normalizedName = NormalizeForMatch(displayName);
            return executables.FirstOrDefault(path =>
                NormalizeForMatch(Path.GetFileNameWithoutExtension(path)).Equals(normalizedName, StringComparison.Ordinal));
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
        catch (IOException)
        {
            return null;
        }
    }

    private static ApplicationIconReference? ParseIconReference(string? displayIcon, string? executable)
    {
        var path = ParseIconPath(displayIcon) ?? executable;
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        var index = 0;
        if (!string.IsNullOrWhiteSpace(displayIcon))
        {
            var comma = displayIcon.LastIndexOf(',');
            if (comma >= 0)
            {
                _ = int.TryParse(displayIcon[(comma + 1)..].Trim(), out index);
            }
        }

        return new ApplicationIconReference(path, index);
    }

    private static string? ParseIconPath(string? displayIcon)
    {
        if (string.IsNullOrWhiteSpace(displayIcon))
        {
            return null;
        }

        var value = Environment.ExpandEnvironmentVariables(displayIcon.Trim());
        var comma = value.LastIndexOf(',');
        if (comma > 0 && int.TryParse(value[(comma + 1)..].Trim(), out _))
        {
            value = value[..comma];
        }

        return value.Trim().Trim('"');
    }

    public static bool IsWindowsSystemPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        try
        {
            var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            return !string.IsNullOrWhiteSpace(windows) &&
                   Path.GetFullPath(path).StartsWith(
                       Path.GetFullPath(windows) + Path.DirectorySeparatorChar,
                       StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }

    private static string CreateStableId(InstalledApplicationType type, string identity)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes($"{type}|{identity.Trim().ToUpperInvariant()}"));
        return Convert.ToHexString(bytes);
    }

    private static string NormalizeForMatch(string value) =>
        new(value.Where(char.IsLetterOrDigit).Select(char.ToUpperInvariant).ToArray());

    private static string? Normalize(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}

public static class ApplicationInventoryDeduplicator
{
    public static IReadOnlyList<InstalledApplicationInfo> Deduplicate(
        IEnumerable<InstalledApplicationInfo> candidates)
    {
        var groups = candidates
            .Where(static application => !string.IsNullOrWhiteSpace(application.DisplayName))
            .GroupBy(CreateDeduplicationKey, StringComparer.OrdinalIgnoreCase);
        var results = new List<InstalledApplicationInfo>();

        foreach (var group in groups)
        {
            var items = group.ToArray();
            var preferred = items
                .OrderByDescending(static item => item.ExecutableExists)
                .ThenByDescending(static item => item.ApplicationType == InstalledApplicationType.MicrosoftStoreOrMsix)
                .ThenByDescending(static item => !string.IsNullOrWhiteSpace(item.Publisher))
                .First();
            var sources = items.SelectMany(static item => item.DiscoverySources)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(static source => source, StringComparer.OrdinalIgnoreCase)
                .ToArray();
            var systemComponent = items.Any(static item => item.IsWindowsSystemComponent);
            var type = systemComponent
                ? InstalledApplicationType.SystemComponent
                : items.Any(static item => item.ApplicationType == InstalledApplicationType.MicrosoftStoreOrMsix)
                    ? InstalledApplicationType.MicrosoftStoreOrMsix
                    : items.Any(static item => item.ApplicationType == InstalledApplicationType.Win32)
                        ? InstalledApplicationType.Win32
                        : InstalledApplicationType.Unknown;

            results.Add(preferred with
            {
                Publisher = FirstNonEmpty(items.Select(static item => item.Publisher)),
                Version = FirstNonEmpty(items.Select(static item => item.Version)),
                InstallLocation = FirstNonEmpty(items.Select(static item => item.InstallLocation)),
                MainExecutablePath = FirstNonEmpty(items.Select(static item => item.MainExecutablePath)),
                ApplicationType = type,
                Icon = items.Select(static item => item.Icon).FirstOrDefault(static icon => icon is not null),
                ExecutableExists = items.Any(static item => item.ExecutableExists),
                IsWindowsSystemComponent = systemComponent,
                DiscoverySources = sources
            });
        }

        return results
            .OrderBy(static application => application.DisplayName, StringComparer.CurrentCultureIgnoreCase)
            .ThenBy(static application => application.Publisher, StringComparer.CurrentCultureIgnoreCase)
            .ToArray();
    }

    private static string CreateDeduplicationKey(InstalledApplicationInfo application)
    {
        if (application.ApplicationType == InstalledApplicationType.MicrosoftStoreOrMsix ||
            application.DiscoverySources.Contains("Microsoft Store/MSIX package identity", StringComparer.OrdinalIgnoreCase))
        {
            return "STORE|" + application.Id;
        }

        if (!string.IsNullOrWhiteSpace(application.MainExecutablePath))
        {
            try
            {
                return "EXE|" + Path.GetFullPath(application.MainExecutablePath).TrimEnd(Path.DirectorySeparatorChar);
            }
            catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
            {
                return "EXE-INVALID|" + application.MainExecutablePath;
            }
        }

        return string.Join('|', new[]
        {
            "META",
            application.DisplayName.Trim(),
            application.Publisher?.Trim() ?? string.Empty,
            application.Version?.Trim() ?? string.Empty,
            application.InstallLocation?.Trim().TrimEnd(Path.DirectorySeparatorChar) ?? string.Empty
        });
    }

    private static string? FirstNonEmpty(IEnumerable<string?> values) =>
        values.FirstOrDefault(static value => !string.IsNullOrWhiteSpace(value));
}
