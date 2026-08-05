using Microsoft.Win32;
using System.Globalization;
using System.Reflection;
using System.Runtime.InteropServices;

namespace QuietShield.Windows.Discovery.Applications;

public sealed record UninstallRegistration(
    string RegistryIdentity,
    string DisplayName,
    string? Publisher,
    string? Version,
    string? InstallLocation,
    string? DisplayIcon,
    bool IsSystemComponent,
    string Source);

public sealed record StartMenuEntry(string DisplayName, string ShortcutPath, string? TargetPath, string Source);

public interface IUninstallRegistrationSource
{
    Task<IReadOnlyList<UninstallRegistration>> ReadAsync(CancellationToken cancellationToken);
}

public interface IStorePackageSource
{
    Task<IReadOnlyList<Integration.StoreApplicationIdentity>> ReadAsync(CancellationToken cancellationToken);
}

public interface IStartMenuEntrySource
{
    Task<IReadOnlyList<StartMenuEntry>> ReadAsync(CancellationToken cancellationToken);
}

public sealed class RegistryUninstallRegistrationSource : IUninstallRegistrationSource
{
    private const string UninstallPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

    public Task<IReadOnlyList<UninstallRegistration>> ReadAsync(CancellationToken cancellationToken) =>
        Task.Run<IReadOnlyList<UninstallRegistration>>(() => ReadRegistrations(cancellationToken), cancellationToken);

    private static List<UninstallRegistration> ReadRegistrations(CancellationToken cancellationToken)
    {
        var results = new List<UninstallRegistration>();
        var locations = new[]
        {
            (RegistryHive.LocalMachine, RegistryView.Registry64, "HKLM-64"),
            (RegistryHive.LocalMachine, RegistryView.Registry32, "HKLM-32"),
            (RegistryHive.CurrentUser, RegistryView.Registry64, "HKCU-64"),
            (RegistryHive.CurrentUser, RegistryView.Registry32, "HKCU-32")
        };

        foreach (var location in locations)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(location.Item1, location.Item2);
                using var uninstall = baseKey.OpenSubKey(UninstallPath, false);
                if (uninstall is null)
                {
                    continue;
                }

                foreach (var subKeyName in uninstall.GetSubKeyNames())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    using var entry = uninstall.OpenSubKey(subKeyName, false);
                    var displayName = entry?.GetValue("DisplayName") as string;
                    if (string.IsNullOrWhiteSpace(displayName))
                    {
                        continue;
                    }

                    results.Add(new UninstallRegistration(
                        $"{location.Item3}:{subKeyName}",
                        displayName.Trim(),
                        Normalize(entry?.GetValue("Publisher") as string),
                        Normalize(entry?.GetValue("DisplayVersion") as string),
                        Normalize(entry?.GetValue("InstallLocation") as string),
                        Normalize(entry?.GetValue("DisplayIcon") as string),
                        ReadBoolean(entry?.GetValue("SystemComponent")),
                        location.Item3));
                }
            }
            catch (UnauthorizedAccessException)
            {
                // An inaccessible registration hive is a read-only discovery warning, not a reason to elevate.
            }
            catch (System.Security.SecurityException)
            {
                // Continue with the remaining accessible read-only sources.
            }
            catch (IOException)
            {
                // A registration may disappear during uninstall; continue with a consistent partial result.
            }
        }

        return results;
    }

    private static bool ReadBoolean(object? value) => value switch
    {
        int number => number != 0,
        string text when int.TryParse(text, out var number) => number != 0,
        _ => false
    };

    private static string? Normalize(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}

public sealed class StartMenuEntrySource : IStartMenuEntrySource
{
    public Task<IReadOnlyList<StartMenuEntry>> ReadAsync(CancellationToken cancellationToken) =>
        Task.Run<IReadOnlyList<StartMenuEntry>>(() => ReadEntries(cancellationToken), cancellationToken);

    private static List<StartMenuEntry> ReadEntries(CancellationToken cancellationToken)
    {
        var results = new List<StartMenuEntry>();
        var roots = new[]
        {
            (Environment.GetFolderPath(Environment.SpecialFolder.StartMenu), "Per-user Start menu"),
            (Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu), "Common Start menu")
        };

        foreach (var root in roots.Where(static root => !string.IsNullOrWhiteSpace(root.Item1)))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!Directory.Exists(root.Item1))
            {
                continue;
            }

            IEnumerable<string> shortcuts;
            try
            {
                shortcuts = Directory.EnumerateFiles(root.Item1, "*.lnk", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var shortcut in shortcuts)
            {
                cancellationToken.ThrowIfCancellationRequested();
                results.Add(new StartMenuEntry(
                    Path.GetFileNameWithoutExtension(shortcut),
                    shortcut,
                    TryResolveShortcutTarget(shortcut),
                    root.Item2));
            }
        }

        return results;
    }

    private static string? TryResolveShortcutTarget(string shortcutPath)
    {
        object? shell = null;
        object? shortcut = null;
        try
        {
            var shellType = Type.GetTypeFromProgID("WScript.Shell", false);
            if (shellType is null)
            {
                return null;
            }

            shell = Activator.CreateInstance(shellType);
            shortcut = shellType.InvokeMember(
                "CreateShortcut",
                BindingFlags.InvokeMethod,
                null,
                shell,
                new object[] { shortcutPath },
                CultureInfo.InvariantCulture);
            var target = shortcut?.GetType().InvokeMember(
                "TargetPath",
                BindingFlags.GetProperty,
                null,
                shortcut,
                null,
                CultureInfo.InvariantCulture) as string;
            return string.IsNullOrWhiteSpace(target) ? null : target;
        }
        catch (COMException)
        {
            return null;
        }
        catch (TargetInvocationException)
        {
            return null;
        }
        finally
        {
            ReleaseComObject(shortcut);
            ReleaseComObject(shell);
        }
    }

    private static void ReleaseComObject(object? value)
    {
        if (value is not null && Marshal.IsComObject(value))
        {
            _ = Marshal.FinalReleaseComObject(value);
        }
    }
}
