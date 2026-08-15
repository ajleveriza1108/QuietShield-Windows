using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Windows.Input;
using QuietShield.Core.ConnectionLock;
using QuietShield.Core.Protection;
using QuietShield.Core.Simulation;

namespace QuietShield.App.ViewModels;

public sealed partial class MainViewModel
{
    private static readonly string[] BasicNavigationTitles =
    {
        "Dashboard",
        "Data Saving & Wi-Fi",
        "Program Connection Lock",
        "DNS Protection",
        "Activity and Statistics",
        "Private Browser",
        "File Safety",
        "Settings"
    };

    private bool _showAdvancedNavigation;
    private bool _showSystemAndUnsupportedApplications;
    private string _privateBrowserLaunchStatus = "Private Browser is ready to launch when its development runtime is available.";

    public ObservableCollection<NavigationItem> VisibleNavigationItems { get; } = new();

    public ICommand ToggleAdvancedNavigationCommand { get; private set; } = null!;
    public ICommand LaunchPrivateBrowserCommand { get; private set; } = null!;

    public IReadOnlyList<QuietShield.Core.Protection.ProgramConnectionPolicy> PersistentProgramPolicies { get; } = new[]
    {
        QuietShield.Core.Protection.ProgramConnectionPolicy.Blocked,
        QuietShield.Core.Protection.ProgramConnectionPolicy.AllowedOnAll
    };

    public bool ShowAdvancedNavigation
    {
        get => _showAdvancedNavigation;
        private set
        {
            if (SetField(ref _showAdvancedNavigation, value))
            {
                OnPropertyChanged(nameof(AdvancedNavigationButtonText));
                RebuildVisibleNavigationItems();
            }
        }
    }

    public string AdvancedNavigationButtonText => ShowAdvancedNavigation
        ? "Fewer tools"
        : "More tools";

    public bool ShowSystemAndUnsupportedApplications
    {
        get => _showSystemAndUnsupportedApplications;
        set
        {
            if (SetField(ref _showSystemAndUnsupportedApplications, value))
            {
                ApplyFilter();
            }
        }
    }

    public string PrivateBrowserLaunchStatus
    {
        get => _privateBrowserLaunchStatus;
        private set => SetField(ref _privateBrowserLaunchStatus, value);
    }

    public bool IsProtectionOverview => SelectedPage.Title == "Protection";
    public bool IsParentChildControls => SelectedPage.Title == "Parent and Child Controls";
    public bool IsPrivateBrowser => SelectedPage.Title == "Private Browser";
    public bool IsFileSafety => SelectedPage.Title == "File Safety";
    public bool IsUpdates => SelectedPage.Title == "Updates";

    private void InitializeGuiUsabilityR2()
    {
        ToggleAdvancedNavigationCommand = new AsyncRelayCommand(() =>
        {
            ShowAdvancedNavigation = !ShowAdvancedNavigation;
            return Task.CompletedTask;
        });

        LaunchPrivateBrowserCommand = new AsyncRelayCommand(LaunchPrivateBrowserAsync);
        RebuildVisibleNavigationItems();
    }

    private void RebuildVisibleNavigationItems()
    {
        VisibleNavigationItems.Clear();

        foreach (var item in NavigationItems)
        {
            if (ShowAdvancedNavigation || BasicNavigationTitles.Contains(item.Title, StringComparer.Ordinal))
            {
                VisibleNavigationItems.Add(item);
            }
        }

        if (!ShowAdvancedNavigation &&
            !VisibleNavigationItems.Any(item => string.Equals(item.Title, SelectedPage.Title, StringComparison.Ordinal)))
        {
            SelectedPage = NavigationItems[0];
        }
    }

    private bool ShouldShowApplicationInMainList(ApplicationListItem application)
    {
        if (ShowSystemAndUnsupportedApplications)
        {
            return true;
        }

        return !application.Application.IsWindowsSystemComponent &&
               application.Application.MainExecutablePath is not null &&
               application.Application.ExecutableExists;
    }

    private Task LaunchPrivateBrowserAsync()
    {
        const string path = @"D:\Windows Projects\QuietShield-Windows\artifacts\bin\QuietShield.PrivateBrowser\Release\net10.0-windows\QuietShield.PrivateBrowser.exe";

        if (!File.Exists(path))
        {
            PrivateBrowserLaunchStatus = "Private Browser runtime is not built yet. Run the backend/runtime build first.";
            return Task.CompletedTask;
        }

        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = path,
            UseShellExecute = true
        });

        PrivateBrowserLaunchStatus = process is null
            ? "Windows did not start the Private Browser runtime."
            : "Private Browser launched.";

        return Task.CompletedTask;
    }
}
