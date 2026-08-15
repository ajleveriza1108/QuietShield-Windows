using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Text.Json;
using System.Windows;
using System.Windows.Input;
using Microsoft.Win32;
using QuietShield.Core.ServiceFoundation;

namespace QuietShield.App.ViewModels;

public sealed partial class MainViewModel
{
    private static readonly JsonSerializerOptions ConsumerJsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    private AsyncRelayCommand? _protectionToggleCommand;
    private AsyncRelayCommand? _refreshConsumerProtectionCommand;
    private AsyncRelayCommand? _openProtectionPageCommand;
    private AsyncRelayCommand? _openProgramLockPageCommand;
    private AsyncRelayCommand? _openDataSavingPageCommand;
    private AsyncRelayCommand? _openPrivateBrowserPageCommand;
    private AsyncRelayCommand? _openFileSafetyPageCommand;
    private AsyncRelayCommand? _openActivityPageCommand;
    private AsyncRelayCommand? _openDnsProtectionPageCommand;
    private AsyncRelayCommand? _openParentControlsPageCommand;
    private AsyncRelayCommand? _openSettingsPageCommand;
    private AsyncRelayCommand? _createConsumerBackupCommand;
    private AsyncRelayCommand? _restoreConsumerBackupCommand;

    private bool _consumerProtectionIsOn;
    private bool _consumerProtectionBusy = true;
    private string _consumerProtectionHeadline = "Protection status pending";
    private string _consumerProtectionDetail =
        "QuietShield is checking the Windows protection service.";
    private string _consumerProtectionStateLabel = "CHECKING";
    private string _consumerLastAction = "Ready.";

    private bool _quickDataSaving = true;
    private bool _quickPrivateBrowser = true;
    private bool _quickFileSafety = true;
    private bool _quickActivity = true;
    private bool _quickDns;
    private bool _quickSettings;

    private static string ConsumerRoot =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "QuietShield",
            "Consumer");

    private static string ConsumerSettingsPath =>
        Path.Combine(ConsumerRoot, "settings.json");

    public ICommand ProtectionToggleCommand =>
        _protectionToggleCommand ??=
            new AsyncRelayCommand(
                ToggleConsumerProtectionAsync,
                () => !ConsumerProtectionBusy);

    public ICommand RefreshConsumerProtectionCommand =>
        _refreshConsumerProtectionCommand ??=
            new AsyncRelayCommand(
                () => RefreshConsumerProtectionStateAsync(CancellationToken.None),
                () => !ConsumerProtectionBusy);

    public ICommand OpenProtectionPageCommand =>
        _openProtectionPageCommand ??=
            NavigationCommand("Protection");

    public ICommand OpenProgramLockPageCommand =>
        _openProgramLockPageCommand ??=
            NavigationCommand("Program Connection Lock");

    public ICommand OpenDataSavingPageCommand =>
        _openDataSavingPageCommand ??=
            NavigationCommand("Data Saving & Wi-Fi");

    public ICommand OpenPrivateBrowserPageCommand =>
        _openPrivateBrowserPageCommand ??=
            NavigationCommand("Private Browser");

    public ICommand OpenFileSafetyPageCommand =>
        _openFileSafetyPageCommand ??=
            NavigationCommand("File Safety");

    public ICommand OpenActivityPageCommand =>
        _openActivityPageCommand ??=
            NavigationCommand("Activity and Statistics");

    public ICommand OpenDnsProtectionPageCommand =>
        _openDnsProtectionPageCommand ??=
            NavigationCommand("DNS Protection");

    public ICommand OpenParentControlsPageCommand =>
        _openParentControlsPageCommand ??=
            NavigationCommand("Parent and Child Controls");

    public ICommand OpenSettingsPageCommand =>
        _openSettingsPageCommand ??=
            NavigationCommand("Settings");

    public ICommand CreateConsumerBackupCommand =>
        _createConsumerBackupCommand ??=
            new AsyncRelayCommand(CreateConsumerBackupAsync);

    public ICommand RestoreConsumerBackupCommand =>
        _restoreConsumerBackupCommand ??=
            new AsyncRelayCommand(RestoreConsumerBackupAsync);

    public bool ConsumerProtectionIsOn
    {
        get => _consumerProtectionIsOn;
        private set
        {
            if (SetField(ref _consumerProtectionIsOn, value))
            {
                OnPropertyChanged(nameof(ProtectionToggleLabel));
                OnPropertyChanged(nameof(ProtectionToggleHint));
            }
        }
    }

    public bool ConsumerProtectionBusy
    {
        get => _consumerProtectionBusy;
        private set
        {
            if (SetField(ref _consumerProtectionBusy, value))
            {
                _protectionToggleCommand?.RaiseCanExecuteChanged();
                _refreshConsumerProtectionCommand?.RaiseCanExecuteChanged();
                OnPropertyChanged(nameof(ProtectionToggleLabel));
            }
        }
    }

    public string ConsumerProtectionHeadline
    {
        get => _consumerProtectionHeadline;
        private set => SetField(ref _consumerProtectionHeadline, value);
    }

    public string ConsumerProtectionDetail
    {
        get => _consumerProtectionDetail;
        private set => SetField(ref _consumerProtectionDetail, value);
    }

    public string ConsumerProtectionStateLabel
    {
        get => _consumerProtectionStateLabel;
        private set => SetField(ref _consumerProtectionStateLabel, value);
    }

    public string ConsumerLastAction
    {
        get => _consumerLastAction;
        private set => SetField(ref _consumerLastAction, value);
    }

    public string ProtectionToggleLabel =>
        ConsumerProtectionBusy
            ? "Please wait..."
            : ConsumerProtectionIsOn
                ? "Turn Off"
                : "Turn On";

    public string ProtectionToggleHint =>
        ConsumerProtectionIsOn
            ? "Stops the QuietShield Protection Service after confirmation. Existing app-specific Firewall rules remain until changed."
            : "Starts the installed QuietShield Protection Service after an explicit Windows UAC confirmation.";

    public bool QuickDataSaving
    {
        get => _quickDataSaving;
        set
        {
            if (SetField(ref _quickDataSaving, value))
            {
                SaveConsumerSettings();
            }
        }
    }

    public bool QuickPrivateBrowser
    {
        get => _quickPrivateBrowser;
        set
        {
            if (SetField(ref _quickPrivateBrowser, value))
            {
                SaveConsumerSettings();
            }
        }
    }

    public bool QuickFileSafety
    {
        get => _quickFileSafety;
        set
        {
            if (SetField(ref _quickFileSafety, value))
            {
                SaveConsumerSettings();
            }
        }
    }

    public bool QuickActivity
    {
        get => _quickActivity;
        set
        {
            if (SetField(ref _quickActivity, value))
            {
                SaveConsumerSettings();
            }
        }
    }

    public bool QuickDns
    {
        get => _quickDns;
        set
        {
            if (SetField(ref _quickDns, value))
            {
                SaveConsumerSettings();
            }
        }
    }

    public bool QuickSettings
    {
        get => _quickSettings;
        set
        {
            if (SetField(ref _quickSettings, value))
            {
                SaveConsumerSettings();
            }
        }
    }

    private AsyncRelayCommand NavigationCommand(string pageTitle) =>
        new(
            () =>
            {
                NavigateConsumerPage(pageTitle);
                return Task.CompletedTask;
            });

    private void NavigateConsumerPage(string pageTitle)
    {
        var target = NavigationItems.FirstOrDefault(
            item => string.Equals(
                item.Title,
                pageTitle,
                StringComparison.Ordinal));

        if (target is not null)
        {
            SelectedPage = target;
        }
    }

    private async Task InitializeConsumerControlCenterAsync(
        CancellationToken cancellationToken)
    {
        ConsumerProtectionBusy = true;

        try
        {
            LoadConsumerSettings();

            await RefreshConsumerProtectionStateAsync(
                    cancellationToken)
                .ConfigureAwait(true);
        }
        finally
        {
            // Do not expose an actionable Turn On/Turn Off button until
            // QuietShield has resolved the actual Windows service state.
            ConsumerProtectionBusy = false;
        }
    }


    private async Task RefreshConsumerProtectionStateAsync(
        CancellationToken cancellationToken)
    {
        var windowsService =
            await QuietShield.App.Runtime.ProtectionServiceControlR34.QueryAsync(
                    CancellationToken.None)
                .ConfigureAwait(true);

        WriteProtectionIpcDiagnosticR3543(
            "Refresh | WindowsService=" +
            windowsService.State +
            " | Pipe=" +
            QuietShieldServiceProtocol.ProductionPipeName);

        if (windowsService.State !=
            QuietShield.App.Runtime.QuietShieldWindowsServiceState.Running)
        {
            switch (windowsService.State)
            {
                case QuietShield.App.Runtime.QuietShieldWindowsServiceState.NotInstalled:
                    ConsumerProtectionIsOn = false;
                    ConsumerProtectionStateLabel = "NOT INSTALLED";
                    ConsumerProtectionHeadline = "Protection Service Not Installed";
                    ConsumerProtectionDetail =
                        "QuietShieldService is not installed on this Windows installation.";
                    ConsumerLastAction =
                        "No protection setting was changed.";
                    return;

                case QuietShield.App.Runtime.QuietShieldWindowsServiceState.StartPending:
                    ConsumerProtectionIsOn = false;
                    ConsumerProtectionStateLabel = "STARTING";
                    ConsumerProtectionHeadline = "Protection Service Starting";
                    ConsumerProtectionDetail =
                        "Windows is starting QuietShieldService.";
                    ConsumerLastAction =
                        "Refresh after the Windows service reaches Running.";
                    return;

                case QuietShield.App.Runtime.QuietShieldWindowsServiceState.StopPending:
                    ConsumerProtectionIsOn = true;
                    ConsumerProtectionStateLabel = "STOPPING";
                    ConsumerProtectionHeadline = "Protection Service Stopping";
                    ConsumerProtectionDetail =
                        "Windows is stopping QuietShieldService.";
                    ConsumerLastAction =
                        "Refresh after the Windows service reaches Stopped.";
                    return;

                case QuietShield.App.Runtime.QuietShieldWindowsServiceState.Stopped:
                    ConsumerProtectionIsOn = false;
                    ConsumerProtectionStateLabel = "OFF";
                    ConsumerProtectionHeadline = "Protection Service Stopped";
                    ConsumerProtectionDetail =
                        "QuietShieldService is installed but not running.";
                    ConsumerLastAction =
                        string.IsNullOrWhiteSpace(windowsService.BinaryPath)
                            ? "Click Turn On to start the installed Protection Service."
                            : "Installed service: " + windowsService.BinaryPath;
                    return;

                default:
                    ConsumerProtectionIsOn = false;
                    ConsumerProtectionStateLabel = "NEEDS ATTENTION";
                    ConsumerProtectionHeadline = "Protection Service Needs Attention";
                    ConsumerProtectionDetail =
                        windowsService.StatusText;
                    ConsumerLastAction =
                        "Windows service state could not be confirmed.";
                    return;
            }
        }

        // Windows SCM is authoritative for whether the master Protection Service
        // is running. IPC health is reported separately.
        ConsumerProtectionIsOn = true;

        try
        {
            using var timeout =
                CancellationTokenSource.CreateLinkedTokenSource(
                    cancellationToken);

            timeout.CancelAfter(
                TimeSpan.FromSeconds(5));

            var response =
                await CreateProductionServiceClientR3543().SendAsync(
                        ServiceMessageKind.GetServiceStatus,
                        payload: null,
                        timeout.Token)
                    .ConfigureAwait(true);

            ServiceStatusSnapshot? snapshot = null;

            if (response.Status == ServiceResponseStatus.Ok)
            {
                snapshot =
                    response.Payload.Deserialize<ServiceStatusSnapshot>(
                        ConsumerJsonOptions);
            }

            if (snapshot is not null &&
                snapshot.ServiceRunning)
            {
                ConsumerProtectionStateLabel =
                    snapshot.IpcConnected
                        ? "ON"
                        : "RUNNING - IPC ISSUE";

                ConsumerProtectionHeadline =
                    "Protection Service Running";

                ConsumerProtectionDetail =
                    snapshot.IpcConnected
                        ? "QuietShieldService is running and the production Service IPC connection is healthy."
                        : "QuietShieldService is running, but its IPC health flag needs attention.";

                ConsumerLastAction =
                    snapshot.PersistentEnforcementAvailable
                        ? "Persistent Program Connection Lock is available."
                        : "The Protection Service is running, but persistent enforcement is not currently available.";

                WriteProtectionIpcDiagnosticR3543(
                    "Refresh PASSED | Response=Ok" +
                    " | ServiceRunning=" +
                    snapshot.ServiceRunning +
                    " | IpcConnected=" +
                    snapshot.IpcConnected +
                    " | PersistentEnforcementAvailable=" +
                    snapshot.PersistentEnforcementAvailable);

                return;
            }

            ConsumerProtectionStateLabel =
                "RUNNING - IPC ISSUE";

            ConsumerProtectionHeadline =
                "Protection Service Running";

            ConsumerProtectionDetail =
                "Windows reports QuietShieldService as running, but the production IPC status response was incomplete.";

            ConsumerLastAction =
                "Use Refresh or review protection-ipc.log.";

            WriteProtectionIpcDiagnosticR3543(
                "Refresh IPC INCOMPLETE | ResponseStatus=" +
                response.Status);
        }
        catch (OperationCanceledException)
        {
            ConsumerProtectionStateLabel =
                "RUNNING - IPC ISSUE";

            ConsumerProtectionHeadline =
                "Protection Service Running";

            ConsumerProtectionDetail =
                "Windows reports QuietShieldService as running, but the production IPC status request timed out.";

            ConsumerLastAction =
                "Protection remains running at the Windows service level. Review protection-ipc.log.";

            WriteProtectionIpcDiagnosticR3543(
                "Refresh IPC TIMEOUT | WindowsService=Running");
        }
        catch (Exception exception)
        {
            ConsumerProtectionStateLabel =
                "RUNNING - IPC ISSUE";

            ConsumerProtectionHeadline =
                "Protection Service Running";

            ConsumerProtectionDetail =
                "Windows reports QuietShieldService as running, but the desktop app could not complete the production IPC request.";

            ConsumerLastAction =
                exception.Message;

            WriteProtectionIpcDiagnosticR3543(
                "Refresh IPC ERROR | " +
                exception.GetType().Name +
                " | " +
                exception.Message);
        }
    }

    private async Task ToggleConsumerProtectionAsync()
    {
        if (ConsumerProtectionBusy)
        {
            return;
        }

        // Capture exactly what the user clicked BEFORE refreshing state.
        // A stale startup label must never turn a Turn On click into
        // a Turn Off operation, or vice versa.
        var requestedTurnOn =
            !ConsumerProtectionIsOn;

        ConsumerProtectionBusy = true;

        try
        {
            await RefreshConsumerProtectionStateAsync(
                    CancellationToken.None)
                .ConfigureAwait(true);

            if (requestedTurnOn)
            {
                // The UI was stale but Windows already reports protection on.
                // Refresh the display and do not show a confirmation or UAC.
                if (ConsumerProtectionIsOn)
                {
                    ConsumerLastAction =
                        "QuietShield Protection is already running. No UAC request was needed.";
                    return;
                }

                var service =
                    await QuietShield.App.Runtime.ProtectionServiceControlR34.QueryAsync(
                            CancellationToken.None)
                        .ConfigureAwait(true);

                if (!service.IsInstalled)
                {
                    ConsumerProtectionHeadline =
                        "Protection Service Not Installed";
                    ConsumerProtectionStateLabel =
                        "NOT INSTALLED";
                    ConsumerProtectionDetail =
                        "QuietShieldService must be registered before protection can be turned on.";
                    ConsumerLastAction =
                        "No UAC request was made because there is no installed service to start.";

                    MessageBox.Show(
                        "QuietShieldService is not installed on this Windows installation.\n\n" +
                        "No Windows setting was changed.",
                        "Protection Service Not Installed",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);

                    return;
                }

                var startAnswer =
                    MessageBox.Show(
                        "Turn on QuietShield Protection?\n\n" +
                        "Windows will show one UAC prompt to start the already-installed QuietShield Protection Service.\n\n" +
                        "Installed service:\n" +
                        (string.IsNullOrWhiteSpace(service.BinaryPath)
                            ? "QuietShieldService"
                            : service.BinaryPath) +
                        "\n\nThis does not install a new service, change Windows DNS adapters, or enable the still-gated machine-wide Data Saving Firewall layer.",
                        "Turn On QuietShield Protection",
                        MessageBoxButton.YesNo,
                        MessageBoxImage.Information,
                        MessageBoxResult.Yes);

                if (startAnswer != MessageBoxResult.Yes)
                {
                    ConsumerLastAction =
                        "Turn On cancelled.";
                    return;
                }

                ConsumerProtectionHeadline =
                    "Starting Protection Service";
                ConsumerProtectionStateLabel =
                    "STARTING";
                ConsumerProtectionDetail =
                    "Waiting for Windows authorization and the Windows service state.";

                await QuietShield.App.Runtime.ProtectionServiceControlR34.RunElevatedAsync(
                        "start",
                        CancellationToken.None)
                    .ConfigureAwait(true);

                await RefreshConsumerProtectionStateAsync(
                        CancellationToken.None)
                    .ConfigureAwait(true);

                ConsumerLastAction =
                    ConsumerProtectionIsOn
                        ? ConsumerProtectionStateLabel == "ON"
                            ? "QuietShield Protection Service is running and Service IPC is connected."
                            : "QuietShieldService is running, but Service IPC still needs attention."
                        : "QuietShieldService did not reach Running. Review the master-control diagnostic log.";

                return;
            }

            // The user clicked Turn Off. If another event already stopped
            // the service, just refresh; never reverse into a start request.
            if (!ConsumerProtectionIsOn)
            {
                ConsumerLastAction =
                    "QuietShield Protection is already stopped. No UAC request was needed.";
                return;
            }

            var answer =
                MessageBox.Show(
                    "Turn off the QuietShield Protection Service?\n\n" +
                    "Existing Program Connection Lock Firewall rules are persistent and remain exactly as configured until you change those app rules.\n\n" +
                    "Windows DNS adapter activation and machine-wide Data Saving enforcement remain safety-gated.",
                    "Turn Off QuietShield Protection",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning,
                    MessageBoxResult.No);

            if (answer != MessageBoxResult.Yes)
            {
                ConsumerLastAction =
                    "Turn Off cancelled.";
                return;
            }

            ConsumerProtectionHeadline =
                "Stopping Protection Service";
            ConsumerProtectionStateLabel =
                "STOPPING";
            ConsumerProtectionDetail =
                "Waiting for Windows authorization to stop QuietShieldService.";

            await QuietShield.App.Runtime.ProtectionServiceControlR34.RunElevatedAsync(
                    "stop",
                    CancellationToken.None)
                .ConfigureAwait(true);

            await RefreshConsumerProtectionStateAsync(
                    CancellationToken.None)
                .ConfigureAwait(true);

            ConsumerLastAction =
                ConsumerProtectionIsOn
                    ? "QuietShieldService is still running. Review the master-control diagnostic log."
                    : "QuietShieldService is stopped. Existing persistent app rules were not silently changed.";
        }
        catch (Win32Exception exception) when (exception.NativeErrorCode == 1223)
        {
            ConsumerLastAction =
                "Windows authorization was cancelled.";

            await RefreshConsumerProtectionStateAsync(
                    CancellationToken.None)
                .ConfigureAwait(true);
        }
        catch (Exception exception)
        {
            ConsumerLastAction =
                exception.Message;

            await RefreshConsumerProtectionStateAsync(
                    CancellationToken.None)
                .ConfigureAwait(true);

            MessageBox.Show(
                exception.Message,
                "QuietShield Protection",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }
        finally
        {
            ConsumerProtectionBusy = false;
        }
    }


    private static Task<int> RunElevatedServiceControlAsync(
        string action) =>
        QuietShield.App.Runtime.ProtectionServiceControlR34.RunElevatedAsync(
            action,
            CancellationToken.None);

    private void LoadConsumerSettings()
    {
        try
        {
            if (!File.Exists(ConsumerSettingsPath))
            {
                return;
            }

            var json = File.ReadAllText(ConsumerSettingsPath);
            var settings = JsonSerializer.Deserialize<ConsumerSettings>(
                json,
                ConsumerJsonOptions);

            if (settings is null)
            {
                return;
            }

            _quickDataSaving = settings.QuickDataSaving;
            _quickPrivateBrowser = settings.QuickPrivateBrowser;
            _quickFileSafety = settings.QuickFileSafety;
            _quickActivity = settings.QuickActivity;
            _quickDns = settings.QuickDns;
            _quickSettings = settings.QuickSettings;

            OnPropertyChanged(nameof(QuickDataSaving));
            OnPropertyChanged(nameof(QuickPrivateBrowser));
            OnPropertyChanged(nameof(QuickFileSafety));
            OnPropertyChanged(nameof(QuickActivity));
            OnPropertyChanged(nameof(QuickDns));
            OnPropertyChanged(nameof(QuickSettings));
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
        catch (JsonException)
        {
        }
    }

    private void SaveConsumerSettings()
    {
        try
        {
            Directory.CreateDirectory(ConsumerRoot);

            var settings = new ConsumerSettings(
                QuickDataSaving,
                QuickPrivateBrowser,
                QuickFileSafety,
                QuickActivity,
                QuickDns,
                QuickSettings);

            File.WriteAllText(
                ConsumerSettingsPath,
                JsonSerializer.Serialize(settings, ConsumerJsonOptions));
        }
        catch (IOException exception)
        {
            ConsumerLastAction = "Settings could not be saved: " + exception.Message;
        }
        catch (UnauthorizedAccessException exception)
        {
            ConsumerLastAction = "Settings could not be saved: " + exception.Message;
        }
    }

    private async Task CreateConsumerBackupAsync()
    {
        await Task.Yield();

        var dialog = new SaveFileDialog
        {
            Title = "Create QuietShield backup file",
            Filter = "QuietShield backup (*.zip)|*.zip",
            FileName = "QuietShield-backup-" +
                DateTime.Now.ToString("yyyyMMdd-HHmm", CultureInfo.InvariantCulture) +
                ".zip",
            AddExtension = true,
            DefaultExt = ".zip"
        };

        if (dialog.ShowDialog() != true)
        {
            return;
        }

        var tempRoot = Path.Combine(
            Path.GetTempPath(),
            "QuietShieldBackup-" + Guid.NewGuid().ToString("N"));

        try
        {
            Directory.CreateDirectory(tempRoot);

            CopyIfExists(
                ConsumerSettingsPath,
                Path.Combine(tempRoot, "Consumer", "settings.json"));

            var operatingMode = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "QuietShield",
                "Modes",
                "operating-mode.json");

            CopyIfExists(
                operatingMode,
                Path.Combine(tempRoot, "Modes", "operating-mode.json"));

            var manifest = new
            {
                Product = "QuietShield Windows",
                CreatedAtLocal = DateTimeOffset.Now,
                Contents = new[]
                {
                    "Consumer quick-action preferences",
                    "Operating mode/profile preference"
                },
                Excluded = new[]
                {
                    "Licensing secrets",
                    "Diagnostics",
                    "Authentication material",
                    "Windows service state",
                    "Firewall rules"
                }
            };

            File.WriteAllText(
                Path.Combine(tempRoot, "backup-info.json"),
                JsonSerializer.Serialize(manifest, ConsumerJsonOptions));

            if (File.Exists(dialog.FileName))
            {
                File.Delete(dialog.FileName);
            }

            ZipFile.CreateFromDirectory(
                tempRoot,
                dialog.FileName,
                CompressionLevel.Optimal,
                includeBaseDirectory: false);

            ConsumerLastAction = "Backup file created.";
        }
        finally
        {
            TryDeleteDirectory(tempRoot);
        }
    }

    private async Task RestoreConsumerBackupAsync()
    {
        await Task.Yield();

        var dialog = new OpenFileDialog
        {
            Title = "Restore QuietShield backup",
            Filter = "QuietShield backup (*.zip)|*.zip",
            CheckFileExists = true,
            Multiselect = false
        };

        if (dialog.ShowDialog() != true)
        {
            return;
        }

        var answer = MessageBox.Show(
            "Restore the saved QuietShield consumer preferences and operating mode?\n\n" +
            "Protection credentials, service state, Firewall rules and licensing information are not restored.",
            "Restore QuietShield Backup",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question,
            MessageBoxResult.No);

        if (answer != MessageBoxResult.Yes)
        {
            return;
        }

        var tempRoot = Path.Combine(
            Path.GetTempPath(),
            "QuietShieldRestore-" + Guid.NewGuid().ToString("N"));

        try
        {
            ZipFile.ExtractToDirectory(
                dialog.FileName,
                tempRoot,
                overwriteFiles: true);

            RestoreIfSafe(
                Path.Combine(tempRoot, "Consumer", "settings.json"),
                ConsumerSettingsPath);

            var operatingModeDestination = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "QuietShield",
                "Modes",
                "operating-mode.json");

            RestoreIfSafe(
                Path.Combine(tempRoot, "Modes", "operating-mode.json"),
                operatingModeDestination);

            LoadConsumerSettings();
            ConsumerLastAction =
                "Backup restored. Restart QuietShield to reload the operating-mode file.";
        }
        finally
        {
            TryDeleteDirectory(tempRoot);
        }
    }

    private static void CopyIfExists(string source, string destination)
    {
        if (!File.Exists(source))
        {
            return;
        }

        var directory = Path.GetDirectoryName(destination);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        File.Copy(source, destination, overwrite: true);
    }

    private static void RestoreIfSafe(string source, string destination)
    {
        if (!File.Exists(source))
        {
            return;
        }

        var file = new FileInfo(source);
        if (file.Length > 2 * 1024 * 1024)
        {
            throw new InvalidDataException(
                "Backup file entry exceeds the QuietShield safe restore limit.");
        }

        var directory = Path.GetDirectoryName(destination);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        File.Copy(source, destination, overwrite: true);
    }

    private static void TryDeleteDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private sealed record ConsumerSettings(
        bool QuickDataSaving = true,
        bool QuickPrivateBrowser = true,
        bool QuickFileSafety = true,
        bool QuickActivity = true,
        bool QuickDns = false,
        bool QuickSettings = false);
}
