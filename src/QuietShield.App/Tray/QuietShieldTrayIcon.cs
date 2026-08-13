using System.Runtime.InteropServices;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Interop;
using QuietShield.App.ViewModels;

namespace QuietShield.App.Tray;

public sealed class QuietShieldTrayIcon : IDisposable
{
    private const int TrayCallbackMessage = 0x8001;
    private const int WmLeftButtonUp = 0x0202;
    private const int WmRightButtonUp = 0x0205;
    private const uint NotifyIconId = 1;
    private const uint NotifyIconAdd = 0x00000000;
    private const uint NotifyIconModify = 0x00000001;
    private const uint NotifyIconDelete = 0x00000002;
    private const uint NotifyIconMessage = 0x00000001;
    private const uint NotifyIconIcon = 0x00000002;
    private const uint NotifyIconTip = 0x00000004;
    private static readonly IntPtr ApplicationIconResource = new(32512);

    private MainWindow? _window;
    private MainViewModel? _viewModel;
    private Action? _requestExit;
    private HwndSource? _source;
    private ContextMenu? _contextMenu;
    private MenuItem? _openItem;
    private MenuItem? _dataSavingItem;
    private MenuItem? _wiFiItem;
    private MenuItem? _exitItem;
    private NotifyIconData _notifyData;
    private bool _iconAdded;

    public void Initialize(
        MainWindow window,
        MainViewModel viewModel,
        Action requestExit)
    {
        ArgumentNullException.ThrowIfNull(window);
        ArgumentNullException.ThrowIfNull(viewModel);
        ArgumentNullException.ThrowIfNull(requestExit);

        if (_iconAdded)
        {
            return;
        }

        _window = window;
        _viewModel = viewModel;
        _requestExit = requestExit;

        var handle = new WindowInteropHelper(window).Handle;
        if (handle == IntPtr.Zero)
        {
            throw new InvalidOperationException(
                "QuietShield could not obtain its WPF window handle for the tray icon.");
        }

        _source = HwndSource.FromHwnd(handle) ??
            throw new InvalidOperationException(
                "QuietShield could not attach its tray callback to the WPF window.");

        _source.AddHook(WindowProcedure);
        BuildContextMenu();

        var icon = LoadIcon(IntPtr.Zero, ApplicationIconResource);
        if (icon == IntPtr.Zero)
        {
            throw new InvalidOperationException(
                "Windows did not provide the default application icon for the QuietShield tray.");
        }

        _notifyData = new NotifyIconData
        {
            Size = (uint)Marshal.SizeOf<NotifyIconData>(),
            WindowHandle = handle,
            Id = NotifyIconId,
            Flags = NotifyIconMessage | NotifyIconIcon | NotifyIconTip,
            CallbackMessage = TrayCallbackMessage,
            IconHandle = icon,
            ToolTip = "QuietShield Windows",
            Info = string.Empty,
            InfoTitle = string.Empty
        };

        if (!ShellNotifyIcon(NotifyIconAdd, ref _notifyData))
        {
            _source.RemoveHook(WindowProcedure);
            _source = null;
            throw new InvalidOperationException(
                "Windows rejected the QuietShield notification-area icon.");
        }

        _iconAdded = true;
        _viewModel.PropertyChanged += OnViewModelPropertyChanged;
        UpdateModePresentation();
    }

    public void Dispose()
    {
        if (_viewModel is not null)
        {
            _viewModel.PropertyChanged -= OnViewModelPropertyChanged;
        }

        if (_iconAdded)
        {
            _ = ShellNotifyIcon(NotifyIconDelete, ref _notifyData);
            _iconAdded = false;
        }

        if (_source is not null)
        {
            _source.RemoveHook(WindowProcedure);
            _source = null;
        }

        if (_openItem is not null)
        {
            _openItem.Click -= OnOpenClick;
        }

        if (_dataSavingItem is not null)
        {
            _dataSavingItem.Click -= OnDataSavingClick;
        }

        if (_wiFiItem is not null)
        {
            _wiFiItem.Click -= OnWiFiClick;
        }

        if (_exitItem is not null)
        {
            _exitItem.Click -= OnExitClick;
        }

        if (_contextMenu is not null)
        {
            _contextMenu.IsOpen = false;
        }

        _contextMenu = null;
        _openItem = null;
        _dataSavingItem = null;
        _wiFiItem = null;
        _exitItem = null;
        _window = null;
        _viewModel = null;
        _requestExit = null;

        GC.SuppressFinalize(this);
    }

    private void BuildContextMenu()
    {
        _openItem = new MenuItem { Header = "Open QuietShield" };
        _dataSavingItem = new MenuItem
        {
            Header = "Data Saving Mode",
            IsCheckable = true
        };
        _wiFiItem = new MenuItem
        {
            Header = "Wi-Fi Mode",
            IsCheckable = true
        };
        _exitItem = new MenuItem { Header = "Exit QuietShield" };

        _openItem.Click += OnOpenClick;
        _dataSavingItem.Click += OnDataSavingClick;
        _wiFiItem.Click += OnWiFiClick;
        _exitItem.Click += OnExitClick;

        _contextMenu = new ContextMenu
        {
            Placement = PlacementMode.MousePoint
        };

        _contextMenu.Items.Add(_openItem);
        _contextMenu.Items.Add(new Separator());
        _contextMenu.Items.Add(_dataSavingItem);
        _contextMenu.Items.Add(_wiFiItem);
        _contextMenu.Items.Add(new Separator());
        _contextMenu.Items.Add(_exitItem);
    }

    private IntPtr WindowProcedure(
        IntPtr window,
        int message,
        IntPtr wParam,
        IntPtr lParam,
        ref bool handled)
    {
        if (message != TrayCallbackMessage)
        {
            return IntPtr.Zero;
        }

        var trayMessage = unchecked((int)lParam.ToInt64());

        switch (trayMessage)
        {
            case WmLeftButtonUp:
                _window?.ShowFromTray();
                handled = true;
                break;

            case WmRightButtonUp:
                if (_contextMenu is not null)
                {
                    _contextMenu.IsOpen = true;
                }

                handled = true;
                break;
        }

        return IntPtr.Zero;
    }

    private void OnOpenClick(object sender, System.Windows.RoutedEventArgs args) =>
        _window?.ShowFromTray();

    private void OnDataSavingClick(object sender, System.Windows.RoutedEventArgs args) =>
        _viewModel?.UseDataSavingModeCommand.Execute(null);

    private void OnWiFiClick(object sender, System.Windows.RoutedEventArgs args) =>
        _viewModel?.UseWiFiModeCommand.Execute(null);

    private void OnExitClick(object sender, System.Windows.RoutedEventArgs args) =>
        _requestExit?.Invoke();

    private void OnViewModelPropertyChanged(
        object? sender,
        System.ComponentModel.PropertyChangedEventArgs args)
    {
        if (string.Equals(
                args.PropertyName,
                nameof(MainViewModel.OperatingModeDisplay),
                StringComparison.Ordinal) ||
            string.Equals(
                args.PropertyName,
                nameof(MainViewModel.OperatingMode),
                StringComparison.Ordinal))
        {
            UpdateModePresentation();
        }
    }

    private void UpdateModePresentation()
    {
        if (_viewModel is null)
        {
            return;
        }

        if (_dataSavingItem is not null)
        {
            _dataSavingItem.IsChecked = _viewModel.IsDataSavingModeActive;
        }

        if (_wiFiItem is not null)
        {
            _wiFiItem.IsChecked = _viewModel.IsWiFiModeActive;
        }

        if (!_iconAdded)
        {
            return;
        }

        _notifyData.ToolTip = _viewModel.IsDataSavingModeActive
            ? "QuietShield - Data Saving"
            : "QuietShield - Wi-Fi Mode";

        _ = ShellNotifyIcon(NotifyIconModify, ref _notifyData);
    }

#pragma warning disable SYSLIB1054
    [DllImport("shell32.dll", EntryPoint = "Shell_NotifyIconW", CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ShellNotifyIcon(
        uint message,
        ref NotifyIconData data);

    [DllImport("user32.dll", EntryPoint = "LoadIconW", CharSet = CharSet.Unicode)]
    private static extern IntPtr LoadIcon(
        IntPtr instance,
        IntPtr iconName);
#pragma warning restore SYSLIB1054

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NotifyIconData
    {
        public uint Size;
        public IntPtr WindowHandle;
        public uint Id;
        public uint Flags;
        public uint CallbackMessage;
        public IntPtr IconHandle;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string ToolTip;

        public uint State;
        public uint StateMask;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string Info;

        public uint TimeoutOrVersion;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string InfoTitle;

        public uint InfoFlags;
        public Guid ItemGuid;
        public IntPtr BalloonIconHandle;
    }
}
