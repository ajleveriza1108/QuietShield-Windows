using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using QuietShield.App.Controls;
using QuietShield.App.ViewModels;
using QuietShield.App.Windowing;
using QuietShield.Core.Presentation;

namespace QuietShield.App;

public partial class MainWindow : Window
{
    private const int WmPowerBroadcast = 0x0218;
    private const int PbtApmResumeAutomatic = 0x0012;
    private readonly MainViewModel _viewModel;
    private readonly IWindowPlacementStore _placementStore;
    private readonly IDisplayWorkAreaProvider _workAreas;
    private HwndSource? _source;
    private bool _userRequestedCompactNavigation;

    internal bool CloseToTrayEnabled { get; set; }

    public MainWindow(
        MainViewModel viewModel,
        IWindowPlacementStore placementStore,
        IDisplayWorkAreaProvider workAreas)
    {
        _viewModel = viewModel;
        _placementStore = placementStore;
        _workAreas = workAreas;
        InitializeComponent();
        DataContext = viewModel;
        SourceInitialized += OnSourceInitialized;
        SizeChanged += OnSizeChanged;
        Closing += OnClosing;
        Closed += OnClosed;
        ApplyResponsiveLayout();
    }

    internal ResponsivePageShell ResponsivePage => PageShell;
    internal FrameworkElement NavigationArea => NavigationPane;
    internal FrameworkElement PageArea => PageShell;
    internal Panel LayoutRoot => RootLayout;

    internal void ApplyValidationSize(double width, double height)
    {
        WindowState = WindowState.Normal;
        Width = Math.Max(MinWidth, width);
        Height = Math.Max(MinHeight, height);
        ApplyResponsiveLayout();
        UpdateLayout();
    }

    private void OnNavigationToggleClick(object sender, RoutedEventArgs args) =>
        ToggleNavigation();

    private void OnBrandMouseLeftButtonUp(object sender, MouseButtonEventArgs args)
    {
        if (args.ChangedButton == MouseButton.Left)
        {
            ToggleNavigation();
        }
    }

    private void OnWindowPreviewKeyDown(object sender, KeyEventArgs args)
    {
        if (args.Key == Key.B && Keyboard.Modifiers.HasFlag(ModifierKeys.Control))
        {
            ToggleNavigation();
            args.Handled = true;
        }
    }

    private void ToggleNavigation()
    {
        _userRequestedCompactNavigation = !_userRequestedCompactNavigation;
        ApplyResponsiveLayout();
    }

    private void OnTitleBarMouseLeftButtonDown(object sender, MouseButtonEventArgs args)
    {
        if (args.ChangedButton != MouseButton.Left)
        {
            return;
        }

        if (args.ClickCount == 2)
        {
            ToggleMaximizeRestore();
            return;
        }

        if (args.ButtonState == MouseButtonState.Pressed)
        {
            DragMove();
        }
    }

    private void OnMinimizeClick(object sender, RoutedEventArgs args) =>
        WindowState = WindowState.Minimized;

    private void OnMaximizeRestoreClick(object sender, RoutedEventArgs args) =>
        ToggleMaximizeRestore();

    private void OnCloseClick(object sender, RoutedEventArgs args) =>
        Close();

    private void ToggleMaximizeRestore() =>
        WindowState = WindowState == WindowState.Maximized
            ? WindowState.Normal
            : WindowState.Maximized;

    private void OnSizeChanged(object sender, SizeChangedEventArgs args) =>
        ApplyResponsiveLayout();

    private void ApplyResponsiveLayout()
    {
        if (!IsInitialized)
        {
            return;
        }

        var width = ActualWidth > 0d ? ActualWidth : Width;

        if (_userRequestedCompactNavigation)
        {
            NavigationColumn.Width = new GridLength(64d);
            _viewModel.IsNavigationCompact = true;
        }
        else
        {
            var mode = ResponsiveLayout.GetNavigationMode(width, false);
            NavigationColumn.Width = new GridLength(ResponsiveLayout.GetNavigationWidth(mode));
            _viewModel.IsNavigationCompact = mode == NavigationDisplayMode.Compact;
        }

        var padding = ResponsiveLayout.GetPagePadding(width);
        var compactPadding = Math.Max(12d, Math.Min(padding, 18d));
        PageShell.Margin = new Thickness(compactPadding, 6d, compactPadding, 14d);
    }

    private void OnSourceInitialized(object? sender, EventArgs args)
    {
        _source = HwndSource.FromHwnd(new WindowInteropHelper(this).Handle);
        _source?.AddHook(WindowProcedure);
        WindowPlacementCoordinator.Restore(this, _placementStore, _workAreas);
        ApplyResponsiveLayout();
    }

    private void OnClosing(object? sender, CancelEventArgs args)
    {
        WindowPlacementCoordinator.Save(this, _placementStore);

        if (!CloseToTrayEnabled)
        {
            return;
        }

        args.Cancel = true;
        ShowInTaskbar = false;
        Hide();
    }

    internal void ShowFromTray()
    {
        ShowInTaskbar = true;
        Show();

        if (WindowState == WindowState.Minimized)
        {
            WindowState = WindowState.Normal;
        }

        Activate();
    }

    private void OnClosed(object? sender, EventArgs args)
    {
        _source?.RemoveHook(WindowProcedure);
        _source = null;
    }

    private IntPtr WindowProcedure(
        IntPtr window,
        int message,
        IntPtr wParam,
        IntPtr lParam,
        ref bool handled)
    {
        if (message == WmPowerBroadcast && wParam.ToInt32() == PbtApmResumeAutomatic)
        {
            _ = _viewModel.RefreshAfterResumeAsync();
        }

        return IntPtr.Zero;
    }
}
