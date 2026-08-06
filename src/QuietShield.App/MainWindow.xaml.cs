using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
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

    private void OnNavigationToggleClick(object sender, RoutedEventArgs args)
    {
        _userRequestedCompactNavigation = !_userRequestedCompactNavigation;
        ApplyResponsiveLayout();
    }

    private void OnSizeChanged(object sender, SizeChangedEventArgs args) => ApplyResponsiveLayout();

    private void ApplyResponsiveLayout()
    {
        if (!IsInitialized) return;
        var width = ActualWidth > 0d ? ActualWidth : Width;
        var mode = ResponsiveLayout.GetNavigationMode(width, _userRequestedCompactNavigation);
        NavigationColumn.Width = new GridLength(ResponsiveLayout.GetNavigationWidth(mode));
        _viewModel.IsNavigationCompact = mode == NavigationDisplayMode.Compact;
        var padding = ResponsiveLayout.GetPagePadding(width);
        PageShell.Margin = new Thickness(padding);
    }

    private void OnSourceInitialized(object? sender, EventArgs args)
    {
        _source = HwndSource.FromHwnd(new WindowInteropHelper(this).Handle);
        _source?.AddHook(WindowProcedure);
        WindowPlacementCoordinator.Restore(this, _placementStore, _workAreas);
        ApplyResponsiveLayout();
    }

    private void OnClosing(object? sender, CancelEventArgs args) => WindowPlacementCoordinator.Save(this, _placementStore);

    private void OnClosed(object? sender, EventArgs args)
    {
        _source?.RemoveHook(WindowProcedure);
        _source = null;
    }

    private IntPtr WindowProcedure(IntPtr window, int message, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (message == WmPowerBroadcast && wParam.ToInt32() == PbtApmResumeAutomatic)
        {
            _ = _viewModel.RefreshAfterResumeAsync();
        }

        return IntPtr.Zero;
    }
}
