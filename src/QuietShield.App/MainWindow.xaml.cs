using System.Windows;
using System.Windows.Interop;
using QuietShield.App.ViewModels;

namespace QuietShield.App;

public partial class MainWindow : Window
{
    private const int WmPowerBroadcast = 0x0218;
    private const int PbtApmResumeAutomatic = 0x0012;
    private readonly MainViewModel _viewModel;
    private HwndSource? _source;

    public MainWindow(MainViewModel viewModel)
    {
        _viewModel = viewModel;
        InitializeComponent();
        DataContext = viewModel;
        SourceInitialized += OnSourceInitialized;
        Closed += OnClosed;
    }

    private void OnSourceInitialized(object? sender, EventArgs args)
    {
        _source = HwndSource.FromHwnd(new WindowInteropHelper(this).Handle);
        _source?.AddHook(WindowProcedure);
    }

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
