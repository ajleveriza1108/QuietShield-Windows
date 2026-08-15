// QuietShield Backend Integration 11 R1
using System.Windows;
using System.Windows.Threading;

namespace QuietShield.Tray;

public partial class App : Application, IDisposable
{
    private TrayHost? _tray;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        _tray = new TrayHost();
        _tray.Initialize();

        if (e.Args.Contains("--smoke", StringComparer.OrdinalIgnoreCase))
        {
            var timer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(2)
            };

            timer.Tick += (_, _) =>
            {
                timer.Stop();
                Shutdown();
            };

            timer.Start();
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        Dispose();
        base.OnExit(e);
    }

    public void Dispose()
    {
        _tray?.Dispose();
        _tray = null;
        GC.SuppressFinalize(this);
    }
}
