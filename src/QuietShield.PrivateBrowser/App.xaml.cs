// QuietShield Backend Integration 07 R1
using System.Windows;

namespace QuietShield.PrivateBrowser;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var smoke = e.Args.Contains("--smoke", StringComparer.OrdinalIgnoreCase);
        var incognito = e.Args.Contains("--incognito", StringComparer.OrdinalIgnoreCase);
        var window = new MainWindow(smoke, incognito);
        MainWindow = window;
        window.Show();
    }
}
