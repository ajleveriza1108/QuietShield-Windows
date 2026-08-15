using System.Windows.Threading;
using QuietShield.App.Runtime;

namespace QuietShield.App;

public partial class App
{
    public App()
    {
        DispatcherUnhandledException += OnRuntimeDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += OnRuntimeDomainUnhandledException;
        TaskScheduler.UnobservedTaskException += OnRuntimeUnobservedTaskException;
    }

    private static void OnRuntimeDispatcherUnhandledException(
        object sender,
        DispatcherUnhandledExceptionEventArgs args)
    {
        IntegrationRuntimeDiagnostics.WriteException(
            "DispatcherUnhandledException",
            "An unhandled WPF dispatcher exception reached the application boundary.",
            args.Exception);

        args.Handled = false;
    }

    private static void OnRuntimeDomainUnhandledException(
        object sender,
        UnhandledExceptionEventArgs args)
    {
        if (args.ExceptionObject is Exception exception)
        {
            IntegrationRuntimeDiagnostics.WriteException(
                "AppDomainUnhandledException",
                "An unhandled application-domain exception reached the process boundary.",
                exception);
        }
        else
        {
            IntegrationRuntimeDiagnostics.WriteMessage(
                "AppDomainUnhandledException",
                "A non-Exception object reached the process boundary.");
        }
    }

    private static void OnRuntimeUnobservedTaskException(
        object? sender,
        UnobservedTaskExceptionEventArgs args)
    {
        IntegrationRuntimeDiagnostics.WriteException(
            "UnobservedTaskException",
            "A task exception was not observed before finalization.",
            args.Exception);
    }
}
