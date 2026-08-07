namespace QuietShield.Architecture.Tests;

[TestClass]
public sealed class Phase10BTransactionTimeoutSafetyTests
{
    private static readonly string RepositoryRoot = FindRepositoryRoot();

    [TestMethod]
    public void RealServiceAndControlRequestsGetTransactionBudgetWhileDiagnosticsStayFast()
    {
        var source = File.ReadAllText(Path.Combine(
            RepositoryRoot,
            "src",
            "QuietShield.Service",
            "DiagnosticServiceOptions.cs"));

        Assert.Contains(
            "serviceMode || controlRequest is not null",
            source);

        Assert.Contains(
            "TimeSpan.FromSeconds(150)",
            source);

        Assert.Contains(
            "TimeSpan.FromSeconds(5)",
            source);

        Assert.Contains(
            "TimeSpan.FromSeconds(durationSeconds), requestTimeout, activation",
            source);
    }

    [TestMethod]
    public void PerRequestCancellationDoesNotTerminateServiceIpcListener()
    {
        var source = File.ReadAllText(Path.Combine(
            RepositoryRoot,
            "src",
            "QuietShield.Core",
            "ServiceFoundation",
            "NamedPipeIpc.cs"));

        var serviceStopCatch = source.IndexOf(
            "catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)",
            StringComparison.Ordinal);

        var recoverableTimeoutCatch = source.IndexOf(
            "catch (OperationCanceledException)",
            serviceStopCatch + 1,
            StringComparison.Ordinal);

        Assert.IsGreaterThanOrEqualTo(0, serviceStopCatch);
        Assert.IsGreaterThan(serviceStopCatch, recoverableTimeoutCatch);

        Assert.Contains(
            "Keep the service IPC listener",
            source);
    }

    [TestMethod]
    public void FirewallBackendTimeoutKillsOnlyItsExactChildProcessTree()
    {
        var source = File.ReadAllText(Path.Combine(
            RepositoryRoot,
            "src",
            "QuietShield.Service",
            "PowerShellPersistentFirewallBackend.cs"));

        Assert.Contains(
            "WaitForExit(30_000)",
            source);

        Assert.Contains(
            "process.Kill(entireProcessTree: true)",
            source);
    }

    [TestMethod]
    public void FirewallBackendTimeoutBecomesControlledServiceResponse()
    {
        var source = File.ReadAllText(Path.Combine(
            RepositoryRoot,
            "src",
            "QuietShield.Service",
            "DiagnosticServiceRequestHandler.cs"));

        Assert.Contains(
            "or TimeoutException",
            source);
    }

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "QuietShield.sln")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new InvalidOperationException(
            "QuietShield repository root could not be located.");
    }
}