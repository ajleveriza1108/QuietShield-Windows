namespace QuietShield.Architecture.Tests;

[TestClass]
public sealed class BackendRuntimeSelfTestBudgetR423Tests
{
    private static readonly string RepositoryRoot = FindRepositoryRoot();

    [TestMethod]
    public void ProductionLiveDnsSelfTestUsesIndependentParallelBoundedProbes()
    {
        var source = File.ReadAllText(Path.Combine(
            RepositoryRoot,
            "src",
            "QuietShield.Service",
            "ProductionBackendRuntimeR40.cs"));

        StringAssert.Contains(source, "R4.2.3 bounded live DNS self-test budget");
        StringAssert.Contains(source, "Task.WhenAll(probeTasks)");
        StringAssert.Contains(source, "TimeSpan.FromSeconds(3)");
        StringAssert.Contains(source, "CancellationToken.None");
        StringAssert.Contains(source, "failures.Select");
    }

    [TestMethod]
    public void BackendAcceptanceProvidesExpandedDiagnosticIpcBudget()
    {
        var source = File.ReadAllText(Path.Combine(
            RepositoryRoot,
            "src",
            "QuietShield.BackendAcceptance",
            "Program.cs"));

        StringAssert.Contains(source, "R4.2.3 diagnostic IPC budget");
        StringAssert.Contains(source, "TimeSpan.FromSeconds(60)");
    }

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "QuietShield.sln")))
                return directory.FullName;
            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("QuietShield repository root was not found.");
    }
}
