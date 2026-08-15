namespace QuietShield.Architecture.Tests;

[TestClass]
public sealed class ServiceIpcStartupR429Tests
{
    private static readonly string RepositoryRoot = FindRepositoryRoot();

    [TestMethod]
    public void PipeFactoryCreationIsInsideTheGuardedRecoveryBlock()
    {
        var path = Path.Combine(RepositoryRoot, "src", "QuietShield.Core", "ServiceFoundation", "NamedPipeIpc.cs");
        var source = File.ReadAllText(path);
        var method = source.IndexOf("public async Task RunAsync(CancellationToken cancellationToken)", StringComparison.Ordinal);
        var tryIndex = source.IndexOf("try", method, StringComparison.Ordinal);
        var factory = source.IndexOf("await using var server = _serverFactory();", method, StringComparison.Ordinal);
        Assert.IsTrue(method >= 0 && tryIndex > method && factory > tryIndex, "Pipe creation must occur inside the guarded recovery block.");
    }

    [TestMethod]
    public void ProductionPipeDoesNotRequestChangePermissionsHandleRight()
    {
        var path = Path.Combine(RepositoryRoot, "src", "QuietShield.Service", "ServiceNamedPipeFactory.cs");
        var source = File.ReadAllText(path);
        Assert.IsFalse(source.Contains("PipeAccessRights.ChangePermissions", StringComparison.Ordinal), "Production IPC must not request ChangePermissions as an additional handle right.");
        Assert.IsTrue(source.Contains("R4.2.9 least-privilege pipe handle", StringComparison.Ordinal));
    }

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "QuietShield.sln"))) return directory.FullName;
            directory = directory.Parent;
        }
        throw new DirectoryNotFoundException("QuietShield repository root was not found.");
    }
}
