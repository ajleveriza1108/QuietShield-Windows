using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using QuietShield.Core.ConnectionLock;
using QuietShield.Core.ConnectionLock.Transactions;
using QuietShield.Core.ServiceFoundation;
using QuietShield.Service;

namespace QuietShield.Windows.Tests;

[TestClass]
public sealed class Phase10AServiceAndIpcTests
{
    [TestMethod]
    public async Task ServiceRuntimeStartsHeartbeatsAndStopsCleanly()
    {
        using var directory = new TemporaryDirectory();
        var runtime = CreateRuntime(directory.Path);
        await runtime.StartAsync(CancellationToken.None);
        Assert.AreEqual("HealthyDiagnostic", runtime.GetHealth().State);
        await runtime.RecordHeartbeatAsync(CancellationToken.None);
        Assert.AreEqual(1L, runtime.GetHealth().HeartbeatSequence);
        await runtime.StopAsync(CancellationToken.None);
        Assert.AreEqual("Stopped", runtime.GetHealth().State);
        var state = await new AtomicJsonStateStore<PersistentServiceState>(1).ReadValidatedAsync(runtime.StatePath, CancellationToken.None);
        Assert.AreEqual("Clean", state.Health.LastShutdown);
    }

    [TestMethod]
    public async Task InvalidPersistentStateDisablesAutomaticEnforcement()
    {
        using var directory = new TemporaryDirectory();
        await File.WriteAllTextAsync(Path.Combine(directory.Path, "service-state.json"), "corrupt");
        await File.WriteAllTextAsync(Path.Combine(directory.Path, "last-known-good-state.json"), "also-corrupt");
        var runtime = CreateRuntime(directory.Path);
        await runtime.StartAsync(CancellationToken.None);
        Assert.AreEqual("InvalidState", runtime.GetHealth().State);
        Assert.IsFalse(runtime.GetHealth().StateIntegrityValid);
        Assert.AreEqual("Not active", runtime.GetStatus().PersistentEnforcementStatus);
    }

    [TestMethod]
    public async Task InterruptedCheckpointProducesRecoveryRequiredWithoutApplying()
    {
        using var directory = new TemporaryDirectory();
        var state = CreateState(new(Guid.NewGuid(), ProgramLockTransactionState.ApplyStarted, DateTimeOffset.UtcNow, true, "Interrupted test transaction."));
        var store = new AtomicJsonStateStore<PersistentServiceState>(1);
        await store.SaveAsync(Path.Combine(directory.Path, "service-state.json"), state, CancellationToken.None);
        await store.SaveAsync(Path.Combine(directory.Path, "last-known-good-state.json"), state, CancellationToken.None);
        var runtime = CreateRuntime(directory.Path);
        await runtime.StartAsync(CancellationToken.None);
        Assert.AreEqual("RecoveryRequired", runtime.GetHealth().State);
        Assert.IsTrue(runtime.GetHealth().InterruptedTransactionDetected);
        Assert.AreEqual("Not active", runtime.GetStatus().PersistentEnforcementStatus);
    }

    [TestMethod]
    public async Task NamedPipeSupportsPingStatusPreviewReconnectAndModifyingRefusal()
    {
        using var fixture = await ServerFixture.StartAsync();
        var client = new NamedPipeQuietShieldServiceClient(fixture.PipeName, TimeSpan.FromSeconds(3));
        Assert.AreEqual(ServiceResponseStatus.Ok, (await client.SendAsync(ServiceMessageKind.Ping, null, CancellationToken.None)).Status);
        Assert.AreEqual(ServiceResponseStatus.Ok, (await client.SendAsync(ServiceMessageKind.GetServiceStatus, null, CancellationToken.None)).Status);
        Assert.AreEqual(ServiceResponseStatus.Ok, (await client.SendAsync(ServiceMessageKind.PreviewPolicyPlan,
            new PolicyPreviewRequest(Core.Protection.ProgramConnectionPolicy.Blocked), CancellationToken.None)).Status);
        foreach (var kind in new[] { ServiceMessageKind.RequestProfileActivation, ServiceMessageKind.RequestProgramRuleChange,
                     ServiceMessageKind.RequestTemporaryAllowance, ServiceMessageKind.RequestRollback })
        {
            var response = await client.SendAsync(kind, new { test = true }, CancellationToken.None);
            Assert.AreEqual(ServiceResponseStatus.NotActive, response.Status);
            Assert.AreEqual(QuietShieldServiceProtocol.NotActiveMessage, response.Message);
        }
    }

    [TestMethod]
    public async Task NamedPipeRejectsMalformedJsonAndUnsupportedProtocol()
    {
        using var fixture = await ServerFixture.StartAsync();
        var malformed = await SendRawAsync(fixture.PipeName, Encoding.UTF8.GetBytes("{broken"));
        Assert.AreEqual(ServiceResponseStatus.InvalidRequest, malformed.Status);
        var request = new ServiceRequest(999, Guid.NewGuid(), ServiceMessageKind.Ping, ServiceMessageSerializer.EmptyPayload);
        var unsupported = await SendRawAsync(fixture.PipeName, JsonSerializer.SerializeToUtf8Bytes(request, ServiceMessageSerializer.Options));
        Assert.AreEqual(ServiceResponseStatus.UnsupportedProtocol, unsupported.Status);
    }

    [TestMethod]
    public async Task NamedPipeRejectsOversizedFrameBeforeReadingPayload()
    {
        using var fixture = await ServerFixture.StartAsync();
        await using var client = new NamedPipeClientStream(".", fixture.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        await client.ConnectAsync(3000);
        await client.WriteAsync(BitConverter.GetBytes(QuietShieldServiceProtocol.MaximumMessageBytes + 1));
        await client.FlushAsync();
        var response = JsonSerializer.Deserialize<ServiceResponse>(await BoundedMessageFrame.ReadAsync(client, CancellationToken.None), ServiceMessageSerializer.Options);
        Assert.IsNotNull(response);
        Assert.AreEqual(ServiceResponseStatus.InvalidRequest, response.Status);
    }

    [TestMethod]
    public async Task NamedPipeConnectionHonorsBoundedTimeoutAndCancellation()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(150));
        var client = new NamedPipeQuietShieldServiceClient("QuietShield.Missing." + Guid.NewGuid().ToString("N"), TimeSpan.FromMilliseconds(150));
        try
        {
            await client.SendAsync(ServiceMessageKind.Ping, null, cancellation.Token);
            Assert.Fail("A missing local pipe unexpectedly connected.");
        }
        catch (Exception exception) when (exception is OperationCanceledException or TimeoutException)
        {
            Assert.IsTrue(cancellation.IsCancellationRequested || exception is TimeoutException);
        }
    }

    [TestMethod]
    public async Task ServerCancellationEndsCleanlyWithoutAClient()
    {
        var handler = new StubHandler();
        var server = new NamedPipeQuietShieldServer("QuietShield.Cancel." + Guid.NewGuid().ToString("N"), handler);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        await server.RunAsync(cancellation.Token);
        Assert.IsTrue(cancellation.IsCancellationRequested);
    }

    private static async Task<ServiceResponse> SendRawAsync(string pipeName, byte[] bytes)
    {
        await using var client = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        await client.ConnectAsync(3000);
        await BoundedMessageFrame.WriteAsync(client, bytes, CancellationToken.None);
        return JsonSerializer.Deserialize<ServiceResponse>(await BoundedMessageFrame.ReadAsync(client, CancellationToken.None), ServiceMessageSerializer.Options)!;
    }

    private static PersistentServiceRuntime CreateRuntime(string stateRoot) => new(
        new(true, false, false, "QuietShield.Tests." + Guid.NewGuid().ToString("N"), stateRoot, null, TimeSpan.Zero, TimeSpan.FromSeconds(2), null, null, null),
        new AtomicJsonStateStore<PersistentServiceState>(1),
        NullLogger<PersistentServiceRuntime>.Instance);

    private static PersistentServiceState CreateState(PersistentTransactionCheckpoint checkpoint) => new(
        1,
        ConnectionLockProfile.BlockAllId,
        Array.Empty<PersistentProgramPolicy>(),
        Array.Empty<ProgramTemporaryAllowance>(),
        Array.Empty<ConnectionPolicySchedule>(),
        Array.Empty<ConnectionCompatibilityExclusion>(),
        checkpoint,
        new(ConnectionLockProfile.BlockAllId, new string('A', 64), DateTimeOffset.UtcNow, true),
        new("Created", 0, null, "Clean", null));

    private sealed class StubHandler : IQuietShieldServiceRequestHandler
    {
        public Task<ServiceResponse> HandleAsync(ServiceRequest request, CancellationToken cancellationToken) => Task.FromResult(
            new ServiceResponse(1, request.RequestId, ServiceResponseStatus.Ok, "Pong", ServiceMessageSerializer.EmptyPayload));
    }

    private sealed class ServerFixture : IDisposable
    {
        private readonly CancellationTokenSource _cancellation;
        private readonly Task _serverTask;
        private readonly TemporaryDirectory _directory;
        private ServerFixture(string pipeName, CancellationTokenSource cancellation, Task serverTask, TemporaryDirectory directory)
        {
            PipeName = pipeName;
            _cancellation = cancellation;
            _serverTask = serverTask;
            _directory = directory;
        }
        public string PipeName { get; }
        public static async Task<ServerFixture> StartAsync()
        {
            var directory = new TemporaryDirectory();
            var runtime = CreateRuntime(directory.Path);
            await runtime.StartAsync(CancellationToken.None);
            var handler = new DiagnosticServiceRequestHandler(runtime,
                new ReadOnlyPersistentPolicyCoordinator(new ReadOnlyPersistentPolicyPreflight()),
                new InactiveServiceProgramPolicyCoordinator());
            var pipe = "QuietShield.Tests." + Guid.NewGuid().ToString("N");
            var cancellation = new CancellationTokenSource();
            var task = new NamedPipeQuietShieldServer(pipe, handler).RunAsync(cancellation.Token);
            return new(pipe, cancellation, task, directory);
        }
        public void Dispose()
        {
            _cancellation.Cancel();
            Assert.IsTrue(_serverTask.Wait(TimeSpan.FromSeconds(3)));
            _cancellation.Dispose();
            _directory.Dispose();
        }
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "QuietShield-Phase10A-Windows-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path);
        }
        public string Path { get; }
        public void Dispose() { if (Directory.Exists(Path)) Directory.Delete(Path, true); }
    }
}
