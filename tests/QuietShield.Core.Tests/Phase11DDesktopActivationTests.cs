using System.Text.Json;
using QuietShield.Core.Protection;
using QuietShield.Core.ServiceFoundation;

namespace QuietShield.Core.Tests;

[TestClass]
public sealed class Phase11DDesktopActivationTests
{
    [TestMethod]
    public async Task BlockedRequestUsesExactServiceAuthorizationAndPersistsOnlyAfterCommit()
    {
        using var fixture = new WorkflowFixture();
        var configuration = await fixture.CaptureAsync(ProgramConnectionPolicy.Blocked);
        var result = await fixture.Workflow.ApplyAsync(configuration, new(true, true), CancellationToken.None);
        Assert.AreEqual(DesktopActivationState.Applied, result.State);
        Assert.AreEqual(DesktopActivationIssue.None, result.Issue);
        Assert.IsNotNull(fixture.Store.Configuration);
        Assert.AreEqual(fixture.AuthorizationId, fixture.Client.ChangeRequest?.ApprovedRehearsalId);
        Assert.AreEqual(ProgramConnectionPolicy.Blocked, fixture.Client.ChangeRequest?.Policy);
    }

    [TestMethod]
    public async Task AllowedOnAllRequestRequiresVerifiedExactRuleAbsence()
    {
        using var fixture = new WorkflowFixture(ProgramConnectionPolicy.AllowedOnAll);
        var configuration = await fixture.CaptureAsync(ProgramConnectionPolicy.AllowedOnAll);
        var result = await fixture.Workflow.ApplyAsync(configuration, new(true, true), CancellationToken.None);
        Assert.AreEqual(DesktopActivationState.Applied, result.State);
        Assert.AreEqual(ProgramConnectionPolicy.AllowedOnAll, fixture.Store.Configuration?.Policy);
        Assert.IsFalse(fixture.Client.ChangeResult.ExactRulePresent);
    }

    [TestMethod]
    public async Task ServiceUnavailableAndStoppedRemainDistinctAndNeverSendPolicy()
    {
        using var fixture = new WorkflowFixture();
        var configuration = await fixture.CaptureAsync(ProgramConnectionPolicy.Blocked);
        var unavailable = await fixture.Workflow.ApplyAsync(configuration, new(false, false), CancellationToken.None);
        var stopped = await fixture.Workflow.ApplyAsync(configuration, new(true, false), CancellationToken.None);
        Assert.AreEqual(DesktopActivationIssue.ServiceUnavailable, unavailable.Issue);
        Assert.AreEqual(DesktopActivationIssue.ServiceStopped, stopped.Issue);
        Assert.AreEqual(0, fixture.Client.RequestCount);
    }

    [TestMethod]
    public async Task IpcFailureDoesNotPersistRequestedPolicy()
    {
        using var fixture = new WorkflowFixture(throwOnStatus: true);
        var configuration = await fixture.CaptureAsync(ProgramConnectionPolicy.Blocked);
        var result = await fixture.Workflow.ApplyAsync(configuration, new(true, true), CancellationToken.None);
        Assert.AreEqual(DesktopActivationIssue.IpcFailure, result.Issue);
        Assert.IsNull(fixture.Store.Configuration);
    }

    [TestMethod]
    public async Task MissingAndChangedExecutableAreRefusedBeforeIpcMutation()
    {
        using var fixture = new WorkflowFixture();
        var missingConfiguration = await fixture.CaptureAsync(ProgramConnectionPolicy.Blocked);
        File.Delete(fixture.ExecutablePath);
        var missing = await fixture.Workflow.ApplyAsync(missingConfiguration, new(true, true), CancellationToken.None);
        Assert.AreEqual(DesktopActivationIssue.TargetExecutableMissing, missing.Issue);
        File.WriteAllBytes(fixture.ExecutablePath, [0x51, 0x53, 0x32]);
        var changedConfiguration = await fixture.CaptureAsync(ProgramConnectionPolicy.Blocked);
        File.WriteAllBytes(fixture.ExecutablePath, [0x51, 0x53, 0x33]);
        var changed = await fixture.Workflow.ApplyAsync(changedConfiguration, new(true, true), CancellationToken.None);
        Assert.AreEqual(DesktopActivationIssue.TargetHashChanged, changed.Issue);
        Assert.AreEqual(0, fixture.Client.RequestCount);
    }

    [TestMethod]
    public async Task NetworkSpecificPolicyRemainsSimulationOnly()
    {
        using var fixture = new WorkflowFixture();
        var result = await fixture.Validator.CaptureAsync(new("Target", fixture.ExecutablePath, null, false), "standard", ProgramConnectionPolicy.WiFiOnly, CancellationToken.None);
        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(DesktopActivationIssue.UnsupportedPersistentPolicy, result.Issue);
        Assert.AreEqual(0, fixture.Client.RequestCount);
    }

    [TestMethod]
    public async Task SavedPolicyReconcilesAfterDesktopRestartWithoutAutomaticApply()
    {
        using var fixture = new WorkflowFixture();
        var configuration = await fixture.CaptureAsync(ProgramConnectionPolicy.Blocked);
        fixture.Store.Configuration = configuration;
        var restarted = new DesktopProgramActivationWorkflow(fixture.Client, fixture.Store, fixture.Validator);
        var loaded = await restarted.LoadAsync(CancellationToken.None);
        var status = fixture.Status with
        {
            ProgramPolicies = [new(configuration.StableApplicationIdentity, configuration.Policy, true)],
            LastKnownGoodPolicyStatus = "Validated"
        };
        var reconciled = restarted.Reconcile(new(true, true), status, false);
        Assert.AreEqual(DesktopActivationState.Ready, loaded.State);
        Assert.AreEqual(DesktopActivationState.Applied, reconciled.State);
        Assert.AreEqual(0, fixture.Client.RequestCount);
    }

    [TestMethod]
    public async Task RecoveryStateTakesPrecedenceOverStaleDesktopConfiguration()
    {
        using var fixture = new WorkflowFixture();
        fixture.Store.Configuration = await fixture.CaptureAsync(ProgramConnectionPolicy.Blocked);
        await fixture.Workflow.LoadAsync(CancellationToken.None);
        var recovery = fixture.Workflow.Reconcile(new(true, true), fixture.Status with
        {
            TransactionStatus = "Interrupted transaction requires explicit recovery",
            RecoveryReadiness = "Explicit rollback required"
        }, false);
        Assert.AreEqual(DesktopActivationState.Recovering, recovery.State);
        Assert.AreEqual(DesktopActivationIssue.TransactionRolledBack, recovery.Issue);
        Assert.AreEqual(0, fixture.Client.RequestCount);
    }

    [TestMethod]
    public async Task RecoveredLastKnownGoodStateIsReportedWithoutRawExceptionText()
    {
        using var fixture = new WorkflowFixture();
        var configuration = await fixture.CaptureAsync(ProgramConnectionPolicy.Blocked);
        fixture.Store.Configuration = configuration;
        await fixture.Workflow.LoadAsync(CancellationToken.None);
        var recovered = fixture.Workflow.Reconcile(new(true, true), fixture.Status with
        {
            LastKnownGoodPolicyStatus = "Recovered from validated last-known-good policy",
            ProgramPolicies = [new(configuration.StableApplicationIdentity, configuration.Policy, true)]
        }, false);
        Assert.AreEqual(DesktopActivationIssue.RecoverySucceeded, recovered.Issue);
        StringAssert.Contains(recovered.CustomerMessage, "recovery succeeded");
    }

    private sealed class WorkflowFixture : IDisposable
    {
        private readonly string _root;
        public WorkflowFixture(ProgramConnectionPolicy changePolicy = ProgramConnectionPolicy.Blocked, bool throwOnStatus = false)
        {
            _root = Path.Combine(Path.GetTempPath(), "QuietShield-Phase11D-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_root);
            ExecutablePath = Path.Combine(_root, "CustomerApp.exe");
            File.WriteAllBytes(ExecutablePath, [0x51, 0x53, 0x31]);
            AuthorizationId = Guid.NewGuid();
            Status = new("Installed", "Service IPC", "Available", "standard", "Validated", "No transaction", "Ready",
                DateTimeOffset.UtcNow, true, true, true, true, Array.Empty<PersistentProgramPolicy>(), AuthorizationId);
            Client = new FakeServiceClient(Status, new(Guid.NewGuid(), changePolicy, "QuietShield.ProgramLock.test", "Committed",
                changePolicy == ProgramConnectionPolicy.Blocked, Array.Empty<string>()), throwOnStatus);
            Store = new MemoryStore();
            Validator = new WindowsInstalledProgramTargetValidator([_root]);
            Workflow = new DesktopProgramActivationWorkflow(Client, Store, Validator);
        }

        public string ExecutablePath { get; }
        public Guid AuthorizationId { get; }
        public ServiceStatusSnapshot Status { get; }
        public FakeServiceClient Client { get; }
        public MemoryStore Store { get; }
        public WindowsInstalledProgramTargetValidator Validator { get; }
        public DesktopProgramActivationWorkflow Workflow { get; }

        public async Task<DesktopProgramPolicyConfiguration> CaptureAsync(ProgramConnectionPolicy policy)
        {
            var result = await Validator.CaptureAsync(new("Customer App", ExecutablePath, null, false), "standard", policy, CancellationToken.None);
            Assert.IsTrue(result.IsValid, result.CustomerMessage);
            return result.Configuration!;
        }

        public void Dispose() { if (Directory.Exists(_root)) Directory.Delete(_root, true); }
    }

    private sealed class MemoryStore : IDesktopProgramPolicyStore
    {
        public DesktopProgramPolicyConfiguration? Configuration { get; set; }
        public Task<DesktopProgramPolicyConfiguration?> LoadAsync(CancellationToken cancellationToken) => Task.FromResult(Configuration);
        public Task SaveAsync(DesktopProgramPolicyConfiguration configuration, CancellationToken cancellationToken) { Configuration = configuration; return Task.CompletedTask; }
    }

    private sealed class FakeServiceClient : IQuietShieldServiceClient
    {
        private readonly ServiceStatusSnapshot _status;
        private readonly bool _throwOnStatus;
        public FakeServiceClient(ServiceStatusSnapshot status, ProgramRuleChangeResponse changeResult, bool throwOnStatus)
        { _status = status; ChangeResult = changeResult; _throwOnStatus = throwOnStatus; }
        public int RequestCount { get; private set; }
        public ProgramRuleChangeRequest? ChangeRequest { get; private set; }
        public ProgramRuleChangeResponse ChangeResult { get; }

        public Task<ServiceResponse> SendAsync(ServiceMessageKind messageKind, object? payload, CancellationToken cancellationToken)
        {
            RequestCount++;
            if (messageKind == ServiceMessageKind.GetServiceStatus)
            {
                if (_throwOnStatus) throw new IOException("internal pipe detail");
                return Task.FromResult(Response(ServiceResponseStatus.Ok, _status));
            }
            ChangeRequest = Assert.IsInstanceOfType<ProgramRuleChangeRequest>(payload);
            return Task.FromResult(Response(ServiceResponseStatus.Ok, ChangeResult));
        }

        private static ServiceResponse Response(ServiceResponseStatus status, object payload) =>
            new(1, Guid.NewGuid(), status, "test", JsonSerializer.SerializeToElement(payload, ServiceMessageSerializer.Options));
    }
}
