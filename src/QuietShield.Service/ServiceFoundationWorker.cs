using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using QuietShield.Core.ServiceFoundation;

namespace QuietShield.Service;

public sealed class ServiceFoundationWorker : BackgroundService
{
    private readonly PersistentServiceRuntime _runtime;
    private readonly IHeartbeatDelay _delay;
    private readonly IServiceProgramPolicyCoordinator _policyCoordinator;

    public ServiceFoundationWorker(PersistentServiceRuntime runtime, IHeartbeatDelay delay, IServiceProgramPolicyCoordinator policyCoordinator)
    {
        _runtime = runtime;
        _delay = delay;
        _policyCoordinator = policyCoordinator;
    }

    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        await _runtime.StartAsync(cancellationToken).ConfigureAwait(false);
        _runtime.SetPersistentEnforcementAvailable(_policyCoordinator.PersistentEnforcementAvailable);
        await _policyCoordinator.RecoverInterruptedAsync(cancellationToken).ConfigureAwait(false);
        await base.StartAsync(cancellationToken).ConfigureAwait(false);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                await _runtime.RecordHeartbeatAsync(stoppingToken).ConfigureAwait(false);
                await _delay.WaitAsync(TimeSpan.FromSeconds(5), stoppingToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await base.StopAsync(cancellationToken).ConfigureAwait(false);
        await _runtime.StopAsync(cancellationToken).ConfigureAwait(false);
    }
}

public sealed class ServiceIpcWorker : BackgroundService
{
    private readonly NamedPipeQuietShieldServer _server;
    public ServiceIpcWorker(NamedPipeQuietShieldServer server) => _server = server;
    protected override Task ExecuteAsync(CancellationToken stoppingToken) => _server.RunAsync(stoppingToken);
}

public sealed class DiagnosticDurationWorker : BackgroundService
{
    private readonly DiagnosticServiceOptions _options;
    private readonly IHostApplicationLifetime _lifetime;
    public DiagnosticDurationWorker(DiagnosticServiceOptions options, IHostApplicationLifetime lifetime)
    {
        _options = options;
        _lifetime = lifetime;
    }
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Delay(_options.Duration, stoppingToken).ConfigureAwait(false);
        _lifetime.StopApplication();
    }
}
