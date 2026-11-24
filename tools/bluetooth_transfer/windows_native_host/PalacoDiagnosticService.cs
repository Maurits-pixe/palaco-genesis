// SCM-compatible Windows Service entry point. DRAFT/HOLD: DO NOT INSTALL.
// No TPM, credentials, authority, import, or replay-resistant native state.
// A named-pipe user boundary is not proof of an authorized caller.
using System.ServiceProcess;

namespace Palaco.Bluetooth.NativeHost;

internal sealed class PalacoDiagnosticService : ServiceBase
{
    private CancellationTokenSource? _stop;
    private Task? _serverTask;

    public PalacoDiagnosticService()
    {
        ServiceName = "PALACO-BT-Diagnostic-HOLD";
        CanStop = true;
        CanPauseAndContinue = false;
        CanShutdown = true;
        AutoLog = false;
    }

    protected override void OnStart(string[] args)
    {
        // Startup never issues privileges and never enables transfers.
        if (_stop is not null)
            throw new InvalidOperationException("Service already started");
        // Fail closed if SCM has not provisioned the expected service SID.
        // No installation or service SID provisioning is done by this program.
        if (!WindowsClientIdentityGate.HasExpectedServiceSid())
            throw new InvalidOperationException("Unverified Windows service SID: HOLD");
        _stop = new CancellationTokenSource();
        _serverTask = Task.Run(() => Program.RunServerAsync(_stop.Token));
    }

    protected override void OnStop() => StopWorker();

    protected override void OnShutdown() => StopWorker();

    private void StopWorker()
    {
        CancellationTokenSource? cancellation = _stop;
        Task? worker = _serverTask;
        if (cancellation is null) return;
        cancellation.Cancel();
        try
        {
            // Bound SCM stop; never auto-restart or authorize on failure.
            if (worker is not null)
                worker.Wait(TimeSpan.FromSeconds(8));
        }
        catch (AggregateException)
        {
            // Worker errors do not grant any additional capability.
        }
        finally
        {
            _serverTask = null;
            _stop = null;
            cancellation.Dispose();
        }
    }
}
