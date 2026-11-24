// Windows-only CI: exercise the real diagnostic host across process lifetimes.
// No service installation, elevation, TPM, cross-account role tests or BLE.
// The only permitted successful reply remains fixed HOLD/DENY.
using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text;

namespace Palaco.Bluetooth.NativeHost;

internal static class WindowsPipeProcessTest
{
    private const string PipeName = "PALACO-BT-NATIVE-DIAGNOSTIC-V1";

    internal static async Task<bool> RunAsync()
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrEmpty(Environment.ProcessPath))
            return false;

        using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(55));
        string stage = "start";
        try
        {
            using (Process server = StartHost())
            try
            {
                stage = "first separate-process inspection";
                if (!await SendValidWithStartupRetry(limit.Token))
                    return Failed(stage);
                stage = "disconnect mid-frame";
                await AbandonPartialFrame(limit.Token);
                stage = "recovery after interrupted client";
                if (!await WindowsPipeIntegrationTest.SendAsync(
                        WindowsPipeIntegrationTest.MakeInspectFrame(), true, limit.Token))
                    return Failed(stage);
                stage = "request timeout";
                await AbandonPartialFrameAfterTimeout(limit.Token);
                stage = "recovery after deadline";
                if (!await WindowsPipeIntegrationTest.SendAsync(
                        WindowsPipeIntegrationTest.MakeInspectFrame(), true, limit.Token))
                    return Failed(stage);
            }
            finally
            {
                StopHost(server);
            }

            using (Process restarted = StartHost())
            try
            {
                stage = "inspection after host process restart";
                if (!await SendValidWithStartupRetry(limit.Token))
                    return Failed(stage);
            }
            finally
            {
                StopHost(restarted);
            }
            Console.WriteLine("Windows separate-process IPC PASS (disconnect, timeout, restart; HOLD/DENY)");
            return true;
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException
                                       or UnauthorizedAccessException or System.ComponentModel.Win32Exception
                                       or OperationCanceledException or TimeoutException)
        {
            Console.Error.WriteLine($"Windows separate-process IPC FAIL at {stage}: {ex.GetType().Name}");
            return false;
        }
    }

    private static Process StartHost()
    {
        var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = Environment.ProcessPath
                    ?? throw new InvalidOperationException("Missing executable path"),
                Arguments = "--serve",
                UseShellExecute = false,
                CreateNoWindow = true,
            },
        };
        if (!process.Start())
        {
            process.Dispose();
            throw new InvalidOperationException("Cannot start diagnostic host");
        }
        return process;
    }

    private static void StopHost(Process process)
    {
        if (!process.HasExited)
        {
            process.Kill(entireProcessTree: true);
            if (!process.WaitForExit(5000))
                throw new TimeoutException("Diagnostic child did not stop");
        }
    }

    private static async Task<bool> SendValidWithStartupRetry(CancellationToken cancel)
    {
        // Try connecting while the child creates its first named-pipe instance.
        for (int attempt = 0; attempt < 3; attempt++)
        {
            try
            {
                return await WindowsPipeIntegrationTest.SendAsync(
                    WindowsPipeIntegrationTest.MakeInspectFrame(), true, cancel);
            }
            catch (TimeoutException) when (attempt < 2)
            {
                await Task.Delay(100, cancel);
            }
        }
        return false;
    }

    private static async Task AbandonPartialFrame(CancellationToken cancel)
    {
        using var client = await ConnectAsync(cancel);
        byte[] header = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(header, 100);
        await client.WriteAsync(header, cancel);
        await client.WriteAsync(Encoding.ASCII.GetBytes("partial"), cancel);
        await client.FlushAsync(cancel);
        // Dispose without completing 100-byte body; service must not reply.
    }

    private static async Task AbandonPartialFrameAfterTimeout(CancellationToken cancel)
    {
        using (var client = await ConnectAsync(cancel))
        {
            // Send a short frame header but never the declared body.
            byte[] header = new byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(header, 100);
            await client.WriteAsync(header, cancel);
            await client.FlushAsync(cancel);
            await Task.Delay(TimeSpan.FromSeconds(6), cancel);
            // Never complete the body; server deadline should expire.
        }
    }

    private static async Task<NamedPipeClientStream> ConnectAsync(CancellationToken cancel)
    {
        var pipe = new NamedPipeClientStream(
            ".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous,
            TokenImpersonationLevel.Impersonation);
        try
        {
            await pipe.ConnectAsync(3000, cancel);
            return pipe;
        }
        catch
        {
            pipe.Dispose();
            throw;
        }
    }

    private static bool Failed(string stage)
    {
        Console.Error.WriteLine($"Windows separate-process IPC FAIL at {stage}");
        return false;
    }
}
