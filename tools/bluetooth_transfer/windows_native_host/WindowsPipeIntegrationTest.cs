// Windows CI integration probe: actual local pipe I/O, no SCM installation.
// Tests only same-account diagnostic path. Not hardware/privileged attestation.
using System.Buffers.Binary;
using System.IO.Pipes;
using System.Text;

namespace Palaco.Bluetooth.NativeHost;

internal static class WindowsPipeIntegrationTest
{
    private const string PipeName = "PALACO-BT-NATIVE-DIAGNOSTIC-V1";

    internal static async Task<bool> RunAsync()
    {
        if (!OperatingSystem.IsWindows())
            return false;

        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        Task server = Program.RunServerAsync(stop.Token);
        string stage = "valid inspection";
        try
        {
            bool acceptedButDenied = await SendAsync(
                MakeInspectFrame(), expectResponse: true, stop.Token);
            stage = "unsupported operation";
            bool rejectedOperation = await SendAsync(
                MakeInspectFrame().Replace(
                    "\"inspect\"", "\"execute\"", StringComparison.Ordinal),
                expectResponse: false, stop.Token);
            stage = "oversized prefix";
            bool oversizedRejected = await SendAsync(
                "oversized", expectResponse: false, stop.Token,
                overrideLength: 1025);
            stage = "reconnect inspection";
            bool secondAcceptedButDenied = await SendAsync(
                MakeInspectFrame(), expectResponse: true, stop.Token);
            Console.WriteLine($"IPC scenarios: valid={acceptedButDenied}, invalidOperation={rejectedOperation}, oversized={oversizedRejected}, reconnect={secondAcceptedButDenied}");
            bool ok = acceptedButDenied && rejectedOperation
                && oversizedRejected && secondAcceptedButDenied;
            Console.WriteLine(ok
                ? "Windows named-pipe integration PASS (same-account, HOLD/DENY only)"
                : "Windows named-pipe integration FAIL");
            return ok;
        }
        catch (Exception ex) when (ex is IOException or TimeoutException
                                       or OperationCanceledException
                                       or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"Windows named-pipe integration FAIL at {stage}: {ex.GetType().Name}");
            return false;
        }
        finally
        {
            stop.Cancel();
            try
            {
                await server.WaitAsync(TimeSpan.FromSeconds(5));
            }
            catch (OperationCanceledException) { }
            catch (TimeoutException) { }
        }
    }

    private static async Task<bool> SendAsync(
        string text, bool expectResponse, CancellationToken cancel,
        int? overrideLength = null)
    {
        using var pipe = new NamedPipeClientStream(
            ".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        await pipe.ConnectAsync(5000, cancel);
        byte[] body = Encoding.ASCII.GetBytes(text);
        byte[] header = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(
            header, overrideLength ?? body.Length);
        try
        {
            await pipe.WriteAsync(header, cancel);
            if (overrideLength is null)
                await pipe.WriteAsync(body, cancel);
            await pipe.FlushAsync(cancel);
        }
        catch (IOException) when (!expectResponse)
        {
            // Peer intentionally disconnected on malformed frame.
            return true;
        }
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancel);
        timeout.CancelAfter(TimeSpan.FromSeconds(5));

        using var response = new MemoryStream();
        byte[] buffer = new byte[256];
        while (response.Length < 256)
        {
            int size = await pipe.ReadAsync(buffer, timeout.Token);
            if (size == 0) break;
            response.Write(buffer, 0, size);
            if (Array.IndexOf(buffer, (byte)'\n', 0, size) >= 0)
                break;
        }

        string received = Encoding.ASCII.GetString(response.ToArray());
        if (!expectResponse) return received.Length == 0;
        return received ==
            "{\"protocol\":\"PALACO-BT-WIN-HOST-V1\",\"decision\":\"HOLD\",\"authorization\":\"DENY\",\"native_security_verified\":false}\n";
    }

    private static string MakeInspectFrame()
    {
        return "{\"challenge\":\"" + new string('c', 64) +
               "\",\"device_binding\":\"" + new string('d', 64) +
               "\",\"generation\":1,\"namespace\":\"" + new string('a', 64) +
               "\",\"operation\":\"inspect\",\"protocol\":\"PALACO-BT-WIN-IPC-V1\"}";
    }
}
