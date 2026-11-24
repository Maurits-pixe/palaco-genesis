// PALACO Bluetooth Windows native host prototype v5.1.
// This is a Windows-only user-session console host, NOT an installed Windows
// service, privileged endpoint, TPM driver, authenticated service, or BLE stack.
// Every IPC request is denied. Never use this as a production security boundary.
using System.Buffers.Binary;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.ServiceProcess;

namespace Palaco.Bluetooth.NativeHost;

internal static class Program
{
    private const string PipeName = "PALACO-BT-NATIVE-DIAGNOSTIC-V1";
    private const int MaxPayload = 1024;
    private static readonly byte[] Deny = Encoding.ASCII.GetBytes(
        "{\"protocol\":\"PALACO-BT-WIN-HOST-V1\",\"decision\":\"HOLD\",\"authorization\":\"DENY\",\"native_security_verified\":false}\n");

    public static async Task<int> Main(string[] args)
    {
        if (args.Length == 1 && args[0] == "--self-test")
            return SelfTest() ? 0 : 1;

        if (args.Length != 1 || !OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("Windows-only diagnostic host. Use --self-test, --serve, or --service.");
            return 2;
        }
        if (args[0] == "--service")
        {
            ServiceBase.Run(new PalacoDiagnosticService());
            return 0;
        }
        if (args[0] != "--serve")
            return 2;

        using var stop = new CancellationTokenSource();
        Console.CancelKeyPress += (_, evt) =>
        {
            evt.Cancel = true;
            stop.Cancel();
        };

        Console.WriteLine("PALACO diagnostic IPC host: HOLD / DENY (no TPM, no authority)");
        await RunServerAsync(stop.Token);
        return 0;
    }

    internal static async Task RunServerAsync(CancellationToken cancellation)
    {
        while (!cancellation.IsCancellationRequested)
        {
            // Explicit same-account DACL. NOT caller authentication or a
            // reviewed service SID. Failure to create the pipe is fail-closed.
            using var pipe = WindowsPipeSecurity.CreateDiagnosticPipe();
            try
            {
                await pipe.WaitForConnectionAsync(cancellation);
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
                deadline.CancelAfter(TimeSpan.FromSeconds(5));
                await ReadRequestSafely(pipe, deadline.Token);
                // Even valid requests receive the identical fixed DENY response.
                await pipe.WriteAsync(Deny, deadline.Token);
                await pipe.FlushAsync(deadline.Token);
            }
            catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException
                                           or InvalidDataException)
            {
                // Transport/timeout errors are fail-closed. No request body is logged.
            }
        }
    }

    private static async Task ReadRequestSafely(Stream stream, CancellationToken cancel)
    {
        byte[] header = new byte[4];
        await stream.ReadExactlyAsync(header, cancel);
        int length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length <= 0 || length > MaxPayload)
            throw new InvalidDataException("bounded IPC frame required");

        byte[] frame = new byte[length];
        await stream.ReadExactlyAsync(frame, cancel);
        if (!IsInspectOnlyFrame(frame))
            throw new InvalidDataException("unsupported IPC inspection request");
    }

    private static bool IsInspectOnlyFrame(byte[] frame)
    {
        if (frame.Length == 0 || frame.Length > MaxPayload) return false;
        try
        {
            using var doc = JsonDocument.Parse(frame);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
                return false;
            var expected = new HashSet<string>(StringComparer.Ordinal)
            {
                "protocol", "operation", "namespace", "device_binding",
                "generation", "challenge"
            };
            foreach (var field in doc.RootElement.EnumerateObject())
                if (!expected.Remove(field.Name)) return false; // also rejects duplicates
            if (expected.Count != 0) return false;
            var root = doc.RootElement;
            return root.GetProperty("protocol").ValueKind == JsonValueKind.String
                && root.GetProperty("protocol").GetString() == "PALACO-BT-WIN-IPC-V1"
                && root.GetProperty("operation").ValueKind == JsonValueKind.String
                && root.GetProperty("operation").GetString() == "inspect"
                && IsLowerHex64(root.GetProperty("namespace"))
                && IsLowerHex64(root.GetProperty("device_binding"))
                && IsLowerHex64(root.GetProperty("challenge"))
                && root.GetProperty("generation").ValueKind == JsonValueKind.Number
                && root.GetProperty("generation").TryGetInt64(out long generation)
                && generation > 0;
        }
        catch (JsonException) { return false; }
        catch (InvalidOperationException) { return false; }
    }

    private static bool IsLowerHex64(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.String) return false;
        string? value = element.GetString();
        return value is { Length: 64 }
            && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    }

    private static bool SelfTest()
    {
        byte[] valid = Encoding.ASCII.GetBytes(
            "{\"challenge\":\"" + new string('c', 64) +
            "\",\"device_binding\":\"" + new string('d', 64) +
            "\",\"generation\":1,\"namespace\":\"" + new string('a', 64) +
            "\",\"operation\":\"inspect\",\"protocol\":\"PALACO-BT-WIN-IPC-V1\"}");
        string good = Encoding.ASCII.GetString(valid);
        bool ok = IsInspectOnlyFrame(valid)
            && !IsInspectOnlyFrame(Encoding.ASCII.GetBytes(good.Replace(
                "\"inspect\"", "\"authorize\"", StringComparison.Ordinal)))
            && !IsInspectOnlyFrame(Encoding.ASCII.GetBytes(good.Replace(
                "\"generation\":1", "\"generation\":0", StringComparison.Ordinal)))
            && !IsInspectOnlyFrame(Encoding.ASCII.GetBytes(good.Replace(
                "\"challenge\"", "\"challenge\":0,\"challenge\"", StringComparison.Ordinal)))
            && !IsInspectOnlyFrame(new byte[MaxPayload + 1])
            && !IsInspectOnlyFrame(Encoding.ASCII.GetBytes("{}"))
            && Deny.AsSpan().SequenceEqual(Encoding.ASCII.GetBytes(
                "{\"protocol\":\"PALACO-BT-WIN-HOST-V1\",\"decision\":\"HOLD\",\"authorization\":\"DENY\",\"native_security_verified\":false}\n"));
        if (ok && OperatingSystem.IsWindows())
        {
            try
            {
                using var restrictedPipe = WindowsPipeSecurity.CreateDiagnosticPipe();
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException
                                           or System.Security.SecurityException)
            {
                ok = false;
            }
        }
        Console.WriteLine(ok ? "Windows host self-checks PASS (no hardware tests)" :
                               "Windows host self-checks FAIL");
        return ok;
    }
}
