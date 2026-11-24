// Windows CI cross-account access check. Uses a temporary non-admin user
// created and deleted by the CI harness. NO service installation or elevation.
// LogonUser creates a real alternate Windows logon token. If that token can
// open the process-account-only diagnostic pipe, the test MUST fail.
using Microsoft.Win32.SafeHandles;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Palaco.Bluetooth.NativeHost;

internal static partial class WindowsCrossAccountTest
{
    [LibraryImport("advapi32.dll", EntryPoint = "LogonUserW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool LogonUser(
        string username, string domain, string password, int logonType,
        int logonProvider, out SafeAccessTokenHandle token);

    internal static async Task<bool> RunAsync()
    {
        if (!OperatingSystem.IsWindows()) return false;
        string? username = Environment.GetEnvironmentVariable("PALACO_TEST_USER");
        string? password = Environment.GetEnvironmentVariable("PALACO_TEST_PASSWORD");
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrEmpty(password))
        {
            Console.Error.WriteLine("Cross-account test requires ephemeral CI credentials: HOLD");
            return false;
        }

        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(25));
        Task server = Program.RunServerAsync(deadline.Token);
        try
        {
            // Ensure pipe is ready and same-account path remains DENY only.
            if (!await WindowsPipeIntegrationTest.SendAsync(
                    WindowsPipeIntegrationTest.MakeInspectFrame(), true, deadline.Token))
                return Fail("same-account baseline");

            if (!LogonUser(username, ".", password, 2, 0, out SafeAccessTokenHandle token))
                return Fail("alternate Windows logon unavailable");
            using (token)
            {
                using var other = WindowsIdentity.RunImpersonated(token, WindowsIdentity.GetCurrent);
                using var current = WindowsIdentity.GetCurrent();
                if (other.User is null || current.User is null || other.User.Equals(current.User))
                    return Fail("alternate OS account SID not distinct");

                // The connector must be genuinely created/opened while the
                // alternate Windows token is impersonated. A successful pipe
                // connection here is a security regression, even if DENY
                // would later be returned by the server.
                bool connected = await WindowsIdentity.RunImpersonated(token, async () =>
                {
                    using var pipe = new NamedPipeClientStream(
                        ".", "PALACO-BT-NATIVE-DIAGNOSTIC-V1",
                        PipeDirection.InOut, PipeOptions.Asynchronous,
                        TokenImpersonationLevel.Impersonation);
                    try
                    {
                        await pipe.ConnectAsync(1500, deadline.Token);
                        return true;
                    }
                    catch (UnauthorizedAccessException) { return false; }
                    catch (IOException) { return false; }
                    catch (TimeoutException) { return false; }
                });
                if (connected) return Fail("unauthorized account opened pipe");
            }

            // No outage or weakened ACL after attempted unauthorized access.
            if (!await WindowsPipeIntegrationTest.SendAsync(
                    WindowsPipeIntegrationTest.MakeInspectFrame(), true, deadline.Token))
                return Fail("post-rejection same-account baseline");
            Console.WriteLine("Windows cross-account named-pipe rejection PASS (distinct real OS token)");
            return true;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException
                                       or OperationCanceledException
                                       or System.ComponentModel.Win32Exception
                                       or InvalidOperationException)
        {
            return Fail("Windows API or transport: " + ex.GetType().Name);
        }
        finally
        {
            deadline.Cancel();
            try { await server.WaitAsync(TimeSpan.FromSeconds(5)); }
            catch (OperationCanceledException) { }
            catch (TimeoutException) { }
        }
    }

    private static bool Fail(string reason)
    {
        Console.Error.WriteLine("Windows cross-account IPC FAIL at " + reason);
        return false;
    }
}
