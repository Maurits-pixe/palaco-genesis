using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
namespace Palaco.WindowsTpm {
    // Public metadata only; never a counter value, attestation, freshness or grant.
    public sealed class CounterPublicObservation {
        public readonly uint NvIndex;
        public readonly uint Attributes;
        public readonly string NameHex;
        public bool AntiRollbackVerified { get { return false; } }
        public bool RuntimeAuthorized { get { return false; } }
        internal CounterPublicObservation(uint index, uint attributes, byte[] name) {
            NvIndex = index; Attributes = attributes;
            NameHex = BitConverter.ToString(name).Replace("-", "").ToLowerInvariant();
        }
    }
    public static class CounterPublicReader {
        private const int MaxResponseBytes = 4096;
        public static byte[] BuildReadPublic(uint index) {
            ValidateIndex(index);
            byte[] result = new byte[14];
            result[0] = 0x80; result[1] = 0x01;
            Put32(result, 2, 14); Put32(result, 6, 0x00000169); Put32(result, 10, index);
            return result;
        }
        public static CounterPublicObservation ParseReadPublic(byte[] response, uint expectedIndex, byte[] expectedName) {
            ValidateIndex(expectedIndex); ValidateName(expectedName);
            if (response == null || response.Length < 12 || response.Length > MaxResponseBytes)
                throw new ArgumentException("INVALID_RESPONSE_SIZE");
            if (U16(response, 0) != 0x8001 || U32(response, 2) != (uint)response.Length)
                throw new ArgumentException("INVALID_RESPONSE_HEADER");
            if (U32(response, 6) != 0) throw new ArgumentException("TPM_RESPONSE_ERROR");
            int publicSize = U16(response, 10);
            if (publicSize < 14 || publicSize > 46 || 12 + publicSize + 2 > response.Length)
                throw new ArgumentException("INVALID_PUBLIC_SIZE");
            int nameOffset = 12 + publicSize;
            if (U16(response, nameOffset) != 34 || nameOffset + 36 != response.Length)
                throw new ArgumentException("INVALID_NAME_SIZE");
            if (U32(response, 12) != expectedIndex || U16(response, 16) != 0x000b)
                throw new ArgumentException("INDEX_OR_NAME_ALGORITHM_MISMATCH");
            uint attributes = U32(response, 18);
            int policySize = U16(response, 22);
            if ((policySize != 0 && policySize != 32) || publicSize != 14 + policySize)
                throw new ArgumentException("INVALID_AUTH_POLICY_SIZE");
            if ((attributes & 0x000000f0) != 0x00000010 || U16(response, 24 + policySize) != 8)
                throw new ArgumentException("EIGHT_BYTE_COUNTER_REQUIRED");
            byte[] publicArea = new byte[publicSize];
            Array.Copy(response, 12, publicArea, 0, publicSize);
            byte[] calculatedName = new byte[34]; calculatedName[1] = 0x0b;
            using (SHA256 sha = SHA256.Create())
                Array.Copy(sha.ComputeHash(publicArea), 0, calculatedName, 2, 32);
            for (int i = 0; i < 34; i++) {
                if (response[nameOffset + 2 + i] != calculatedName[i] || expectedName[i] != calculatedName[i])
                    throw new ArgumentException("PINNED_NV_NAME_MISMATCH");
            }
            return new CounterPublicObservation(expectedIndex, attributes, calculatedName);
        }
        // Only NV_ReadPublic is exposed. No arbitrary command submission.
        public static CounterPublicObservation Read(uint index, byte[] expectedName) {
            byte[] command = BuildReadPublic(index); ValidateName(expectedName);
            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
                throw new PlatformNotSupportedException("WINDOWS_REQUIRED");
            ContextParameters parameters = new ContextParameters { Version = 2, Flags = 4 };
            IntPtr context = IntPtr.Zero;
            uint status = Tbsi_Context_Create(ref parameters, out context);
            if (status != 0) throw new InvalidOperationException("TBS_CONTEXT_FAILED_" + status.ToString("x8"));
            try {
                byte[] response = new byte[MaxResponseBytes];
                uint responseSize = (uint)response.Length;
                status = Tbsip_Submit_Command(context, 0, 200, command, (uint)command.Length, response, ref responseSize);
                if (status != 0 || responseSize > MaxResponseBytes)
                    throw new InvalidOperationException("TBS_READ_FAILED_" + status.ToString("x8"));
                byte[] exact = new byte[(int)responseSize];
                Array.Copy(response, exact, exact.Length);
                return ParseReadPublic(exact, index, expectedName);
            } finally { Tbsip_Context_Close(context); }
        }
        private static void ValidateIndex(uint index) {
            if ((index & 0xff000000) != 0x01000000) throw new ArgumentException("NV_INDEX_REQUIRED");
        }
        private static void ValidateName(byte[] name) {
            if (name == null || name.Length != 34 || name[0] != 0 || name[1] != 0x0b)
                throw new ArgumentException("SHA256_NV_NAME_REQUIRED");
        }
        private static int U16(byte[] b, int p) { return (b[p] << 8) | b[p + 1]; }
        private static uint U32(byte[] b, int p) {
            return ((uint)b[p] << 24) | ((uint)b[p + 1] << 16) | ((uint)b[p + 2] << 8) | b[p + 3];
        }
        private static void Put32(byte[] b, int p, uint v) {
            b[p] = (byte)(v >> 24); b[p + 1] = (byte)(v >> 16); b[p + 2] = (byte)(v >> 8); b[p + 3] = (byte)v;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct ContextParameters { public uint Version; public uint Flags; }
        [DllImport("tbs.dll", ExactSpelling = true)]
        private static extern uint Tbsi_Context_Create(ref ContextParameters parameters, out IntPtr context);
        [DllImport("tbs.dll", ExactSpelling = true)]
        private static extern uint Tbsip_Submit_Command(IntPtr context, uint locality, uint priority,
            byte[] command, uint commandSize, [Out] byte[] response, ref uint responseSize);
        [DllImport("tbs.dll", ExactSpelling = true)]
        private static extern uint Tbsip_Context_Close(IntPtr context);
    }
}
