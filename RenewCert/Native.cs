using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace NewRenewCert
{
    public static class Native
    {

        // ReSharper disable InconsistentNaming

        public const int FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern SafeFileHandle CreateFile(
            string lpFileName,
            [MarshalAs(UnmanagedType.U4)] FileAccess dwDesiredAccess,
            [MarshalAs(UnmanagedType.U4)] FileShare dwShareMode,
            IntPtr lpSecurityAttributes,
            [MarshalAs(UnmanagedType.U4)] FileMode dwCreationDisposition,
            [MarshalAs(UnmanagedType.U4)] FileAttributes dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int ReadFile(
            SafeFileHandle handle,
            IntPtr bytes,
            uint numBytesToRead,
            out int lpNumberOfBytesRead,
            IntPtr lpOverlapped);

        [DllImport("kernel32.dll")]
        public static extern bool WriteFile(
            SafeFileHandle hFile,
            IntPtr lpBuffer,
            uint nNumberOfBytesToWrite,
            out int lpNumberOfBytesWritten, // actually uint
            IntPtr lpOverlapped);           // actually [In] ref System.Threading.NativeOverlapped

        [StructLayout(LayoutKind.Sequential)]
        public class SYSTEMTIME
        {
            [MarshalAs(UnmanagedType.U2)]
            public short Year;
            [MarshalAs(UnmanagedType.U2)]
            public short Month;
            [MarshalAs(UnmanagedType.U2)]
            public short DayOfWeek;
            [MarshalAs(UnmanagedType.U2)]
            public short Day;
            [MarshalAs(UnmanagedType.U2)]
            public short Hour;
            [MarshalAs(UnmanagedType.U2)]
            public short Minute;
            [MarshalAs(UnmanagedType.U2)]
            public short Second;
            [MarshalAs(UnmanagedType.U2)]
            public short Milliseconds;

            public SYSTEMTIME()
            { }
            public SYSTEMTIME(DateTime dt)
            {
                dt = dt.ToUniversalTime();  // SetSystemTime expects the SYSTEMTIME in UTC
                Year = (short)dt.Year;
                Month = (short)dt.Month;
                DayOfWeek = (short)dt.DayOfWeek;
                Day = (short)dt.Day;
                Hour = (short)dt.Hour;
                Minute = (short)dt.Minute;
                Second = (short)dt.Second;
                Milliseconds = (short)dt.Millisecond;
            }

            /// <summary> Converts this to a DateTime in UTC. </summary>
            public DateTime ToDate()
            {
                return new DateTime(Year, Month, Day, Hour, Minute, Second, Milliseconds);
            }

        }

        public static string GetErrorMessage(int error)
        {
            var m = typeof(System.ComponentModel.Win32Exception).GetMethod("GetErrorMessage",
                                                                           BindingFlags.NonPublic | BindingFlags.Static);
            return (string)m.Invoke(null, new object[] { error });
        }

    }
    internal class Win32Native
    {
        [DllImport("AdvApi32.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CryptReleaseContext(IntPtr ctx, int flags);

        [DllImport("AdvApi32.dll", EntryPoint = "CryptAcquireContextW", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CryptAcquireContext(
           out IntPtr providerContext,
           string containerName,
           string providerName,
           uint providerType,
           uint flags);

        [DllImport("AdvApi32.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CryptDestroyKey(IntPtr cryptKeyHandle);

        [DllImport("AdvApi32.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CryptGenKey(
           IntPtr providerContext,
           int algorithmId,
           uint flags,
           out IntPtr cryptKeyHandle);

        [DllImport("Crypt32.dll", SetLastError = true, ExactSpelling = true)]
        internal static extern IntPtr CertCreateSelfSignCertificate(
           IntPtr providerHandle,
           ref Crypt.CRYPT_DATA_BLOB pSubjectIssuerBlob,
           int flags,
           IntPtr pinfo,
           ref CRYPT_ALGORITHM_IDENTIFIER pSignatureAlgorithm,
           Native.SYSTEMTIME pStartTime,
            Native.SYSTEMTIME pEndTime,
           IntPtr extensions);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool FileTimeToSystemTime(
           [In] ref long fileTime,
           [Out] SystemTime systemTime);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern IntPtr LocalAlloc([In] uint uFlags, [In] IntPtr sizetdwBytes);

        [StructLayout(LayoutKind.Sequential)]
        internal class CryptoApiBlob
        {
            public int DataLength;
            public IntPtr Data;

            public CryptoApiBlob(int dataLength, IntPtr data)
            {
                this.DataLength = dataLength;
                this.Data = data;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        internal class SystemTime
        {
            public short Year;
            public short Month;
            public short DayOfWeek;
            public short Day;
            public short Hour;
            public short Minute;
            public short Second;
            public short Milliseconds;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CRYPT_KEY_PROV_INFO
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszContainerName;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszProvName;
            public uint dwProvType;
            public uint dwFlags;
            public uint cProvParam;
            public IntPtr rgProvParam;
            public uint dwKeySpec;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CRYPT_ALGORITHM_IDENTIFIER
        {
            [MarshalAs(UnmanagedType.LPStr)]
            public string pszObjId;
            public CRYPTOAPI_BLOB parameters;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct CRYPTOAPI_BLOB
        {
            public uint cbData;
            public IntPtr pbData;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal class CryptKeyProviderParam
        {
            public int pwszContainerName;
            public IntPtr pbData;
            public int cbData;
            public int dwFlags;
        }

    }
}
