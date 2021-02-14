using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace SMT.Helpers
{
    class RegHelper
    {
        enum KEY_SET_INFORMATION_CLASS
        {
            KeyWriteTimeInformation = 0,
            KeyWow64FlagsInformation = 1,
            KeyControlFlagsInformation = 2,
            KeySetVirtualizationInformation = 3,
            KeySetDebugInformation = 4,
            KeySetHandleTagsInformation = 5,
            KeySetLayerInformation = 6,
            MaxKeySetInfoClass = 7
        }

        [StructLayout(LayoutKind.Explicit)]
        private struct LARGE_INTEGER
        {
            [FieldOffset(0)]
            public int Low;
            [FieldOffset(4)]
            public int High;
            [FieldOffset(0)]
            public long QuadPart;

            // use only when QuadPart canot be passed
            public long ToInt64()
            {
                return ((long)this.High << 32) | (uint)this.Low;
            }

            public static LARGE_INTEGER FromInt64(long value)
            {
                return new LARGE_INTEGER
                {
                    Low = (int)(value),
                    High = (int)((value >> 32))
                };
            }

        }

        [StructLayout(LayoutKind.Sequential)]
        private struct KEY_WRITE_TIME_INFORMATION
        {
            public LARGE_INTEGER LastWriteTime;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FILETIME
        {
            private long timestamp;
            public DateTime Local
            {
                get { return DateTime.FromFileTime(this.timestamp); }
                set { this.timestamp = value.ToFileTime(); }
            }
            public DateTime Utc
            {
                get { return DateTime.FromFileTimeUtc(this.timestamp); }
                set { this.timestamp = value.ToFileTimeUtc(); }
            }
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int RegQueryInfoKey(
                IntPtr hKey,
                [Out()] StringBuilder lpClass,
                ref uint lpcchClass,
                IntPtr lpReserved,
                out uint lpcSubkey,
                out uint lpcchMaxSubkeyLen,
                out uint lpcchMaxClassLen,
                out uint lpcValues,
                out uint lpcchMaxValueNameLen,
                out uint lpcbMaxValueLen,
                IntPtr lpSecurityDescriptor,
                out FILETIME lpftLastWriteTime);

        [DllImport("ntdll.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern int NtSetInformationKey(IntPtr KeyHandle, KEY_SET_INFORMATION_CLASS KeyInformationClass, IntPtr KeyInformationData, int DataLength);

        private static IntPtr GetRegistryKeyHandle(RegistryKey registryKey)
        {
            IntPtr ret = IntPtr.Zero;

            Type registryKeyType = typeof(RegistryKey);

            System.Reflection.FieldInfo fieldInfo =
            registryKeyType.GetField("hkey", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);

            SafeHandle handle = (SafeHandle)fieldInfo.GetValue(registryKey);
            ret = handle.DangerousGetHandle();

            return ret;
        }

        public static DateTime GetRegistryKeyDateTime(RegistryKey key)
        {
            IntPtr hKey = GetRegistryKeyHandle(key);
            FILETIME timestamp;
            uint lpcchClass = 0;
            uint lpcSubkey = 0;
            uint lpcchMaxSubkeyLen = 0;
            uint lpcchMaxClassLen = 0;
            uint lpcValues = 0;
            uint lpcchMaxValueNameLen = 0;
            uint lpcbMaxValueLen = 0;

            int result = RegQueryInfoKey(
                hKey,
                new StringBuilder(),
                ref lpcchClass,
                IntPtr.Zero,
                out lpcSubkey,
                out lpcchMaxSubkeyLen,
                out lpcchMaxClassLen,
                out lpcValues,
                out lpcchMaxValueNameLen,
                out lpcbMaxValueLen,
                IntPtr.Zero,
                out timestamp);


            if (result != 0)
            {
                throw new Win32Exception(result);
            }

            return timestamp.Local;
        }
        public static void SetRegistryKeyDateTime(RegistryKey key, DateTime timestamp)
        {
            IntPtr hKey = GetRegistryKeyHandle(key);
            LARGE_INTEGER largeIntDateTime = LARGE_INTEGER.FromInt64(timestamp.ToFileTime());
            KEY_WRITE_TIME_INFORMATION keyWriteTimeInfo;
            keyWriteTimeInfo.LastWriteTime = largeIntDateTime;
            int dataLength = Marshal.SizeOf(typeof(KEY_WRITE_TIME_INFORMATION));
            IntPtr ptrKeyWriteTimeInfo = Marshal.AllocHGlobal(dataLength);
            Marshal.StructureToPtr(keyWriteTimeInfo, ptrKeyWriteTimeInfo, false);
            int result = NtSetInformationKey(hKey, KEY_SET_INFORMATION_CLASS.KeyWriteTimeInformation, ptrKeyWriteTimeInfo, dataLength);
            if (result != 0)
            {
                throw new Win32Exception(result);
            }

            Marshal.FreeHGlobal(ptrKeyWriteTimeInfo);
        }
    }
}
