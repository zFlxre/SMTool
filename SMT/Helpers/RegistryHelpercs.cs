using Microsoft.Win32;
using System;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Text;

namespace SMT
{
    /// <summary>
    /// Source: https://stackoverflow.com/questions/33708391/c-sharp-winapi-getting-registry-last-write-date
    /// Credits: https://stackoverflow.com/users/3648500/adam
    /// </summary>
    [Obsolete]
    internal class RegistryHelperCS
    {
        [DllImport("advapi32.dll", EntryPoint = "RegQueryInfoKey", CallingConvention = CallingConvention.Winapi, SetLastError = true)]
        private static extern int RegQueryInfoKey(
           UIntPtr hkey,
           out StringBuilder lpClass,
           ref uint lpcbClass,
           IntPtr lpReserved,
           out uint lpcSubKeys,
           out uint lpcbMaxSubKeyLen,
           out uint lpcbMaxClassLen,
           out uint lpcValues,
           out uint lpcbMaxValueNameLen,
           out uint lpcbMaxValueLen,
           out uint lpcbSecurityDescriptor,
           ref FILETIME lpftLastWriteTime);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern int RegCloseKey(UIntPtr hKey);


        [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
        private static extern int RegOpenKeyEx(
          UIntPtr hKey,
          string subKey,
          int ulOptions,
          int samDesired,
          out UIntPtr hkResult);

        private static DateTime ToDateTime(FILETIME ft)
        {
            IntPtr buf = IntPtr.Zero;
            try
            {
                long[] longArray = new long[1];
                int cb = Marshal.SizeOf(ft);
                buf = Marshal.AllocHGlobal(cb);
                Marshal.StructureToPtr(ft, buf, false);
                Marshal.Copy(buf, longArray, 0, 1);
                return DateTime.FromFileTime(longArray[0]);
            }
            finally
            {
                if (buf != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(buf);
                }
            }
        }


        public static DateTime? GetDateModified(RegistryHive registryHive, string path)
        {
            FILETIME lastModified = new FILETIME();
            uint lpcbClass = new uint();
            IntPtr lpReserved = new IntPtr();
            UIntPtr key = UIntPtr.Zero;

            try
            {
                try
                {
                    UIntPtr hive = new UIntPtr(unchecked((uint)registryHive));
                    if (RegOpenKeyEx(hive, path, 0, (int)RegistryRights.ReadKey, out key) != 0)
                    {
                        return null;
                    }

                    if (RegQueryInfoKey(
                                 key,
                                 out StringBuilder sb,
                                 ref lpcbClass,
                                 lpReserved,
                                 out uint lpcbSubKeys,
                                 out uint lpcbMaxKeyLen,
                                 out uint lpcbMaxClassLen,
                                 out uint lpcValues,
                                 out uint maxValueName,
                                 out uint maxValueLen,
                                 out uint securityDescriptor,
                                 ref lastModified) != 0)
                    {
                        return null;
                    }

                    DateTime result = ToDateTime(lastModified);
                    return result;
                }
                finally
                {
                    if (key != UIntPtr.Zero)
                    {
                        RegCloseKey(key);
                    }
                }
            }
            catch
            {
                return null;
            }
        }
    }
}