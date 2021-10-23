using System;
using System.IO;

namespace TikiLoader
{
    public static class Win32
    {
        public static bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, ref IntPtr lpSize)
        {
            object[] parameters = { lpAttributeList, dwAttributeCount, 0, lpSize };
            var retVal = (bool)Generic.DynamicApiInvoke("kernel32.dll", "InitializeProcThreadAttributeList", typeof(Delegates.InitializeProcThreadAttributeList), ref parameters);

            lpSize = (IntPtr)parameters[3];
            return retVal;
        }
        
        public static bool UpdateProcThreadAttribute(IntPtr lpAttributeList, IntPtr attribute, IntPtr lpValue)
        {
            object[] parameters = { lpAttributeList, (uint)0, attribute, lpValue, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero };
            var retVal = (bool)Generic.DynamicApiInvoke("kernel32.dll", "UpdateProcThreadAttribute", typeof(Delegates.UpdateProcThreadAttribute), ref parameters);
            return retVal;
        }
        
        public static bool DeleteProcThreadAttribute(IntPtr lpAttributeList)
        {
            object[] parameters = { lpAttributeList };
            var retVal = (bool)Generic.DynamicApiInvoke("kernel32.dll", "DeleteProcThreadAttributeList", typeof(Delegates.DeleteProcThreadAttributeList), ref parameters);
            return retVal;
        }
        
        public static bool CreateProcessA(string applicationName, string workingDirectory, uint creationFlags, Data.Win32.Kernel32.STARTUPINFOEX startupInfoEx, out Data.Win32.Kernel32.PROCESS_INFORMATION processInformation)
        {
            var pa = new Data.Win32.WinBase.SECURITY_ATTRIBUTES();
            var ta = new Data.Win32.WinBase.SECURITY_ATTRIBUTES();
            var pi = new Data.Win32.Kernel32.PROCESS_INFORMATION();

            object[] parameters = { applicationName, null, pa, ta, false, creationFlags, IntPtr.Zero, workingDirectory, startupInfoEx, pi };
            var result = (bool)Generic.DynamicApiInvoke(@"kernel32.dll", @"CreateProcessA", typeof(Delegates.CreateProcessA), ref parameters);

            if (!result) processInformation = pi;

            processInformation = (Data.Win32.Kernel32.PROCESS_INFORMATION)parameters[9];
            return result;
        }
        
        public static uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds)
        {
            object[] parameters = { hHandle, dwMilliseconds };
            return (uint)Generic.DynamicApiInvoke(@"kernel32.dll", @"WaitForSingleObject", typeof(Delegates.WaitForSingleObject), ref parameters);
        }
        
        public static bool CloseHandle(IntPtr handle)
        {
            object[] parameters = { handle };
            var retVal = (bool)Generic.DynamicApiInvoke("kernel32.dll", "CloseHandle", typeof(Delegates.CloseHandle), ref parameters);
            return retVal;
        }
    }
}