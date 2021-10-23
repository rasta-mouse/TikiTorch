using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace TikiLoader
{
    public static class Utilities
    {
        public static Data.Win32.Kernel32.PROCESS_INFORMATION SpawnProcess(string binaryPath, string workingDirectory, bool blockDlls = false, int ppid = 0, bool suspended = false)
        {
            var startupInfoEx = new Data.Win32.Kernel32.STARTUPINFOEX();
            startupInfoEx.Startupinfo.cb = (uint)Marshal.SizeOf(startupInfoEx);
            startupInfoEx.Startupinfo.dwFlags = (uint)Data.Win32.Kernel32.STARTF.STARTF_USESHOWWINDOW;
            
            var lpValue = Marshal.AllocHGlobal(IntPtr.Size);
            var lpSize = IntPtr.Zero;

            var attributeCount = 0;
            if (ppid != 0) attributeCount++;
            if (blockDlls) attributeCount++;
            
            // always false the first time, lpSize is given a value
            _ = Win32.InitializeProcThreadAttributeList(
                IntPtr.Zero,
                attributeCount,
                ref lpSize);

            startupInfoEx.lpAttributeList = Marshal.AllocHGlobal(lpSize);
            
            // should be true this time
            var success = Win32.InitializeProcThreadAttributeList(
                startupInfoEx.lpAttributeList,
                attributeCount,
                ref lpSize);
            
            if (!success)
                throw new Exception("Failed to InitializeProcThreadAttributeList");

            if (blockDlls)
            {
                Marshal.WriteIntPtr(lpValue,
                    Is64Bit ?
                        new IntPtr(Data.Win32.Kernel32.BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON)
                        : new IntPtr(unchecked((uint)Data.Win32.Kernel32.BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON)));
                
                success = Win32.UpdateProcThreadAttribute(
                    startupInfoEx.lpAttributeList,
                    (IntPtr)Data.Win32.Kernel32.PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                    lpValue);

                if (!success)
                    throw new Exception("Failed to UpdateProcThreadAttribute for BlockDLLs");
            }

            if (ppid != 0)
            {
                var hParent = Process.GetProcessById(ppid).Handle;
                lpValue = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(lpValue, hParent);
                
                success = Win32.UpdateProcThreadAttribute(
                    startupInfoEx.lpAttributeList,
                    (IntPtr)Data.Win32.Kernel32.PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                    lpValue);
                
                if (!success)
                    throw new Exception("Failed to UpdateProcThreadAttribute for PPID Spoofing");
            }

            var flags = Data.Win32.Kernel32.EXTENDED_STARTUPINFO_PRESENT;
            if (suspended) flags |= Data.Win32.Kernel32.CREATE_SUSPENDED;

            success = Win32.CreateProcessA(
                binaryPath,
                workingDirectory,
                flags,
                startupInfoEx,
                out var pi);

            if (!success)
                throw new Exception($"Failed to spawn {binaryPath}");

            // suppose we don't really care if this fails, it's not critical
            _ = Win32.DeleteProcThreadAttribute(startupInfoEx.lpAttributeList);
            Marshal.FreeHGlobal(lpValue);

            return pi;
        }

        public static bool Is64Bit => IntPtr.Size == 8;
    }
}