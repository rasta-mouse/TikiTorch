using System;
using System.Runtime.InteropServices;

namespace TikiLoader
{
    public static class Native
    {
        public static Data.Native.PROCESS_BASIC_INFORMATION NtQueryInformationProcessBasicInformation(IntPtr hProcess)
        {
            _ = NtQueryInformationProcess(hProcess, Data.Native.PROCESSINFOCLASS.ProcessBasicInformation, out var pProcInfo);
            return (Data.Native.PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(pProcInfo, typeof(Data.Native.PROCESS_BASIC_INFORMATION));
        }
        
        public static bool NtQueryInformationProcessWow64Information(IntPtr hProcess)
        {
            _ = NtQueryInformationProcess(hProcess, Data.Native.PROCESSINFOCLASS.ProcessWow64Information, out var pProcInfo);
            return Marshal.ReadIntPtr(pProcInfo) != IntPtr.Zero;
        }
        
        private static uint NtQueryInformationProcess(IntPtr hProcess, Data.Native.PROCESSINFOCLASS processInfoClass, out IntPtr pProcInfo)
        {
            int processInformationLength;
            uint retLen = 0;

            switch (processInfoClass)
            {
                case Data.Native.PROCESSINFOCLASS.ProcessWow64Information:
                    pProcInfo = Marshal.AllocHGlobal(IntPtr.Size);
                    RtlZeroMemory(pProcInfo, IntPtr.Size);
                    processInformationLength = IntPtr.Size;
                    break;
                
                case Data.Native.PROCESSINFOCLASS.ProcessBasicInformation:
                    var pbi = new Data.Native.PROCESS_BASIC_INFORMATION();
                    pProcInfo = Marshal.AllocHGlobal(Marshal.SizeOf(pbi));
                    RtlZeroMemory(pProcInfo, Marshal.SizeOf(pbi));
                    Marshal.StructureToPtr(pbi, pProcInfo, true);
                    processInformationLength = Marshal.SizeOf(pbi);
                    break;
                
                default:
                    throw new InvalidOperationException($"Invalid ProcessInfoClass: {processInfoClass}");
            }

            object[] parameters = { hProcess, processInfoClass, pProcInfo, processInformationLength, retLen };

            var result = (uint)Generic.DynamicApiInvoke("ntdll.dll", "NtQueryInformationProcess", typeof(Delegates.NtQueryInformationProcess), ref parameters);
            pProcInfo = (IntPtr)parameters[2];

            return result;
        }
        
        private static void RtlZeroMemory(IntPtr destination, int length)
        {
            object[] parameters = { destination, length };
            Generic.DynamicApiInvoke("ntdll.dll", "RtlZeroMemory", typeof(Delegates.RtlZeroMemory), ref parameters);
        }
        
        public static void RtlInitUnicodeString(ref Data.Native.UNICODE_STRING destinationString, [MarshalAs(UnmanagedType.LPWStr)] string sourceString)
        {
            object[] parameters = { destinationString, sourceString };
            Generic.DynamicApiInvoke("ntdll.dll", "RtlInitUnicodeString", typeof(Delegates.RtlInitUnicodeString), ref parameters);
            destinationString = (Data.Native.UNICODE_STRING)parameters[0];
        }
        
        public static uint LdrLoadDll(IntPtr pathToFile, uint dwFlags, ref Data.Native.UNICODE_STRING moduleFileName, ref IntPtr moduleHandle)
        {
            object[] parameters = { pathToFile, dwFlags, moduleFileName, moduleHandle };
            var result = (uint)Generic.DynamicApiInvoke("ntdll.dll", "LdrLoadDll", typeof(Delegates.LdrLoadDll), ref parameters);
            
            moduleHandle = (IntPtr)parameters[3];
            return result;
        }
        
        public static IntPtr NtAllocateVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, IntPtr zeroBits, ref IntPtr regionSize, uint allocationType, uint protect)
        {
            object[] parameters = { processHandle, baseAddress, zeroBits, regionSize, allocationType, protect };
            _ = (uint)Generic.DynamicApiInvoke("ntdll.dll", "NtAllocateVirtualMemory", typeof(Delegates.NtAllocateVirtualMemory), ref parameters);

            baseAddress = (IntPtr)parameters[1];
            return baseAddress;
        }
        
        public static uint NtWriteVirtualMemory(IntPtr processHandle, IntPtr baseAddress, IntPtr buffer, uint bufferLength)
        {
            uint bytesWritten = 0;
            object[] parameters = { processHandle, baseAddress, buffer, bufferLength, bytesWritten };

            _ = (uint)Generic.DynamicApiInvoke("ntdll.dll", "NtWriteVirtualMemory", typeof(Delegates.NtWriteVirtualMemory), ref parameters);
            bytesWritten = (uint)parameters[4];
            return bytesWritten;
        }
        
        public static void NtFreeVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, ref IntPtr regionSize, uint freeType)
        {
            object[] parameters = { processHandle, baseAddress, regionSize, freeType };
            _ = (uint)Generic.DynamicApiInvoke("ntdll.dll", "NtFreeVirtualMemory", typeof(Delegates.NtFreeVirtualMemory), ref parameters);
        }
        
        public static uint NtCreateThreadEx(ref IntPtr threadHandle, Data.Win32.WinNT.ACCESS_MASK desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, bool createSuspended, int stackZeroBits, int sizeOfStack, int maximumStackSize, IntPtr attributeList)
        {
            object[] parameters = { threadHandle, desiredAccess, objectAttributes, processHandle, startAddress, parameter, createSuspended, stackZeroBits,
                sizeOfStack, maximumStackSize, attributeList };

            var result = (uint)Generic.DynamicApiInvoke("ntdll.dll", "NtCreateThreadEx", typeof(Delegates.NtCreateThreadEx), ref parameters);
            threadHandle = (IntPtr)parameters[0];
            return result;
        }
        
        public static uint NtProtectVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, ref IntPtr regionSize, uint newProtect)
        {
            uint oldProtect = 0;
            object[] parameters = { processHandle, baseAddress, regionSize, newProtect, oldProtect };

            _ = (uint)Generic.DynamicApiInvoke(@"ntdll.dll", @"NtProtectVirtualMemory", typeof(Delegates.NtProtectVirtualMemory), ref parameters);
            oldProtect = (uint)parameters[4];
            return oldProtect;
        }
        
        public static uint NtReadVirtualMemory(IntPtr processHandle, IntPtr baseAddress, IntPtr buffer, ref uint numberOfBytesToRead)
        {
            uint numberOfBytesRead = 0;
            object[] parameters = { processHandle, baseAddress, buffer, numberOfBytesToRead, numberOfBytesRead };

            _ = (uint)Generic.DynamicApiInvoke("ntdll.dll", "NtReadVirtualMemory", typeof(Delegates.NtReadVirtualMemory), ref parameters);

            numberOfBytesRead = (uint)parameters[4];
            return numberOfBytesRead;
        }
        
        public static uint NtCreateSection(ref IntPtr sectionHandle, uint desiredAccess, IntPtr objectAttributes, ref ulong maximumSize, uint sectionPageProtection, uint allocationAttributes, IntPtr fileHandle)
        {
            object[] parameters = { sectionHandle, desiredAccess, objectAttributes, maximumSize, sectionPageProtection, allocationAttributes, fileHandle };
            var result = (uint)Generic.DynamicApiInvoke("ntdll.dll", "NtCreateSection", typeof(Delegates.NtCreateSection), ref parameters);

            sectionHandle = (IntPtr)parameters[0];
            maximumSize = (ulong)parameters[3];

            return result;
        }
        
        public static uint NtMapViewOfSection(IntPtr sectionHandle, IntPtr processHandle, ref IntPtr baseAddress, IntPtr zeroBits, IntPtr commitSize, IntPtr sectionOffset, ref ulong viewSize, uint inheritDisposition, uint allocationType, uint win32Protect)
        {
            object[] parameters = { sectionHandle, processHandle, baseAddress, zeroBits, commitSize, sectionOffset, viewSize, inheritDisposition, allocationType, win32Protect };
            var result = (uint)Generic.DynamicApiInvoke("ntdll.dll", "NtMapViewOfSection", typeof(Delegates.NtMapViewOfSection), ref parameters);

            baseAddress = (IntPtr) parameters[2];
            viewSize = (ulong) parameters[6];

            return result;
        }
        
        public static uint NtUnmapViewOfSection(IntPtr hProcess, IntPtr baseAddress)
        {
            object[] parameters = { hProcess, baseAddress };
            var result = (uint)Generic.DynamicApiInvoke("ntdll.dll", "NtUnmapViewOfSection", typeof(Delegates.NtUnmapViewOfSection), ref parameters);
            return result;
        }
        
        public static uint NtResumeThread(IntPtr hThread, IntPtr suspendCount)
        {
            object[] parameters = { hThread, suspendCount };
            var result = (uint)Generic.DynamicApiInvoke("ntdll.dll", "NtResumeThread", typeof(Delegates.NtResumeThread), ref parameters);
            return result;
        }
    }
}