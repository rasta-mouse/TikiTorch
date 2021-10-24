using System;
using System.Runtime.InteropServices;

namespace TikiLoader
{
    public struct Delegates
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool InitializeProcThreadAttributeList(
            IntPtr lpAttributeList,
            int dwAttributeCount,
            int dwFlags,
            ref IntPtr lpSize);
        
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool UpdateProcThreadAttribute(
            IntPtr lpAttributeList,
            uint dwFlags,
            IntPtr attribute,
            IntPtr lpValue,
            IntPtr cbSize,
            IntPtr lpPreviousValue,
            IntPtr lpReturnSize);
        
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool DeleteProcThreadAttributeList(
            IntPtr lpAttributeList);
        
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool CreateProcessA(
            string lpApplicationName,
            string lpCommandLine,
            ref Data.Win32.WinBase.SECURITY_ATTRIBUTES lpProcessAttributes,
            ref Data.Win32.WinBase.SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref Data.Win32.Kernel32.STARTUPINFOEX lpStartupInfoEx,
            out Data.Win32.Kernel32.PROCESS_INFORMATION lpProcessInformation);
        
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate void RtlZeroMemory(
            IntPtr destination,
            int length);
        
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtQueryInformationProcess(
            IntPtr processHandle,
            Data.Native.PROCESSINFOCLASS processInformationClass,
            IntPtr processInformation,
            int processInformationLength,
            ref uint returnLength);
        
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate void RtlInitUnicodeString(
            ref Data.Native.UNICODE_STRING destinationString,
            [MarshalAs(UnmanagedType.LPWStr)]
            string sourceString);
        
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint LdrLoadDll(
            IntPtr pathToFile,
            uint dwFlags,
            ref Data.Native.UNICODE_STRING moduleFileName,
            ref IntPtr moduleHandle);
        
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtAllocateVirtualMemory(
            IntPtr processHandle,
            ref IntPtr baseAddress,
            IntPtr zeroBits,
            ref IntPtr regionSize,
            uint allocationType,
            uint protect);
        
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtWriteVirtualMemory(
            IntPtr processHandle,
            IntPtr baseAddress,
            IntPtr buffer,
            uint bufferLength,
            ref uint bytesWritten);
        
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtReadVirtualMemory(
            IntPtr processHandle,
            IntPtr baseAddress,
            IntPtr buffer,
            uint numberOfBytesToRead,
            ref uint numberOfBytesRead);
        
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtFreeVirtualMemory(
            IntPtr processHandle,
            ref IntPtr baseAddress,
            ref IntPtr regionSize,
            uint freeType);
        
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtCreateThreadEx(
            ref IntPtr threadHandle,
            Data.Win32.WinNT.ACCESS_MASK desiredAccess,
            IntPtr objectAttributes,
            IntPtr processHandle,
            IntPtr startAddress,
            IntPtr parameter,
            bool createSuspended,
            int stackZeroBits,
            int sizeOfStack,
            int maximumStackSize,
            IntPtr attributeList);
        
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint WaitForSingleObject(
            IntPtr hHandle,
            uint dwMilliseconds);
        
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtProtectVirtualMemory(
            IntPtr processHandle,
            ref IntPtr baseAddress,
            ref IntPtr regionSize,
            uint newProtect,
            ref uint oldProtect);
        
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtUnmapViewOfSection(
            IntPtr hProc,
            IntPtr baseAddress);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtResumeThread(
            IntPtr hThread,
            IntPtr suspendCount);
        
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtCreateSection(
            ref IntPtr sectionHandle,
            uint desiredAccess,
            IntPtr objectAttributes,
            ref ulong maximumSize,
            uint sectionPageProtection,
            uint allocationAttributes,
            IntPtr fileHandle);
        
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtMapViewOfSection(
            IntPtr sectionHandle,
            IntPtr processHandle,
            ref IntPtr baseAddress,
            IntPtr zeroBits,
            IntPtr commitSize,
            IntPtr sectionOffset,
            ref ulong viewSize,
            uint inheritDisposition,
            uint allocationType,
            uint win32Protect);
        
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool CloseHandle(IntPtr hProcess);
    }
}