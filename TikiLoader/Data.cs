using System;
using System.Runtime.InteropServices;

namespace TikiLoader
{
    public static class Data
    {
        public static class Win32
        {
            public static class Kernel32
            {
                public const uint MEM_COMMIT = 0x1000;
                public const uint MEM_RESERVE = 0x2000;
                public const uint MEM_RELEASE = 0x8000;

                public const uint PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;
                public const uint PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY = 0x20007;

                public const long BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON = 0x100000000000;

                public const int CREATE_SUSPENDED = 0x4;
                public const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
                
                [Flags]
                public enum STARTF : uint
                {
                    STARTF_USESHOWWINDOW = 0x00000001,
                }
                
                [Flags]
                public enum StandardRights : uint
                {
                    Delete = 0x00010000,
                    ReadControl = 0x00020000,
                    WriteDac = 0x00040000,
                    WriteOwner = 0x00080000,
                    Synchronize = 0x00100000,
                    Required = 0x000f0000,
                    Read = ReadControl,
                    Write = ReadControl,
                    Execute = ReadControl,
                    All = 0x001f0000,

                    SpecificRightsAll = 0x0000ffff,
                    AccessSystemSecurity = 0x01000000,
                    MaximumAllowed = 0x02000000,
                    GenericRead = 0x80000000,
                    GenericWrite = 0x40000000,
                    GenericExecute = 0x20000000,
                    GenericAll = 0x10000000
                }
                
                [StructLayout(LayoutKind.Sequential)]
                public struct STARTUPINFO
                {
                    public uint cb;
                    public string lpReserved;
                    public string lpDesktop;
                    public string lpTitle;
                    public uint dwX;
                    public uint dwY;
                    public uint dwXSize;
                    public uint dwYSize;
                    public uint dwXCountChars;
                    public uint dwYCountChars;
                    public uint dwFillAttribute;
                    public uint dwFlags;
                    public ushort wShowWindow;
                    public ushort cbReserved2;
                    public IntPtr lpReserved2;
                    public IntPtr hStdInput;
                    public IntPtr hStdOutput;
                    public IntPtr hStdError;
                };

                [StructLayout(LayoutKind.Sequential)]
                public struct STARTUPINFOEX
                {
                    public STARTUPINFO Startupinfo;
                    public IntPtr lpAttributeList;
                }
                
                [StructLayout(LayoutKind.Sequential)]
                public struct PROCESS_INFORMATION
                {
                    public IntPtr hProcess;
                    public IntPtr hThread;
                    public uint dwProcessId;
                    public uint dwThreadId;
                };
            }

            public static class WinNT
            {
                public const uint INFINITE = 0xFFFFFFFF;

                public const uint PAGE_READWRITE = 0x04;
                public const uint PAGE_EXECUTE_READ = 0x20;
                public const uint PAGE_EXECUTE_READWRITE = 0x40;
                
                public const uint SEC_COMMIT = 0x08000000;

                public enum ACCESS_MASK : uint
                {
                    MAXIMUM_ALLOWED = 0x02000000,
                };
            }

            public static class WinBase
            {
                [StructLayout(LayoutKind.Sequential)]
                public struct SECURITY_ATTRIBUTES
                {
                    uint nLength;
                    IntPtr lpSecurityDescriptor;
                    bool bInheritHandle;
                };
            }
        }
        
        public static class Native
        {
            [StructLayout(LayoutKind.Sequential)]
            public struct UNICODE_STRING
            {
                public ushort Length;
                public ushort MaximumLength;
                public IntPtr Buffer;
            }
            
            public struct PROCESS_BASIC_INFORMATION
            {
                public IntPtr ExitStatus;
                public IntPtr PebBaseAddress;
                public IntPtr AffinityMask;
                public IntPtr BasePriority;
                public UIntPtr UniqueProcessId;
                public int InheritedFromUniqueProcessId;

                public int Size => Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION));
            }

            public enum PROCESSINFOCLASS : int
            {
                ProcessBasicInformation = 0
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct LIST_ENTRY
            {
                public IntPtr Flink;
                public IntPtr Blink;
            }
        }
        
        public static class PE
        {
            [StructLayout(LayoutKind.Explicit)]
            public struct ApiSetNamespace
            {
                [FieldOffset(0x0C)]
                public int Count;

                [FieldOffset(0x10)]
                public int EntryOffset;
            }
            
            [StructLayout(LayoutKind.Explicit)]
            public struct ApiSetNamespaceEntry
            {
                [FieldOffset(0x04)]
                public int NameOffset;

                [FieldOffset(0x08)]
                public int NameLength;

                [FieldOffset(0x10)]
                public int ValueOffset;

                [FieldOffset(0x14)]
                public int ValueLength;
            }
            
            [StructLayout(LayoutKind.Explicit)]
            public struct ApiSetValueEntry
            {
                [FieldOffset(0x00)]
                public int Flags;

                [FieldOffset(0x04)]
                public int NameOffset;

                [FieldOffset(0x08)]
                public int NameCount;

                [FieldOffset(0x0C)]
                public int ValueOffset;

                [FieldOffset(0x10)]
                public int ValueCount;
            }
            
            [StructLayout(LayoutKind.Sequential)]
            public struct LDR_DATA_TABLE_ENTRY
            {
                public Native.LIST_ENTRY InLoadOrderLinks;
                public Native.LIST_ENTRY InMemoryOrderLinks;
                public Native.LIST_ENTRY InInitializationOrderLinks;
                public IntPtr DllBase;
                public IntPtr EntryPoint;
                public uint SizeOfImage;
                public Native.UNICODE_STRING FullDllName;
                public Native.UNICODE_STRING BaseDllName;
            }
        }
    }
}