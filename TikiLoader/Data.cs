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
                ProcessBasicInformation = 0, // 0, q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
                ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
                ProcessIoCounters, // q: IO_COUNTERS
                ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX
                ProcessTimes, // q: KERNEL_USER_TIMES
                ProcessBasePriority, // s: KPRIORITY
                ProcessRaisePriority, // s: ULONG
                ProcessDebugPort, // q: HANDLE
                ProcessExceptionPort, // s: HANDLE
                ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
                ProcessLdtInformation, // 10
                ProcessLdtSize,
                ProcessDefaultHardErrorMode, // qs: ULONG
                ProcessIoPortHandlers, // (kernel-mode only)
                ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
                ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
                ProcessUserModeIOPL,
                ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
                ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
                ProcessWx86Information,
                ProcessHandleCount, // 20, q: ULONG, PROCESS_HANDLE_INFORMATION
                ProcessAffinityMask, // s: KAFFINITY
                ProcessPriorityBoost, // qs: ULONG
                ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
                ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
                ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
                ProcessWow64Information, // q: ULONG_PTR
                ProcessImageFileName, // q: UNICODE_STRING
                ProcessLUIDDeviceMapsEnabled, // q: ULONG
                ProcessBreakOnTermination, // qs: ULONG
                ProcessDebugObjectHandle, // 30, q: HANDLE
                ProcessDebugFlags, // qs: ULONG
                ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables, otherwise enables
                ProcessIoPriority, // qs: ULONG
                ProcessExecuteFlags, // qs: ULONG
                ProcessResourceManagement,
                ProcessCookie, // q: ULONG
                ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
                ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION
                ProcessPagePriority, // q: ULONG
                ProcessInstrumentationCallback, // 40
                ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
                ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]
                ProcessImageFileNameWin32, // q: UNICODE_STRING
                ProcessImageFileMapping, // q: HANDLE (input)
                ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
                ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
                ProcessGroupInformation, // q: USHORT[]
                ProcessTokenVirtualizationEnabled, // s: ULONG
                ProcessConsoleHostProcess, // q: ULONG_PTR
                ProcessWindowInformation, // 50, q: PROCESS_WINDOW_INFORMATION
                ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
                ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
                ProcessDynamicFunctionTableInformation,
                ProcessHandleCheckingMode,
                ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
                ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
                MaxProcessInfoClass
            };

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
                [FieldOffset(0x0C)] public int Count;

                [FieldOffset(0x10)] public int EntryOffset;
            }

            [StructLayout(LayoutKind.Explicit)]
            public struct ApiSetNamespaceEntry
            {
                [FieldOffset(0x04)] public int NameOffset;

                [FieldOffset(0x08)] public int NameLength;

                [FieldOffset(0x10)] public int ValueOffset;

                [FieldOffset(0x14)] public int ValueLength;
            }

            [StructLayout(LayoutKind.Explicit)]
            public struct ApiSetValueEntry
            {
                [FieldOffset(0x00)] public int Flags;

                [FieldOffset(0x04)] public int NameOffset;

                [FieldOffset(0x08)] public int NameCount;

                [FieldOffset(0x0C)] public int ValueOffset;

                [FieldOffset(0x10)] public int ValueCount;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct PE_META_DATA
            {
                public uint Pe;
                public bool Is32Bit;
                public IMAGE_FILE_HEADER ImageFileHeader;
                public IMAGE_OPTIONAL_HEADER32 OptHeader32;
                public IMAGE_OPTIONAL_HEADER64 OptHeader64;
                public IMAGE_SECTION_HEADER[] Sections;
            }

            [StructLayout(LayoutKind.Sequential, Pack = 1)]
            public struct IMAGE_FILE_HEADER
            {
                public ushort Machine;
                public ushort NumberOfSections;
                public uint TimeDateStamp;
                public uint PointerToSymbolTable;
                public uint NumberOfSymbols;
                public ushort SizeOfOptionalHeader;
                public ushort Characteristics;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct IMAGE_DATA_DIRECTORY
            {
                public uint VirtualAddress;
                public uint Size;
            }

            [StructLayout(LayoutKind.Sequential, Pack = 1)]
            public struct IMAGE_OPTIONAL_HEADER32
            {
                public ushort Magic;
                public byte MajorLinkerVersion;
                public byte MinorLinkerVersion;
                public uint SizeOfCode;
                public uint SizeOfInitializedData;
                public uint SizeOfUninitializedData;
                public uint AddressOfEntryPoint;
                public uint BaseOfCode;
                public uint BaseOfData;
                public uint ImageBase;
                public uint SectionAlignment;
                public uint FileAlignment;
                public ushort MajorOperatingSystemVersion;
                public ushort MinorOperatingSystemVersion;
                public ushort MajorImageVersion;
                public ushort MinorImageVersion;
                public ushort MajorSubsystemVersion;
                public ushort MinorSubsystemVersion;
                public uint Win32VersionValue;
                public uint SizeOfImage;
                public uint SizeOfHeaders;
                public uint CheckSum;
                public ushort Subsystem;
                public ushort DllCharacteristics;
                public uint SizeOfStackReserve;
                public uint SizeOfStackCommit;
                public uint SizeOfHeapReserve;
                public uint SizeOfHeapCommit;
                public uint LoaderFlags;
                public uint NumberOfRvaAndSizes;

                public IMAGE_DATA_DIRECTORY ExportTable;
                public IMAGE_DATA_DIRECTORY ImportTable;
                public IMAGE_DATA_DIRECTORY ResourceTable;
                public IMAGE_DATA_DIRECTORY ExceptionTable;
                public IMAGE_DATA_DIRECTORY CertificateTable;
                public IMAGE_DATA_DIRECTORY BaseRelocationTable;
                public IMAGE_DATA_DIRECTORY Debug;
                public IMAGE_DATA_DIRECTORY Architecture;
                public IMAGE_DATA_DIRECTORY GlobalPtr;
                public IMAGE_DATA_DIRECTORY TLSTable;
                public IMAGE_DATA_DIRECTORY LoadConfigTable;
                public IMAGE_DATA_DIRECTORY BoundImport;
                public IMAGE_DATA_DIRECTORY IAT;
                public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
                public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
                public IMAGE_DATA_DIRECTORY Reserved;
            }

            [StructLayout(LayoutKind.Sequential, Pack = 1)]
            public struct IMAGE_OPTIONAL_HEADER64
            {
                public ushort Magic;
                public byte MajorLinkerVersion;
                public byte MinorLinkerVersion;
                public uint SizeOfCode;
                public uint SizeOfInitializedData;
                public uint SizeOfUninitializedData;
                public uint AddressOfEntryPoint;
                public uint BaseOfCode;
                public ulong ImageBase;
                public uint SectionAlignment;
                public uint FileAlignment;
                public ushort MajorOperatingSystemVersion;
                public ushort MinorOperatingSystemVersion;
                public ushort MajorImageVersion;
                public ushort MinorImageVersion;
                public ushort MajorSubsystemVersion;
                public ushort MinorSubsystemVersion;
                public uint Win32VersionValue;
                public uint SizeOfImage;
                public uint SizeOfHeaders;
                public uint CheckSum;
                public ushort Subsystem;
                public ushort DllCharacteristics;
                public ulong SizeOfStackReserve;
                public ulong SizeOfStackCommit;
                public ulong SizeOfHeapReserve;
                public ulong SizeOfHeapCommit;
                public uint LoaderFlags;
                public uint NumberOfRvaAndSizes;

                public IMAGE_DATA_DIRECTORY ExportTable;
                public IMAGE_DATA_DIRECTORY ImportTable;
                public IMAGE_DATA_DIRECTORY ResourceTable;
                public IMAGE_DATA_DIRECTORY ExceptionTable;
                public IMAGE_DATA_DIRECTORY CertificateTable;
                public IMAGE_DATA_DIRECTORY BaseRelocationTable;
                public IMAGE_DATA_DIRECTORY Debug;
                public IMAGE_DATA_DIRECTORY Architecture;
                public IMAGE_DATA_DIRECTORY GlobalPtr;
                public IMAGE_DATA_DIRECTORY TLSTable;
                public IMAGE_DATA_DIRECTORY LoadConfigTable;
                public IMAGE_DATA_DIRECTORY BoundImport;
                public IMAGE_DATA_DIRECTORY IAT;
                public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
                public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
                public IMAGE_DATA_DIRECTORY Reserved;
            }
            
            [StructLayout(LayoutKind.Explicit)]
            public struct IMAGE_SECTION_HEADER
            {
                [FieldOffset(0)]
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
                public char[] Name;
                [FieldOffset(8)]
                public uint VirtualSize;
                [FieldOffset(12)]
                public uint VirtualAddress;
                [FieldOffset(16)]
                public uint SizeOfRawData;
                [FieldOffset(20)]
                public uint PointerToRawData;
                [FieldOffset(24)]
                public uint PointerToRelocations;
                [FieldOffset(28)]
                public uint PointerToLinenumbers;
                [FieldOffset(32)]
                public ushort NumberOfRelocations;
                [FieldOffset(34)]
                public ushort NumberOfLinenumbers;
                [FieldOffset(36)]
                public DataSectionFlags Characteristics;

                public string Section => new(Name);
            }
            
            [Flags]
            public enum DataSectionFlags : uint
            {
                TYPE_NO_PAD = 0x00000008,
                CNT_CODE = 0x00000020,
                CNT_INITIALIZED_DATA = 0x00000040,
                CNT_UNINITIALIZED_DATA = 0x00000080,
                LNK_INFO = 0x00000200,
                LNK_REMOVE = 0x00000800,
                LNK_COMDAT = 0x00001000,
                NO_DEFER_SPEC_EXC = 0x00004000,
                GPREL = 0x00008000,
                MEM_FARDATA = 0x00008000,
                MEM_PURGEABLE = 0x00020000,
                MEM_16BIT = 0x00020000,
                MEM_LOCKED = 0x00040000,
                MEM_PRELOAD = 0x00080000,
                ALIGN_1BYTES = 0x00100000,
                ALIGN_2BYTES = 0x00200000,
                ALIGN_4BYTES = 0x00300000,
                ALIGN_8BYTES = 0x00400000,
                ALIGN_16BYTES = 0x00500000,
                ALIGN_32BYTES = 0x00600000,
                ALIGN_64BYTES = 0x00700000,
                ALIGN_128BYTES = 0x00800000,
                ALIGN_256BYTES = 0x00900000,
                ALIGN_512BYTES = 0x00A00000,
                ALIGN_1024BYTES = 0x00B00000,
                ALIGN_2048BYTES = 0x00C00000,
                ALIGN_4096BYTES = 0x00D00000,
                ALIGN_8192BYTES = 0x00E00000,
                ALIGN_MASK = 0x00F00000,
                LNK_NRELOC_OVFL = 0x01000000,
                MEM_DISCARDABLE = 0x02000000,
                MEM_NOT_CACHED = 0x04000000,
                MEM_NOT_PAGED = 0x08000000,
                MEM_SHARED = 0x10000000,
                MEM_EXECUTE = 0x20000000,
                MEM_READ = 0x40000000,
                MEM_WRITE = 0x80000000
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