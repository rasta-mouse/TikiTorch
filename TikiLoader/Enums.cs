using System;

namespace TikiLoader
{
    public class Enums
    {
        public enum ThreadInformationClass : uint
        {
            ThreadBasicInformation,
            ThreadTimes,
            ThreadPriority,
            ThreadBasePriority,
            ThreadAffinityMask,
            ThreadImpersonationToken,
            ThreadDescriptorTableEntry,
            ThreadEnableAlignmentFaultFixup,
            ThreadEventPair,
            ThreadQuerySetWin32StartAddress,
            ThreadZeroTlsCell, // 10
            ThreadPerformanceCount,
            ThreadAmILastThread,
            ThreadIdealProcessor,
            ThreadPriorityBoost,
            ThreadSetTlsArrayAddress,
            ThreadIsIoPending,
            ThreadHideFromDebugger,
            ThreadBreakOnTermination,
            ThreadSwitchLegacyState,
            ThreadIsTerminated, // 20
            ThreadLastSystemCall,
            ThreadIoPriority,
            ThreadCycleTime,
            ThreadPagePriority,
            ThreadActualBasePriority,
            ThreadTebInformation,
            ThreadCSwitchMon,
            MaxThreadInfoClass
        }

        [Flags]
        public enum CreationFlags
        {
            CreateSuspended = 0x00000004,
            DetachedProcesds = 0x00000008,
            CreateNoWindow = 0x08000000,
            ExtendedStartupInfoPresent = 0x00080000
        }

        [Flags]
        public enum LogonFlags
        {
            LogonWithProfile = 0x00000001,
            LogonNetCredentialsOnly = 0x00000002
        }

        [Flags]
        public enum AllocationType
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            LargePages = 0x20000000,
            SecCommit = 0x08000000
    }

        [Flags]
        public enum MemoryProtection
        {
            Execute = 0x10,
            ExecuteRead = 0x20,
            ExecuteReadWrite = 0x40,
            ExecuteWriteCopy = 0x80,
            NoAccess = 0x01,
            ReadOnly = 0x02,
            ReadWrite = 0x04,
            WriteCopy = 0x08,
            GuardModifierflag = 0x100,
            NoCacheModifierflag = 0x200,
            WriteCombineModifierflag = 0x400
        }
    }
}