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
            CREATE_SUSPENDED = 0x00000004,
            DETACHED_PROCESS = 0x00000008,
            CREATE_NEW_CONSOLE = 0x00000010,
            CREATE_NEW_PROCESS_GROUP = 0x00000200,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            CREATE_SEPARATE_WOW_VDM = 0x00000800,
            CREATE_DEFAULT_ERROR_MODE = 0x04000000,
            CREATE_NO_WINDOW = 0x08000000
        }

        [Flags]
        public enum LogonFlags
        {
            LOGON_WITH_PROFILE = 0x00000001,
            LOGON_NETCREDENTIALS_ONLY = 0x00000002

        }
    }
}
