using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace TikiLoader
{
    public static class Generic
    {
        public static object DynamicApiInvoke(string dllName, string functionName, Type functionDelegateType, ref object[] parameters, bool canLoadFromDisk = false, bool resolveForwards = true)
        {
            var pFunction = GetLibraryAddress(dllName, functionName, canLoadFromDisk, resolveForwards);
            return DynamicFunctionInvoke(pFunction, functionDelegateType, ref parameters);
        }
        
        private static object DynamicFunctionInvoke(IntPtr functionPointer, Type functionDelegateType, ref object[] parameters)
        {
            var funcDelegate = Marshal.GetDelegateForFunctionPointer(functionPointer, functionDelegateType);
            return funcDelegate.DynamicInvoke(parameters);
        }
        
        private static IntPtr GetLibraryAddress(string dllName, string functionName, bool canLoadFromDisk = false, bool resolveForwards = true)
        {
            var hModule = GetLoadedModuleAddress(dllName);
            
            if (hModule == IntPtr.Zero && canLoadFromDisk)
            {
                hModule = LoadModuleFromDisk(dllName);
                
                if (hModule == IntPtr.Zero)
                {
                    throw new FileNotFoundException(dllName + ", unable to find the specified file.");
                }
            }
            else if (hModule == IntPtr.Zero)
            {
                throw new DllNotFoundException(dllName + ", Dll was not found.");
            }

            return GetExportAddress(hModule, functionName, resolveForwards);
        }
        
        private static IntPtr GetLoadedModuleAddress(string dllName)
        {
            var modules = Process.GetCurrentProcess().Modules;
            
            foreach (ProcessModule module in modules)
                if (module.FileName.ToLower().EndsWith(dllName.ToLower()))
                    return module.BaseAddress;

            return IntPtr.Zero;
        }
        
        public static IntPtr LoadModuleFromDisk(string dllPath)
        {
            var uModuleName = new Data.Native.UNICODE_STRING();
            Native.RtlInitUnicodeString(ref uModuleName, dllPath);

            var hModule = IntPtr.Zero;
            _ = Native.LdrLoadDll(IntPtr.Zero, 0, ref uModuleName, ref hModule);

            return hModule;
        }
        
        public static IntPtr GetExportAddress(IntPtr moduleBase, string exportName, bool resolveForwards = true)
        {
            var functionPtr = IntPtr.Zero;
            
            try
            {
                // Traverse the PE header in memory
                var peHeader = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + 0x3C));
                var optHeader = moduleBase.ToInt64() + peHeader + 0x18;
                var magic = Marshal.ReadInt16((IntPtr)optHeader);
                long pExport = 0;
                
                if (magic == 0x010b) pExport = optHeader + 0x60;
                else pExport = optHeader + 0x70;

                // Read -> IMAGE_EXPORT_DIRECTORY
                var exportRva = Marshal.ReadInt32((IntPtr)pExport);
                var ordinalBase = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + exportRva + 0x10));
                var numberOfNames = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + exportRva + 0x18));
                var functionsRva = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + exportRva + 0x1C));
                var namesRva = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + exportRva + 0x20));
                var ordinalsRva = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + exportRva + 0x24));

                // Loop the array of export name RVA's
                for (var i = 0; i < numberOfNames; i++)
                {
                    var functionName = Marshal.PtrToStringAnsi((IntPtr)(moduleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + namesRva + i * 4))));
                    
                    if (string.IsNullOrWhiteSpace(functionName)) continue;
                    if (!functionName.Equals(exportName, StringComparison.OrdinalIgnoreCase)) continue;
                    
                    var functionOrdinal = Marshal.ReadInt16((IntPtr)(moduleBase.ToInt64() + ordinalsRva + i * 2)) + ordinalBase;
                    var functionRva = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + functionsRva + (4 * (functionOrdinal - ordinalBase))));
                    functionPtr = (IntPtr)((long)moduleBase + functionRva);
                        
                    if (resolveForwards) functionPtr = GetForwardAddress(functionPtr);
                    break;
                }
            }
            catch
            {
                throw new InvalidOperationException("Failed to parse module exports.");
            }

            if (functionPtr == IntPtr.Zero)
                throw new MissingMethodException(exportName + ", export not found.");

            return functionPtr;
        }
        
        private static IntPtr GetForwardAddress(IntPtr exportAddress, bool canLoadFromDisk = false)
        {
            var functionPtr = exportAddress;
            
            try
            {
                // Assume it is a forward. If it is not, we will get an error
                var forwardNames = Marshal.PtrToStringAnsi(functionPtr);
                if (string.IsNullOrWhiteSpace(forwardNames)) return functionPtr;
                
                var values = forwardNames.Split('.');

                if (values.Length > 1)
                {
                    var forwardModuleName = values[0];
                    var forwardExportName = values[1];

                    // Check if it is an API Set mapping
                    var apiSet = GetApiSetMapping();
                    var lookupKey = forwardModuleName.Substring(0, forwardModuleName.Length - 2) + ".dll";
                    
                    if (apiSet.ContainsKey(lookupKey)) forwardModuleName = apiSet[lookupKey];
                    else forwardModuleName += ".dll";

                    var hModule = GetPebLdrModuleEntry(forwardModuleName);
                    
                    if (hModule == IntPtr.Zero && canLoadFromDisk)
                        hModule = LoadModuleFromDisk(forwardModuleName);
                    
                    if (hModule != IntPtr.Zero)
                        functionPtr = GetExportAddress(hModule, forwardExportName);
                }
            }
            catch
            {
                // Do nothing, it was not a forward
            }
            
            return functionPtr;
        }
        
        public static IntPtr GetPebLdrModuleEntry(string dllName)
        {
            // Get _PEB pointer
            var pbi = Native.NtQueryInformationProcessBasicInformation((IntPtr)(-1));

            // Set function variables
            uint ldrDataOffset = 0;
            uint inLoadOrderModuleListOffset = 0;
            
            if (IntPtr.Size == 4)
            {
                ldrDataOffset = 0xc;
                inLoadOrderModuleListOffset = 0xC;
            }
            else
            {
                ldrDataOffset = 0x18;
                inLoadOrderModuleListOffset = 0x10;
            }

            // Get module InLoadOrderModuleList -> _LIST_ENTRY
            var pebLdrData = Marshal.ReadIntPtr((IntPtr)((ulong)pbi.PebBaseAddress + ldrDataOffset));
            var pInLoadOrderModuleList = (IntPtr)((ulong)pebLdrData + inLoadOrderModuleListOffset);
            var le = (Data.Native.LIST_ENTRY)Marshal.PtrToStructure(pInLoadOrderModuleList, typeof(Data.Native.LIST_ENTRY));

            // Loop entries
            var flink = le.Flink;
            var hModule = IntPtr.Zero;
            var dte = (Data.PE.LDR_DATA_TABLE_ENTRY)Marshal.PtrToStructure(flink, typeof(Data.PE.LDR_DATA_TABLE_ENTRY));
            while (dte.InLoadOrderLinks.Flink != le.Blink)
            {
                // Match module name
                var fullName = Marshal.PtrToStringUni(dte.FullDllName.Buffer);
                if (string.IsNullOrWhiteSpace(fullName)) continue;
                
                if (fullName.EndsWith(dllName, StringComparison.OrdinalIgnoreCase))
                    hModule = dte.DllBase;

                // Move Ptr
                flink = dte.InLoadOrderLinks.Flink;
                dte = (Data.PE.LDR_DATA_TABLE_ENTRY)Marshal.PtrToStructure(flink, typeof(Data.PE.LDR_DATA_TABLE_ENTRY));
            }

            return hModule;
        }
        
        private static Dictionary<string, string> GetApiSetMapping()
        {
            var pbi = Native.NtQueryInformationProcessBasicInformation((IntPtr)(-1));
            var apiSetMapOffset = IntPtr.Size == 4 ? (uint)0x38 : 0x68;

            // Create mapping dictionary
            var apiSetDict = new Dictionary<string, string>();

            var pApiSetNamespace = Marshal.ReadIntPtr((IntPtr)((ulong)pbi.PebBaseAddress + apiSetMapOffset));
            var apiSetNamespace = (Data.PE.ApiSetNamespace)Marshal.PtrToStructure(pApiSetNamespace, typeof(Data.PE.ApiSetNamespace));
            
            for (var i = 0; i < apiSetNamespace.Count; i++)
            {
                var setEntry = new Data.PE.ApiSetNamespaceEntry();

                var pSetEntry = (IntPtr)((ulong)pApiSetNamespace + (ulong)apiSetNamespace.EntryOffset + (ulong)(i * Marshal.SizeOf(setEntry)));
                setEntry = (Data.PE.ApiSetNamespaceEntry)Marshal.PtrToStructure(pSetEntry, typeof(Data.PE.ApiSetNamespaceEntry));

                var apiSetEntryName = Marshal.PtrToStringUni((IntPtr)((ulong)pApiSetNamespace + (ulong)setEntry.NameOffset), setEntry.NameLength / 2);
                var apiSetEntryKey = apiSetEntryName.Substring(0, apiSetEntryName.Length - 2) + ".dll" ; // Remove the patch number and add .dll

                var setValue = new Data.PE.ApiSetValueEntry();
                var pSetValue = IntPtr.Zero;

                switch (setEntry.ValueLength)
                {
                    // If there is only one host, then use it
                    case 1:
                        pSetValue = (IntPtr)((ulong)pApiSetNamespace + (ulong)setEntry.ValueOffset);
                        break;
                    
                    case > 1:
                    {
                        // Loop through the hosts until we find one that is different from the key, if available
                        for (var j = 0; j < setEntry.ValueLength; j++)
                        {
                            var host = (IntPtr)((ulong)pApiSetNamespace + (ulong)setEntry.ValueOffset + (ulong)Marshal.SizeOf(setValue) * (ulong)j);
                            if (Marshal.PtrToStringUni(host) != apiSetEntryName)
                                pSetValue = (IntPtr)((ulong)pApiSetNamespace + (ulong)setEntry.ValueOffset + (ulong)Marshal.SizeOf(setValue) * (ulong)j);
                        }
                        
                        // If there is not one different from the key, then just use the key and hope that works
                        if (pSetValue == IntPtr.Zero)
                            pSetValue = (IntPtr)((ulong)pApiSetNamespace + (ulong)setEntry.ValueOffset);
                        
                        break;
                    }
                }

                // Get the host DLL's name from the entry
                setValue = (Data.PE.ApiSetValueEntry)Marshal.PtrToStructure(pSetValue, typeof(Data.PE.ApiSetValueEntry));
                
                var apiSetValue = string.Empty;
                if (setValue.ValueCount != 0)
                {
                    var pValue = (IntPtr)((ulong)pApiSetNamespace + (ulong)setValue.ValueOffset);
                    apiSetValue = Marshal.PtrToStringUni(pValue, setValue.ValueCount / 2);
                }

                // Add pair to dict
                apiSetDict.Add(apiSetEntryKey, apiSetValue);
            }

            // Return dict
            return apiSetDict;
        }
        
        public static IntPtr GetSyscallStub(string functionName)
        {
            // Verify process & architecture
            var isWow64 = Native.NtQueryInformationProcessWow64Information((IntPtr)(-1));
            if (IntPtr.Size == 4 && isWow64)
                throw new InvalidOperationException("Generating Syscall stubs is not supported for WOW64.");

            // Find the path for ntdll by looking at the currently loaded module
            var ntdllPath = string.Empty;
            var procModules = Process.GetCurrentProcess().Modules;
            
            foreach (ProcessModule module in procModules)
            {
                if (!module.FileName.EndsWith("ntdll.dll", StringComparison.OrdinalIgnoreCase)) continue;
                ntdllPath = module.FileName;
                break;
            }

            // Alloc module into memory for parsing
            var pModule = ManualMap.Map.AllocateFileToMemory(ntdllPath);

            // Fetch PE meta data
            var peInfo = GetPeMetaData(pModule);

            // Alloc PE image memory -> RW
            var baseAddress = IntPtr.Zero;
            var regionSize = peInfo.Is32Bit ? (IntPtr)peInfo.OptHeader32.SizeOfImage : (IntPtr)peInfo.OptHeader64.SizeOfImage;
            var sizeOfHeaders = peInfo.Is32Bit ? peInfo.OptHeader32.SizeOfHeaders : peInfo.OptHeader64.SizeOfHeaders;

            var pImage = Native.NtAllocateVirtualMemory(
                (IntPtr)(-1), ref baseAddress, IntPtr.Zero, ref regionSize,
                Data.Win32.Kernel32.MEM_COMMIT | Data.Win32.Kernel32.MEM_RESERVE,
                Data.Win32.WinNT.PAGE_READWRITE
            );

            // Write PE header to memory
            var bytesWritten = Native.NtWriteVirtualMemory((IntPtr)(-1), pImage, pModule, sizeOfHeaders);

            // Write sections to memory
            foreach (var ish in peInfo.Sections)
            {
                // Calculate offsets
                var pVirtualSectionBase = (IntPtr)((ulong)pImage + ish.VirtualAddress);
                var pRawSectionBase = (IntPtr)((ulong)pModule + ish.PointerToRawData);

                // Write data
                bytesWritten = Native.NtWriteVirtualMemory((IntPtr)(-1), pVirtualSectionBase, pRawSectionBase, ish.SizeOfRawData);
                
                if (bytesWritten != ish.SizeOfRawData)
                    throw new InvalidOperationException("Failed to write to memory.");
            }

            // Get Ptr to function
            var pFunc = GetExportAddress(pImage, functionName);
            
            if (pFunc == IntPtr.Zero)
                throw new InvalidOperationException("Failed to resolve ntdll export.");

            // Alloc memory for call stub
            baseAddress = IntPtr.Zero;
            regionSize = (IntPtr)0x50;
            
            var pCallStub = Native.NtAllocateVirtualMemory(
                (IntPtr)(-1), ref baseAddress, IntPtr.Zero, ref regionSize,
                Data.Win32.Kernel32.MEM_COMMIT | Data.Win32.Kernel32.MEM_RESERVE,
                Data.Win32.WinNT.PAGE_READWRITE
            );

            // Write call stub
            bytesWritten = Native.NtWriteVirtualMemory((IntPtr)(-1), pCallStub, pFunc, 0x50);
            
            if (bytesWritten != 0x50)
                throw new InvalidOperationException("Failed to write to memory.");

            // Change call stub permissions
            Native.NtProtectVirtualMemory((IntPtr)(-1), ref pCallStub, ref regionSize, Data.Win32.WinNT.PAGE_EXECUTE_READ);

            // Free temporary allocations
            Marshal.FreeHGlobal(pModule);
            regionSize = peInfo.Is32Bit ? (IntPtr)peInfo.OptHeader32.SizeOfImage : (IntPtr)peInfo.OptHeader64.SizeOfImage;

            Native.NtFreeVirtualMemory((IntPtr)(-1), ref pImage, ref regionSize, Data.Win32.Kernel32.MEM_RELEASE);

            return pCallStub;
        }
        
        private static Data.PE.PE_META_DATA GetPeMetaData(IntPtr pModule)
        {
            var peMetaData = new Data.PE.PE_META_DATA();
            
            try
            {
                var e_lfanew = (uint)Marshal.ReadInt32((IntPtr)((ulong)pModule + 0x3c));
                peMetaData.Pe = (uint)Marshal.ReadInt32((IntPtr)((ulong)pModule + e_lfanew));
                
                // Validate PE signature
                if (peMetaData.Pe != 0x4550)
                    throw new InvalidOperationException("Invalid PE signature.");
                
                peMetaData.ImageFileHeader = (Data.PE.IMAGE_FILE_HEADER)Marshal.PtrToStructure((IntPtr)((ulong)pModule + e_lfanew + 0x4), typeof(Data.PE.IMAGE_FILE_HEADER));
                
                var optHeader = (IntPtr)((ulong)pModule + e_lfanew + 0x18);
                var peArch = (ushort)Marshal.ReadInt16(optHeader);

                switch (peArch)
                {
                    // Validate PE arch
                    case 0x010b:  // Image is x32
                        peMetaData.Is32Bit = true;
                        peMetaData.OptHeader32 = (Data.PE.IMAGE_OPTIONAL_HEADER32)Marshal.PtrToStructure(optHeader, typeof(Data.PE.IMAGE_OPTIONAL_HEADER32));
                        break;
                    
                    case 0x020b:  // Image is x64
                        peMetaData.Is32Bit = false;
                        peMetaData.OptHeader64 = (Data.PE.IMAGE_OPTIONAL_HEADER64)Marshal.PtrToStructure(optHeader, typeof(Data.PE.IMAGE_OPTIONAL_HEADER64));
                        break;
                    
                    default:
                        throw new InvalidOperationException("Invalid magic value (PE32/PE32+).");
                }
                
                // Read sections
                var sectionArray = new Data.PE.IMAGE_SECTION_HEADER[peMetaData.ImageFileHeader.NumberOfSections];
                
                for (var i = 0; i < peMetaData.ImageFileHeader.NumberOfSections; i++)
                {
                    var sectionPtr = (IntPtr)((ulong)optHeader + peMetaData.ImageFileHeader.SizeOfOptionalHeader + (uint)(i * 0x28));
                    sectionArray[i] = (Data.PE.IMAGE_SECTION_HEADER)Marshal.PtrToStructure(sectionPtr, typeof(Data.PE.IMAGE_SECTION_HEADER));
                }
                
                peMetaData.Sections = sectionArray;
            }
            catch
            {
                throw new InvalidOperationException("Invalid module base specified.");
            }
            
            return peMetaData;
        }
    }
}