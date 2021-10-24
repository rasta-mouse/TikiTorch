using System;
using System.IO;
using System.Runtime.InteropServices;

namespace TikiLoader
{
    public static class ManualMap
    {
        public static class Map
        {
            public static IntPtr AllocateFileToMemory(string filePath)
            {
                if (!File.Exists(filePath))
                    throw new InvalidOperationException("Filepath not found.");

                var fileBytes = File.ReadAllBytes(filePath);
                return AllocateBytesToMemory(fileBytes);
            }
            
            private static IntPtr AllocateBytesToMemory(byte[] fileBytes)
            {
                var pFile = Marshal.AllocHGlobal(fileBytes.Length);
                Marshal.Copy(fileBytes, 0, pFile, fileBytes.Length);
                return pFile;
            }
        }
    }
}