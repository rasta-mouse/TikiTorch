using System;
using System.Management;

namespace TikiVader
{
    public class Host
    {
        public static string GetMachineName()
        {
            return Environment.MachineName;
        }

        public static bool IsVirtualMachine()
        {
            using (var searcher = new ManagementObjectSearcher("Select * from Win32_ComputerSystem"))
            {
                using (var items = searcher.Get())
                {
                    foreach (var item in items)
                    {
                        string manufacturer = item["Manufacturer"].ToString().ToLower();

                        if ((manufacturer == "microsoft corporation" && item["Model"].ToString().ToUpperInvariant().Contains("VIRTUAL"))
                            || manufacturer.Contains("vmware")
                            || manufacturer.Contains("xen")
                            || item["Model"].ToString() == "VirtualBox")
                        {
                            return true;
                        }
                    }
                }
            }

            return false;
        }
    }
}