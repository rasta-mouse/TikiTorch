using System.Linq;
using System.Net.NetworkInformation;

namespace TikiVader
{
    public class Network
    {
        public static string GetMACAddress()
        {
            NetworkInterface nic = NetworkInterface.GetAllNetworkInterfaces().First();
            return nic.GetPhysicalAddress().ToString();
        }
    }
}