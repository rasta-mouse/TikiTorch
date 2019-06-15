using System.DirectoryServices.ActiveDirectory;

namespace TikiVader
{
    public class ActiveDirectory
    {
        public static string GetComputerDomainName()
        {
            Domain current = Domain.GetComputerDomain();
            return current.Name;
        }
    }
}