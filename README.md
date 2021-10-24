```
  *   )           )         *   )                        )  
` )  /(   (    ( /(   (   ` )  /(         (           ( /(  
 ( )(_))  )\   )\())  )\   ( )(_))   (    )(     (    )\()) 
(_(_())  ((_) ((_)\  ((_) (_(_())    )\  (()\    )\  ((_)\  
|_   _|   (_) | |(_)  (_) |_   _|   ((_)  ((_)  ((_) | |(_) 
  | |     | | | / /   | |   | |    / _ \ | '_| / _|  | ' \  
  |_|     |_| |_\_\   |_|   |_|    \___/ |_|   \__|  |_||_| 
```

TikiTorch was named in homage to [CACTUSTORCH](https://github.com/vysecurity/CACTUSTORCH) by [Vincent Yiu](https://twitter.com/vysecurity).  The basic concept of CACTUSTORCH is that it spawns a new process, allocates a region of memory, writes shellcode into that region, and then uses `CreateRemoteThread` to execute said shellcode.  Both the process and shellcode are specified by the user.  The primary use case is as a JavaScript/VBScript loader via [DotNetToJScript](https://github.com/tyranid/DotNetToJScript), which can be utilised in a variety of payload types such as HTA and VBA.

TikiTorch takes this a step further by offering more advanced processs spawning and injection:

- Spawn x86 and x64 processes.
- PPID Spoofing and BlockDLLs.
- Supports [Module Stomping](https://offensivedefence.co.uk/posts/module-stomping/) and [Process Hollowing](https://github.com/ambray/ProcessHollowing/blob/master/ShellLoader/Loader.cs) for injection.
- Utilises [DInvoke](https://github.com/TheWover/DInvoke) to call Nt* APIs, or optionally use Syscalls.

The TikiTorch solution has 2 projects:
1. TikiLoader
2. TikiSpawn

The TikiLoader is the core DLL that handles all of the actual spawning and injection logic.  TikiSpawn is a demo console app showing how to consume the TikiLoader.

## Basic Usage

```c#
using System.Diagnostics;
using TikiLoader;

var hollower = new Hollower
{
    BinaryPath = @"C:\Windows\System32\notepad.exe",
    WorkingDirectory = @"C:\Windows\System32",
    ParentId = Process.GetProcessesByName("explorer")[0].Id,
    BlockDlls = true
};
            
hollower.Hollow(Shellcode, true);
```