```
  *   )           )         *   )                        )  
` )  /(   (    ( /(   (   ` )  /(         (           ( /(  
 ( )(_))  )\   )\())  )\   ( )(_))   (    )(     (    )\()) 
(_(_())  ((_) ((_)\  ((_) (_(_())    )\  (()\    )\  ((_)\  
|_   _|   (_) | |(_)  (_) |_   _|   ((_)  ((_)  ((_) | |(_) 
  | |     | | | / /   | |   | |    / _ \ | '_| / _|  | ' \  
  |_|     |_| |_\_\   |_|   |_|    \___/ |_|   \__|  |_||_| 
```

## Intro

TikiTorch was named in homage to [CACTUSTORCH](https://github.com/vysecurity/CACTUSTORCH) by [Vincent Yiu](https://twitter.com/vysecurity).  The basic concept of CACTUSTORCH is that it spawns a new process, then uses `CreateRemoteThread` to run the desired shellcode within that target process.  Both the process and shellcode are specified by the user.

This is pretty flexible as it allows an operator to run an HTTP agent in a process such as `iexplore.exe`, rather than something more arbitrary like `rundll32.exe`.

TikiTorch follows the same concept but uses `Process Hollowing` techniques instead of `CRT`.

## Usage

`TikiTorch` is a Visual Basic solution, split into 8 projects.

- TikiLoader
- TikiSpawn
- TikiSpawnAs
- TikiSpawnElevated
- TikiCpl
- TikiService
- TikiThings
- TikiVader

### TikiLoader
A .NET Library that contains all the process hollowing code, used as a reference by the other Tiki projects.

### TikiSpawn
A .NET Library designed to bootstrap an agent via some initial delivery, can be used with [DotNetToJScript](https://github.com/tyranid/DotNetToJScript) in conjunction with lolbins.

### TikiSpawnAs
A .NET exe used to spawn agents with alternate creds.

```
> TikiSpawnAs.exe
  -d, --domain=VALUE         Domain (defaults to local machine)
  -u, --username=VALUE       Username
  -p, --password=VALUE       Password
  -b, --binary=VALUE         Binary to spawn & hollow
  -h, -?, --help             Show this help
```

### TikiSpawnElevated
A .NET exe used to spawn a high integrity agent using the UAC Token Duplication bypass.  Defunct in 1809 and above.

```
> TikiSpawnElevated.exe
  -b, --binary=VALUE         Binary to spawn & hollow
  -p, --pid=VALUE            Elevated PID to impersonate (optional)
  -h, -?, --help             Show this help
```

### TikiService
A .NET Service Binary, allowing one to execute TikiTorch payloads remotely via the Service Control Manager (à la PsExec).

### TikiCpl
Generates a Control Panel (.cpl) formatted DLL that executes gzipped base64 encoded shellcode from a resource file.  Follow the instructions [here](https://github.com/rvrsh3ll/CPLResourceRunner) to generate shellcode in the correct format.

### TikiThings
A DLL that integrates AppLocker bypasses from [AllTheThings](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1117/src/AllTheThings.cs).

```text
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U TikiThings.dll
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /U TikiThings.dll
regsvr32 /s /u TikiThings.dll
regsvr32 /s TikiThings.dll
rundll32 TikiThings.dll,EntryPoint
odbcconf /s /a { REGSVR TikiThings.dll }
regsvr32 /s /n /i:"blah" TikiThings.dll
```

### TikiVader
Like TikiLoader, a .NET Library that can be used as a reference by the other Tiki projects.  It contains pre-canned functions for enumerating environmental variables such as current domain name and computer hostname, as a means of ensuring the TikiLoader only executes in your desired target environment.  It's not an evasion tactic, but a safety one.

## Aggressor
For Cobalt Strike users, the [Aggressor](https://github.com/rasta-mouse/TikiTorch/tree/master/Aggressor) directory contains `TikiTorch.cna` which provides various beacon commands to automate some TikiTorch tasks.  These also require tools from my [MiscTools repo](https://github.com/rasta-mouse/MiscTools).

## Credits

- Aaron Bray for [Loader.cs](https://github.com/ambray/ProcessHollowing/blob/master/ShellLoader/Loader.cs)
- [James Foreshaw](https://twitter.com/tiraniddo) for C# advice
- [Vincent Yiu](https://twitter.com/vysecurity) for inspiration
- [Kevin Mitnick](@kevinmitnick) for letting me test in his lab
- [Steve Borosh](https://twitter.com/424f424f) for TikiCpl
- [Casey Smith](https://twitter.com/subTee) for [AllTheThings](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1117/src/AllTheThings.cs)
- [Marcus Gelderman](https://gist.github.com/marcgeld) for [psCompress.ps1](https://gist.github.com/marcgeld/bfacfd8d70b34fdf1db0022508b02aca)
- [Will Schroeder](https://twitter.com/harmj0y) for [Seatbelt](https://github.com/GhostPack/Seatbelt)

## Further Reading

- [The Wiki!!](https://github.com/rasta-mouse/TikiTorch/wiki)
- https://rastamouse.me/tags/tikitorch/
- https://www.rythmstick.net/posts/tikitorch/