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

`TikiTorch` is a Visual Basic solution, split into 6 projects.

- TikiLoader
- TikiSpawn
- TikiSpawnAs
- TikiSpawnElevated
- TikiCpl
- TikiThings

### TikiLoader
A .NET Library that contains all the process hollowing code, used as a reference by the other Tiki projects.

### TikiSpawn
A .NET Library designed to bootstrap an agent via some initial delivery, can be used with [DotNetToJScript](https://github.com/tyranid/DotNetToJScript) in conjunction with lolbins.

### TikiSpawnAs
A .NET exe used to spawn agents under different creds.

```
> TikiSpawnAs.exe
  -d, --domain=VALUE         Domain (defaults to local machine)
  -u, --username=VALUE       Username
  -p, --password=VALUE       Password
  -b, --binary=VALUE         Binary to spawn & hollow
  -h, -?, --help             Show this help
```

### TikiSpawnElevated
A .NET exe used to spawn a high integrity agent using the UAC Token Duplication bypass.

```
> TikiSpawnElevated.exe
  -b, --binary=VALUE         Binary to spawn & hollow
  -p, --pid=VALUE            Elevated PID to impersonate (optional)
  -h, -?, --help             Show this help
```

### TikiCpl
Generates a Control Panel (.cpl) formatted DLL that executes gzipped base64 encoded shellcode from a resource.  Following the instructions [here](https://github.com/rvrsh3ll/CPLResourceRunner) to generate shellcode in the correct format.

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

## Credits

- Aaron Bray for [Loader.cs](https://github.com/ambray/ProcessHollowing/blob/master/ShellLoader/Loader.cs)
- [James Foreshaw](https://twitter.com/tiraniddo) for C# advice
- [Vincent Yiu](https://twitter.com/vysecurity) for inspiration
- [Kevin Mitnick](@kevinmitnick) for letting me test in his lab
- [Steve Borosh](https://twitter.com/424f424f) for TikiCpl
- [Casey Smith](https://twitter.com/subTee) for [AllTheThings](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1117/src/AllTheThings.cs)
- [Marcus Gelderman](https://gist.github.com/marcgeld) for [psCompress.ps1](https://gist.github.com/marcgeld/bfacfd8d70b34fdf1db0022508b02aca)

## Further Reading

- https://rastamouse.me/tags/tikitorch/
- https://www.rythmstick.net/posts/tikitorch/