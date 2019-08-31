```
  *   )           )         *   )                        )  
` )  /(   (    ( /(   (   ` )  /(         (           ( /(  
 ( )(_))  )\   )\())  )\   ( )(_))   (    )(     (    )\()) 
(_(_())  ((_) ((_)\  ((_) (_(_())    )\  (()\    )\  ((_)\  
|_   _|   (_) | |(_)  (_) |_   _|   ((_)  ((_)  ((_) | |(_) 
  | |     | | | / /   | |   | |    / _ \ | '_| / _|  | ' \  
  |_|     |_| |_\_\   |_|   |_|    \___/ |_|   \__|  |_||_| 
```

TikiTorch was named in homage to [CACTUSTORCH](https://github.com/vysecurity/CACTUSTORCH) by [Vincent Yiu](https://twitter.com/vysecurity).  The basic concept of CACTUSTORCH is that it spawns a new process, allocates a region of memory, then uses `CreateRemoteThread` to run the desired shellcode within that target process.  Both the process and shellcode are specified by the user.

This is pretty flexible as it allows an operator to run an HTTP agent in a process such as `iexplore.exe`, rather than something more arbitrary like `rundll32` or `powershell`.

TikiTorch follows the same concept but has multiple types of process injection available, which can be specified by the user at compile time.

## Projects

`TikiTorch` is a Visual Basic solution, split into 8 projects.

- TikiLoader
- TikiSpawn
- TikiSpawnAs
- TikiSpawnElevated
- TikiCpl
- TikiService
- TikiThings
- TikiVader

In the first instance, please see the [Wiki](https://github.com/rasta-mouse/TikiTorch/wiki) for usage instructions.

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

- https://rastamouse.me/tags/tikitorch/
- https://www.rythmstick.net/posts/tikitorch/