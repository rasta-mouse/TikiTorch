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

TikiTorch was named in homage to [CACTUSTORCH](https://github.com/vysecurity/CACTUSTORCH) by [Vincent Yui](https://twitter.com/vysecurity).  The basic concept of CACTUSTORCH is that it spawns a new process, then uses `CreateRemoteThread` to run the desired shellcode within that target process.  Both the process and shellcode are specified by the user.

This is pretty flexible as it allows an operator to run an HTTP agent in a process such as `iexplore.exe`, rather than something more arbitrary like `rundll32.exe`.

TikiTorch follows the same concept but uses `Process Hollowing` techniques instead of `CRT`.  I found an interesting implementation that seems to avoid calls to certain functions that are synonymous with hollowing, such as `VirtualAllocEx` and `SetThreadContext`.  I have no idea if this will help the longevity of the tool 🤷

## Usage

The C# is included here if you want to compile the DLL and run it through DotNetToJScript yourself.  Otherwise, simply take the pre-made `TikiTorch_x64.js` / `TikiTorch_x86.js` templates and replace `var targetProcess` and `var encodedShellcode` with your desired values.

TikiTorch works with `x86` & `x64` architectures and `staged` & `stageless` payloads.

## Credits

Aaron for [Loader.cs](https://github.com/ambray/ProcessHollowing/blob/master/ShellLoader/Loader.cs)
[James Foreshaw](https://twitter.com/tiraniddo) for [DotNetToJScript](https://github.com/tyranid/DotNetToJScript)
[Vincent Yui](https://twitter.com/vysecurity) for inspiration