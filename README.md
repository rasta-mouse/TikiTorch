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

TikiTorch follows the same concept but uses `Process Hollowing` techniques instead of `CRT`.  I found an interesting implementation that seems to avoid calls to certain functions that are synonymous with hollowing, such as `VirtualAllocEx` and `SetThreadContext`.  I have no idea if this will help the longevity of the tool 🤷

## Usage

The C# is included here if you want to compile the DLL and run it through DotNetToJScript yourself.  I use custom Resource files for DotNetToJScript to generate the included templates, so your output will look different (though the base64 serialized object should be the same).

Otherwise, simply take the pre-made templates and replace `var tp` and `var sc` with your desired values.  Where `tp` = target process to spawn and `sc` = base64 encoded shellcode.

TikiTorch works with `x86` & `x64` architectures and `staged` & `stageless` payloads.

Most frameworks will provide C# byte array shellcode for staged payloads.  For stageless, you will generally need to output to raw and base64 encode the file, e.g. `[System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes("stageless.bin"))`.

## Credits

- Aaron Bray for [Loader.cs](https://github.com/ambray/ProcessHollowing/blob/master/ShellLoader/Loader.cs)
- [James Foreshaw](https://twitter.com/tiraniddo) for [DotNetToJScript](https://github.com/tyranid/DotNetToJScript)
- [Vincent Yiu](https://twitter.com/vysecurity) for inspiration