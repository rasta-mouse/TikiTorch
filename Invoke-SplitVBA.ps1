function Invoke-SplitVBA{

    Param(
    [String]$InputFile,
    [String]$OutputFile
    )

    if (![System.IO.File]::Exists($InputFile)){
        throw $InputFile + "does not exist"
    }

    if ([System.IO.File]::Exists($OutputFile)){
        $Continue = Read-Host -Prompt "Output file already exists, overwrite? [Y/n]"

        switch ($Continue) {
        "" {continue}
        "y" {continue}
        "Y" {continue}
        "n" {throw "Aborting"; exit}
        "N" {throw "Aborting"; exit}
        default {throw "Aborting"; exit}
        }

        Remove-Item $OutputFile
    }

    $VBA = Get-Content -Path $InputFile
    $i = 0

    while ($i -le ($VBA.Length-300)){
        "sc = sc & " + '"' + $VBA.Substring($i,300) + '"' | Out-File -FilePath $OutputFile -Append
        $i += 300
    }

    "sc = sc & " + '"' + $VBA.Substring($i) + '"' | Out-File -FilePath $OutputFile -Append

    Write-Host "Done"

}