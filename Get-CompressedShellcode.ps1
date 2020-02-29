function Get-CompressedShellcode {

	[CmdletBinding()]        
    Param
   (
    [parameter(Mandatory=$true)]
    [String]
    $inFile,
    [parameter(Mandatory=$false)]
    [int]$encoding
   )
  
   $byteArray = [System.IO.File]::ReadAllBytes($inFile)
   [System.IO.MemoryStream] $output = New-Object System.IO.MemoryStream
   $gzipStream = New-Object System.IO.Compression.GzipStream $output, ([IO.Compression.CompressionMode]::Compress)
   $gzipStream.Write($byteArray, 0, $byteArray.Length)
   $gzipStream.Close()
   $output.Close()
   $tmp = $output.ToArray()

    if($encoding -eq 1 -or $encoding -eq $false){
        $b64 = [System.Convert]::ToBase64String($tmp)
        Write-Output $b64
    }
    else{
        $hex = ($tmp | Format-Hex | Select-Object -Expand Bytes | ForEach-Object { '{0:X2}' -f $_ } | ForEach-Object { $i = 0 } { $i++; @{$true=" ";$false=""}[($i - 1) % 16 -eq 0] + $_ }) -join ' '
        Write-Output $hex.replace("  ", " ")
    }   
}

