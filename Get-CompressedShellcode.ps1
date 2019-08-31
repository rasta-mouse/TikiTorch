function Get-CompressedShellcode {

	[CmdletBinding()]
    Param(
    [String]$inFile
    )

    $byteArray = [System.IO.File]::ReadAllBytes($inFile)
    [System.IO.MemoryStream] $output = New-Object System.IO.MemoryStream
    $gzipStream = New-Object System.IO.Compression.GzipStream $output, ([IO.Compression.CompressionMode]::Compress)
    $gzipStream.Write($byteArray, 0, $byteArray.Length)
    $gzipStream.Close()
    $output.Close()
    $tmp = $output.ToArray()
    
    $b64 = [System.Convert]::ToBase64String($tmp)
    Write-Output $b64
}