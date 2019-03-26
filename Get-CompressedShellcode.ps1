function Get-CompressedShellcode {

	[CmdletBinding()]
    Param(
    [String]$inFile,
    [String]$outFile
    )

    $byteArray = [System.IO.File]::ReadAllBytes($inFile)

    Write-Verbose "Get-CompressedByteArray"
    [System.IO.MemoryStream] $output = New-Object System.IO.MemoryStream
    $gzipStream = New-Object System.IO.Compression.GzipStream $output, ([IO.Compression.CompressionMode]::Compress)
    $gzipStream.Write( $byteArray, 0, $byteArray.Length )
    $gzipStream.Close()
    $output.Close()
    $tmp = $output.ToArray()
    
    $b64 = [System.Convert]::ToBase64String($tmp)
    [System.IO.File]::WriteAllText($outFile, $b64)
}