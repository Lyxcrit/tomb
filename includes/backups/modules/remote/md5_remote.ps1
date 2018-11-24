Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock {
    $fullPath = Resolve-Path 'c:\Program Files\Internet Explorer\iexplore.exe'
    $md5 = new-object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
    $file = [System.IO.File]::OpenRead($fullPath)
    $hash = [System.BitConverter]::ToString($md5.ComputeHash($file))
    $hash -replace "-", ""
    $file.Dispose()
}