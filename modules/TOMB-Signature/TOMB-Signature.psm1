<#
    .SYNOPSIS: 
    This block of code will parse thru folders and grab the file name and signature of the file.

    .DESCRIPTION: 
    By default this module scans the following directories:
        C:\Windows\System32
        C:\Program Files
        C:\Program Files (x86)
        C:\Users
    For all files ending in .exe, .dll, .txt, .ps1, .psm1, .xls
    This module gathers file information for the following:
        FileName, Digital Signature, SHA1, MD5, FileVersion.

    .NOTES
    DATE:       27 JUN 19
    VERSION:    1.1.2c
    AUTHOR:     Brent Matlock -Lyx

    .PARAMETER Computer
    Used to specify list of computers to collect against, if not provided then hosts are pulled from .\includes\tmp\DomainList.txt

    .EXAMPLE
    Will capture signatures of default directories against localhost
        TOMB-Signature -Computer localhost -Path .

    .EXAMPLE
    Will capture file information against DC01 in the System32 folder
        TOMB-Signature -Computer DC01 -Path .
#>

[cmdletbinding()]
Param (
    # ComputerName of the host you want to connect to.
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][System.Array] $Computer,    
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][System.Array] $Path,
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][System.String] $Method
)

#Build Variable Scope
$timestamp = [Math]::Floor([decimal](Get-Date(Get-Date).ToUniversalTime()-uformat "%s"))
$ts = $timestamp
$(Set-Variable -name Computer -Scope Global) 2>&1 | Out-null
$(Set-Variable -name Path -Scope Global) 2>&1 | Out-null
$(Set-Variable -name Method -Scope Global) 2>&1 | Out-null

#Main Script, collects Processess off hosts and converts the output to Json format in preperation to send to Splunk
Function TOMB-Signature($Computer, $Path){
    cd $Path
    Try {
        $ConnectionCheck = $(Test-Connection -Count 1 -ComputerName $Computer -ErrorAction Stop)
        }
    #If host is unreachable this is placed into the Errorlog: ScheduledTask.log
    Catch [System.Net.NetworkInformation.PingException] {
        "$(Get-Date): Host ${Computer} Status unreachable." |
        Out-File -FilePath $Path\logs\ErrorLog\signature.log -Append
        }
    Catch [System.Management.Automation.Remoting.PSRemotingTransportException] {
        "$(Get-Date): Host ${Computer} Access Denied" |
        Out-File -FilePath $Path\logs\ErrorLog\signature.log -Append
        }
    If ($ConnectionCheck){ Get-CollectionMethod($Method) }
    Else {
        "$(Get-Date) : ERROR MESSAGE : $($Error[0])" | Out-File -FilePath $Path\logs\ErrorLog\signature.log -Append
    }
}

Function Get-CollectionMethod($Method){
    If(!($Method)){
        Signature-CollectWinRM($Computer)
    }
    If($Method -eq "WinRM"){
        Signature-CollectWinRM($Computer)
    }
    If($Method -eq "CIM"){
        Signature-CollectCIM($Computer)
    }
}

#Prepare function to be passed to remote host
Function Sigs($Computer) {
    $FileDirectory = Get-ChildItem -File "C:\Windows\*", "C:\Program Files\*", "C:\Program Files (x86)\*", "C:\Users\*" -Include "*.dll","*.exe" -Depth 10 -Recurse
    Foreach ($File in $FileDirectory) {
        $Signature = (Get-AuthenticodeSignature "$File").SignerCertificate.Thumbprint
        $Org = (Get-AuthenticodeSignature "$File").SignerCertificate.DnsNameList.Unicode
        $sigstatus = (Get-AuthenticodeSignature "$File").StatusMessage
        $Sha256 = (Get-FileHash -a SHA256 $File).Hash
        $MD5 = (Get-FileHash -a MD5 $File).Hash
        $FileVersion = Get-ChildItem $File | Foreach-Object { "{0}" -f [System.Diagnostics.FileVersionInfo]::GetVersionInfo($_).FileVersion }
        $obj = $obj + "{ ComputerName: $Computer, File: $File, Signature: $Signature, Orginization: $Org, Status: $sigstatus, SHA256: $Sha256, MD5: $MD5, FileVersion: $FileVersion }`r`n"
    }
    return $obj
}

Function Signature-CollectWinRM($Computer){
    $Signatures = $(Invoke-Command -ComputerName $Computer -ScriptBlock ${function:Sigs} -ArgumentList $Computer -ErrorVariable Message 2>$Message)
    Try { $Signatures
        If($null -ne $Signatures){
            Foreach($obj in $Signatures){
                #Output is encoded with UTF8 in order for Splunk to parse correctly
                $obj | Out-File -FilePath $Path\Files2Forward\temp\Signature\${Computer}_${ts}_Signature.json -Append -Encoding utf8
            }
        }
        Else {
            "$(Get-Date) : $($Message)" | Out-File -FilePath $Path\logs\ErrorLog\signature.log -Append
               Signature-CollectCIM
        }
    }
    Catch [System.Net.NetworkInformation.PingException] {
        "$(Get-Date): Host ${Computer} Status unreachable after." | Out-File -FilePath $Path\logs\ErrorLog\signature.log
    }
    CleanUp
}

# Connect to remote hosts via DCOM (Used when WinRM or WMI are not enabled/Configured)
Function Signature-CollectCIM {
    # Place Additional Directories in includes\SignatureDirectories.txt (If no Paths are provided, defaults to 'System32', 'Program Files' and 'Program Files (x86)'
    $DirectoryList = $(Get-content $Path\includes\SignatureDirectories.txt -ErrorAction SilentlyContinue | Where-Object {$_ -notmatch "^#"}) 
    If(!($DirectoryList)){
        $DirectoryList = "\\Windows\\System32\\%","\\Program Files(x86)\\%"
    }
    $Filter = (($DirectoryList | % { "Path -Like '$_'" }) -join ' OR ').replace("-Like","Like")
    # Set session option to force connection to DCOM
    $SessionOption = New-CimSessionOption -Protocol DCOM
    # Generate connection, Connections are grouped off name: "SignatureCollection" or called via $Computer parameter
    New-CimSession -ComputerName ${Computer}_SignatureCollection -SessionOption $SessionOption -SkipTestConnection
    $FileSystemInfo = $(Get-CimInstance -ComputerName $Computer -Class CIM_DataFile -filter "Drive='C:' AND Path Like '\\users\\mmls_svc\\desktop\\%' AND Extension='exe'" | Select Name,Version,Manufacturer,Status)
    Foreach ($obj in $FileSystemInfo){
        # Create Empty Containers
        $MD5 = ""
        $MD5hash = ""
        $MD5bytes = ""
        $SHA256 = ""
        $SHA256hash = ""
        $SHA256bytes = ""
        # Begin Compilation
        $File =  ($obj.Name)
        $Signature = (Get-AuthenticodeSignature $obj.Name -EA SilentlyContinue).SignerCertificate.Thumbprint
        $Org = ($obj.Manufacturer)
        $sigstatus = ($obj.Status)
        # Prep object for Conversion to IO Stream
        [byte[]]$filebytes = ""
        $filebytes = [System.IO.File]::ReadAllBytes($File)
        # Generate MD5 for object
        $MD5hash = [System.Security.Cryptography.HashAlgorithm]::Create("MD5")
        $MD5bytes = ($MD5hash.ComputeHash($filebytes))
        $MD5bytes | % { $MD5 += $_.ToString("X2")}
        # Generate SHA256 for object
        $SHA256hash = [System.Security.Cryptography.HashAlgorithm]::Create("SHA256")
        $SHA256bytes = ($SHA256hash.ComputeHash($filebytes))
        $SHA256bytes | % { $SHA256 += $_.ToString("X2")}
        $FileVersion = ($obj.Version)
        # Package Output
        $outputFiles = $outputFiles + "{ ComputerName: $Computer, File: $File, Signature: $Signature, Orginization: $Org, Status: $sigstatus, SHA256: $Sha256, MD5: $MD5, FileVersion: $FileVersion }`r`n"      
    }
    $outputFiles | Out-File -FilePath $Path\Files2Forward\temp\Signature\${Computer}_Signature.json -Append -Encoding utf8
    # Remove CimSession
    Remove-CimSession -ComputerName ${Computer}_SignatureCollection -Verbose
    CleanUp
}

Function CleanUp{
    Move-Item -Path $Path\Files2Forward\temp\Signature\${Computer}_Signature.json `
              -Destination $Path\Files2Forward\Signature\${Computer}_${ts}_Signature.json
    Remove-Item -Path $Path\Files2Forward\temp\Signature\${Computer}_Signature.json
}

#Alias registration for deploying with -Collects parameter via TOMB.ps1
New-Alias -Name Signature -Value TOMB-Signature
New-Alias -Name SignatureWinRM -Value SignatureCollectWinRM
New-Alias -Name SignatureCIM -Value SignatureCollectCIM
Export-ModuleMember -Alias * -Function * -ErrorAction SilentlyContinue