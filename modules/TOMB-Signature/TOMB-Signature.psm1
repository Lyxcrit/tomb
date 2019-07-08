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
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][System.Array] $Path
)

#Build Variable Scope
$timestamp = [Math]::Floor([decimal](Get-Date(Get-Date).ToUniversalTime()-uformat "%s"))
$ts = $timestamp
$(Set-Variable -name Computer -Scope Global) 2>&1 | Out-null
$(Set-Variable -name Path -Scope Global) 2>&1 | Out-null

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
    If ($ConnectionCheck){ SignatureCollect($Computer) }
    Else {
        "$(Get-Date) : ERROR MESSAGE : $($Error[0])" | Out-File -FilePath $Path\logs\ErrorLog\signature.log -Append
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

Function SignatureCollect($Computer){
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
        }
    }
    Catch [System.Net.NetworkInformation.PingException] {
        "$(Get-Date): Host ${Computer} Status unreachable after." | Out-File -FilePath $Path\logs\ErrorLog\signature.log
    }
    CleanUp
}

Function CleanUp{
    $File = $(Get-Content -FilePath $Path\Files2Forward\temp\Signature\${Computer}_Signature.json) -replace "`t",""
    $File | Out-File -FilePath $Path\Files2Forward\Signature\${Computer}_${ts}_Signature.json -Encoding UTF8
    Remove-Item -Path $Path\Files2Forward\temp\Signature\${Computer}_Signature.json
}

#Alias registration for deploying with -Collects parameter via TOMB.ps1
New-Alias -Name Signature -Value TOMB-Signature
Export-ModuleMember -Alias * -Function * -ErrorAction SilentlyContinue