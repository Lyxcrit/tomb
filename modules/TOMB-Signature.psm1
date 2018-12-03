<#
    
    .SYNOPSIS: 
    This block of code will parse thru folders and grab the file name and signature of the file.

    .DESCRIPTION: 
    By default the block only scans the %SystemRoot%\System32 folder, you can add additional folders by modifying the following skeleton
    IMPORTANT: It is important that you do not touch the original script. While modifying/testing script you should always create a backup.
    Incase you break the script there is an original located under 'TOMB\modules\backup'

    .NOTES
    DATE:       03 DEC 18
    VERSION:    1.0.2
    AUTHOR:     Brent Matlock
    
    .EXAMPLE
    When searching for specific file type extensions you can add the -Include parameter, which will take WILDCARDS
        'Get-ChildItem -Include "*.exe","*.dll"'
    .EXAMPLE
    When searching subfolders make sure to include the -Recurse parameter.
        'Get-ChildItem -Include "*.exe","*.dll" -Recurse'

#>

#Main Script, collects Signatures off hosts and converts the output to Json format in preperation to send to Splunk
Function TOMB-Signature {
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)][System.Array]$Computer,
        [Parameter(Mandatory = $false)][string[]]$Path )
    If ( $Computer -eq $null ) { $Computer = $( Get-Content .\includes\tmp\DomainList.txt )}
    If ( $Path -eq $null ) {
        $FileDirectory = $( Get-ChildItem -File "C:\Windows\System32\*.dll" )   #DO NOT CHANGE, This is the default folder. Include additional Folders below
        Foreach ($File in $FileDirectory) {
            $Signature = $(( Get-AuthenticodeSignature "$File").SignerCertificate.Subject )
            $Sha1 = Get-FileHash -a SHA1 $File
            $Sha1 = $Sha1.Hash 
            $MD5 = Get-FileHash -a MD5 $File
            $MD5 = $MD5.Hash
            $File = $( Get-ChildItem $File | Foreach-Object { "{0}" -f [System.Diagnostics.FileVersionInfo]::GetVersionInfo($_).FileVersion } )
            Try {
            "{ File : ${File} , Signature : ${Signature} , Sha1 : ${Sha1} , MD5 : ${MD5}" | Out-File -FilePath .\Files2Forward\${Computer}_Signatures_System32.json -Append 
            } 
            Catch { $Error[0] | Out-File -FilePath .\logs\ErrorLog\signatures.log }
        }
    }
    Else { 
        Foreach ( $Folder in $Path ) {
            $Files = ( Get-ChildItem $Folder )
            Foreach ( $File in $Files ) {
                $Signature = $(( Get-AuthenticodeSignature "$File").SignerCertificate.Subject )
                $Sha1 = Get-FileHash -a SHA1 $File
                $Sha1 = $Sha1.Hash 
                $MD5 = Get-FileHash -a MD5 $File
                $MD5 = $MD5.Hash
                $File = $( Get-ChildItem $File | Foreach-Object { "{0}" -f [System.Diagnostics.FileVersionInfo]::GetVersionInfo($_).FileVersion } )
                Try {
                "{ File : ${File} , Signature : ${Signature} , Sha1 : ${Sha1} , MD5 : ${MD5}" | Out-File -FilePath .\Files2Forward\${Computer}_Signatures_${Folder}.json -Append 
                }
                Catch { $Error[0] | Out-File -FilePath .\logs\ErrorLog\signatures.log } 
            }
        }
    }
}


#Alias registration for deploying with -Collects parameter via TOMB.ps1
New-Alias -Name Signature -Value TOMB-Signature
Export-ModuleMember -Alias * -Function *