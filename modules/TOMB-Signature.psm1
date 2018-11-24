<#
    
    .SYNOPSIS: 
    This block of code will parse thru folders and grab the file name and signature of the file.

    .DESCRIPTION: 
    By default the block only scans the %SystemRoot%\System32 folder, you can add additional folders by modifying the following skeleton
    IMPORTANT: It is important that you do not touch the original script. While modifying/testing script you should always create a backup.
    Incase you break the script there is an original located under 'TOMB\modules\backup'

    .NOTES
    DATE:       1 OCT 18
    VERSION:    1.0
    AUTHOR:     Brent Matlock
    
    .EXAMPLE
    When searching for specific file type extensions you can add the -Include parameter, which will take WILDCARDS
        'Get-ChildItem -Include "*.exe","*.dll"'
    .EXAMPLE
    When searching subfolders make sure to include the -Recurse parameter.
        'Get-ChildItem -Include "*.exe","*.dll" -Recurse'

#>


Function TOMB-Signature {
   Param(
   [Parameter(Mandatory=$false, ValueFromPipeline=$true)][System.Array]$Computer,
   [Parameter(Mandatory=$false)][string[]]$Path )
        If ( $Computer -EQ $null ){ $Computer = $( Get-Content .\includes\tmp\DomainList.txt )}
        If ( $Path -EQ "" -OR $Path -EQ "Default" -OR $Path -EQ "default" ){
            $FileDirectory = $( Get-ChildItem -File "C:\Windows\System32\*.dll" )   #DO NOT CHANGE, This is the default folder. Include additional Folders below
            Foreach ($File in [array]$FileDirectory){
                $Signature = $(( Get-AuthenticodeSignature "$File").SignerCertificate.Subject )
                $FileVersion = $( Get-ChildItem $File | Foreach-Object { "{0}" -f [System.Diagnostics.FileVersionInfo]::GetVersionInfo($_).FileVersion } )
                    Try{ "{ File: "+$File, 
                         "; Signature:"+$Signature,
                         "; FileVersion:"+$FileVersion `
                         | Out-File -FilePath .\Files2Forward\"$Computer"_Signatures_System32.json -Append } 
                    Catch{ $Error[0] | Out-File -FilePath .\logs\ErrorLog\signatures.log }
                }
            }
        Else { 
            Foreach ( $Folder in [array]$Path ){
                $File = ( Get-ChildItem $Folder )
                Foreach ( $File in $Folder ){
                    $Signature = $(( Get-AuthenticodeSignature "$File").SignerCertificate.Subject )
                    $FileVersion = $( Get-ChildItem $File | ForEach-Object { "{0}" -f [System.Diagnostics.FileVersionInfo]::GetVersionInfo($_).FileVersion } )
                        Try{ "{ File: "+$File, 
                             "; Signature: "+$Signature, 
                             "; FileVersion: "+$FileVersion `
                             | Out-File -FilePath .\Files2Forward\"$Computer"_Signatures_"$Folder".json -Append }
                        Catch { $Error[0] | Out-File -FilePath .\logs\ErrorLog\signatures.log } 
                }
            }
        }
    }


#Alias registration for deploying with -Collects parameter via TOMB.ps1
New-Alias -Name Signature -Value TOMB-Signature
Export-ModuleMember -Alias * -Function *