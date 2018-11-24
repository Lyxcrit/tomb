<#
    .SYNOPSIS: 
    This block of code will parse thru folders and grab the file name and signature of the file.

    .DESCRIPTION: 
    By default the block only scans the %SystemRoot%\System32 folder, you can add additional folders by modifying the following skeleton
    IMPORTANT: It is important that you do not touch the original script. While modifying/testing script you should always create a backup.
    Incase you break the script there is an original located under 'TOMB\includes\backup'

    .EXAMPLE
~~~~~~~~~~~~~~~
    SKELETON FOR ADDING NEW FILES
$VariableName = $(Get-ChildItem -File "FILEPATH")    
Foreach ($File in $VariableName){
    $Signature = $((Get-AuthenticodeSignature "$VariableName").SignerCertificate.Subject )
    If ($?){ "File : $File ; Signature : $Signature ; FileVersion : $FileVersion" `
    | Out-File -Filepath "outfile\Files2Forward\Signatures_FOLDERAME.csv" -Append }
    Else { "$File : No Signature Found" }
~~~~~~~~~~~~~~~
DO NOT TOUCH LINES 30-40 COPY AND PASTE SKELETON BELOW LINE 40

    .EXAMPLE
    When searching for specific file type extensions you can add the -Include parameter, which will take WILDCARDS
    'Get-ChildItem -Include "*.exe","*.dll"'
    .EXAMPLE
    When searching subfolders make sure to include the -Recurse parameter.
    'Get-ChildItem -Include "*.exe","*.dll" -Recurse'
#>


$outfile = 'C:\Users\bmatlock\Desktop\Scripts\TOMB_3\'
$FileDirectory = $(Get-ChildItem -File "C:\Windows\System32\*.dll")   #DO NOT CHANGE, This is the default folder. Include additional Folders below

Foreach ($File in $FileDirectory){
    $Signature = $((Get-AuthenticodeSignature "$File").SignerCertificate.Subject )
    $FileVersion = $(Get-ChildItem $File | Foreach-Object { "{0}" -f [System.Diagnostics.FileVersionInfo]::GetVersionInfo($_).FileVersion } )
        If ($?){ "File : $File ; Signature : $Signature ; FileVersion : $FileVersion" `
        | Out-File -FilePath "$outfile\Files2Forward\Signatures_System32.csv" -Append }
        Else { "$File : No Signature Found" }
        }



    