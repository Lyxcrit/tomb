<#
    .SYNOPSIS
    Collects user properties, and information from active directory via WinRM.

    .NOTES
    DATE:           29 AUG 19
    VERSION:        1.1.5
    AUTHOR:         Brent Matlock -Lyx
         
     .DESCRIPTION
    Used to pull user information from Active Directory with WMI (Windows Management Instrumentation) Calls.

    .PARAMETER Server
    Used to specify domain controller to pull information front.
    
    .PARAMETER Path
    Used to specify where output folder should be, by default when launched via TOMB.ps1 this is the execution path
    where TOMB.ps1 is invoked.

    .EXAMPLE 
    Capture information via DNS
        TOMB-AdUser -Server dc01.foo.bar

    .EXAMPLE
    Capture information via IP Address
        TOMB-AdUser -Server 1.1.1.1
#>

[cmdletbinding()]
Param (
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][System.Array] $Server,
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][System.Array] $Path
)

#Build Variable Scope
$(Set-Variable -name Server -Scope Global) 2>&1 | Out-null
$(Set-Variable -name Path -Scope Global) 2>&1 | Out-null 

#Main Script, collects Processess off hosts and converts the output to Json format in preperation to send to Splunk
Function TOMB-AdUser($Server){
    $timestamp = [Math]::Floor([decimal](Get-Date(Get-Date).ToUniversalTime()-uformat "%s"))
    #Generation of the scriptblock and allows remote machine to read variables being passed.
    Try { $AdUser = $(Get-AdUser -Filter * -Properties * -Server $Server)
        If($AdUser -ne $null){
            Foreach($obj in $AdUser){
                #Output is encoded with UTF8 in order to Splunk to parse correctly
                $obj | Convertto-Json -Compress | Out-File -FilePath $Path\Files2Forward\temp\AdUser\${timestamp}_AdUser.json -Encoding utf8 -Append 
            }
        }        
    }
    Catch [System.Security.Authentication.AuthenticationException] { 
        "$(Get-Date) | Invalid Credentials" | Out-File -FilePath $Path\logs\ErrorLog\Process.log -Append }
    Catch [Microsoft.ActiveDirectory.Management.ADServerDownException] { 
        "$(Get-Date) | Active Directory Server Cannot be reached" | Out-File -FilePath $Path\logs\ErrorLog\Process.log -Append }
    CleanUp
}

Function CleanUp {
    Move-Item -Path $Path\Files2Forward\temp\AdUser\${timestamp}_AdUser.json `
    -Destination $Path\Files2Forward\AdUser\${timestamp}_AdUser.json
}

#Alias registration for deploying with -Collects via TOMB.ps1
New-Alias -Name AdUser -Value TOMB-AdUser
Export-ModuleMember -Alias * -Function * -ErrorAction SilentlyContinue
