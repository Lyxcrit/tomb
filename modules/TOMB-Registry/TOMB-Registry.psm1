<#
    .SYNOPSIS
    Collects Windows Registry Objects on the Host. Modular loaded via TOMB or TOMB_GUI.

     .DESCRIPTION
    Used to pull Registry objects from host such as 'HLKM:\Software' via WMI (Windows Management Instrumentation) Calls.
    Module will allow any objects to be collected, as long as user has permissions to pull those keys.
    preventing the ability to prevent pulling the same log multiple times and ensure each pull presents you with new data.

    .NOTES
    DATE:       20 MAR 19
    VERSION:    1.1.1
    AUTHOR:     Brent Matlock -Lyx

    .PARAMETER Computer
    Used to specify computer to be collected on

    .PARAMETER HiveKey
    Used to specify hive to collect

    .PARAMETER Path
    Used to specify where output folder should be, by default when launched via TOMB.ps1 this is the execution path
    where TOMB.ps1 is invoked.

    .EXAMPLE
    Will Return Registry entries for the HLKM:SOFTWARE branch against the localhost
        TOMB-Registry -Computer $env:COMPUTERNAME -HiveKey 'hklm:\software'
    .EXAMPLE
    Will run the default Registry keys to collect against the localhost
        TOMB-Registry -Computer $env:COMPUTERNAME
#>

[cmdletbinding()]
Param (
    #ComputerName of the host you want to connect to.
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][System.Array] $Computer,
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][System.Array] $HiveKey,
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][System.Array] $Path
)

#Build Variable Scope
$(Set-Variable -name Computer -Scope Global) 2>&1 | Out-null
$(Set-Variable -name HiveKey -Scope Global) 2>&1 | Out-null
$(Set-Variable -name Path -Scope Global) 2>&1 | Out-null

#Main Script, collects Registry off hosts and converts the output to Json format in preperation to send to Splunk
Function TOMB-Registry($Computer, $HiveKey, $Path){
    cd $Path
    Try {
        $ConnectionCheck = $(Test-Connection -Count 1 -ComputerName $Computer -ErrorAction Stop)
        }
    #If host is unreachable this is placed into the Errorlog: Registry.log
    Catch [System.Net.NetworkInformation.PingException] {
        "$(Get-Date): Host ${Computer} Status unreachable." |
        Out-File -FilePath $Path\logs\ErrorLog\registry.log -Append
        break
        }
    #If user cannot reach host due to permission requirements this is placed in Errorlog: Registry.log
    Catch [System.Management.Automation.Remoting.PSRemotingTransportException] {
        "$(Get-Date): Host ${Computer} Access Denied" |
        Out-File -FilePath $Path\logs\ErrorLog\registry.log -Append
        break
    }
    If ($ConnectionCheck){ RegistryCollect($Computer) }
    Else {
        break
    }
}


Function RegistryCollect($Computer, $HiveKey){
    If ($null -eq $HiveKey) {
        [System.Array]$HiveKey = $(Get-Content .\includes\RegistryKeys.txt)           
        }
    Foreach ($Key in $HiveKey) {
        # Using scriptblock in order to keep lines short
        $Registry = "(Get-ItemProperty $Key -EA SilentlyContinue) | Select * -ExcludeProperty PS*,*Volume* "
        $Registries = [ScriptBlock]::Create($Registry)
        $Registry_List = $(Invoke-Command -ComputerName $Computer -ScriptBlock $Registries -ArgumentList $Key -ErrorVariable Message 2>$Message)
        Try { $Registry_List
            If ($Registry_List -ne $null){
                Foreach ($obj in $Registry_List){
                    #Add additional keypair so Hivekey is listed with content
                    Add-Member -InputObject $obj -MemberType NoteProperty -Force -Name "Hive" -Value $Key
                    $obj | TOMB-Json | Out-File -FilePath $Path\Files2Forward\temp\Registry\${Computer}_registry.json -Append -Encoding utf8
                }
            }
            Else {
                #Error Collection for remote side
                "$(Get-Date) : ${Computer} : ${Message}" | Out-File -File $Path\logs\ErrorLog\registry.log -Append
            }
        }
        Catch {
            #Error Collection for local side
            "$(Get-Date) : ${Computer} : $($Error[0]) " | Out-File -FilePath $Path\logs\ErrorLog\registry.log -Append
        }
    }
    Move-Item -Path $Path\Files2Forward\temp\Registry\${Computer}_registry.json -Destination $Path\Files2Forward\Registry\${Computer}_registry.json
    Remove-Item $Path\Files2Forward\temp\Registry\${Computer}_registry.json
}

#Alias registration for deploying with -Collects via TOMB.ps1
New-Alias -Name Registry -Value TOMB-Registry
Export-ModuleMember -Alias * -Function * -ErrorAction SilentlyContinue