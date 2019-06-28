<#
    .SYNOPSIS
    Collects Windows Registry Objects on the Host. Modular loaded via TOMB or TOMB_GUI.

     .DESCRIPTION
    Used to pull Registry objects from host such as 'HLKM:\Software' via WMI (Windows Management Instrumentation) Calls.
    Module will allow any objects to be collected, as long as user has permissions to pull those keys.
    preventing the ability to prevent pulling the same log multiple times and ensure each pull presents you with new data.

    .NOTES
    DATE:       26 JUN 19
    VERSION:    1.1.2b
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
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][string[]] $Computer,
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][System.Array] $HiveKey,
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][System.Array] $Path
)

#Build Variable Scope
$(Set-Variable -name Computer -Scope Global) 2>&1 | Out-null
$(Set-Variable -name HiveKey -Scope Global) 2>&1 | Out-null
$(Set-Variable -name Path -Scope Global) 2>&1 | Out-null

#Main Script, collects Registry off hosts and converts the output to Json format in preperation to send to Splunk
Function TOMB-Registry($Computer, $Path) {
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
    If ($ConnectionCheck){ RegistryCollect }
    Else {
        break
    }
}

Function Registries($HiveKey){
    Foreach ($Key in $HiveKey) {
        # Using scriptblock in order to keep lines short
        Get-Item $Key | Select-Object * -ExpandProperty property |
        Select-Object *,@{N="computer_name";E={$_.PSComputerName}},@{N="ChildKey";E={$_.PSChildName}},@{N="Property";E={$_.Name+"\\"+$_}},@{N="KeyValue";E={$(Get-ItemProperty -Path $Key -Name $_)[0].$_}} `
        -ExcludeProperty Name,property,Length,ValueCount,PSP*,PSI*,Handle,View,SubKeyCount,PSComputerName
    }
}

Function RegistryCollect {
    If ($null -eq $HiveKey) { [System.Array]$HiveKey = $(Get-Content $Path\includes\RegistryKeys.txt)}
    $Registry_List = $(Invoke-Command -ComputerName $Computer -ScriptBlock ${function:Registries} -ArgumentList $HiveKey,$Computer -ErrorVariable Message 2>$Message)
    Try { $Registry_List
        If ($Registry_List -ne $null){
            Foreach ($obj in $Registry_List){
                #Add additional keypair so Hivekey is listed with content
                #Add-Member -InputObject $obj -MemberType NoteProperty -Force -Name "Hive" -Value $Key
                Add-Member -InputObject $obj -MemberType NoteProperty -Force -Name "computer_name" -Value ${Computer}
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
        "$(Get-Date) : ${Computer} : $($Error[0]) Was null " | Out-File -FilePath $Path\logs\ErrorLog\registry.log -Append
    }
    CleanUp
}

Function CleanUp{
    Move-Item -Path $Path\Files2Forward\temp\Registry\${Computer}_registry.json `
    -Destination $Path\Files2Forward\Registry\${Computer}_registry.json
}

#Alias registration for deploying with -Collects via TOMB.ps1
New-Alias -Name Registry -Value TOMB-Registry
Export-ModuleMember -Alias * -Function * -ErrorAction SilentlyContinue