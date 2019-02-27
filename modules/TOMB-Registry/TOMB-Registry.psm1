<#
    .SYNOPSIS
    Collects Windows Registry Objects on the Host. Modular loaded via TOMB or TOMB_GUI.

     .DESCRIPTION
    Used to pull Registry objects from host such as 'HLKM:\Software' via WMI (Windows Management Instrumentation) Calls.
    Module will allow any objects to be collected, as long as user has permissions to pull those keys.
    preventing the ability to prevent pulling the same log multiple times and ensure each pull presents you with new data.

    .NOTES
    DATE:       27 FEB 19
    VERSION:    1.0.5
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
    # ComputerName of the host you want to connect to.
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
    #If host is unreachable this is placed into the Errorlog: Process.log
    Catch [System.Net.NetworkInformation.PingException] {
        "$(Get-Date): Host ${Computer} Status unreachable." |
        Out-File -FilePath $Path\logs\ErrorLog\registry.log -Append
        }
    Catch [System.Management.Automation.Remoting.PSRemotingTransportException] {
        "$(Get-Date): Host ${Computer} Access Denied" |
        Out-File -FilePath $Path\logs\ErrorLog\registry.log -Append
    }
    If ($ConnectionCheck){ RegistryCollect($Computer) }
    Else {
        "$(Get-Date) : $($Error[0])" | Out-File -FilePath $Path\logs\ErrorLog\registry.log -Append
    }
}


Function RegistryCollect($Computer, $HiveKey){
    If ($HiveKey -EQ $null) {
        [System.Array]$HiveKey = `
            "REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\",
            "REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run\",
            "REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce\",
            "REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce\Setup\",
            "REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx\",
            "REGISTRY::HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run\",
            "REGISTRY::HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce\",
            "REGISTRY::HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce\Setup\",
            "REGISTRY::HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx\",
            "REGISTRY::HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\",
            "REGISTRY::HKEY_USERS\\*\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\",
            "REGISTRY::HKEY_USERS\\*\Software\Microsoft\Windows\CurrentVersion\Run\",
            "REGISTRY::HKEY_USERS\\*\Software\Microsoft\Windows\CurrentVersion\RunOnce\",
            "REGISTRY::HKEY_USERS\\*\Software\Microsoft\Windows\CurrentVersion\RunOnce\Setup\",
            "REGISTRY::HKEY_USERS\\*\Software\Microsoft\Windows\CurrentVersion\RunOnceEx\",
            "REGISTRY::HKEY_USERS\\*\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\",
            "REGISTRY::HKEY_USERS\\*\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run\",
            "REGISTRY::HKEY_USERS\\*\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce\",
            "REGISTRY::HKEY_USERS\\*\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce\Setup\",
            "REGISTRY::HKEY_USERS\\*\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx\"
    }
    Foreach ($Key in $HiveKey) {
        $Registry = "(Get-ItemProperty $Key -EA SilentlyContinue) | Select * -ExcludeProperty PS*,*Volume* "
        $Registries = [ScriptBlock]::Create($Registry)
        $Registry_List = $(Invoke-Command -ComputerName $Computer -ScriptBlock $Registries -ErrorVariable Message 2>$Message)
        Try { $Registry_List
            If ($Registy_List -ne $null){
                Foreach ($obj in $Registry_List){
                    $obj | TOMB-Json | Out-File -FilePath $Path\Files2Forward\${Computer}_registry.json -Append -Encoding utf8
                }
            }
            Else {
                "$(Get-Date) : $($Message)" | Out-File -File $Path\logs\ErrorLog\registry.log -Append
            }
        }
        Catch {
            "$(Get-Date) : $($Error[0])" | Out-File -FilePath $Path\logs\ErrorLog\registry.log
        }
    }
}

#Alias registration for deploying with -Collects via TOMB.ps1
New-Alias -Name Registry -Value TOMB-Registry
Export-ModuleMember -Alias * -Function * -ErrorAction SilentlyContinue