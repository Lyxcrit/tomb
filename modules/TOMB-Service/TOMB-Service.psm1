<#
    .SYNOPSIS
    Collects running services running on machine. Modular loaded via TOMB or TOMB_GUI.

    .NOTES
    DATE:       26 JUN 19
    VERSION:    1.1.2b
    AUTHOR:     Brent Matlock -Lyx

     .DESCRIPTION
    Used to pull services from host with WMI (Windows Management Instrumentation) Calls.

    .PARAMETER Computer
    Used to specify list of computers to collect against, if not provided then hosts are pulled from .\includes\tmp\DomainList.txt

    .PARAMETER Path
    Used to specify where output folder should be, by default when launched via TOMB.ps1 this is the execution path
    where TOMB.ps1 is invoked.

    .EXAMPLE
    Will capture services on localmachine.
        TOMB-Service -computername $evn:computername
    .EXAMPLE
    Will capture services from the domain controller on the cyber.lab domain.
        TOMB-Service -ComputerName DC01 -AD '.cyber.lab'
#>

[cmdletbinding()]
Param (
    # ComputerName of the host you want to connect to.
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][System.Array] $Computer,
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][System.Array] $Path
)

#Build Variable Scope
$timestamp = [Math]::Floor([decimal](Get-Date(Get-Date).ToUniversalTime()-uformat "%s"))
$(Set-Variable -name timestamp -Scope Global) 2>&1 | Out-null
$(Set-Variable -name Computer -Scope Global) 2>&1 | Out-null
$(Set-Variable -name Path -Scope Global) 2>&1 | Out-null

#Main Script, collects Services off hosts and converts the output to Json format in preperation to send to Splunk
Function TOMB-Service($Computer, $Path){
    cd $Path
    Try {
        $ConnectionCheck = $(Test-Connection -Count 1 -ComputerName $Computer -ErrorAction Stop)
        }
    #If host is unreachable this is placed into the Errorlog: Process.log
    Catch [System.Net.NetworkInformation.PingException] {
        "$(Get-Date): Host ${Computer} Status unreachable." |
        Out-File -FilePath $Path\logs\ErrorLog\service.log -Append
        }
    Catch [System.Management.Automation.Remoting.PSRemotingTransportException] {
        "$(Get-Date): Host ${Computer} Access Denied" |
        Out-File -FilePath $Path\logs\ErrorLog\service.log -Append
        }
    If ($ConnectionCheck){ ServiceWinRM($Computer) }
    Else {
        "$(Get-Date) : ERROR MESSAGE : $($Error[0])" | Out-File -FilePath $Path\logs\ErrorLog\service.log -Append
    }
}

Function ServiceWinRM($Computer){
    #Generation of the scriptblock and allows remote machine to read variables being passed.
    $Service = "(Get-WmiObject -Class 'Win32_Service' -ErrorAction Stop) | Select * -Exclude __*,*Properties,*Path,Qualifiers,Scope,Options"
    $Services = [ScriptBlock]::Create($Service)
    $Service_List = $(Invoke-Command -ComputerName $Computer -ScriptBlock $Services -ErrorVariable Message 2>$Message)
    Try { $Service_List
        If($Service_List -ne $null){
            Foreach($obj in $Service_List){
                $obj | Convertto-Json -Compress |
                Out-File -FilePath $Path\Files2Forward\temp\Service\${Computer}_${timestamp}_service.json -Append -Encoding utf8
            }
        }
        Else {
            #WinRM Failed, Move to WMI
            "$(Get-Date) : $($Message)" | Out-File -FilePath $Path\logs\ErrorLog\service.log -Append
            ServiceWMI
        }
    }
    Catch [System.Net.NetworkInformation.PingException] {
        "$(Get-Date): Host ${Computer} Status unreachable after." |
        Out-File -FilePath $Path\logs\ErrorLog\service.log -Append
    }
    CleanUp
}

Function ServiceWMI{
    $Service_List = $((Get-WmiObject -Class 'Win32_Service' -ComputerName $Computer -ErrorAction Stop) | Select * -Exclude __*,*Properties,*Path,QUalifiers,Scope,Options)
    Try{
        If($Service_List -ne $null){
            Foreach ($obj in $Service_List){
                $obj | TOMB-Json |
                Out-File -FilePath $Path\Files2Forward\temp\Service\${Computer}_${timestamp}_service.json -Append -Encoding utf8
            }
        }
        Else {
            "$(Get-Date) : $($Message)" | Out-File -FilePath $Path\logs\ErrorLog\service.log -Append
        }
    }
    Catch [System.Net.NetworkInformation.PingException] {
        "$(Get-Date): Host ${Computer} Status unreachable after." |
    Out-File -FilePath $Path\logs\ErrorLog\service.log -Append
    }
    CleanUp
}

Function CleanUp{
    Move-Item -Path $Path\Files2Forward\temp\Service\${Computer}_${timestamp}.json 
    -Destination $Path\Files2Forward\Service\${Computer}_${timestamp}_service.json
}

#Alias registration for deploying with -Collects parameter via TOMB.ps1
New-Alias -Name Service -Value TOMB-Service
Export-ModuleMember -Alias * -Function * -ErrorAction SilentlyContinue