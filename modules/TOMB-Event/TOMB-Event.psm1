<#
    .SYNOPSIS
    Collects Windows Logs on the Host. Modular loaded via TOMB.ps1.

    .DESCRIPTION
    Used to pull Event logs from host such as EventCode 4624 (Successful Logon) or EventCode 4625 (Failed Logon) via WMI (Windows Management 
    Instrumentation) Calls. Module will allow any logs to be collected, as long as user has permissions to pull those logs. RecordNumbers are 
    saved inside 'TOMB\modules\DO_NOT_DELETE\' on a per machine per EventCode basis, preventing the pulling of same log multiple times and 
    ensure each pull presents you with new data.

    .NOTES
    DATE:       27 JAN 19
    VERSION:    1.0.5
    AUTHOR:     Brent Matlock -Lyx

    .PARAMETER Computer
    Used to specify list of computers to collect against, if not provided then hosts are pulled from .\includes\tmp\DomainList.txt

    .PARAMETER LogID
    Used to specify list of EventID to collect against, if not provided default list activates.
    When this parameter is not provided the default profile is loaded from .\includes\EventIDs.txt to switch an event on/off 
    simply comment or uncomment the specific line. Each event listed also provides a short description to make choices easier.

    .EXAMPLE
    Will Return Successful logins and logouts for localhost
    TOMB-LogEventLog -Computer $env:COMPUTERNAME -LogID 4624,4625
#>

[cmdletbinding()]
Param (
    # ComputerName of the host you want to connect to.
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][System.Array] $Computer,
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][System.Array] $Path,
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][System.Array] $LogID,
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][System.Array] $AD
)

#Build Variable Scope
$(Set-Variable -name Computer -Scope Global) 2>&1 | Out-null
$(Set-Variable -name LogID -Scope Global) 2>&1 | Out-null
$(Set-Variable -name Path -Scope Global) 2>&1 | Out-null

#Main Script, collects Eventlogs off hosts and converts the output to Json format in preperation to send to Splunk
Function TOMB-Event($Computer, $Path, $LogID) {
    cd $Path
    Try { 
        $connectionCheck = $(Test-Connection -Count 1 -ComputerName $Computer -ErrorAction Stop) 
        }
    #If host is unreachable this is placed into the Errorlog: Process.log
    Catch [System.Net.NetworkInformation.PingException] { 
        "$(Get-Date): Host ${Computer} Status unreachable." | 
        Out-File -FilePath $Path\logs\ErrorLog\windowslogs.log -Append 
        }
    Catch [System.Management.Automation.Remoting.PSRemotingTransportException] { 
        "$(Get-Date): Host ${Computer} Access Denied" | 
        Out-File -FilePath $Path\logs\ErrorLog\windowslogs.log -Append 
        }
    If ($connectionCheck){ EventCollect($Computer) }
    Else { 
        "$(Get-Date) : $($Error[0])" | Out-File -FilePath $Path\logs\ErrorLog\windowslog.log -Append 
    }
}

Function EventCollect($Computer, $LogID){
    If ($null -eq $LogID) { 
        $LogIDs = $(Get-content $Path\includes\EventIDs.txt | Where {$_ -notmatch "^#"}) 
        }
    Foreach ($LogID in $LogIDs) { 
        [string[]]$LogIDx += $LogID -Split("`t") | Select -First 1 
        }
    Foreach ($Log in $LogIDx) {
        #Verify that Timestamp exists, if not found sets date to Current-30Days
        $LastRun = (Get-Content -Path $Path\modules\DO_NOT_DELETE\${Computer}_${Log}_timestamp.log -ErrorAction SilentlyContinue)
        If ($LastRun.Length -eq 0) { $LastRun = 1 }
        #Generation of the scriptblock and allows remote machine to read variables being passed.
        $EventLog = "(Get-WmiObject Win32_NTLogEvent -Filter 'EventCode=$Log and (RecordNumber > $LastRun)' -EA Stop) | 
                      Select * -Exclude __*,*Properties,Scope,*Path,*Strings,Options,Qual*"
        $EventLogs = [Scriptblock]::Create($EventLog)
        $EventLogFinal = $(Invoke-Command -ComputerName $Computer -ScriptBlock $EventLogs -ErrorVariable Message 2>$Message)
        Try { $EventLogFinal
            #Verify if any collections were made, if not script drops file creation and moves on.
            If ($EventLogFinal -ne $null){ 
                Foreach($obj in $EventLogFinal){ 
                    $obj | TOMB-Json | 
                Out-File -FilePath $Path\Files2Forward\Events\${Computer}_${Log}_logs.json -Append -Encoding UTF8
            $EventLogFinal.RecordNumber[0] | Out-File -FilePath $Path\modules\DO_NOT_DELETE\${Computer}_${Log}_timestamp.log 
            }
        }
            Else { 
                "$(Get-Date) : $($Message)" | Out-File -FilePath $Path\logs\ErrorLog\windowslogs.log -Append
                }
            }
        #Any exception messages that were generated due to error are placed in the Errorlog: Windowslogs.log
        Catch { 
            "$(Get-Date): $($Error[0])" | Out-File -FilePath $Path\logs\ErrorLog\windowslogs.log 
        }
    }
}


#Alias registration for deploying with -Collects parameter via TOMB.ps1
New-Alias -Name Event -Value TOMB-Event
Export-ModuleMember -Alias * -Function *