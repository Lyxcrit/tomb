<#
    .SYNOPSIS
    Collects Windows Logs on the Host. Modular loaded via TOMB.ps1.
             
     .DESCRIPTION
    Used to pull Event logs from host such as EventCode 4624 (Successful Logon) or EventCode 4625 (Failed Logon) via WMI (Windows Management Instrumentation) Calls.
    Module will allow any logs to be collected, as long as user has permissions to pull those logs. RecordNumbers are saved inside 'TOMB\modules\DO_NOT_DELETE\' on
    a per machine per EventCode basis, preventing the pulling of same log multiple times and ensure each pull presents you with new data. 

    .NOTES
    DATE:       03 DEC 18
    VERSION:    1.0.2
    AUTHOR:     Brent Matlock

    .PARAMETER Computer
    Used to specify list of computers to collect against, if not provided then hosts are pulled from .\includes\tmp\DomainList.txt

    .PARAMETER LogID
    Used to specify list of EventID to collect against, if not provided default list activates. 
    Modification of the defaults is provided under the '#Used to fill null parameters with 'Default' settings"

    .EXAMPLE 
    Will Return Successful logins and logouts for localhost
        TOMB-LogEventLog -Computer $env:COMPUTERNAME -LogID 4624,4625
#>

#Main Script, collects Eventlogs off hosts and converts the output to Json format in preperation to send to Splunk
Function TOMB-EventLog {
    Param(
        [Parameter(Mandatory, ValueFromPipeline = $true)][string[]]$Computer,
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)][String[]]$LogID,
        [Parameter(Mandatory = $false)][string]$AD )
    #Used to fill null parameters with "Default" settings
    If ($null -eq $Computer) { $Computer = Get-Content .\includes\tmp\DomainList.txt }
    If ($null -eq $LogID) { $LogID = 4624, 4625, 1100, 1102 }
    foreach ($Machine in $Computer) {
        foreach ($Log in $LogID) {
            #Verify that Timestamp exists, if not found sets date to Current-30Days
            $LastRun = (Get-Content -Path ".\modules\DO_NOT_DELETE\${Machine}_${Log}_timestamp.log" -ErrorAction SilentlyContinue)
            If ($LastRun.Length -eq 0) { $LastRun = 1 }
            $EventLog = "Get-WmiObject Win32_NTLogEvent -Filter 'EventCode=$Log and (RecordNumber > $LastRun)'" 
            $EventLogs = [Scriptblock]::Create($EventLog)
            $EventLogFinal = Invoke-Command -ComputerName $Machine -ScriptBlock $EventLogs -ArgumentList $Log, $LastRun
            Try {
                $EventLogFinal | ConvertTo-Json | Out-File -FilePath .\Files2Forward\${Machine}_${Log}_logs.json -Append
                $EventLogFinal.RecordNumber[0]  | Out-File -FilePath .\modules\DO_NOT_DELETE\${Machine}_${Log}_timestamp.log 
            }
            Catch { $_.Exception.Message | Out-File -FilePath .\logs\ErrorLog\windowslogs.log -Append }
        }
    }
}



#Legacy Script, used in order to create a "Mock" json format. 
Function TOMB-EventLog-Mock {
    Param( 
        [Parameter(Mandatory = $true)][string]$Computer, 
        [Parameter(Mandatory = $true)][int[]]$LogID )
    $lastrun = [DateTime]::Parse($( Get-Content -Path .\modules\DO_NOT_DELETE\"$Computer"_timestamp.log ) ) 
    If ($Error) { $lastrun = (Get-Date).AddDays(-30) }
    Foreach ( $id in [array]$LogID ) {
        "Application", "System", "Security"| ForEach-Object { Get-EventLog -ComputerName $Computer -LogName $_ -After $lastrun | Where-Object InstanceId -EQ $id `
                | ForEach-Object {
                Try {
                    "{ Category:" + $_.Category,
                    ",`r`nCategoryNumber: " + $_.CategoryNumber,
                    ",`r`nContainer:" + $_.Container,
                    ",`r`nData:" + $_.Data,
                    ",`r`nEntryType" + $_.EntryType,
                    ",`r`nIndex:" + $_.Index,
                    ",`r`nInstanceId:" + $_.InstanceId,
                    ",`r`,MachineName:" + $_.MachineName,
                    ",`r`nMessage:" + $_.Message,
                    ",`r`nReplacementStrings:" + $_.ReplacementStrings,
                    ",`r`nSite:" + $_.Site,
                    ",`r`nSource:" + $_.Source,
                    ",`r`nTimeGenerated:" + $_.TimeGenerated,
                    ",`r`nTimeWritten:" + $_.TimeWritten,
                    ",`r`nUserName:" + $_.UserName,
                    ",`r`nEventID:" + $_.EventID + "}" | Out-File -FilePath .\Files2Forward\"$Computer"_"$id"_logs.json -Append 
                }
                Catch { $Error[0] | Out-File -FilePath .\logs\ErrorLog\windowslogs.log }
            }
            $TimeStamp_Generation = ( Get-Date | Out-File -FilePath .\DO_NOT_DELETE\"$Computer"_"$id"_timestamp.log )
            $TimeStamp_Generation
        } 
    } 
}

#Alias registration for deploying with -Collects parameter via TOMB.ps1
New-Alias -Name EventLog -Value TOMB-EventLog
New-Alias -Name EventLog.Mock -Value TOMB-EventLog-Mock
Export-ModuleMember -Alias * -Function *

