<#
    .SYNOPSIS
    Collects Windows Logs on the Host. Modular loaded via TOMB or TOMB_GUI. In an attempt to make this easier an InstanceId is provided and all 3 log types are searched.
             
     .DESCRIPTION
    Used to pull Event logs from host such as EventID 4624 (Successful Logon) or EventID 4625 (Failed Logon) via WMI (Windows Management Instrumentation) Calls.
    Module will allow any logs to be collected, as long as user has permissions to pull those logs. Timestamps are present inside 'TOMB\modules\eventlogs\tmp'
    preventing the ability to prevent pulling the same log multiple times and ensure each pull presents you with new data. 

    .NOTES
    DATE:       23 NOV 18
    VERSION:    1.0.1
    AUTHOR:     Brent Matlock

    .EXAMPLE 
    Will Return Successful logins and logouts for localhost
        TOMB-LogFiles -computerName $env:COMPUTERNAME -log_id 4624,4625
#>

#Main Script, collects Eventlogs off hosts and converts the output to Json format in preperation to send to Splunk
Function TOMB-EventLog {
    Param( 
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)][System.Array]$Computer,
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)][System.Array]$LogID,
        [Parameter(Mandatory = $false)][string]$AD )
    #Used to fill null parameters, setup as Default settings
    If ($Computer -eq $null) { $Computer = $( Get-Content .\includes\tmp\DomainList.txt ) }
    If ($LogID -eq $null) { $LogID = 4624, 4625, 1100, 1102 }
    #Logic for Collection
    Foreach ($Machine in $Computer) {
        #Verify if Timestamp exists, if not sets the date to Current-30Days
        $LastRun = $( Get-Content -Path .\modules\DO_NOT_DELETE\"$Machine"_"$LogID"_timestamp.log -ErrorVariable $TimeStamp_Missing -ErrorAction SilentlyContinue )  
        [DateTime]$TimeStamp_Missing = $($LastRun = (Get-Date).AddDays(-30).ToString()) 
        Foreach ($Log in $LogID) {
            #Logic branch for each provided log entry, LogID is checked against all 3 Eventlog types "Application, System, Security"
            [System.Array]$EventLogs = $( Invoke-Command { "Application", "Security", "System" | Foreach-Object { Get-EventLog -LogName $_ -After $LastRun | Where-Object EventId -eq $Log } } -ComputerName $Machine$AD) 
            Foreach ($item in $EventLogs) {
                Try { ConvertTo-Json20 -item $item | Out-File -FilePath ."$Machine"_"$Log"_eventlogs.json -Append }
                Catch { $Error.Message | Out-File -FilePath .\logs\ErrorLog\windowslogs.log -Append }
            }
            $TimeStamp_Generation = ( Get-Date | Out-File -FilePath .\modules\DO_NOT_DELETE\"$Machine"_"$Log"_timestamp.log ); $TimeStamp_Generation
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

