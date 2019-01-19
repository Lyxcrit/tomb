<#
    .SYNOPSIS
    Collects Windows Logs on the Host. Modular loaded via TOMB.ps1.
             
     .DESCRIPTION
    Used to pull Event logs from host such as EventCode 4624 (Successful Logon) or EventCode 4625 (Failed Logon) via WMI (Windows Management Instrumentation) Calls.
    Module will allow any logs to be collected, as long as user has permissions to pull those logs. RecordNumbers are saved inside 'TOMB\modules\DO_NOT_DELETE\' on
    a per machine per EventCode basis, preventing the pulling of same log multiple times and ensure each pull presents you with new data. 

    .NOTES
    DATE:       19 JAN 19
    VERSION:    1.0.3
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
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)][string[]]$Computer,
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)][String[]]$LogID,
        [Parameter(Mandatory = $false)][string]$AD )
    #Used to fill null parameters with "Default" settings
    If ($null -eq $Computer) { $Computer = Get-Content .\includes\tmp\DomainList.txt }
    If ($null -eq $LogID) { $LogIDs = $(Get-content .\includes\EventIDs.txt | Where {$_ -notmatch "^#"}) }
    Foreach ($LogID in $LogIDs) { [string[]]$LogIDx += $LogID -Split("`t") | SElect -Skip 1 | Select -First 1 }
    foreach ($Machine in $Computer) {
        #Verify that host is reachable. 
        if(Test-Connection -Count 1 -ComputerName $Machine -ErrorAction SilentlyContinue){
        foreach ($Log in $LogIDx) {
            #Verify that Timestamp exists, if not found sets date to Current-30Days
            $LastRun = (Get-Content -Path ".\modules\DO_NOT_DELETE\${Machine}_${Log}_timestamp.log" -ErrorAction SilentlyContinue)
            If ($LastRun.Length -eq 0) { $LastRun = 1 }
            #Generation of the scriptblock and allows remote machine to read variables being passed.
            $EventLog = "Get-WmiObject Win32_NTLogEvent -Filter 'EventCode=$Log and (RecordNumber > $LastRun)'" 
            $EventLogs = [Scriptblock]::Create($EventLog)
            $EventLogFinal = Invoke-Command -ComputerName $Machine -ScriptBlock $EventLogs -ArgumentList $Log, $LastRun
            Try {
                #Verify if any collections were made, if not script drops file creation and moves on. 
                if ($EventLogFinal.Length -gt 1){
                    $EventLogFinal | ConvertTo-Json20 | Out-File -FilePath .\Files2Forward\${Machine}_${Log}_logs.json -Append -Encoding utf8
                    $EventLogFinal.RecordNumber[0]  | Out-File -FilePath .\modules\DO_NOT_DELETE\${Machine}_${Log}_timestamp.log }
                else { Continue }
            }
            #ANy exception messages that were generated due to error are placed in the Errorlog: Windowslogs.log
            Catch { $_.Exception.Message | Out-File -FilePath .\logs\ErrorLog\windowslogs.log -Append }
            }
        }
        #If host is unreachable this is placed into the Errorlog: Windowslogs.log
        Else { "$(Get-Date): Host ${Machine} Status unreachable." | Out-File -FilePath .\logs\ErrorLog\windowslogs.log -Append  }
    }
    Clear-Variable Log* 
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

