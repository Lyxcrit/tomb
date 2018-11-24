<#
    .SYNOPSIS
        Collects Windows Logs on the Host. Modular loaded via TOMB or TOMB_GUI. In an attempt to make this easier an InstanceId is provided and all 3 log types are searched.
             
     .DESCRIPTION
        Used to pull Event logs from host such as EventID 4624 (Successful Logon) or EventID 4625 (Failed Logon) via WMI (Windows Management Instrumentation) Calls.
        Module will allow any logs to be collected, as long as user has permissions to pull those logs. Timestamps are present inside 'TOMB\modules\eventlogs\tmp'
        preventing the ability to prevent pulling the same log multiple times and ensure each pull presents you with new data. 

    .README
        If you want to change the default lookup time for first pulls (Default 30 days) change the following:
            Line 30:  $TimeSTamp_Missing = $( $LastRun = (Get-Date).AddDays([Insert Negative Int]))
            This will take the CURRENT time and set the variable back to your desired date. ie. If you want to pull the previous week, you would use (-7)

    .EXAMPLE 
        GUI: No examples provided, please see included web help for futher information. 
        CLI: TOMB-LogFiles -computerName $env:COMPUTERNAME -log_id 4624,4625
            Will Return Successful logins and logouts for localhost
#>


Function TOMB-EventLog {
    Param( 
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)][System.Array]$Computer,
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)][System.Array]$LogID,
        [Parameter(Mandatory=$false)][string]$AD )
        Write-Host "Computer is: $Computer"
        Write-Host "Log ID is: $LogID"
        if($Computer -eq $null){ $Computer = $( Get-Content .\includes\tmp\DomainList.txt )}
        #if ($LogID -eq $null){ $LogID = 4624,4625,1100,1102 }
        foreach ($Machine in $Computer){
        $LastRun = [DateTime]::Parse($( Get-Content -Path .\modules\DO_NOT_DELETE\"$Machine$AD"_timestamp.log -ErrorVariable $TimeStamp_Missing -ErrorAction SilentlyContinue ) ) 
        [String]$TimeStamp_Missing = $($LastRun = (Get-Date).AddDays(-30))
            foreach ($Log in $LogID){
                Try { [array]$EventLogs = $( "Application","Security","System" | foreach { Get-EventLog -ComputerName $Machine$AD -LogName $_ -After $LastRun | Where InstanceId -EQ $Log } ) }
                Catch { $Error[0] | Out-File -FilePath .\logs\ErrorLog\windowslogs.log -Append }
                    foreach ($item in $EventLogs){ ConvertTo-Json20 -item $item | Out-File -FilePath .\Files2Forward\"$Machine"_"$Log"_eventlogs.json -Append 
                                                   $EventLogs.Clear() 
                                                   $item.Clear() }
            $TimeStamp_Generation = ( Get-Date | Out-File -FilePath .\modules\DO_NOT_DELETE\"$Machine$AD"_"$Log"_timestamp.log )
            } 
        } 
    }


Function TOMB-EventLog-Mock {
    Param( 
        [Parameter(Mandatory=$true)][string]$Computer, 
        [Parameter(Mandatory=$true)][int[]]$LogID )
        $lastrun = [DateTime]::Parse($( Get-Content -Path .\modules\DO_NOT_DELETE\"$Computer"_timestamp.log ) ) 
            if ($Error){ $lastrun = (Get-Date).AddDays(-30) }
            foreach ( $id in [array]$LogID ){ "Application","System","Security"| foreach { Get-EventLog -ComputerName $Computer -LogName $_ -After $lastrun | Where InstanceId -EQ $id `
             | foreach {
                Try {
                    "{ Category:"+$_.Category,
                    ",`r`nCategoryNumber: "+$_.CategoryNumber,
                    ",`r`nContainer:"+$_.Container,
                    ",`r`nData:"+$_.Data,
                    ",`r`nEntryType"+$_.EntryType,
                    ",`r`nIndex:"+$_.Index,
                    ",`r`nInstanceId:"+$_.InstanceId,
                    ",`r`,MachineName:"+$_.MachineName,
                    ",`r`nMessage:"+$_.Message,
                    ",`r`nReplacementStrings:"+$_.ReplacementStrings,
                    ",`r`nSite:"+$_.Site,
                    ",`r`nSource:"+$_.Source,
                    ",`r`nTimeGenerated:"+$_.TimeGenerated,
                    ",`r`nTimeWritten:"+$_.TimeWritten,
                    ",`r`nUserName:"+$_.UserName,
                    ",`r`nEventID:"+$_.EventID + "}" | Out-File -FilePath .\Files2Forward\"$Computer"_"$id"_logs.json -Append 
                    }
                Catch { $Error[0] | Out-File -FilePath .\logs\ErrorLog\windowslogs.log }
                }
            $TimeStamp_Generation = ( Get-Date | Out-File -FilePath .\DO_NOT_DELETE\"$Computer"_"$id"_timestamp.log )
            } 
        } 
    }

#Alias registration for deploying with -Collects parameter via TOMB.ps1
New-Alias -Name EventLog -Value TOMB-EventLog
New-Alias -Name EventLog.Mock -Value TOMB-EventLog-Mock
Export-ModuleMember -Alias * -Function *

