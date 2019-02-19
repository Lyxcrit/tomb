<#
    .SYNOPSIS
    Collects scheduled tasks on machine. Modular loaded via TOMB.ps1

    .NOTES
    DATE:       18 FEB 19
    VERSION:    1.0.4a
    AUTHOR:     Brent Matlock -Lyx
         
     .DESCRIPTION
    Used to pull Scheduled Tasks from host with WMI (Windows Management Instrumentation) Calls.

    .PARAMETER Computer
    Used to specify list of computers to collect against
        If not provided then hosts are pulled from .\includes\tmp\DomainList.txt when the -Domain parameter is used
        If not provided then hosts are pulled from .\includes\tmp\StaticList.txt otherwise
   
    .PARAMETER Path
    Used to specify where output folder should be, by default when launched via TOMB.ps1 this is the execution path
    where TOMB.ps1 is invoked.

    .EXAMPLE 
    Will capture scheduled tasks on localmachine.
        TOMB-ScheduledTask -Computer $env:computername 
#>

[cmdletbinding()]
Param (
    # ComputerName of the host you want to connect to.
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][System.Array] $Computer,    
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][System.Array] $Path
)

#Build Variable Scope
$(Set-Variable -name Computer -Scope Global) 2>&1 | Out-null
$(Set-Variable -name Path -Scope Global) 2>&1 | Out-null 

#Main Script, collects Processess off hosts and converts the output to Json format in preperation to send to Splunk
Function TOMB-ScheduledTask($Computer, $Path){
    cd $Path
    Try {
        $ConnectionCheck = $(Test-Connection -Count 1 -ComputerName $Computer -ErrorAction Stop)
        }
    #If host is unreachable this is placed into the Errorlog: ScheduledTask.log
    Catch [System.Net.NetworkInformation.PingException] {
        "$(Get-Date): Host ${Computer} Status unreachable." |
        Out-File -FilePath $Path\logs\ErrorLog\scheduledtask.log -Append
        }
    Catch [System.Management.Automation.Remoting.PSRemotingTransportException] {
        "$(Get-Date): Host ${Computer} Access Denied" |
        Out-File -FilePath $Path\logs\ErrorLog\scheduledtask.log -Append
        }
    If ($ConnectionCheck){ ScheduledTaskCollect($Computer) }
    Else {
        "$(Get-Date) : ERROR MESSAGE : $($Error[0])" | Out-File -FilePath $Path\logs\ErrorLog\scheduledtask.log -Append
    }
}

#Used to build out the initial ScriptBlock
Function SchedTask {
    Get-ScheduledTask -TaskPath '\' |
    ForEach-Object { [pscustomobject]@{
        Server = $env:COMPUTERNAME
        Name = $_.TaskName
        Path = $_.TaskPath
        Description = $_.Description
        Author = $_.Author
        RunAsUser = $_.Principal.userid
        LastRunTime = ($_ | Get-ScheduledTaskInfo).LastRunTime
        LastResult = ($_ | Get-ScheduledTaskInfo).LastTaskResult
        NextRun = ($_ | Get-ScheduledTaskInfo).NextRunTime
        Status = $_.State
        Command = $_.Actions.execute
        Arguments = $_.Actions.Arguments }}
}

Function ScheduledTaskCollect($Computer){
    #Generation of the scriptblock and allows remote machine to read variables being passed.
    $ScheduleTask = $(Invoke-Command -ComputerName $Computer -ScriptBlock ${function:Schedtask} -ErrorVariable Message 2>$Message)
    Try { $ScheduleTask
        If($ScheduleTask -ne $null){
            Foreach($obj in $ScheduleTask){
                #Output is encoded with UTF8 in order to Splunk to parse correctly
                $obj | TOMB-Json | Out-File -FilePath $Path\Files2Forward\SchedTask\${Computer}_ScheduledTask.json -Append -Encoding utf8
            }
        }
        Else {
            "$(Get-Date) : $($Message)" | Out-File -FilePath $Path\logs\ErrorLog\scheduledtask.log -Append
        }
    }
    Catch [System.Net.NetworkInformation.PingException] {
        "$(Get-Date): Host ${Computer} Status unreachable after."
    Out-File -FilePath $Path\logs\ErrorLog\scheduledtask.log
    }
}


#Alias registration for deploying with -Collects via TOMB.ps1
New-Alias -Name SchedTask -Value TOMB-ScheduledTask
Export-ModuleMember -Alias * -Function * -ErrorAction SilentlyContinue