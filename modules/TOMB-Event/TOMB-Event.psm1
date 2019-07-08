<#
    .SYNOPSIS
    Collects Windows Logs on the Host. Modular loaded via TOMB.ps1.

    .DESCRIPTION
    Used to pull Event logs from host such as EventCode 4624 (Successful Logon) or EventCode 4625 (Failed Logon) via WMI (Windows Management 
    Instrumentation) Calls. Module will allow any logs to be collected, as long as user has permissions to pull those logs. RecordNumbers are 
    saved inside 'TOMB\modules\DO_NOT_DELETE\' on a per machine per EventCode basis, preventing the pulling of same log multiple times and 
    ensure each pull presents you with new data.

    .NOTES
    DATE:       27 JUN 19
    VERSION:    1.1.2c
    AUTHOR:     Brent Matlock -Lyx

    .PARAMETER Computer
    Used to specify list of computers to collect against, if not provided then hosts are pulled from .\includes\tmp\DomainList.txt

    .PARAMETER Path
    Used to specify where output folder should be, by default when launched via TOMB.ps1 this is the execution path
    where TOMB.ps1 is invoked.

    .PARAMETER -Profile
    Used to specify different event identifiers to collect based off user preferences, or requirements.
    Profiles are built in the /includes/ directory with the naming convention of "EventID_[profilename].txt", when parameter not present the
    "default" profile is loaded.

    .EXAMPLE
    Will Return Successful logins and logouts via profile UserAccess for localhost
    TOMB-LogEventLog -Computer $env:COMPUTERNAME -Profile "UserAccess"
#>

[cmdletbinding()]
Param (
    # ComputerName of the host you want to connect to.
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][System.Array] $Computer,
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][System.Array] $Path,
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][String] $Profile
)

#Build Variable Scope
$timestamp = [Math]::Floor([decimal](Get-Date(Get-Date).ToUniversalTime()-uformat "%s"))
$ts = $timestamp
$(Set-Variable -name Computer -Scope Global) 2>&1 | Out-Null
$(Set-Variable -name LastRun -Scope Global) 2>&1 | Out-Null
$(Set-Variable -name Profile -Scope Global) 2>&1 | Out-Null
$(Set-Variable -name LogID -Scope Global) 2>&1 | Out-Null
$(Set-Variable -name Path -Scope Global) 2>&1 | Out-Null

#Main Script, collects Eventlogs off hosts and converts the output to Json format in preperation to send to Splunk
Function TOMB-Event($Computer, $Path, $Profile) {
    cd $Path
    Try { 
        $ConnectionCheck = $(Test-Connection -Count 1 -ComputerName $Computer -ErrorAction Stop) 
        }
    #If host is unreachable this is placed into the Errorlog: Process.log
    Catch [System.Net.NetworkInformation.PingException] { 
        "$(Get-Date): Host ${Computer} Status unreachable." | 
        Out-File -FilePath $Path\logs\ErrorLog\windowslog.log -Append 
        }
    Catch [System.Management.Automation.Remoting.PSRemotingTransportException] { 
        "$(Get-Date): Host ${Computer} Access Denied" | 
        Out-File -FilePath $Path\logs\ErrorLog\windowslog.log -Append 
        }
    Catch [ParameterArgumentValidationError] {
        "$(Get-Date): ComputerName Parameter invalid or null" |
        Out-File -FilePath $Path\logs\ErrorLog\windowslog.log -Append
        }
    If ($ConnectionCheck) {
        EventCollect($Computer, $Profile)
    }
}

Function EventParse($Log, $LastRun) {
    $Events = Get-WinEvent -LogName 'System','Security' -FilterXPath "*/System/EventID=$Log" |
              Where-Object -FilterScript { $_.RecordId -gt $LastRun }
    ForEach ($Event in $Events) {
        # Convert the event to XML
        $eventXML = [xml]$Event.ToXml()
        # Iterate through each one of the XML message properties
        For ($i=0; $i -lt $eventXML.Event.EventData.Data.Count; $i++) {
            # Grab properties and append values to each
            Add-Member -InputObject $Event -MemberType NoteProperty -Force `
                -Name  $eventXML.Event.EventData.Data[$i].name `
                -Value $eventXML.Event.EventData.Data[$i].'#text'
        }
        $obj = $($Event | Select-Object *,@{N="EventID";E={$_.Id}}, 
                                        @{N="RecordID";E={$_.RecordId}},
                                        @{N="ComputerName";E={$_.MachineName}},
                                        @{N="MD5";E={$_.Hashes -replace "MD5=",""}},
                                        @{N="SHA1";E={$_.Hashes -replace "SHA1=",""}},
                                        @{N="SHA256";E={$_.Hashes -replace "SHA256=",""}},
                                        @{N="Description";E={$_.KeywordsDisplayNames}},
                                        @{N="ProcessID";E={[Convert]::ToInt64($_.ProcessId,16)}},
                                        @{N="NewProcessID";E={[Convert]::ToInt64($_.NewProcessId,16)}},
                                        @{N="SubjectLogonID";E={[Convert]::ToInt64($_.SubjectLogonId,16)}},
                                        @{N="TargetLogonID";E={[Convert]::ToInt64($_.TargetLogonId,16)}},
                                        @{N="TimeCreated";E={[DateTime]$_.TimeCreated -replace '\\/'.""}} `
        -Exclude Message,*Properties,Bookmark,*Keyword*,Matched*,Provider*,ActivityId,Id,Opcode,Version,MachineName,Hashes, `
                 *ActivityId,Qualifiers,ProcessId,NewProcessId,SubjectLogonId,TimeCreated,RecordId,TargetLogonId)
    return $obj
    }        
}

Function EventCollect {
    If (!($Profile)) { $Profile = "Default" }
    $LogIDs = $(Get-content $Path\includes\EventID_${Profile}.txt | Where-Object {$_ -notmatch "^#"}) 
    Foreach ($LogID in $LogIDs) { 
        [string[]]$LogIDx += $LogID -Split("`t") | Select-Object -First 1 
        }
    Foreach ($Log in $LogIDx) {
        #Verify that Timestamp exists, if not found sets date to Current-30Days
        $LastRun = (Get-Content -Path $Path\modules\DO_NOT_DELETE\${Computer}_${Log}_timestamp.log -ErrorAction SilentlyContinue)
        If ($LastRun.Length -eq 0) { $LastRun = 1 }
        #Generation of the scriptblock and allows remote machine to read variables being passed.
        $EventLogFinal = $(Invoke-Command -ComputerName $Computer -ScriptBlock ${function:EventParse} -ErrorVariable Message 2>$Message -ErrorAction Stop -ArgumentList $Log, $LastRun)
        Try { $EventLogFinal
            #Verify if any collections were made, if not script drops file creation and moves on.
            If ($null -ne $EventLogFinal){
                Foreach($obj in $EventLogFinal){ 
                    $obj | TOMB-Json -Compress | 
                    Out-File -FilePath $Path\Files2Forward\temp\Events\${Computer}_${Log}_logs.json -Append # -Encoding UTF8
                    $obj.RecordID[0] | Out-File -FilePath $Path\modules\DO_NOT_DELETE\${Computer}_${Log}_timestamp.log
                    CleanUp
                }
            }
        }
        #Any exception messages that were generated due to error are placed in the Errorlog: Windowslogs.log
        Catch {
            "$(Get-Date): $(${Computer}), $(${Message})" | Out-File -FilePath $Path\logs\ErrorLog\windowslog.log -Append
            If ($_.exception -eq "*no events*"){
                "$(Get-Date): No Events Found for ${Computer}:${Log}" | Out-File -FilePath $Path\logs\ErrorLog\windowslog.log -Append
            }
            Elif($_.exception -eq "Parameter Cannot be set*"){
                "$(Get-Date): Parameter fucked up" | Out-File -FilePath .\logs\ErrorLog\windowslog.log -Append
            }
            Else {
                "$(Get-Date): Test" | Out-File -FilePath $Path\logs\ErrorLog\windowslog.log -Append
            }
        }
    }
}

Function CleanUp {
    $File = $(Get-Content $Path\Files2Forward\temp\Events\${Computer}_${Log}_logs.json)
    $File | Out-File -FilePath $Path\Files2Forward\Events\${Computer}_${Log}_${ts}_logs.json -Encoding UTF8
    Remove-Item -Path "${Path}\Files2Forward\temp\Events\${Computer}_${Log}_logs.json"
}

#Alias registration for deploying with -Collects parameter via TOMB.ps1
New-Alias -Name Event -Value TOMB-Event
Export-ModuleMember -Alias * -Function * -ErrorAction SilentlyContinue