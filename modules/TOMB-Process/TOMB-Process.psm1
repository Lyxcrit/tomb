<#
    .SYNOPSIS
    Collects running Processs running on machine. Modular loaded via TOMB.ps1

    .NOTES
    DATE:       20 MAR 19
    VERSION:    1.1.1
    AUTHOR:     Brent Matlock -Lyx
         
     .DESCRIPTION
    Used to pull Processs from host with WMI (Windows Management Instrumentation) Calls.

    .PARAMETER Computer
    Used to specify list of computers to collect against
        If not provided then hosts are pulled from .\includes\tmp\DomainList.txt when the -Domain parameter is used
        If not provided then hosts are pulled from .\includes\tmp\StaticList.txt otherwise
   
    .PARAMETER Path
    Used to specify where output folder should be, by default when launched via TOMB.ps1 this is the execution path
    where TOMB.ps1 is invoked.

    .EXAMPLE 
    Will capture Processs on localmachine.
        TOMB-Process -computername $evn:computername 
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
Function TOMB-Process($Computer, $Path){
    cd $Path
    Try {
        $ConnectionCheck = $(Test-Connection -Count 1 -ComputerName $Computer -ErrorAction Stop)
        }
    #If host is unreachable this is placed into the Errorlog: Process.log
    Catch [System.Net.NetworkInformation.PingException] {
        "$(Get-Date): Host ${Computer} Status unreachable." |
        Out-File -FilePath $Path\logs\ErrorLog\Process.log -Append
        }
    Catch [System.Management.Automation.Remoting.PSRemotingTransportException] {
        "$(Get-Date): Host ${Computer} Access Denied" |
        Out-File -FilePath $Path\logs\ErrorLog\Process.log -Append
        }
    If ($ConnectionCheck){ ProcessCollect($Computer) }
    Else {
        "$(Get-Date) : ERROR MESSAGE : $($Error[0])" | Out-File -FilePath $Path\logs\ErrorLog\Process.log -Append
    }
}

Function ProcessCollect($Computer){
    #Generation of the scriptblock and allows remote machine to read variables being passed.
    $Process = "(Get-WmiObject -Class 'Win32_Process' -ErrorAction Stop) | Select * -Exclude __*,*Properties,*Path,Qualifiers,Scope,Options"
    $Processes = [ScriptBlock]::Create($Process)
    $Process_List = $(Invoke-Command -ComputerName $Computer -ScriptBlock $Processes -ErrorVariable Message 2>$Message)
    Try { $Process_List
        If($Process_List -ne $null){
            Foreach($obj in $Process_List){
                #Output is encoded with UTF8 in order to Splunk to parse correctly
                $obj | TOMB-Json | Out-File -FilePath $Path\Files2Forward\temp\Process\${Computer}_Process.json -Append -Encoding utf8
            }
        }
        Else {
            "$(Get-Date) : $($Message)" | Out-File -FilePath $Path\logs\ErrorLog\Process.log -Append
        }
    }
    Catch [System.Net.NetworkInformation.PingException] {
        "$(Get-Date): Host ${Computer} Status unreachable after."
    Out-File -FilePath $Path\logs\ErrorLog\Process.log
    }
    Move-Item -Path $Path\Files2Forward\temp\Process\${Computer}_Process.json -Destination $Path\Files2Forward\Process\${Computer}_Process.json
    Remove-Item $Path\Files2Forward\temp\Process\${Computer}_Process.json
}


#Alias registration for deploying with -Collects via TOMB.ps1
New-Alias -Name Process -Value TOMB-Process
Export-ModuleMember -Alias * -Function * -ErrorAction SilentlyContinue
