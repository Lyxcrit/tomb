<#
    .SYNOPSIS
    Collects running Processs running on host. Modular loaded via TOMB.ps1
    Script will first attempt to connect via Invoke-Command (WinRM) if attempt fails a secondary attempt will
    be made via WMI(RPC) and finally attempt to connect via CIM(DCOM).

    .NOTES
    DATE:       09 AUG 19
    VERSION:    1.1.4
    AUTHOR:     Brent Matlock -Lyx
         
     .DESCRIPTION
    Used to pull Processs from host with WinRM/WMI/DCOM calls.

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
    .EXAMPLE
    Will capture services from the domain controller on the example.com domain.
        TOMB-Service -ComputerName DC01.example.com'
    .EXAMPLE
    Use specific collection method (WinRM / WMI(RPC) / CIM(DCOM))
        TOMB-Process -ComputerName DC01.example.com -Method CIM
#>

[cmdletbinding()]
Param (
    # ComputerName of the host you want to connect to.
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][System.Array] $Computer,    
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][System.Array] $Path,
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][System.String] $Method
)

#Build Variable Scope
$timestamp = [Math]::Floor([decimal](Get-Date(Get-Date).ToUniversalTime()-uformat "%s"))
$(Set-Variable -name timestamp -Scope Global) 2>&1 | Out-null
$(Set-Variable -name Computer -Scope Global) 2>&1 | Out-null
$(Set-Variable -name Path -Scope Global) 2>&1 | Out-null
$(Set-Variable -name Method -Scope Global) 2>&1 | Out-null

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
    If ($ConnectionCheck){ Get-CollectionMethod($Method) }
    Else {
        "$(Get-Date) : ERROR MESSAGE : $($Error[0])" | Out-File -FilePath $Path\logs\ErrorLog\Process.log -Append
    }
}

Function Get-CollectionMethod($Method){
    If(!($Method)){
        Process-CollectWinRM($Computer)
    }
    If($Method -eq "WinRM"){
        Process-CollectWinRM($Computer)
    }
    If($Method -eq "WMI"){
        Process-CollectWMI($Computer)
    }
    If($Method -eq "CIM"){
        Process-CollectCIM($Computer)
    }
}

Function Processes {
    $Process_List = (Get-WmiObject -Class 'Win32_Process' -ErrorAction Stop) |
                    Select-Object * -Exclude __*,*Properties,*Path,Qualifiers,Scope,Options
    $obj = $Process_List | Add-Member -MemberType NoteProperty -Name ComputerName -Value $Computer
    return $obj
}

Function Process-CollectWinRM($Computer){
    Generation of the scriptblock and allows remote machine to read variables being passed.
    $Process = "(Get-WmiObject -Class 'Win32_Process' -ErrorAction Stop) | Select-Object * -Exclude __*,*Properties,*Path,Qualifiers,Scope,Options | Add-Member -MemberType NoteProperty -Name ComputerName -Value $Computer"
    $Processes = [ScriptBlock]::Create($Process)
    $Process_List = $(Invoke-Command -ComputerName $Computer -ScriptBlock ${function:Processes} )
    Try { $Process_List
        If($null -ne $Process_List){
            Foreach($obj in $Process_List){
                #Output is encoded with UTF8 in order to Splunk to parse correctly
                $obj | Json -Compress | 
                Out-File -FilePath $Path\Files2Forward\temp\Process\${Computer}_Process.json -Append -Encoding utf8
            }
        }
        Else {
            # WinRM Failed, most to WMI (DCOM)
            "$(Get-Date) : ${Message} : WinRM Failed" | Out-File -FilePath $Path\logs\ErrorLog\Process.log -Append
               Process-CollectWMI
        }
    }
    Catch [System.Net.NetworkInformation.PingException] {
        "$(Get-Date): ${Computer} : WinRM Collection failed, or Host no longer available." | 
           Out-File -FilePath $Path\logs\ErrorLog\Process.log
    }
    CleanUp
}

Function Process-CollectWMI {
    $ts = $timestamp
    $Process_List = $((Get-WmiObject -Class 'Win32_Process' -ComputerName $Computer -ErrorAction Stop -ErrorVariable Message 2>$Message) | `
                    Select-Object * -Exclude __*,*Properties,*Path,Qualifiers,Scope,Options)
    Try{ 
        If($null -ne $Process_List){
            Foreach ($obj in $Process_List){
                $obj | Json -Compress |
                Out-File -FilePath $Path\Files2Forward\temp\Process\${Computer}_Process.json -Append -Encoding utf8
            }
        }
        Else {
            "$(Get-Date) : ${Message} : WMI Failed" | Out-File -FilePath $Path\logs\ErrorLog\Process.log -Append
               Process-CollectCIM
        }
    }
    Catch [System.Net.NetworkInformation.PingException] {
        "$(Get-Date): ${Computer} : WMI Collection failed, or Host no longer available" |
           Out-File -FilePath $Path\logs\ErrorLog\Process.log
    }
    CleanUp
}

Function Process-CollectCIM {
    $ts = $timestamp
    Try{
        $Computer = "localhost"
        $SessionOption = New-CimSessionOption -Protocol DCOM
        New-CimSession -ComputerName $Computer -Name $Computer -SessionOption $SessionOption -SkipTestConnection
        $Process_List = $(Get-CimInstance -ComputerName $Computer -ClassName Win32_Process | 
                          Select * -Exclude __*,*Properties,*Path,Qualifiers,Scope,Options)                          
        If($null -ne $Process_List){
            Foreach ($obj in $Process_List){
                $obj | Add-Member -MemberType NoteProperty -Name ComputerName -Value $Computer 
                $obj | Json -Compress |
                Out-File -FilePath $Path\Files2Forward\temp\Process\${Computer}_Process.json -Append -Encoding utf8
            }
        }
        Else {
            "$(Get-Date): ${Computer} : CIM Collection failed, or Host no longer available" |
               Out-File -FilePath $Path\logs\ErrorLog\Process.log -Append
        }
    }
    Catch {
        "$(Get-Date): ${Computer} : CIM Connection error" |
           Out-File -FilePath $Path\logs\ErrorLog\Process.log -Append
    }
    Remove-CimSession -ComputerName $Computer
    CleanUp
}

Function CleanUp {
    Move-Item -Path $Path\Files2Forward\temp\Process\${Computer}_Process.json `
              -Destination $Path\Files2Forward\Process\${Computer}_${ts}_Process.json
    Remove-Item -Path $Path\Files2Forward\temp\Process\${Computer}_Process.json
}

#Alias registration for deploying with -Collects via TOMB.ps1
New-Alias -Name Process -Value TOMB-Process
New-Alias -Name ProcessWinRM -Value Process-CollectWinRM
New-Alias -Name ProcessWMI -Value Process-CollectWMI
New-Alias -Name ProcessCIM -Value Process-CollectCIM
Export-ModuleMember -Alias * -Function * -ErrorAction SilentlyContinue
