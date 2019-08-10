<#
    .SYNOPSIS
    Collects Services running/installed on host. Modular loaded via TOMB.ps1
    Script will first attempt to connect via Invoke-Command (WinRM) if attempt fails a secondary attempt will
    be made via WMI(RPC) and finally attempt to connect via CIM(DCOM)

    .NOTES
    DATE:       09 AUG 19
    VERSION:    1.1.4
    AUTHOR:     Brent Matlock -Lyx

     .DESCRIPTION
    Used to pull Processs from host with WinRM/WMI/DCOM calls.

    .PARAMETER Computer
    Used to specify list of computers to collect against, if not provided then hosts are pulled from .\includes\tmp\DomainList.txt

    .PARAMETER Path
    Used to specify where output folder should be, by default when launched via TOMB.ps1 this is the execution path
    where TOMB.ps1 is invoked.

    .EXAMPLE
    Will capture services on localmachine.
        TOMB-Service -computername $evn:computername
    .EXAMPLE
    Will capture services from the domain controller on the example.com domain.
        TOMB-Service -ComputerName DC01.example.com'
    .EXAMPLE
    Use specific collection method (WinRM / WMI(RPC) / CIM(DCOM))
        TOMB-Service -ComputerName DC01.example.com -Method CIM
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
$ts = $timestamp
$(Set-Variable -name timestamp -Scope Global) 2>&1 | Out-null
$(Set-Variable -name Computer -Scope Global) 2>&1 | Out-null
$(Set-Variable -name Path -Scope Global) 2>&1 | Out-null
$(Set-Variable -name Method -Scope Global) 2>&1 | Out-null

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
    If ($ConnectionCheck){ Get-CollectionMethod($Method) }
    Else {
        "$(Get-Date) : ERROR MESSAGE : $($Error[0])" | Out-File -FilePath $Path\logs\ErrorLog\service.log -Append
    }
}

Function Get-CollectionMethod($Method){
    If(!($Method)){
        Service-CollectWinRM($Computer)
    }
    If($Method -eq "WinRM"){
        Service-CollectWinRM($Computer)
    }
    If($Method -eq "WMI"){
        Service-CollectWMI($Computer)
    }
    If($Method -eq "CIM"){
        Service-CollectCIM($Computer)
    }
}

Function Service-CollectWinRM($Computer){
    #Generation of the scriptblock and allows remote machine to read variables being passed.
    $Service = "(Get-WmiObject -Class 'Win32_Service' -ErrorAction Stop) | Select * -Exclude __*,*Properties,*Path,Qualifiers,Scope,Options"
    $Services = [ScriptBlock]::Create($Service)
    $Service_List = $(Invoke-Command -ComputerName $Computer -ScriptBlock $Services -ErrorVariable Message 2>$Message)
    Try { $Service_List
        If($null -ne $Service_List){
            Foreach($obj in $Service_List){
                $obj | Json -Compress |
                Out-File -FilePath $Path\Files2Forward\temp\Service\${Computer}_service.json -Append -Encoding UTF8
            }
        }
        Else {
            #WinRM Failed, Move to WMI
            "$(Get-Date) : ${Message} : WinRM Failed" | Out-File -FilePath $Path\logs\ErrorLog\service.log -Append
               Service-CollectWMI
        }
    }
    Catch [System.Net.NetworkInformation.PingException] {
        "$(Get-Date): ${Computer} : WinRM Collection failed, or Host no longer available" |
           Out-File -FilePath $Path\logs\ErrorLog\service.log -Append
    }
    CleanUp
}

Function Service-CollectWMI{
    $Service_List = $((Get-WmiObject -Class 'Win32_Service' -ComputerName $Computer -ErrorAction Stop) | Select-Object * -Exclude __*,*Properties,*Path,QUalifiers,Scope,Options)
    Try{
        If($null -ne $Service_List){
            Foreach ($obj in $Service_List){
                $obj | Json -Compress |
                Out-File -FilePath $Path\Files2Forward\temp\Service\${Computer}_service.json -Append -Encoding UTF8
            }
        }
        Else {
            "$(Get-Date) : ${Message} : WMI Failed" | Out-File -FilePath $Path\logs\ErrorLog\service.log -Append
               ServiceCIM
        }
    }
    Catch [System.Net.NetworkInformation.PingException] {
        "$(Get-Date): ${Computer} : WMI Collection failed, or Host no longer available" |
           Out-File -FilePath $Path\logs\ErrorLog\service.log -Append
    }
    CleanUp
}

Function Service-CollectCIM {
    $ts = $timestamp
    Try{
        $SessionOption = New-CimSessionOption -Protocol DCOM
        New-CimSession -ComputerName $Computer -Name $Computer -SessionOption $SessionOption -SkipTestConnection
        $Service_List = $(Get-CimInstance -ComputerName $Computer -ClassName Win32_Service | 
                          Select * -Exclude __*,*Properties,*Path,Qualifiers,Scope,Options)                          
        If($null -ne $Service_List){
            Foreach ($obj in $Service_List){
                $obj | Add-Member -MemberType NoteProperty -Name ComputerName -Value $Computer 
                $obj | Json -Compress |
                Out-File -FilePath $Path\Files2Forward\temp\Service\${Computer}_service.json -Append -Encoding utf8
            }
        }
        Else {
            "$(Get-Date): ${Computer} : CIM Collection failed, or Host no longer available" |
               Out-File -FilePath $Path\logs\ErrorLog\Service.log -Append
        }
    }
    Catch {
        "$(Get-Date): ${Computer} : CIM Connection error" |
           Out-File -FilePath $Path\logs\ErrorLog\Service.log -Append
    }
    Remove-CimSession -ComputerName $Computer
    CleanUp
}

Function CleanUp{
    Move-Item -Path $Path\Files2Forward\temp\Process\${Computer}_service.json `
              -Destination $Path\Files2Forward\Process\${Computer}_${ts}_service.json
    Remove-Item $Path\Files2Forward\temp\Service\${Computer}_service.json
}

#Alias registration for deploying with -Collects parameter via TOMB.ps1
New-Alias -Name Service -Value TOMB-Service
New-Alias -Name ServiceWinRM -Value Service-CollectWinRM
New-Alias -Name ServiceWMI -Value Service-CollectWMI
New-Alias -Name ServiceCIM -Value Service-CollectCIM
Export-ModuleMember -Alias * -Function * -ErrorAction SilentlyContinue