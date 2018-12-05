<#
    .SYNOPSIS
    Collects running services running on machine. Modular loaded via TOMB or TOMB_GUI.

    .NOTES
    DATE:       05 DEC 18
    VERSION:    1.0.2
    AUTHOR:     Brent Matlock
         
     .DESCRIPTION
    Used to pull services from host with WMI (Windows Management Instrumentation) Calls.

    .PARAMETER Computer
    Used to specify list of computers to collect against, if not provided then hosts are pulled from .\includes\tmp\DomainList.txt

    .EXAMPLE 
    Will capture services on localmachine.
        TOMB-Service -computername $evn:computername 
    .EXAMPLE
    Will capture services from the domain controller on the cyber.lab domain.
        TOMB-Service -ComputerName DC01 -AD '.cyber.lab'
#>

#Main Script, collects Services off hosts and converts the output to Json format in preperation to send to Splunk
Function TOMB-Service {
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)][System.Array]$Computer,
        [Parameter(Mandatory = $false)][string]$AD )
    if ($Computer -eq $null) { $Computer = $(Get-Content .\includes\tmp\DomainList.txt)}
    foreach ($Machine in $Computer) {
        #Verify that host is reachable.
        if (Test-Connection -Count 1 -ComputerName $Machine){
            #Generation of the scriptblock and allows remote machine to read variables being passed.
            $Service = "Get-WmiObject -Class 'Win32_Service' -ComputerName $Machine$AD -Property * "
            $Services = [ScriptBlock]::Create($Service)
            $Service_List = Invoke-Command -ComputerName $Machine -ScriptBlock $Services
            Try { $Service_List | ConvertTo-Json | Out-File -FilePath .\Files2Forward\${Machine}${AD}_service.json -Append -Encoding utf8 }
            Catch { $Error[0] | Out-File -FilePath .\logs\ErrorLog\service.log -Append } }
        #If host is unreachable this is placed into the Errorlog: Service.log
        else { "$(Get-Date): Host ${Machine} Status unreachable." | Out-File -FilePath .\logs\ErrorLog\service.log -Append }
    }
}   
 
#Legacy Script, used in order to create a "Mock" json format.
Function TOMB-Services-MOCK {
    Param(
        [Parameter(Mandatory = $true)]$Computer )
    Try {
        $Service_List = $( Get-WmiObject -Class 'Win32_Service' -ComputerName $Computer ) | foreach {
            "{ AcceptPause:" + $_.AcceptPause, 
            ", AcceptStop:" + $_.AcceptStop,
            ", Caption:" + $_.Caption,
            ", CheckPoint:" + $_.CheckPoint,
            ", CreationClassName:" + $_.CreationClassName
            ", DelayedAutoStart:" + $_.DelayedAutoStart,                                                                                                                                                                        
            ", Description:" + $_.Description,                                                                                                                                                                         
            ", DesktopInteract:" + $_.DesktopInteract,
            ", DisconnectedSessions:" + $_.DisconnectedSessions,
            ", DisplayName:" + $_.DisplayName,
            ", ErrorControl:" + $_.ErrorControl,
            ", ExitCode:" + $_.ExitCode,
            ", InstallDate:" + $_.InstallDate,
            ", Name:" + $_.Name,
            ", PathName:" + $_.PathName,
            ", ProcessId:" + $_.ProcessId,
            ", ServiceSpecificExitCode:" + $_.ServiceSpecificExitCode,
            ", ServiceType:" + $_.ServiceType,
            ", Started:" + $_.Started, 
            ", StartMode:" + $_.Startmode,
            ", StartName:" + $_.StartName,
            ", State:" + $_.State,
            ", Status:" + $_.Status,
            ", SystemCreationClassName:" + $_.SystemCreationClassName, 
            ", SystemName:" + $_.SystemName,
            ", TagId:" + $_.TagId, 
            ", TotalSessions:" + $_.TotalSessions, 
            ", WaitHint:" + $_.WaitHint,
            ", __CLASS:" + $_.__CLASS,
            ", __DERIVATION:" + $_.__DERIVATION,
            ", __DYNASTY:" + $_.__DYNASTY,
            ", __GENUS:" + $_.__GENUS,
            ", __NAMESPACE:" + $_.__NAMESPACE,
            ", __PATH:" + $_.__PATH, 
            ", __PROPERTY_COUNT:" + $_.__PROPERTY_COUNT, 
            ", __RELPATH:" + $_.__RELPATH, 
            ", __SERVER:" + $_.__SERVER,
            ", __SUPERCLASS:" + $_.__SUPERCLASS + "}"} `
            | Out-File -FilePath ..\..\Files2Forward\"$Computer"_services.json
    }
    Catch { "Get-Date : $Error[0]" | Out-File -FilePath ..\..\Logs\ErrorLog\Services.log -Append }
}

#Alias registration for deploying with -Collects parameter via TOMB.ps1
New-Alias -Name Service -Value TOMB-Service
New-Alias -Name Service.Mock -Value TOMB-Service-MOCK
Export-ModuleMember -Alias * -Function * -ErrorAction SilentlyContinue