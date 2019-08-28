<#
    .SYNOPSIS
    Collects Connections running/installed on host. Modular loaded via TOMB.ps1
    Script will first attempt to connect via Invoke-Command (WinRM) if attempt fails a secondary attempt will
    be made via WMI(RPC) and finally attempt to connect via CIM(DCOM)

    .NOTES
    DATE:       28 AUG 19
    VERSION:    1.1.4 ??????????????????????????????????????????????????
    AUTHOR:     Brent Matlock -Lyx

     .DESCRIPTION
    Used to pull Connections from host with WinRM/WMI/DCOM calls.

    .PARAMETER Computer
    Used to specify list of computers to collect against, if not provided then hosts are pulled from .\includes\tmp\DomainList.txt

    .PARAMETER Path
    Used to specify where output folder should be, by default when launched via TOMB.ps1 this is the execution path
    where TOMB.ps1 is invoked.

    .EXAMPLE
    Will capture connections on localmachine.
        TOMB-Connection -computername $evn:computername
    .EXAMPLE
    Will capture connections from the domain controller on the example.com domain.
        TOMB-Connection -ComputerName DC01.example.com'
    .EXAMPLE
    Use specific collection method (WinRM / WMI(RPC) / CIM(DCOM))
        TOMB-Connection -ComputerName DC01.example.com -Method CIM
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

#Main Script, collects Connections off hosts and converts the output to Json format in preperation to send to Splunk
Function TOMB-Connection($Computer, $Path){
    cd $Path
    Try {
        $ConnectionCheck = $(Test-Connection -Count 1 -ComputerName $Computer -ErrorAction Stop)
        }
    #If host is unreachable this is placed into the Errorlog: Connection.log
    Catch [System.Net.NetworkInformation.PingException] {
        "$(Get-Date): Host ${Computer} Status unreachable." |
        Out-File -FilePath $Path\logs\ErrorLog\connection.log -Append
        }
    Catch [System.Management.Automation.Remoting.PSRemotingTransportException] {
        "$(Get-Date): Host ${Computer} Access Denied" |
        Out-File -FilePath $Path\logs\ErrorLog\connection.log -Append
        }
    If ($ConnectionCheck){ Get-CollectionMethod($Method) }
    Else {
        "$(Get-Date) : ERROR MESSAGE : $($Error[0])" | Out-File -FilePath $Path\logs\ErrorLog\connection.log -Append
    }
}
Function Get-CollectionMethod($Method){
    If(!($Method)){
        Connection-CollectWinRM($Computer)
    }
    If($Method -eq "WinRM"){
        Connection-CollectWinRM($Computer)
    }
    If($Method -eq "WMI"){
        Connection-CollectWMI($Computer)
    }
    If($Method -eq "CIM"){
        Connection-CollectCIM($Computer)
    }
}



Function Connection-CollectWinRM($Computer){
    $stateList = 'Closed','Listen','SynSent','SynReceived','Established','FinWait1','FinWait2','CloseWait','Closing','LastAck','TimeWait','DeleteTCB'
    #Generation of the scriptblock and allows remote machine to read variables being passed.
    $Connection = "(Get-WmiObject -Class 'MSFT_NetTCPConnection' -Namespace root/standardcimv2) | Select-Object CreationTime,LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess,state"
    $Connections = [ScriptBlock]::Create($Connection)
    $Connection_List = $(Invoke-Command -ComputerName $Computer -ScriptBlock $Connections -ErrorVariable Message 2>$Message)
    Try { $Connection_List
        If($null -ne $Connection_List){
            #Add state description and protocol properties to log
            Foreach ($obj in $Connection_List){$num=$obj.'state';$num--;$stateD=$stateList[$num];$obj | Add-Member -NotePropertyName stateDescription -NotePropertyValue $stateD; $obj | Add-Member -NotePropertyName Protocol -NotePropertyValue 'TCP'
            }
            Foreach($obj in $Connection_List){
                $obj | Json -Compress |
                Out-File -FilePath $Path\Files2Forward\temp\Connection\${Computer}_connection.json -Append -Encoding UTF8
            }
        #WinRM TCP Success
        "$(Get-Date) : ${Message} : WinRM TCP Success" | Out-File -FilePath $Path\logs\ErrorLog\connection.log -Append
        }
        Else {
            #WinRM Failed, Move to WMI
            "$(Get-Date) : ${Message} : WinRM Failed" | Out-File -FilePath $Path\logs\ErrorLog\connection.log -Append
               Connection-CollectWMI
        }
    }
    Catch [System.Net.NetworkInformation.PingException] {
        "$(Get-Date): ${Computer} : WinRM Collection failed, or Host no longer available" |
           Out-File -FilePath $Path\logs\ErrorLog\connection.log -Append
    }

    $Connection = "(Get-WmiObject -Class 'MSFT_NetUDPEndpoint' -Namespace root/standardcimv2) | Select-Object CreationTime,LocalAddress,LocalPort,OwningProcess,state,RemotePort,RemoteAddress"
    $Connections = [ScriptBlock]::Create($Connection)
    $Connection_List = $(Invoke-Command -ComputerName $Computer -ScriptBlock $Connections -ErrorVariable Message 2>$Message)
    Try { $Connection_List
        If($null -ne $Connection_List){
            #Add protocol properties to log
            Foreach ($obj in $Connection_List){$obj | Add-Member -NotePropertyName Protocol -NotePropertyValue 'UDP'
            }
            Foreach($obj in $Connection_List){
                $obj | Json -Compress |
                Out-File -FilePath $Path\Files2Forward\temp\Connection\${Computer}_connection.json -Append -Encoding UTF8
            }
        #WinRM UDP Success
        "$(Get-Date) : ${Message} : WinRM UDP Success" | Out-File -FilePath $Path\logs\ErrorLog\connection.log -Append
        }
        Else {
            #WinRM Failed, Move to WMI
            "$(Get-Date) : ${Message} : WinRM Failed" | Out-File -FilePath $Path\logs\ErrorLog\connection.log -Append
               Connection-CollectWMI
        }
    }
    Catch [System.Net.NetworkInformation.PingException] {
        "$(Get-Date): ${Computer} : WinRM Collection failed, or Host no longer available" |
           Out-File -FilePath $Path\logs\ErrorLog\connection.log -Append
    }
    CleanUp
}

Function Connection-CollectWMI{
    $stateList = 'Closed','Listen','SynSent','SynReceived','Established','FinWait1','FinWait2','CloseWait','Closing','LastAck','TimeWait','DeleteTCB'
    $Connection_List = $((Get-WmiObject -Class 'MSFT_NetTCPConnection' -Namespace root/standardcimv2) | Select-Object CreationTime,LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess,state)
    Try{
        If($null -ne $Connection_List){
            #Add state description and protocol properties to log
            Foreach ($obj in $Connection_List){$num=$obj.'state';$num--;$stateD=$stateList[$num];$obj | Add-Member -NotePropertyName stateDescription -NotePropertyValue $stateD; $obj | Add-Member -NotePropertyName Protocol -NotePropertyValue 'TCP'}
            Foreach ($obj in $Connection_List){
                $obj | Json -Compress |
                Out-File -FilePath $Path\Files2Forward\temp\Connection\${Computer}_connection.json -Append -Encoding UTF8
            }
        #WMI TCP Success
        "$(Get-Date) : WMI TCP Collection Success" | Out-File -FilePath $Path\logs\ErrorLog\connection.log -Append
        }
        Else {
            "$(Get-Date) : ${Message} : WMI Failed" | Out-File -FilePath $Path\logs\ErrorLog\connection.log -Append
               ConnectionCIM
        }
    }
    Catch [System.Net.NetworkInformation.PingException] {
        "$(Get-Date): ${Computer} : WMI Collection failed, or Host no longer available" |
           Out-File -FilePath $Path\logs\ErrorLog\connection.log -Append
    }
    $Connection = $((Get-WmiObject -Class 'MSFT_NetUDPEndpoint' -Namespace root/standardcimv2) | Select-Object CreationTime,LocalAddress,LocalPort,OwningProcess,state,RemotePort,RemoteAddress)
    Try{
        If($null -ne $Connection_List){
            #Add protocol properties to log
            Foreach ($obj in $Connection_List){$obj | Add-Member -NotePropertyName Protocol -NotePropertyValue 'UDP'}
            Foreach ($obj in $Connection_List){
                $obj | Json -Compress |
                Out-File -FilePath $Path\Files2Forward\temp\Connection\${Computer}_connection.json -Append -Encoding UTF8
            }
        #WMI UDP Success
        "$(Get-Date) : WMI UDP Collection Success" | Out-File -FilePath $Path\logs\ErrorLog\connection.log -Append
        }
        Else {
            "$(Get-Date) : ${Message} : WMI Failed" | Out-File -FilePath $Path\logs\ErrorLog\connection.log -Append
               ConnectionCIM
        }
    }
    Catch [System.Net.NetworkInformation.PingException] {
        "$(Get-Date): ${Computer} : WMI Collection failed, or Host no longer available" |
           Out-File -FilePath $Path\logs\ErrorLog\connection.log -Append
    }
    CleanUp
}

Function Connection-CollectCIM {
    $stateList = 'Closed','Listen','SynSent','SynReceived','Established','FinWait1','FinWait2','CloseWait','Closing','LastAck','TimeWait','DeleteTCB'
    $ts = $timestamp
    Try{
        $SessionOption = New-CimSessionOption -Protocol DCOM
        New-CimSession -ComputerName $Computer -Name $Computer -SessionOption $SessionOption -SkipTestConnection
         $Connection_List = $(Get-CimInstance -Class MSFT_NetTCPConnection -Namespace root/standardcimv2 | Select-Object CreationTime,LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess,state)                          
        If($null -ne $Connection_List){
            #Add state description and protocol properties to log
            Foreach ($obj in $Connection_List){$num=$obj.'state';$num--;$stateD=$stateList[$num];$obj | Add-Member -NotePropertyName stateDescription -NotePropertyValue $stateD; $obj | Add-Member -NotePropertyName Protocol -NotePropertyValue 'TCP'}
            Foreach ($obj in $Connection_List){
                $obj | Add-Member -MemberType NoteProperty -Name ComputerName -Value $Computer 
                $obj | Json -Compress |
                Out-File -FilePath $Path\Files2Forward\temp\Connection\${Computer}_connection.json -Append -Encoding utf8
            }
        #CIM Success
        "$(Get-Date) : ${Message} : CIM TCP Collection Success" | Out-File -FilePath $Path\logs\ErrorLog\connection.log -Append

        }
        Else {
            "$(Get-Date): ${Computer} : CIM Collection failed, or Host no longer available" |
               Out-File -FilePath $Path\logs\ErrorLog\Connection.log -Append
        }
    }
    Catch {
        "$(Get-Date): ${Computer} : CIM Connection error" |
           Out-File -FilePath $Path\logs\ErrorLog\Connection.log -Append
    }
    Try{
        $SessionOption = New-CimSessionOption -Protocol DCOM
        New-CimSession -ComputerName $Computer -Name $Computer -SessionOption $SessionOption -SkipTestConnection
         $Connection_List = $(Get-CimInstance -Class MSFT_NetUDPEndpoint -Namespace root/standardcimv2 | Select-Object CreationTime,LocalAddress,LocalPort,OwningProcess,state,RemotePort,RemoteAddress)                          
        If($null -ne $Connection_List){
            #Add protocol properties to log
            Foreach ($obj in $Connection_List){$obj | Add-Member -NotePropertyName Protocol -NotePropertyValue 'UDP'}
            Foreach ($obj in $Connection_List){
                $obj | Add-Member -MemberType NoteProperty -Name ComputerName -Value $Computer 
                $obj | Json -Compress |
                Out-File -FilePath $Path\Files2Forward\temp\Connection\${Computer}_connection.json -Append -Encoding utf8
            }
        #CIM Success
        "$(Get-Date) : ${Message} : CIM UDP Collection Success" | Out-File -FilePath $Path\logs\ErrorLog\connection.log -Append

        }
        Else {
            "$(Get-Date): ${Computer} : CIM Collection failed, or Host no longer available" |
               Out-File -FilePath $Path\logs\ErrorLog\Connection.log -Append
        }
    }
    Catch {
        "$(Get-Date): ${Computer} : CIM Connection error" |
           Out-File -FilePath $Path\logs\ErrorLog\Connection.log -Append
    }
    Remove-CimSession -ComputerName $Computer
    CleanUp
}

Function CleanUp{
    Move-Item -Path $Path\Files2Forward\temp\Connection\${Computer}_connection.json `
              -Destination $Path\Files2Forward\Connection\${Computer}_${ts}_connection.json
    Remove-Item $Path\Files2Forward\temp\Connection\${Computer}_connection.json
}

#Alias registration for deploying with -Collects parameter via TOMB.ps1
New-Alias -Name Connection -Value TOMB-Connection
New-Alias -Name ConnectionWinRM -Value Connection-CollectWinRM
New-Alias -Name ConnectionWMI -Value Connection-CollectWMI
New-Alias -Name ConnectionCIM -Value Connection-CollectCIM
Export-ModuleMember -Alias * -Function * -ErrorAction SilentlyContinue
