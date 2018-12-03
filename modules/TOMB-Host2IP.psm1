<#
    .SYNOPSIS
    Collects host names within the given domain and utilizes DNS to resolve those to and IP address. 
     
     .DESCRIPTION
    Used to correlate hostnames and IP addresses within the target domain. Final product is used within Splunk as a lookup table to associate both.

    .NOTES
    DATE:       03 DEC 18
    VERSION:    1.0.2
    AUTHOR:     Brent Matlock

    .PARAMETER Server
    Used to point collection to DNS server where A records reside for Hostname to IP Address conversions.

    .EXAMPLE 
    Will attempt to resolve AD_DNSNAMES.txt against 8.8.8.8
        TOMB-Host2IP -Server 8.8.8.8
#>

Function TOMB-Host2IP {
    Param(
        [Parameter(Mandatory, ValueFromPipeline = $true)][string[]]$Server)
    $AD = Get-ADComputer -Filter * -Server $Server | Select-Object DNSHostName | Format-Table -HideTableHeaders | Out-File -FilePath .\includes\tmp\AD_DNSNAMES.txt -Append
    $ComputerList = Get-Content ".\includes\tmp\AD_DNSNAMES.txt"
    $ComputerList | foreach { $_.TrimEnd()} | Set-Content .\includes\tmp\AD_DNSNAMES.txt
    $ComputerList = Get-Content ".\includes\tmp\AD_DNSNAMES.txt"
    foreach ($machine in $ComputerList) {
        if ($machine.Length -gt 1) {
            Start-Sleep -Milliseconds 500 
            $IPAddress = ([System.Net.Dns]::GetHostByName("$machine").AddressList).IPAddressToString
            Write-Host "$machine, $IPAddress" | Out-File -FilePath .\FIles2Forward\Host2IP.txt
        }
        Else { Continue }
    }
    Remove-Item .\includes\tmp\AD_DNSNAMES.txt
}
