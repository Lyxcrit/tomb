<#
    .SYNOPSIS
    Collects host names within the given domain and utilizes DNS to resolve those to and IP address. 
     
     .DESCRIPTION
    Used to correlate hostnames and IP addresses within the target domain. Final product is used within Splunk as a lookup table to associate both.

    .NOTES
    DATE:       26 JUN 19
    VERSION:    1.1.2b
    AUTHOR:     Brent Matlock -Lyx

    .PARAMETER Server
    Used to point collection to DNS server where A records reside for Hostname to IP Address conversions.

    .EXAMPLE 
    Will attempt to resolve AD_DNSNAMES.txt against 8.8.8.8
        TOMB-Host2IP -Server 8.8.8.8
#>

Function TOMB-Host2IP {
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][String] $Server)
    $AD = Get-ADComputer -Filter * -Server $Server | Select-Object DNSHostName | Format-Table -HideTableHeaders |
          Out-File -FilePath .\includes\tmp\AD_DNSNAMES.txt -Append
    $ComputerList = Get-Content ".\includes\tmp\AD_DNSNAMES.txt"
    $ComputerList | ForEach-Object { $_.TrimEnd()} | Set-Content .\includes\tmp\AD_DNSNAMES.txt
    $ComputerList = Get-Content ".\includes\tmp\AD_DNSNAMES.txt"
    foreach ($Machine in $ComputerList) {
        #Check eachline to verify that the line contains data. When parsing large domains blank lines appear (Need to isolate bug)
        if ($Machine.Length -gt 1) {
            #Generate artificial buffer
            Start-Sleep -Milliseconds 500 
            $IPAddress = ([System.Net.Dns]::GetHostByName("$Machine").AddressList).IPAddressToString
            "$Machine, $IPAddress" | Out-File -FilePath .\FIles2Forward\Host2IP.txt -Encoding utf8 -Append
        }
        Else { Continue }
    }
    #Delete Non-Forwarded Files.
    Remove-Item .\includes\tmp\AD_DNSNAMES.txt
}

#Alias registration for deploying with -Collects parameter via TOMB.ps1
New-Alias -Name Host2IP -Value TOMB-Host2IP
Export-ModuleMember -Alias * -Function *