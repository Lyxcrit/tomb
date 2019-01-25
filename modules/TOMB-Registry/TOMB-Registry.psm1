<#
    .SYNOPSIS
    Collects Windows Registry Objects on the Host. Modular loaded via TOMB or TOMB_GUI.

     .DESCRIPTION
    Used to pull Registry objects from host such as 'HLKM:\Software' via WMI (Windows Management Instrumentation) Calls.
    Module will allow any objects to be collected, as long as user has permissions to pull those keys.
    preventing the ability to prevent pulling the same log multiple times and ensure each pull presents you with new data.

    .NOTES
    DATE:       19 JAN 19
    VERSION:    1.0.3
    AUTHOR:     Brent Matlock

    .EXAMPLE
    Will Return Registry entries for the HLKM:SOFTWARE branch against the localhost
        TOMB-Registry -Computer $env:COMPUTERNAME -HiveKey 'hklm:\software'
    .EXAMPLE
    Will run the default Registry keys to collect against the localhost
        TOMB-Registry -Computer $env:COMPUTERNAME
#>

#Main Script, collects Registry off hosts and converts the output to Json format in preperation to send to Splunk
Function TOMB-Registry {
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)][System.Array]$Computer,
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)][System.Array]$HiveKey )
    If ($HiveKey -EQ $null) {
        [System.Array]$HiveKeys = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software",
        "HKLM:\System\MountedDevices",
        "HKLM:\System\CurrentControlSet\Enum\USB",
        "HKLM:\Software\Microsoft\Command Processor",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
        Foreach ($Key in $HiveKeys) {
            Try { Get-ChildItem -Path $Key | Out-File -FilePath .\Files2Forward\${Computer}_registry.json -Append -Encoding utf8}
            Catch {
                $Error[0] | Out-File -FilePath .\logs\ErrorLog\Registry_logs.log
                Write-Verbose "$Error[0]"
            }
        }
    }
    Else {
        Foreach ($Key in $HiveKeys) {
            Try { Get-ChildItem -Path $Key | Out-File -FilePath .\Files2Forward\${Computer}_registry.json -Append -Encoding utf8}
            Catch {
                $Error[0] | Out-File -FilePath .\logs\ErrorLog\Registry_logs.log
                Write-Verbose "$Error[0]"
            }
        }
    }
}

#Alias registration for deploying with -Collects via TOMB.ps1
New-Alias -Name Registry -Value TOMB-Registry
Export-ModuleMember -Alias * -Function *
