<#
    .SYNOPSIS
        registry.psm1
        Collects Windows Registry Objects on the Host. Modular loaded via TOMB or TOMB_GUI. 
        
             
     .DESCRIPTION
        Used to pull Registry objects from host such as 'HLKM:\Software' via WMI (Windows Management Instrumentation) Calls.
        Module will allow any objects to be collected, as long as user has permissions to pull those keys. 
        preventing the ability to prevent pulling the same log multiple times and ensure each pull presents you with new data. 

    .EXAMPLE 
        GUI: No examples provided, please see included web help for futher information. 
        CLI: TOMB-Registry -computername $env:COMPUTERNAME -hivekey 'hklm:\software'
            Will Return Successful logins and logouts for localhost
#>

Function TOMB-Registry {
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)][string]$Computer, 
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)][array]$HiveKey )
        If ($HiveKey -EQ $null){
            [array]$HiveKeys =  "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
                                "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                                "HKLM:\Software",
                                "HKLM:\System\MountedDevices",
                                "HKLM:\System\CurrentControlSet\Enum\USB",
                                "HKLM:\Software\Microsoft\Command Processor",
                                "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
                                "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" 
            Foreach ($Key in $HiveKeys){
                Try{ Get-ChildItem -Path $Key | Out-File -FilePath .\Files2Forward\"$Computer"_registry.json -Append }
                Catch{ $Error[0] | Out-File -FilePath .\logs\ErrorLog\Registry_logs.log 
                        Write-Verbose "$Error[0]" } } }
        Else {
            Foreach ($Key in $HiveKeys){
                Try{ Get-ChildItem -Path $Key | Out-File -FilePath .\Files2Forward\"$Computer"_registry.json -Append }
                Catch{ $Error[0] | Out-File -FilePath .\logs\ErrorLog\Registry_logs.log 
                        Write-Verbose "$Error[0]" } } }
    }
    

#Alias registration for deploying with -Collects via TOMB.ps1
New-Alias -Name Registry -Value TOMB-Registry
Export-ModuleMember -Alias * -Function *
