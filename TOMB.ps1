<#
    .SYNOPSIS
    Used as the initiator for TOMB execution against Hosts

    .DESCRIPTION
    TOMB (The One Mission Builder) is a host collection script that is setup for forwarding data
    into Splunk via a Splunk Universal Forwarder, as such artifacts collected are converted into JSON
    For this reason, output is hardcoded into the provided file structure for easy setup and execution.
    **For SplunkForwarder setup please read the provided documentation or use the provided Splunk_Setup.ps1 for automated setup.**
    
    .NOTES
    DATE:       24 JAN 19
    VERSION:    1.0.4
    AUTHOR:     Brent Matlock

    .PARAMETER Domain
    Determins if ran against domain objects, or localmachine
    Intent for localmachine is typically baseline of image.
    When provided syntax for Domain should be a string for the
    required orginizational unit to pull hosts from.

    .PARAMETER Server
    Used to specify the Domain Controller you will be collecting from.
    Used when not already domain joined, or when not using internal DNS where hosts reside.

    .PARAMETER Collects
    Used to specify the collections that are gathered from hosts.
    Parameter to be passed should be an array that is seperated by a comma(,).

    .PARAMETER Threads
    Used to limit the number of parallel jobs. Must be used when using the -Domain parameter

    .EXAMPLE
    Collection of processes, services and signature on domain foo.bar
        TOMB -Collects Service,Process,Signatures -Domain "OU=foo,OU=bar"  -Server 8.8.8.8

    .EXAMPLE
    Collection for specific hosts without query of the domain.
        TOMB.ps1 -Collections Service,Process -Computer localhost
#>

#Provides TOMB the ability to use commandline parameters via tabbing
[cmdletbinding()]
Param (
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][System.String] $Domain,
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][System.Array] $Computer,
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][System.Array] $LogID,
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][Int] $Threads,
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][String] $Server,
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][System.Array] $Collects
)

#Importing of modules located within the modules folder.
$IncludeDir = Split-Path -parent $MyInvocation.MyCommand.Path
Import-Module -DisableNameChecking ActiveDirectory,
#$IncludeDir\includes\GUI-Functions.ps1,    #Upcoming GUI implementation
$IncludeDir\modules\TOMB-Event\TOMB-Event.psm1,
$IncludeDir\modules\TOMB-Process\TOMB-Process.psm1,
$IncludeDir\modules\TOMB-Registry\TOMB-Registry.psm1,
$IncludeDir\modules\TOMB-Signature\TOMB-Signature.psm1,
$IncludeDir\modules\TOMB-Host2IP\TOMB-Host2IP.psm1,
$IncludeDir\modules\TOMB-Json\TOMB-Json.psm1,
$IncludeDir\modules\TOMB-Service\TOMB-Service.psm1 -Force 
$CurrentFolder = $IncludeDir
#Adds the modules to $env:PSModulePath for the session
$CurrentValue = [Environment]::GetEnvironmentVariable("PSModulePath", "User")
[Environment]::SetEnvironmentVariable("PSModulePath", $CurrentValue + ";$IncludeDir\modules", "User")

#Set Variable Scoping
$(Set-Variable -name IncludeDir -Scope Global) 2>&1 | Out-Null
$(Set-Variable -name Computer -Scope Global) 2>&1 | Out-null
$(Set-Variable -name Server -Scope Global) 2>&1 | Out-null
$(Set-Variable -name Domain -Scope Global) 2>&1 | Out-null
$(Set-Variable -name LogID -Scope Global) 2>&1 | Out-null
$(Set-Variable -name Collects -Scope Global) 2>&1 | Out-null
$(Set-Variable -name Thread -Scope Global) 2>&1 | Out-Null
$(Set-Variable -name CurrentFolder -Scope Global) 2>&1 | Out-Null
$(Set-Variable -name Json_Convert -Scope GLobal) 2>&1 | Out-Null

#Breakdown to restore PSModules, preventing overflow for continuous running of script.
Function Breakdown {
    Remove-Module -Name TOMB*, GUI*, Powershell2-Json -ErrorAction SilentlyContinue
    Remove-Item -Path .\includes\tmp\DomainList.txt -ErrorAction SilentlyContinue
    #Removes the modules from PSModulePath
    $env:PSModulePath = $env:PSModulePath -replace [regex]::Escape(";$includeDir\modules")
}

#Check Credentials to prevent account lockouts
Function CredCheck { 
    Try { $credCheck = $(Get-ADUser -Filter * -Server $Server -ErrorAction Stop| Select-Object -First 1) }
    Catch [System.Security.Authentication.AuthenticationException] { Write-Host "Invalid Credentials" }
    Catch [Microsoft.ActiveDirectory.Management.ADServerDownException] { Write-Host "Active Directory Server Cannot be reached" }
    If ($credCheck) { Main }
} 

#Initial function to branch logic based off provided parameters.
Function Main {
    #Gathering Domain Computers list if -Domain AND -Server are provided, typically used when NOT domain joined or using DNS
    If ($Domain -and $Server) {
        If ($null -eq $Threads){ Write-Host "`r`n`r`nMust use '-Thread #' when using the '-Domain' switch. Stopping Execution" -foreground Red ; Pause}
        Else {$Domain_Computers = $( Get-ADComputer -Filter * -Properties Name, DistinguishedName -Server $Server -SearchBase $Domain | Select-Object DNSHostName )
        Foreach ($Hostx in $Domain_Computers) { ( $Hostx -replace "@{DNSHostName=", "" ) -replace "}", "" | Out-File -FilePath .\includes\tmp\DomainList.txt -Append}
        Collects }
    }
    #Gathering Domain computers list if -Domain is provided without the -Server parameter, typically used with domain joined or using DNS
    If ($Domain -and ($Server -eq "")) {
        $Domain_Computers = $( Get-ADComputer -Filter * -Properties Name, DistinguishedName -SearchBase $Domain | Select-Object DNSHostName )
        Foreach ($Hostx in $Domain_Computers) { ( $Hostx -replace "@{DNSHostName=", "" ) -replace "}", "" | Out-File -FilePath .\includes\tmp\DomainList.txt -Append}
        Collects
    }
    #Used to run against listed computer(s)
    If ($Computer) {
        Collects
    }
}

Function Collects {
Foreach ($obj in $Collects){
    If ($nuill -eq $Computer) { $ComputerList = $( Get-Content .\includes\tmp\DomainList.txt) }
    Else { $Computer = $ComputerList }
    Foreach ($Computer in $ComputerList){
        While ($(Get-Job -state running).count -ge $Threads){
            Start-Sleep -Milliseconds 500
        }
        If ($obj -eq "Service") {
            Start-Job -InitializationScript { Import-Module -DisableNameChecking TOMB-Service, TOMB-Json -Force} `
                      -ScriptBlock { Param($Computer, $CurrentFolder, $Json_Convert) 
                                    Import-Module -DisableNameChecking TOMB-Service, TOMB-Json -Force
                                    TOMB-Service -Computer $Computer -Path $CurrentFolder} `
                      -ArgumentList $Computer, $CurrentFolder, $Json_Convert }
        If ($obj -eq "Process") { 
            Start-Job -InitializationScript { Import-Module -DisableNameChecking TOMB-Process, TOMB-Json -Force } `
                      -ScriptBlock { Param($Computer, $CurrentFolder, $Json_Convert) 
                                    Import-Module -DisableNameChecking TOMB-Process, TOMB-Json -Force
                                    TOMB-Process -Computer $Computer -Path $CurrentFolder} `
                      -ArgumentList $Computer, $CurrentFolder, $Json_Convert } 
        If ($obj -eq "EventLog") { 
            Start-Job -InitializationScript { Import-Module -DisableNameChecking TOMB-Event, TOMB-Json -Force } `
                      -ScriptBlock { Param($Computer, $LogID, $CurrentFolder, $Json_Convert) 
                                    Import-Module -DisableNameChecking TOMB-Event, TOMB-Json
                                    TOMB-Event -Computer $Computer -LogId $LogID -Path $CurrentFolder} `
                      -ArgumentList $Computer, $LogID, $CurrentFolder, $Json_Convert }
        If ($obj -eq "Signature") { 
            Start-Job -InitializationScript { Import-Module -DisableNameChecking TOMB-Signature } `
                      -ScriptBlock { Param($Computer, $CurrentFolder) 
                                    Import-Module -DisableNameChecking TOMB-Signature
                                    TOMB-Signature -Computer $Computer -Path $CurrentFolder} `
                      -ArgumentList $Computer, $CurrentFolder }
        If ($obj -eq "Registry") { 
            Start-Job -InitializationScript { Import-Module -DisableNameChecking TOMB-Host2IP } `
                      -ScriptBlock { Param($Computer, $CurrentFolder) 
                                    Import-Module -DisableNameChecking TOMB-Host2IP
                                    TOMB-Host2IP -Computer $Computer -Path $CurrentFolder} `
                      -ArgumentList $Computer, $CurrentFolder }
        If ($obj -eq "Host2IP") { .$obj $Server $Threads }
        }
    }
}

CredCheck
Breakdown