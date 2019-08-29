<#
    .SYNOPSIS
    Used as the initiator for TOMB execution against Hosts

    .DESCRIPTION
    TOMB (The One Mission Builder) is a host collection script that is setup for forwarding data
    into Splunk via a Splunk Universal Forwarder, as such artifacts collected are converted into JSON
    For this reason, output is hardcoded into the provided file structure for easy setup and execution.
    **For SplunkForwarder setup please read the provided documentation or use the provided Splunk_Setup.ps1 for automated setup.**
    
    .NOTES
    DATE:       28 AUG 19
    VERSION:    1.1.4
    AUTHOR:     Brent Matlock -Lyx

    .PARAMETER Domain
    Determins if ran against domain objects, or localmachine
    Intent for localmachine is typically baseline of image.
    When provided syntax for Domain should be a string for the
    required orginizational unit to pull hosts from.

    .PARAMETER Server
    Required Parameter when running against domain.
    Used to specify the Domain Controller you will be collecting from.

    .PARAMETER Collects
    Used to specify the collections that are gathered from hosts.
    Parameter to be passed should be an array that is seperated by a comma(,).

    .PARAMETER Threads
    Used to limit the number of parallel jobs. Default value is set to 50.

    .EXAMPLE
    Collection of processes, services and signature on domain foo.bar
        TOMB -Collects Service,Process,Signatures -Domain "OU=foo,OU=bar" -Server 8.8.8.8 -Threads 25

    .EXAMPLE
    Collection for specific hosts without query of the domain.
        TOMB.ps1 -Collects Service,Process -Computer localhost
    .EXAMPLE
    Use specific WinRM/WMI/DCOM collection methods
        TOMB.ps1 -Collects RunAll -Domain "OU=foo,OU=bar" -Server 8.8.8.8 -Method WinRM
#>

#Provides TOMB the ability to use commandline parameters via tabbing
[cmdletbinding()]
Param (
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][System.String] $Domain,
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][System.Array] $Computer,
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][System.Array] $LogID,
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][String] $Profile,
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [ValidateRange(1,500)][Int] $Threads,
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][String] $Server,
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [ValidateSet("Process","Service","Signature","EventLog","SchedTask","Registry","Connection","RunAll")][System.Array] $Collects,
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][String] $Method,
    [switch] $Setup
)

#Importing of modules located within the modules folder.
$IncludeDir = Split-Path -parent $MyInvocation.MyCommand.Path

#Adds the modules to $env:PSModulePath for the session
$env:PSModulePath += ";$IncludeDir\modules"
Import-Module -DisableNameChecking ActiveDirectory,
$IncludeDir\modules\TOMB-Json\TOMB-Json.psm1,
$IncludeDir\modules\TOMB-Event\TOMB-Event.psm1,
$IncludeDir\modules\TOMB-Process\TOMB-Process.psm1,
$IncludeDir\modules\TOMB-Host2IP\TOMB-Host2IP.psm1,
$IncludeDir\modules\TOMB-Service\TOMB-Service.psm1,
$IncludeDir\modules\TOMB-Registry\TOMB-Registry.psm1,
$IncludeDir\modules\TOMB-Signature\TOMB-Signature.psm1,
$IncludeDir\modules\TOMB-Connection\TOMB-Connection.psm1,
$IncludeDir\modules\TOMB-ScheduledTask\TOMB-ScheduledTask.psm1 -Force
$CurrentFolder = $IncludeDir

#Set Variable Scoping
$(Set-Variable -name IncludeDir -Scope Global) 2>&1 | Out-Null
$(Set-Variable -name Computer -Scope Global) 2>&1 | Out-null
$(Set-Variable -name Server -Scope Global) 2>&1 | Out-null
$(Set-Variable -name Domain -Scope Global) 2>&1 | Out-null
$(Set-Variable -name LogID -Scope Global) 2>&1 | Out-null
$(Set-Variable -name Collects -Scope Global) 2>&1 | Out-null
$(Set-Variable -name Thread -Scope Global) 2>&1 | Out-Null
$(Set-Variable -name CurrentFolder -Scope Global) 2>&1 | Out-Null
$(Set-Variable -name Profile -Scope Global) 2>&1 | Out-Null
$(Set-Variable -name Method -Scope Global) 2>&1 | Out-Null

#Breakdown to restore PSModules, preventing overflow for continuous running of script.
Function Breakdown {
    Remove-Module -Name TOMB*, GUI*, Powershell2-Json -ErrorAction SilentlyContinue
    Remove-Item -Path .\includes\tmp\DomainList.txt -ErrorAction SilentlyContinue
    $env:PSModulePath = $env:PSModulePath -replace [regex]::Escape(";$IncludeDir\modules")
}

#Check Credentials to prevent account lockouts
Function CredCheck { 
    Try { $credCheck = $(Get-ADUser -Filter * -Server $Server -ErrorAction Stop | Select-Object -First 1) }
    Catch [System.Security.Authentication.AuthenticationException] { Write-Host "Invalid Credentials" }
    Catch [Microsoft.ActiveDirectory.Management.ADServerDownException] { Write-Host "Active Directory Server Cannot be reached" }
    If (!($credCheck)) { Breakdown }
} 

#Initial function to branch logic based off provided parameters.
Function Main {
    #Parameter Validation
    If ($Domain -and (!($Server))) {
        Write-Host 'Must use -Server when using -Domain. Stopping Execution' -foreground Red ; Pause
    }
    #Used to run Splunk Setup for the TOMB TA
    If ($Setup){
        .\includes\SplunkSetup\SplunkTASetup.ps1 -Path $Path ; Breakdown
    }
    #Required parameters for collecting against domain objects
    If ($Domain -and $Server) {
        CredCheck
        $Domain_Computers = $( Get-ADComputer -Filter * -Properties Name, DistinguishedName -Server $Server -SearchBase $Domain | Select-Object DNSHostName )
        Foreach ($Hostx in $Domain_Computers) { ( $Hostx -replace "@{DNSHostName=", "" ) -replace "}", "" | Out-File -FilePath .\includes\tmp\DomainList.txt -Append }
        Collects #($Computer,$LogID, $Profile)
    }
    #Used to run against listed computer(s)
    If ($Computer) {
        Collects #($Computer,$LogID, $Profile)
    }
    Else { 
        Collects
    }
}

Function Collects { #($Computer, $LogID, $Profile) {
If ($null -eq $Thread){ $Threads = 50 }
If ($Collects -eq "RunAll") { [System.Array]$Collects = "Service","Process","Registry","Signature","SchedTask","EventLog","Connection"}
If ($null -eq $Computer) {
    If (!($Domain)){ $ComputerList = $(Get-Content .\includes\tmp\StaticList.txt | Where {$_ -notmatch "^#"}) }
    Else { $ComputerList = $(Get-Content .\includes\tmp\DomainList.txt -ErrorAction SilentlyContinue ) } }
Else { $ComputerList = $Computer }
Foreach ($Computer in $ComputerList){
    Foreach ($obj in $Collects){
        While ($(Get-Job -state running).count -ge $Threads){
            Start-Sleep -Milliseconds 50
        }
        If ($obj -eq "Connection") { 
            Start-Job -InitializationScript { Import-Module -DisableNameChecking TOMB-Connection, TOMB-Json -Force } `
                      -ScriptBlock { Param($Computer, $CurrentFolder) 
                                    Import-Module -DisableNameChecking TOMB-Connection, TOMB-Json -Force
                                    TOMB-Connection -Computer $Computer -Path $CurrentFolder} `
                      -ArgumentList $Computer, $CurrentFolder, $Json_Convert, $Method }
        If ($obj -eq "Service") {
            Start-Job -InitializationScript { Import-Module -DisableNameChecking TOMB-Service, TOMB-Json -Force } `
                      -ScriptBlock { Param($Computer, $CurrentFolder, $Json_Convert) 
                                    Import-Module -DisableNameChecking TOMB-Service, TOMB-Json -Force
                                    TOMB-Service -Computer $Computer -Path $CurrentFolder -Method $Method} `
                      -ArgumentList $Computer, $CurrentFolder, $Json_Convert, $Method } 
        If ($obj -eq "Process") { 
	        Start-Job -InitializationScript { Import-Module -DisableNameChecking TOMB-Process, TOMB-Json -Force } `
                      -ScriptBlock { Param($Computer, $CurrentFolder, $Json_Convert) 
                                    Import-Module -DisableNameChecking TOMB-Process, TOMB-Json -Force
                                    TOMB-Process -Computer $Computer -Path $CurrentFolder -Method $Method} `
                      -ArgumentList $Computer, $CurrentFolder, $Json_Convert, $Method }
        If ($obj -eq "EventLog") { 
            Start-Job -InitializationScript { Import-Module -DisableNameChecking TOMB-Event, TOMB-Json -Force } `
                      -ScriptBlock { Param($Computer, $Profile, $CurrentFolder, $Json_Convert) 
                                    Import-Module -DisableNameChecking TOMB-Event, TOMB-Json -Force
                                    TOMB-Event -Computer $Computer -Profile $Profile -Path $CurrentFolder} `
                      -ArgumentList $Computer, $Profile, $CurrentFolder, $Json_Convert }
        If ($obj -eq "Signature") {
            Start-Job -InitializationScript { Import-Module -DisableNameChecking TOMB-Signature -Force } `
                      -ScriptBlock { Param($Computer, $CurrentFolder) 
                                    Import-Module -DisableNameChecking TOMB-Signature -Force
                                    TOMB-Signature -Computer $Computer -Path $CurrentFolder -Method $Method} `
                      -ArgumentList $Computer, $CurrentFolder, $Method }
        If ($obj -eq "SchedTask") {
            Start-Job -InitializationScript { Import-Module -DisableNameChecking TOMB-ScheduledTask, TOMB-Json -Force } `
                      -ScriptBlock { Param($Computer, $CurrentFolder) 
                                    Import-Module -DisableNameChecking TOMB-ScheduledTask, TOMB-Json -Force
                                    TOMB-ScheduledTask -Computer $Computer -Path $CurrentFolder} `
                      -ArgumentList $Computer, $CurrentFolder }
        If ($obj -eq "Registry") { 
            Start-Job -InitializationScript { Import-Module -DisableNameChecking TOMB-Registry, TOMB-Json -Force } `
                      -ScriptBlock { Param($Computer, $CurrentFolder) 
                                    Import-Module -DisableNameChecking TOMB-Registry, TOMB-Json -Force
                                    TOMB-Registry -Computer $Computer -Path $CurrentFolder} `
                      -ArgumentList $Computer, $CurrentFolder }
        If ($obj -eq "Host2IP") { .$obj $Server }
        }
    }
}

Function NonValidCollect { 
    "No Valid Collect provided. Please use one of the following:"
    "Service:`t`tServices on host"
    "Process:`t`tProcesses running on host"
    "Signatures:`t`tDirwalk with SHA1|MD5|DigitalCert information"
    "SchedTask:`t`tScheduled Task information from host"
    "Registry:`t`tKey registry collection"
    "EventLog:`t`tWindows Event Logs from host"
    "Connection:`t`tConnections on host"
    "Host2IP:`t`tGenerates lookup table for splunk dashboard 'Host and IP'"
    "ListAll:`t`tProvide User with this menu"
    "RunAll:`t`t`tRun all previously listed collections"
    $Collects = Read-Host "Enter Valid Collect: "
    Collects ($Collects)
}

Main
Breakdown
