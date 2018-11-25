<#
    .SYNOPSIS
    Used as the initiator for TOMB execution against Hosts

    .DESCRIPTION
    TOMB (The One Mission Builder) is a host collection script that is setup for forwarding data
    into Splunk via a Splunk Universal Forwarder, as such artifacts collected are converted into JSON
    For this reason, output is hardcoded into the provided file structure for easy setup and execution.
    **For SplunkForwarder setup please read the provided documentation or use the provided Splunk_Setup.ps1 for automated setup.**
    
    .NOTES
    DATE:       23 NOV 18
    VERSION:    1.0.1
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

    .EXAMPLE
    Collection of processes, services and signature on domain foo.bar
        TOMB -Domain "OU=foo,OU=bar" -Collects "Service,Process,Signatures"
#>

#Provides TOMB the ability to use commandline parameters via tabbing
[cmdletbinding()]
Param (
    # ComputerName of the host you want to connect to.
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][System.String] $Domain,
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][System.String] $Server,
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][System.Array] $Collects,
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][System.Array] $Computer,
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][System.Array] $LogID
)

#Importing of modules located within the modules folder.
$IncludeDir = Split-Path -parent $MyInvocation.MyCommand.Path
Import-Module -DisableNameChecking ActiveDirectory,
$IncludeDir\includes\GUI-Functions.ps1,
$IncludeDir\modules\TOMB-Event.psm1,
$IncludeDir\modules\TOMB-Process.psm1,
$IncludeDir\modules\TOMB-Registry.psm1,
$IncludeDir\modules\TOMB-Service.psm1,
$IncludeDir\modules\TOMB-Signature.psm1,
$IncludeDir\modules\TOMB-Json.psm1 -Force

#Variable storage
Set-Variable -Name $Computer -Scope Global
Set-Variable -Name $LogID -Scope Global

#Breakdown to restore PSModules, preventing overflow for continuous running of script.
Function Breakdown {
    Remove-Module -Name TOMB*, GUI*, Powershell2-Json
    Remove-Item Alias:EventLog, Alias:EventLog.Mock, Alias:Process, Alias:Process.Mock, Alias:Registry, Alias:Service, Alias:Service.Mock, Alias:Signature -Force
    Remove-Item -Path .\includes\tmp\DomainList.txt
}

#Initial function to branch logic based off provided parameters.
Function Main {
    #Gathering Domain Computers list if -Domain AND -Server are provided, typically used when NOT domain joined or using DNS
    If ($Domain -and $Server) {
        $Domain_Computers = $( Get-ADComputer -Filter * -Properties Name, DistinguishedName -Server $Server -SearchBase $Domain | Select-Object DNSHostName )
        Foreach ($Hostx in $Domain_Computers) { ( $Hostx -replace "@{Name=", "" ) -replace "}", "" | Out-File -FilePath .\includes\tmp\DomainList.txt -Append}
        Collects
    }
    #Gathering Domain computers list if -Domain is provided without the -Server parameter, typically used with domain joined or using DNS
    If ($Domain -and ($Server -eq "")) {
        $Domain_Computers = $( Get-ADComputer -Filter * -Properties Name, DistinguishedName -SearchBase $Domain | Select-Object DNSHostName )
        Foreach ($Hostx in $Domain_Computers) { ( $Hostx -replace "@{Name=", "" ) -replace "}", "" | Out-File -FilePath .\includes\tmp\DomainList.txt -Append}
        Collects
    }
    If ($Computer) {
        Collects
    }
}

Function Collects {
    If ($Collects) {
        Foreach ($obj in $Collects) {
            If ($obj -eq "Service") { .$obj $Computer }
            If ($obj -eq "Process") { .$obj $Computer }
            If ($obj -eq "EventLog") { .$obj $Computer $LogID }
            If ($obj -eq "Signature") { .$obj $Computer }
            If ($obj -eq "Registry") { .$obj $Computer }
        }
    }
}

Main
Breakdown