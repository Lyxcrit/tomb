<#
	.SYNOPSIS

    Used to setup Splunk TA for TOMB outputs.



    .DESCRIPTION

    TOMB (The One Mission Builder) is a host collection script that is setup for forwarding data

    into Splunk via a Splunk Universal Forwarder, as such artifacts collected are converted into JSON

    The following script prompts user for a Hostname for the Host of gathered data that is parsed by
    Splunk, as well as where Splunk is currently installed. This data is used to fill in the inputs.conf
    and the TA is installed. 


    .NOTES

    DATE:       28 FEB 19

    VERSION:    1.1.1
    AUTHOR:     Brent Matlock -Lyx


#>
$Path = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
Function SplunkDir {
    Clear-Host
@"
Current Path: $Path
Splunk TA Builder:`r`nThis will walk you thru the Splunk TA setup for TOMB`r`n
Please supply the directories and I will take care of the rest"
"@
    Write-Host "Where is Splunk located on your system?" -ForegroundColor Green
    "Default Shortcuts:"
    "`tWindows`t`tProgram Files\Splunk`r`n`tWindowsFWD`tProgram Files\SplunkUniversalForwarder
    `tLinux`t`t/opt/Splunk`r`n`tLinuxFWD`t/opt/SplunkUniversalForwarder"
    $baseDir = Read-Host "`r`n`t>"
    if ($baseDir -eq "Windows"){ $baseDir = "C:\Program Files\Splunk" }
    if ($baseDir -eq "WindowsFWD"){ $baseDir = "C:\Program Files\SplunkUniversalForwarder" }
    if ($baseDir -eq "Linux"){ $baseDir = "/opt/Splunk" }
    if ($baseDir -eq "LinuxFWD"){ $baseDir = "/opt/SplunkUniversalForwarder/" }
    Write-Host "`r`nYou have entered: ${baseDir}, is this correct?" -ForegroundColor Green
    $confirmation = Read-Host "[Yes] or No"
    if ($confirmation -eq "No"){
        SplunkDir
    }
    if ($confirmation -eq "" -or $confirmation -eq "Yes"){
        SplunkHost
    }
    Else {
        "No Valid Option Supplied"
        pause;SplunkDir
    }
}


Function SplunkHost {
    Clear-Host
    Write-Host "What is the host name you wish to use for Splunk TOMB-TA?" -ForegroundColor Green
    $hostname = Read-Host ">"
    Write-Host "`r`nYou have entered: ${hostname}, is this correct?" -ForegroundColor Green
    $confirmation = Read-Host "[Yes] or No"
    if ($confirmation -eq "No"){
        SplunkHost
    }
    if ($confirmation -eq "" -or $confirmation -eq "Yes") {
        Inputs_Conf_Setup
    }
    Else {
        "No Valid Option Supplied"
        pause;SplunkHost
    }
}


Function Inputs_Conf_Setup {
    Clear-Host
    (Get-Content .\includes\SplunkSetup\inputs_temp.conf).replace('<FILEPATH>',$Path).replace('<HOSTNAME>',$hostname) |
    Set-Content .\includes\SplunkSetup\inputs.conf
    Move-Item .\includes\SplunkSetup\inputs.conf .\includes\SplunkSetup\TA-TOMB\default -Force
    $TA_Folder = ((${baseDir} + "\etc\apps\TA-TOMB") -replace '\\','\') -replace '//','/'
    Copy-Item .\includes\SplunkSetup\TA-TOMB -Recurse -Destination $TA_Folder -FOrce
    "TA has been installed at ${baseDir}\etc\apps`r`nWould you like to restart the Splunk service now?"
    $confirmation = Read-Host "[Yes] or No"
    if ($confirmation -eq "No"){
        "Splunk Service will need to be restarted in order for changes to take affect"
    }
    if ($confirmation -eq "" -or $confirmation -eq "Yes") {
        Try{ 
            $Splunk = (${baseDir} + "\bin\") -replace '\\','\'
            cd $Splunk ; .\Splunk restart
        }
        Catch {
            $Splunk = (${basDir} + "/bin/") -replace '//','/'
            cd $Splunk ; ./Splunk restart
        }
        "Splunk is being restarted. Once Complete TOMB collections will apply the correct sourcetypes and index.`r`n"
    }
    Else {
        "Prparing to exit"
    }
    pause
    Clear-Host
    break  
}


SplunkDir