    "   ___________  ______   ___      ___  _______    "
    "  ("     _   ")/    " \ |"  \    /"  ||   _  "\   " 
    "   )__/  \\__/// ____  \ \   \  //   |(. |_) : )  "
    "      \\_ /  /  /    ): )/\\  \/.    ||:     \/   " 
    "      |.  | (: (____/ //|: \.        |(|  _  \\   " 
    "      \:  |  \        / |.  \    /:  ||: |_) : )  " 
    "       \__|   \"_____/  |___|\__/|___|(_______/   "

# Project TOMB
The One Mission Builder (TOMB) is a project used to aid in the collection of artifacts for forwarding into Splunk via SplunkUniversalForwarder. TOMB uses WMI calls against either single host, or a Domain. Modules can be ran via TOMB.ps1 or by themselves once you import the module you wish to use. TOMB utilizes a build and breakdown method which is used in an effort to keep hosts resources free, and avoid overloading of the PSModule.
### Current Version 1.1.5

## Prerequisits
``` 
* PowerShell Version 2.0+
* Active Directory (RSAT)
* SplunkUniversalForwarder 
* Sysmon
```

## Installing
 
TOMB does not require installing to run the script, in the future a compile script will be written to setup required file structures. In order to forward collections into Splunk a UniversalForwarder needs to be installed on host that will run these scripts. Technology Add-on(TA) for parsing collection is included under the /includes folder and can be setup via using the -setup command. 

### WinRM Troubleshooting (local machine)

1. First turn on WinRM Service.
2. Run this command as an admin:
    a. Enable-PSRemoting -Force -SkipNetworkProfileCheck

## Usages
### Running modules via TOMB.ps1
Execute modules for Process, Service, EventLog, Registry and Signatures against the domain foo.bar using internal DNS 1.1.1.1  
``` .\TOMB.ps1 -Domain "DC=foo,DC=bar" -Server 1.1.1.1 -Collects Process,Service,EventLog,Registry,Signatures ```  
Execute modules for Process, Service against single host with foo.bar domain using internal DNS 1.1.1.1  
``` .\TOMB.ps1 -Server 1.1.1.1 -Computer computer.foo.bar -Collects Process,Service```  
### Running modules without TOMB.ps1
Executing TOMB-Process.psm1 against multiple hosts  
``` Import-Module .\TOMB-Process.psm1; TOMB-Process -Computer 1.foo.bar,2.foo.bar,3.foo.bar```  
Executing TOMB-Process.psm1 against single host  
``` Import-Module .\TOMB-Process.psm1; TOMB-Process -Computer 1.foo.bar```  

## AUTHOR
    Brent Matlock - Lyx

## CONTRIBUTORS
    Will Flato - sirwilhelm
    Joshua Rohr - jjrohr

## CONTACT
    If you have a problem, questions, ideas, suggestion or contributing contact us by email:
    brent.matlock@splunk.com
