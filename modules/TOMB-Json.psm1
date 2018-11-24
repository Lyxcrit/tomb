<#
    .SYNOPSIS
    Used to convert Powershell Objects into JSON formatted information. 

    .DeSCRIPTION
    Due to Powershell Version 2.0 there is not built in commandlet for ConvertTo-Json or ConvertFrom-Json
    These functions provide that functionality for use when environment is not running with a newer version of PowerShell

    .EXAMPLE
    GUI - Non provided see web help for further information
    CLI -
        CONVERTTO-JSON20
        $Var = $( Get-WmiObject -Class 'Win32_Process' )
        Foreach ($obj in $Var){ ConvertTo-Json20 -item $obj | Out-File -FilePath $OUTFILE}

        CONVERTFROM-JSON20
        $Var = $( Get-Content $OUTFILE )
        Foreach ( $obj in $Var){ ConvertFrom-Json20 } 

#>

Function ConvertFrom-Json20([object] $item){
    Add-Type -Assembly System.Web.Extensions
    $PS2JS=New-Object System.Web.Script.Serialization.JavaScriptSerializer
    return ,$PS2JS.DeserializeObject($item)
    }

Function ConvertTo-Json20([object] $item){
    Add-Type -Assembly System.Web.Extensions
    $PS2JS=New-Object System.Web.Script.Serialization.JavaScriptSerializer
    return $PS2JS.Serialize($item)
    }
