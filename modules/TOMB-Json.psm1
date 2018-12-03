<#
    .SYNOPSIS
    Used to convert Powershell Objects into JSON formatted information. 

    .DeSCRIPTION
    Due to Powershell Version 2.0 there is not built in commandlet for ConvertTo-Json or ConvertFrom-Json
    These functions provide that functionality for use when environment is not running with a newer version of PowerShell

    .NOTES
    DATE:       03 DEC 18
    VERSION:    1.0.2
    AUTHOR:     Brent Matlock

    .EXAMPLE
    Converting to JSON from non-json format
        CONVERTTO-JSON20
        $Var = $( Get-WmiObject -Class 'Win32_Process' )
        Foreach ($obj in $Var){ ConvertTo-Json20 -item $obj | Out-File -FilePath $OUTFILE}
    .EXAMPLE
    Convert from json format to non-json format
        CONVERTFROM-JSON20
        $Var = $( Get-Content $OUTFILE )
        Foreach ( $obj in $Var){ ConvertFrom-Json20 } 

#>

Function ConvertFrom-Json20([object] $item) {
    Add-Type -Assembly System.Web.Extensions
    $PS2JS = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    return , $PS2JS.DeserializeObject($item)
}

Function ConvertTo-Json20([object] $item) {
    Add-Type -Assembly System.Web.Extensions
    $PS2JS = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    return $PS2JS.Serialize($item)
}

#Alias registration for deploying with -Collects parameter via TOMB.ps1
New-Alias -Name TOMB-Json20 -Value ConvertTo-Json20
New-Alias -Name ConvertFrom-Json20 -Value ConvertFrom-Json20
Export-ModuleMember -Alias * -Function * -ErrorAction SilentlyContinue
