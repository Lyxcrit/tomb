<#
    .SYNOPSIS
    Used to convert Powershell Objects into JSON formatted information. 

    .DeSCRIPTION
    Due to Powershell Version 2.0 there is not built in commandlet for TOMB-Json
    These functions provide that functionality for use when environment is not running with a newer version of PowerShell 3.0+

    .NOTES
    DATE:       26 JUN 19
    VERSION:    1.1.2b
    AUTHOR:     Brent Matlock -Lyx

    .EXAMPLE
    Converting to JSON from non-json format
        TOMB-JSON
        $Var = $( Get-WmiObject -Class 'Win32_Process' )
        Foreach ($obj in $Var){ $obj | TOMB-Json | Out-File -FilePath $OUTFILE}
#>


function EscapeJson {
    param(
        [String] $String)
    $String -replace '\\', '\\' -replace '\n', '\n' `
        -replace '\u0008', '\b' -replace '\u000C', '\f' -replace '\r', '\r' `
        -replace '\t', '\t' -replace '"', '\"'
}


function GetNumberOrString {
    param(
        $InputObject)
    if ($InputObject -is [System.Byte] -or $InputObject -is [System.Int32] -or `
        ($env:PROCESSOR_ARCHITECTURE -imatch '^(?:amd64|ia64)$' -and $InputObject -is [System.Int64]) -or `
        $InputObject -is [System.Decimal] -or `
        ($InputObject -is [System.Double] -and -not [System.Double]::IsNaN($InputObject) -and -not [System.Double]::IsInfinity($InputObject)) -or `
        $InputObject -is [System.Single] -or $InputObject -is [long] -or `
        ($Script:CoerceNumberStrings -and $InputObject -match $Script:NumberRegex)) {
        "$InputObject"
    }
    else {
        """$(EscapeJson -String $InputObject)"""
    }
}


function ConvertToJsonInternal {
    param(
        $InputObject, # no type for a reason
        [Int32] $WhiteSpacePad = 0)
    [String] $Json = ""
    $Keys = @()
    if ($null -eq $InputObject) {
        $null
    }
    elseif ($InputObject -is [Bool] -and $InputObject -eq $true) {
        $true
    }
    elseif ($InputObject -is [Bool] -and $InputObject -eq $false) {
        $false
    }
    elseif ($InputObject -is [DateTime] -and $Script:DateTimeAsISO8601) {
        """$($InputObject.ToString('yyyy\-MM\-ddTHH\:mm\:ss'))"""
    }
    elseif ($InputObject -is [HashTable]) {
        $Keys = @($InputObject.Keys)
    }
    elseif ($InputObject.GetType().FullName -eq "System.Management.Automation.PSCustomObject") {
        $Keys = @(Get-Member -InputObject $InputObject -MemberType NoteProperty |
            Select-Object -ExpandProperty Name)
    }
    elseif ($InputObject.GetType().Name -match '\[\]|Array') {
        $Json += "[`n" + (($InputObject | ForEach-Object {
            if ($null -eq $_) {
                " " * ((4 * ($WhiteSpacePad / 4)) + 4) + "null"
            }
            elseif ($_ -is [Bool] -and $_ -eq $true) {
                " " * ((4 * ($WhiteSpacePad / 4)) + 4) + "true"
            }
            elseif ($_ -is [Bool] -and $_ -eq $false) {
                " " * ((4 * ($WhiteSpacePad / 4)) + 4) + "false"
            }
            elseif ($_ -is [DateTime] -and $Script:DateTimeAsISO8601) {
                " " * ((4 * ($WhiteSpacePad / 4)) + 4) + """$($_.ToString('yyyy\-MM\-ddTHH\:mm\:ss'))"""
            }
            elseif ($_ -is [HashTable] -or $_.GetType().FullName -eq "System.Management.Automation.PSCustomObject" -or $_.GetType().Name -match '\[\]|Array') {
                " " * ((4 * ($WhiteSpacePad / 4)) + 4) + (ConvertToJsonInternal -InputObject $_ -WhiteSpacePad ($WhiteSpacePad + 4)) -replace '\s*,\s*$'
            }
            else {
                $TempJsonString = GetNumberOrString -InputObject $_
                " " * ((4 * ($WhiteSpacePad / 4)) + 4) + $TempJsonString
            }
        }) -join ",`n") + "`n$(" " * (4 * ($WhiteSpacePad / 4)))],`n"
    }
    else {
        GetNumberOrString -InputObject $InputObject
    }
    if ($Keys.Count) {
        $Json += "{`n"
        foreach ($Key in $Keys) {
            if ($null -eq $InputObject.$Key) {
                $Json += " " * ((4 * ($WhiteSpacePad / 4)) + 4) + """$Key"": null,`n"
            }
            elseif ($InputObject.$Key -is [Bool] -and $InputObject.$Key -eq $true) {
                $Json += " " * ((4 * ($WhiteSpacePad / 4)) + 4) + """$Key"": true,`n"            }
            elseif ($InputObject.$Key -is [Bool] -and $InputObject.$Key -eq $false) {
                $Json += " " * ((4 * ($WhiteSpacePad / 4)) + 4) + """$Key"": false,`n"
            }
            elseif ($InputObject.$Key -is [DateTime] -and $Script:DateTimeAsISO8601) {
                $Json += " " * ((4 * ($WhiteSpacePad / 4)) + 4) + """$Key"": ""$($InputObject.$Key.ToString('yyyy\-MM\-ddTHH\:mm\:ss'))"",`n"
            }
            elseif ($InputObject.$Key -is [HashTable] -or $InputObject.$Key.GetType().FullName -eq "System.Management.Automation.PSCustomObject") {
                $Json += " " * ($WhiteSpacePad + 4) + """$Key"":`n$(" " * ($WhiteSpacePad + 4))"
                $Json += ConvertToJsonInternal -InputObject $InputObject.$Key -WhiteSpacePad ($WhiteSpacePad + 4)
            }
            elseif ($InputObject.$Key.GetType().Name -match '\[\]|Array') {
                $Json += " " * ($WhiteSpacePad + 4) + """$Key"":`n$(" " * ((4 * ($WhiteSpacePad / 4)) + 4))[`n" + (($InputObject.$Key | ForEach-Object {
                    if ($null -eq $_) {
                        " " * ((4 * ($WhiteSpacePad / 4)) + 8) + "null"
                    }
                    elseif ($_ -is [Bool] -and $_ -eq $true) {
                        " " * ((4 * ($WhiteSpacePad / 4)) + 8) + "true"
                    }
                    elseif ($_ -is [Bool] -and $_ -eq $false) {
                        " " * ((4 * ($WhiteSpacePad / 4)) + 8) + "false"
                    }
                    elseif ($_ -is [DateTime] -and $Script:DateTimeAsISO8601) {
                        " " * ((4 * ($WhiteSpacePad / 4)) + 8) + """$($_.ToString('yyyy\-MM\-ddTHH\:mm\:ss'))"""
                    }
                    elseif ($_ -is [HashTable] -or $_.GetType().FullName -eq "System.Management.Automation.PSCustomObject" `
                        -or $_.GetType().Name -match '\[\]|Array') {
                        " " * ((4 * ($WhiteSpacePad / 4)) + 8) + (ConvertToJsonInternal -InputObject $_ -WhiteSpacePad ($WhiteSpacePad + 8)) -replace '\s*,\s*$'
                    }
                    else {
                        $TempJsonString = GetNumberOrString -InputObject $_
                        " " * ((4 * ($WhiteSpacePad / 4)) + 8) + $TempJsonString
                    }
                }) -join ",`n") + "`n$(" " * (4 * ($WhiteSpacePad / 4) + 4 ))],`n"
            }
            else {
                $TempJsonString = GetNumberOrString -InputObject $InputObject.$Key
                $Json += " " * ((4 * ($WhiteSpacePad / 4)) + 4) + """$Key"": $TempJsonString,`n"
            }
        }
        $Json = $Json -replace '\s*,$' # remove trailing comma that'll break syntax
        $Json += "`n" + " " * $WhiteSpacePad + "},`n"
    }
    $Json
}

function TOMB-Json {
    [CmdletBinding()]
    Param(
        [AllowNull()]
        [Parameter(Mandatory=$True,
                   ValueFromPipeline=$True,
                   ValueFromPipelineByPropertyName=$True)]
        $InputObject,
        [Switch] $Compress,
        [Switch] $CoerceNumberStrings = $False,
        [Switch] $DateTimeAsISO8601 = $False)
    Begin{
        $JsonOutput = ""
        $Collection = @()
        [Bool] $Script:CoerceNumberStrings = $CoerceNumberStrings
        [Bool] $Script:DateTimeAsISO8601 = $DateTimeAsISO8601
        [String] $Script:NumberRegex = '^-?\d+(?:(?:\.\d+)?(?:e[+\-]?\d+)?)?$'
    }
    Process {
        if ($_) {
            $Collection += $_
        }
    }
    End {
        if ($Collection.Count) {
            $JsonOutput = ConvertToJsonInternal -InputObject ($Collection | ForEach-Object { $_ })
        }
        else {
            $JsonOutput = ConvertToJsonInternal -InputObject $InputObject
        }
        if ($null -eq $JsonOutput) {
            return $null # becomes an empty string :/
        }
        elseif ($JsonOutput -is [Bool] -and $JsonOutput -eq $true) {
            [Bool] $true # doesn't preserve bool type :/ but works for comparisons against $true
        }
        elseif ($JsonOutput-is [Bool] -and $JsonOutput -eq $false) {
            [Bool] $false # doesn't preserve bool type :/ but works for comparisons against $false
        }
        elseif ($Compress) {
            (
                ($JsonOutput -split "\n" | Where-Object { $_ -match '\S' }) -join "`n" `
                    -replace '^\s*|\s*,\s*$' -replace '\ *\]\ *$', ']'
            ) -replace ( # these next lines compress ...
                '(?m)^\s*("(?:\\"|[^"])+"): ((?:"(?:\\"|[^"])+")|(?:null|true|false|(?:' + `
                    $Script:NumberRegex.Trim('^$') + `
                    ')))\s*(?<Comma>,)?\s*$'), "`${1}:`${2}`${Comma}`n" `
              -replace '(?m)^\s*|\s*\z|[\r\n]+'
        }
        else {
            ($JsonOutput -split "\n" | Where-Object { $_ -match '\S' }) -join "`n" `
                -replace '^\s*|\s*,\s*$' -replace '\ *\]\ *$', ']'
        }
    }
}


#Alias registration for deploying with -Collects parameter via TOMB.ps1
New-Alias -Name TOMB-Json20 -Value TOMB-Json
Export-ModuleMember -Alias * -Function * -ErrorAction SilentlyContinue
