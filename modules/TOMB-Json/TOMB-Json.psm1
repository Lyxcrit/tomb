<#
    .SYNOPSIS
    Used to convert Powershell Objects into JSON formatted information. 

    .DeSCRIPTION
    Due to Powershell Version 2.0 there is not built in commandlet for TOMB-Json
    These functions provide that functionality for use when environment is not running with a newer version of PowerShell 3.0+

    .NOTES
    DATE:       19 JAN 19
    VERSION:    1.0.3
    AUTHOR:     Brent Matlock

    .EXAMPLE
    Converting to JSON from non-json format
        TOMB-JSON
        $Var = $( Get-WmiObject -Class 'Win32_Process' )
        Foreach ($obj in $Var){ $obj | TOMB-Json | Out-File -FilePath $OUTFILE}
#>

Function Escape-JSONString($str){
	if ($str -eq $null) {return ""}
	$str = $str.ToString().Replace('"','\"').Replace('\','\\').Replace("`n",'\n').Replace("`r",'\r').Replace("`t",'\t')
	return $str;
}

Function TOMB-Json($maxDepth = 4,$forceArray = $false) {
	begin { $data = @() }
	process{ $data += $_ }
	end{
		if ($data.length -eq 1 -and $forceArray -eq $false) {
			$value = $data[0]
		} else {	
			$value = $data
		}

		if ($value -eq $null) {
			return "null"
		}

		$dataType = $value.GetType().Name
		
		switch -regex ($dataType) {
	            'String'  {
					return  "`"{0}`"" -f (Escape-JSONString $value )
				}
	            '(System\.)?DateTime'  {return  "`"{0:yyyy-MM-dd}T{0:HH:mm:ss}`"" -f $value}
	            'Int32|Double' {return  "$value"}
				'Boolean' {return  "$value".ToLower()}
	            '(System\.)?Object\[\]' { # array
					
					if ($maxDepth -le 0){return "`"$value`""}
					
					$jsonResult = ''
					foreach($elem in $value){
						#if ($elem -eq $null) {continue}
						if ($jsonResult.Length -gt 0) {$jsonResult +=', '}				
						$jsonResult += ($elem | TOMB-Json -maxDepth ($maxDepth -1))
					}
					return "[" + $jsonResult + "]"
	            }
				'(System\.)?Hashtable' { # hashtable
					$jsonResult = ''
					foreach($key in $value.Keys){
						if ($jsonResult.Length -gt 0) {$jsonResult +=', '}
						$jsonResult += 
@"
	"{0}": {1}
"@ -f $key , ($value[$key] | TOMB-Json -maxDepth ($maxDepth -1) )
					}
					return "{" + $jsonResult + "}"
				}
	            default { #object
					if ($maxDepth -le 0){return  "`"{0}`"" -f (Escape-JSONString $value)}
					
					return "{" +
						(($value | Get-Member -MemberType *property | % { 
@"
	"{0}": {1}
"@ -f $_.Name , ($value.($_.Name) | TOMB-Json -maxDepth ($maxDepth -1) )			
					
					}) -join ', ') + "}"
	    		}
		}
	}
}

#Alias registration for deploying with -Collects parameter via TOMB.ps1
New-Alias -Name TOMB-Json20 -Value TOMB-Json
Export-ModuleMember -Alias * -Function * -ErrorAction SilentlyContinue
