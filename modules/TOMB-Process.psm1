<#
    .SYNOPSIS
    Collects running processes running on machine. Modular loaded via TOMB or TOMB_GUI. 
     
     .DESCRIPTION
    Used to pull processes from host with WMI (Windows Management Instrumentation) Calls.

    .NOTES
    DATE:       23 NOV 18
    VERSION:    1.0.1
    AUTHOR:     Brent Matlock

    .EXAMPLE 
    Captures process information on localhost
        TOMB-Process -ComputerName $env:COMPUTERNAME
    .EXAMPLE
    Captures process information for DC on the 'Test.Domain' domain. 
        TOMB-Process -ComputerName "DCO1" -AD ".Test.Domain"
    .EXAMPLE
    Captures process information for DC and FS on the 'Test.Domain' domain.
        TOMB-Process -ComputerName "DC01","FS01" -AD ".Test.Domain"
#>

#Main Script, collects Processes off hosts and converts the output to Json format in preperation to send to Splunk
Function TOMB-Process {
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)][System.Array]$Computer,
        [Parameter(Mandatory = $false)][string]$AD )
    [array]$Properties = ("Caption", "CommandLine", "CreationClassName", "CreationDate", "CSCreationClassName", "CSName", "Description",
        "ExecutablePath", "ExecutionState", "Handle", "HandleCount", "InstallDate", "KernelModeTime", "MaximumWorkingSetSize",
        "MinimumWorkingSetSize", "Name", "OSCreationClassName", "OSName", "OtherOperationCount", "OtherTransferCount",
        "PageFaults", "PageFileUsage", "ParentProcessId", "PeakPageFileUsage", "PeakVirtualSize", "PeakWorkingSetSize",
        "Priority", "PrivatePageCount", "ProcessId", "QuotaNonPagedPoolUsage", "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage",
        "QuotaPeakPagedPoolUsage", "ReadOperationCount", "ReadTransferCount", "SessionId", "Status", "TerminationDate", "ThreadCount",
        "UserModeTime", "VirtualSize", "WindowsVersion", "WorkingSetSize", "WriteOperationCount", "WriteTransferCount")
    if ($Computer -eq $null) { $Computer = $( Get-Content .\includes\tmp\DomainList.txt) }
    foreach ($Machine in $Computer) {
        $Process_List = $( Get-WmiObject -Class 'Win32_Process' -ComputerName $Machine$AD -Property $Properties )
        foreach ($item in $Process_List) {
            Try { ConvertTo-Json20 -item $item | Out-File -FilePath .\Files2Forward\"$Machine$AD"_process.json -Append }
            Catch { $Error[0] | Out-File -FilePath .\logs\ErrorLog\process.log }
            $item = $null
        }
    }
}
    
#Legacy Script, used in order to create a "Mock" json format.
Function TOMB-Process-Mock {
    Param(
        [Parameter(Mandatory = $true)][string]$Computer)  
    $timestamp = Get-Date 
    Try {
        $Process_List = $( Get-WmiObject -Class 'Win32_Process' -Computername $Computer ) | foreach {
            "{ Caption:" + $_.Caption, 
            ", CommandLine:" + $_.CommandLine,
            ", CreationClassName:" + $_.CreationClassName,
            ", CreationDate:" + $_.CreationDate,
            ", CSCreationClassName:" + $_.CSCreationClassName,
            ", CSName:" + $_.CSName,
            ", Description:" + $_.Description,
            ", ExecutablePath:" + $_.ExecutablePath,
            ", ExecutionState:" + $_.ExecutionState,
            ", Handle:" + $_.Handle,
            ", HandleCount:" + $_.HandleCount,
            ", InstallDate:" + $_.InstallDate,
            ", KernelModeTime:" + $_.KernelModeTime,
            ", MaximumWorkingSetSize:" + $_.MaximumWorkingSetSize,
            ", MinimumWorkingSetSize:" + $_.MinimumWorkingSetSize,
            ", Name:" + $_.Name,
            ", OSCreationClassName:" + $_.OSCreationClassName,
            ", OSName:" + $_.OSName,
            ", OtherOperationCount:" + $_.OtherOperationCount,
            ", OtherTransferCount:" + $_.OtherTransferCount,
            ", PageFaults:" + $_.PageFaults,
            ", PageFileUsage:" + $_.PageFileUsage,
            ", ParentProcessId:" + $_.ParentProcessId,
            ", PeakPageFileUsage:" + $_.PeakPageFileUsage,
            ", PeakVirtualSize:" + $_.PeakVirtualSize,
            ", PeakWorkingSetSize:" + $_.PeakWorkingSetSize,
            ", Priority:" + $_.Priority,
            ", PrivatePageCount:" + $_.PrivatePageCount,
            ", ProcessId:" + $_.ProcessId,
            ", QuotaNonPagedPoolUsage:" + $_.QuotaNonPagedPoolUsage,
            ", QuotaPagedPoolUsage:" + $_.QuotaPagedPoolUsage,
            ", QuotaPeakNonPagedPoolUsage:" + $_.QuotaPeakNonPagedPoolUsage,
            ", QuotaPeakPagedPoolUsage:" + $_.QuotaPeakPagedPoolUsage,
            ", ReadOperationCount:" + $_.ReadOperationCount,
            ", ReadTransferCount:" + $_.ReadTransferCount,
            ", SessionId:" + $_.SessionId,
            ", Status:" + $_.Status,
            ", TerminationDate:" + $_.TerminationDate,
            ", ThreadCount:" + $_.ThreadCount,
            ", UserModeTime:" + $_.UserModeTime,
            ", VirtualSize:" + $_.VirtualSize,
            ", WindowsVersion:" + $_.WindowsVersion,
            ", WorkingSetSize:" + $_.WorkingSetSize,
            ", WriteOperationCount:" + $_.WriteOperationCount,
            ", WriteTransferCount:" + $_.WriteTransferCount,
            ", PSComputerName:" + $_.PSComputerName,
            ", ProcessName:" + $_.ProcessName,
            ", Handles:" + $_.Handles,
            ", VM:" + $_.VM,
            ", WS:" + $_.WS,
            ", Path:" + $_.Path + " }" } | Out-File -FilePath .\Files2Forward\"$Computer"_process.json 
    }
    Catch { 
        "$timestamp : $Error" | Out-File -FilePath .\Logs\ErrorLog\processes.log -Append
    }
}

#Alias registration for deploying with -Collects via TOMB.ps1
New-Alias -Name Process -Value TOMB-Process
New-Alias -Name Process.Mock -Value TOMB-Process-Mock
Export-ModuleMember -Alias * -Function * -ErrorAction SilentlyContinue
