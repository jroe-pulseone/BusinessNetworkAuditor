# WindowsWorkstationAuditor - Memory Analysis Module
# Version 1.3.0

function Get-MemoryAnalysis {
    <#
    .SYNOPSIS
        Analyzes system memory usage, virtual memory, and performance counters
        
    .DESCRIPTION
        Collects comprehensive memory information including RAM usage, virtual memory
        configuration, page file settings, and memory performance analysis.
        
    .OUTPUTS
        Array of PSCustomObjects with Category, Item, Value, Details, RiskLevel, Recommendation
        
    .NOTES
        Requires: Write-LogMessage function
        Permissions: Local user (WMI and performance counter access)
    #>
    
    Write-LogMessage "INFO" "Analyzing memory usage and performance..." "MEMORY"
    
    try {
        $Results = @()
        
        # Get physical memory information (capacity only, not usage snapshot)
        $Computer = Get-CimInstance -ClassName Win32_ComputerSystem
        $TotalMemoryGB = [math]::Round($Computer.TotalPhysicalMemory / 1GB, 2)

        $Results += [PSCustomObject]@{
            Category = "Memory"
            Item = "Physical Memory Capacity"
            Value = "$TotalMemoryGB GB installed"
            Details = "Total installed RAM"
            RiskLevel = "INFO"
            Recommendation = ""
        }

        Write-LogMessage "INFO" "Physical Memory: $TotalMemoryGB GB installed" "MEMORY"
        
        # Get virtual memory (page file) configuration
        try {
            $PageFiles = Get-CimInstance -ClassName Win32_PageFileUsage
            if ($PageFiles) {
                foreach ($PageFile in $PageFiles) {
                    $PageFileSizeGB = [math]::Round($PageFile.AllocatedBaseSize / 1024, 2)

                    $Results += [PSCustomObject]@{
                        Category = "Memory"
                        Item = "Virtual Memory Configuration"
                        Value = "$PageFileSizeGB GB configured"
                        Details = "Page File: $($PageFile.Name), Size: $PageFileSizeGB GB"
                        RiskLevel = "INFO"
                        Recommendation = ""
                    }

                    Write-LogMessage "INFO" "Page File $($PageFile.Name): $PageFileSizeGB GB configured" "MEMORY"
                }
            } else {
                $Results += [PSCustomObject]@{
                    Category = "Memory"
                    Item = "Virtual Memory Configuration"
                    Value = "No page file configured"
                    Details = "System has no virtual memory page file"
                    RiskLevel = "MEDIUM"
                    Recommendation = "Consider configuring virtual memory for system stability"
                }
                Write-LogMessage "WARN" "No page file configured on system" "MEMORY"
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve page file information: $($_.Exception.Message)" "MEMORY"
        }

        Write-LogMessage "SUCCESS" "Memory analysis completed - Total RAM: $TotalMemoryGB GB" "MEMORY"
        return $Results
    }
    catch {
        Write-LogMessage "ERROR" "Failed to analyze memory: $($_.Exception.Message)" "MEMORY"
        return @()
    }
}