# WindowsWorkstationAuditor - Disk Space Analysis Module
# Version 1.3.0

function Get-DiskSpaceAnalysis {
    <#
    .SYNOPSIS
        Analyzes disk space, drive capacity, and storage health status
        
    .DESCRIPTION
        Collects comprehensive disk space information including drive capacity,
        free space percentages, disk health status, and storage risk assessment.
        
    .OUTPUTS
        Array of PSCustomObjects with Category, Item, Value, Details, RiskLevel, Recommendation
        
    .NOTES
        Requires: Write-LogMessage function
        Permissions: Local user (WMI access)
    #>
    
    Write-LogMessage "INFO" "Analyzing disk space and storage..." "DISK"
    
    try {
        $Results = @()
        $Drives = @(Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 })
        
        foreach ($Drive in $Drives) {
            $DriveLetter = $Drive.DeviceID
            $TotalSizeGB = [math]::Round($Drive.Size / 1GB, 2)
            $FreeSpaceGB = [math]::Round($Drive.FreeSpace / 1GB, 2)
            $UsedSpaceGB = $TotalSizeGB - $FreeSpaceGB
            $FreeSpacePercent = [math]::Round(($FreeSpaceGB / $TotalSizeGB) * 100, 1)
            
            # Determine risk level based on free space percentage
            $RiskLevel = if ($FreeSpacePercent -lt 10) { "HIGH" } 
                        elseif ($FreeSpacePercent -lt 20) { "MEDIUM" } 
                        else { "LOW" }
            
            $Recommendation = if ($FreeSpacePercent -lt 15) { 
                "Maintain adequate free disk space for system operations" 
            } else { "" }
            
            $Results += [PSCustomObject]@{
                Category = "Storage"
                Item = "Disk Space ($DriveLetter)"
                Value = "$FreeSpacePercent% free"
                Details = "Total: $TotalSizeGB GB, Used: $UsedSpaceGB GB, Free: $FreeSpaceGB GB"
                RiskLevel = $RiskLevel
                Recommendation = ""
            }
            
            Write-LogMessage "INFO" "Drive $DriveLetter - $FreeSpacePercent% free ($FreeSpaceGB GB / $TotalSizeGB GB)" "DISK"
        }
        
        # Check for disk health using SMART data if available
        try {
            $PhysicalDisks = Get-CimInstance -ClassName Win32_DiskDrive
            foreach ($Disk in $PhysicalDisks) {
                $DiskModel = $Disk.Model
                $DiskSize = [math]::Round($Disk.Size / 1GB, 2)
                $DiskStatus = $Disk.Status
                
                $HealthRisk = if ($DiskStatus -ne "OK") { "HIGH" } else { "LOW" }
                $HealthRecommendation = if ($DiskStatus -ne "OK") { 
                    "Monitor disk health and replace failing drives" 
                } else { "" }
                
                $Results += [PSCustomObject]@{
                    Category = "Storage"
                    Item = "Disk Health"
                    Value = $DiskStatus
                    Details = "$DiskModel ($DiskSize GB)"
                    RiskLevel = $HealthRisk
                    Recommendation = ""
                }
                
                Write-LogMessage "INFO" "Physical disk: $DiskModel - Status: $DiskStatus" "DISK"
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve disk health information: $($_.Exception.Message)" "DISK"
        }
        
        $DriveCount = $Drives.Count
        Write-LogMessage "SUCCESS" "Disk space analysis completed - $DriveCount drives analyzed" "DISK"
        return $Results
    }
    catch {
        Write-LogMessage "ERROR" "Failed to analyze disk space: $($_.Exception.Message)" "DISK"
        return @()
    }
}