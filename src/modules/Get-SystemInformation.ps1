# WindowsWorkstationAuditor - System Information Module
# Version 1.3.0

function Get-SystemInformation {
    <#
    .SYNOPSIS
        Collects comprehensive system information including Azure AD and WSUS detection
        
    .DESCRIPTION
        Gathers OS, hardware, domain status, Azure AD tenant info, MDM enrollment,
        and WSUS configuration details for security assessment.
        
    .OUTPUTS
        Array of PSCustomObjects with Category, Item, Value, Details, RiskLevel, Recommendation
        
    .NOTES
        Requires: Write-LogMessage function
        Permissions: Local user (dsregcmd for Azure AD detection)
    #>
    
    Write-LogMessage "INFO" "Collecting system information..." "SYSTEM"
    
    try {
        $OS = Get-CimInstance -ClassName Win32_OperatingSystem
        $Computer = Get-CimInstance -ClassName Win32_ComputerSystem
        
        # Azure AD and MDM Detection
        $AzureADJoined = $false
        $DomainJoined = $Computer.PartOfDomain
        $DomainName = if ($DomainJoined) { $Computer.Domain } else { "WORKGROUP" }
        $TenantId = ""
        $TenantName = ""
        $MDMEnrolled = $false
        
        try {
            Write-LogMessage "INFO" "Checking Azure AD status with dsregcmd..." "SYSTEM"
            $DsregOutput = & dsregcmd /status 2>$null
            if ($LASTEXITCODE -eq 0) {
                # Check Azure AD joined status
                $AzureADLine = $DsregOutput | Where-Object { $_ -match "AzureAdJoined\s*:\s*YES" }
                $AzureADJoined = $AzureADLine -ne $null
                
                if ($AzureADJoined) {
                    $DomainName = "Azure AD Joined"
                    
                    # Extract Tenant ID
                    $TenantLine = $DsregOutput | Where-Object { $_ -match "TenantId\s*:\s*(.+)" }
                    if ($TenantLine -and $matches[1]) {
                        $TenantId = $matches[1].Trim()
                        Write-LogMessage "INFO" "Azure AD Tenant ID: $TenantId" "SYSTEM"
                    }
                    
                    # Try to get tenant name/domain
                    $TenantDisplayLine = $DsregOutput | Where-Object { $_ -match "TenantDisplayName\s*:\s*(.+)" }
                    if ($TenantDisplayLine -and $matches[1]) {
                        $TenantName = $matches[1].Trim()
                        Write-LogMessage "INFO" "Azure AD Tenant Name: $TenantName" "SYSTEM"
                    } else {
                        $TenantNameLine = $DsregOutput | Where-Object { $_ -match "TenantName\s*:\s*(.+)" }
                        if ($TenantNameLine -and $matches[1]) {
                            $TenantName = $matches[1].Trim()
                            Write-LogMessage "INFO" "Azure AD Tenant Name (alt): $TenantName" "SYSTEM"
                        }
                    }
                    
                    # Check MDM enrollment status
                    $MDMUrlLine = $DsregOutput | Where-Object { $_ -match "MdmUrl\s*:\s*(.+)" }
                    if ($MDMUrlLine) {
                        $MDMEnrolled = $true
                        Write-LogMessage "INFO" "MDM enrolled: Yes" "SYSTEM"
                    } else {
                        Write-LogMessage "INFO" "MDM enrolled: No" "SYSTEM"
                    }
                }
                
                Write-LogMessage "SUCCESS" "Azure AD joined: $AzureADJoined, MDM enrolled: $MDMEnrolled" "SYSTEM"
            } else {
                Write-LogMessage "WARN" "dsregcmd returned exit code: $LASTEXITCODE" "SYSTEM"
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not check Azure AD status: $($_.Exception.Message)" "SYSTEM"
        }
        
        # WSUS Configuration Check
        $WSUSConfigured = $false
        $WSUSServer = ""
        try {
            $WSUSRegKey = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ErrorAction SilentlyContinue
            if ($WSUSRegKey -and $WSUSRegKey.WUServer) {
                $WSUSConfigured = $true
                $WSUSServer = $WSUSRegKey.WUServer
                Write-LogMessage "INFO" "WSUS Server detected: $WSUSServer" "SYSTEM"
            } else {
                # Check local machine settings as fallback
                $WSUSRegKey2 = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" -ErrorAction SilentlyContinue
                if ($WSUSRegKey2 -and $WSUSRegKey2.WUServer) {
                    $WSUSConfigured = $true
                    $WSUSServer = $WSUSRegKey2.WUServer
                    Write-LogMessage "INFO" "WSUS Server detected in local settings: $WSUSServer" "SYSTEM"
                }
            }
            
            if (-not $WSUSConfigured) {
                Write-LogMessage "INFO" "WSUS not configured - using Microsoft Update directly" "SYSTEM"
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not check WSUS configuration: $($_.Exception.Message)" "SYSTEM"
        }
        
        $Results = @()
        
        # Operating System Info
        $Results += [PSCustomObject]@{
            Category = "System"
            Item = "Operating System"
            Value = "$($OS.Caption) $($OS.Version)"
            Details = "Build: $($OS.BuildNumber), Install Date: $($OS.InstallDate)"
            RiskLevel = "INFO"
            Recommendation = ""
        }
        
        # Hardware Info
        $Results += [PSCustomObject]@{
            Category = "System"
            Item = "Hardware"
            Value = "$($Computer.Manufacturer) $($Computer.Model)"
            Details = "RAM: $([math]::Round($Computer.TotalPhysicalMemory/1GB, 2))GB"
            RiskLevel = "INFO"
            Recommendation = ""
        }

        # Processor Details
        try {
            $Processors = Get-CimInstance -ClassName Win32_Processor
            foreach ($Processor in $Processors) {
                $ProcessorName = $Processor.Name
                $ProcessorSpeedGHz = [math]::Round($Processor.MaxClockSpeed / 1000, 2)
                $LogicalProcessors = $Processor.NumberOfLogicalProcessors
                $PhysicalCores = $Processor.NumberOfCores

                $Results += [PSCustomObject]@{
                    Category = "System"
                    Item = "Processor"
                    Value = $ProcessorName
                    Details = "Speed: $ProcessorSpeedGHz GHz, Cores: $PhysicalCores, Logical Processors: $LogicalProcessors"
                    RiskLevel = "INFO"
                    Recommendation = ""
                }

                Write-LogMessage "INFO" "Processor: $ProcessorName - $ProcessorSpeedGHz GHz, $PhysicalCores cores" "SYSTEM"
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve processor details: $($_.Exception.Message)" "SYSTEM"
        }
        
        # Domain Status with Tenant Info
        $DomainDetails = if ($AzureADJoined) { 
            $TenantInfo = if ($TenantName) { 
                "$TenantName ($TenantId)" 
            } else { 
                "Tenant ID: $TenantId" 
            }
            "Azure AD joined - $TenantInfo"
        } elseif ($DomainJoined) { 
            "Domain joined system" 
        } else { 
            "Workgroup system" 
        }
        
        $Results += [PSCustomObject]@{
            Category = "System"
            Item = "Domain Status"
            Value = $DomainName
            Details = $DomainDetails
            RiskLevel = if ($AzureADJoined -or $DomainJoined) { "LOW" } else { "MEDIUM" }
            Recommendation = if (-not $AzureADJoined -and -not $DomainJoined) { "Consider domain or Azure AD joining for centralized management" } else { "" }
        }
        
        # WSUS Configuration Status
        $Results += [PSCustomObject]@{
            Category = "System"
            Item = "WSUS Configuration"
            Value = if ($WSUSConfigured) { "Configured" } else { "Not Configured" }
            Details = if ($WSUSConfigured) { "Server: $WSUSServer" } else { "Using Microsoft Update directly" }
            RiskLevel = "INFO"
            Recommendation = ""
        }
        
        # MDM Enrollment Status (only for Azure AD joined systems)
        if ($AzureADJoined) {
            $Results += [PSCustomObject]@{
                Category = "System"
                Item = "MDM Enrollment"
                Value = if ($MDMEnrolled) { "Enrolled" } else { "Not Enrolled" }
                Details = if ($MDMEnrolled) { "Device enrolled in Mobile Device Management" } else { "Device not enrolled in MDM" }
                RiskLevel = if ($MDMEnrolled) { "LOW" } else { "MEDIUM" }
                Recommendation = if (-not $MDMEnrolled) { "Consider MDM enrollment for device management" } else { "" }
            }
        }
        
        Write-LogMessage "SUCCESS" "System information collected - Domain: $DomainName, WSUS: $WSUSConfigured, MDM: $MDMEnrolled" "SYSTEM"
        return $Results
    }
    catch {
        Write-LogMessage "ERROR" "Failed to collect system information: $($_.Exception.Message)" "SYSTEM"
        return @()
    }
}