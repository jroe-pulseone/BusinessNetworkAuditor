# WindowsWorkstationAuditor - Event Log Analysis Module
# Version 1.3.0

function Get-EventLogAnalysis {
    <#
    .SYNOPSIS
        Analyzes critical system events and security events from Windows Event Logs
        
    .DESCRIPTION
        Collects and analyzes Windows Event Logs for security-relevant events including
        logon failures, system errors, security policy changes, and other critical events
        that may indicate security issues or system problems.
        
        Performance optimized for servers with extensive log histories.
        
    .OUTPUTS
        Array of PSCustomObjects with Category, Item, Value, Details, RiskLevel, Recommendation
        
    .NOTES
        Requires: Write-LogMessage function
        Permissions: Local user (Event Log read access)
        Performance: Limits analysis timeframe based on system type for optimal performance
    #>
    
    Write-LogMessage "INFO" "Analyzing Windows Event Logs for security events..." "EVENTLOG"
    
    try {
        $Results = @()
        
        # Auto-detect system type and get configuration settings
        try {
            $OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
            $IsServer = $OSInfo.ProductType -ne 1  # ProductType: 1=Workstation, 2=DC, 3=Server
        }
        catch {
            $IsServer = $false
        }
        
        # Get event log configuration from config (with fallback defaults)
        $EventLogConfig = $null
        if (Get-Variable -Name "Config" -Scope Global -ErrorAction SilentlyContinue) {
            $EventLogConfig = $Global:Config.settings.eventlog
        }
        
        # Set analysis timeframes based on configuration or intelligent defaults
        if ($EventLogConfig) {
            if ($IsServer) {
                $AnalysisDays = if ($EventLogConfig.analysis_days) { $EventLogConfig.analysis_days } else { 3 }
                $MaxEventsPerQuery = if ($EventLogConfig.max_events_per_query) { $EventLogConfig.max_events_per_query } else { 500 }
            } else {
                $AnalysisDays = if ($EventLogConfig.workstation_analysis_days) { $EventLogConfig.workstation_analysis_days } else { 7 }
                $MaxEventsPerQuery = if ($EventLogConfig.workstation_max_events) { $EventLogConfig.workstation_max_events } else { 1000 }
            }
            Write-LogMessage "INFO" "Using configured event log settings: $AnalysisDays days, max $MaxEventsPerQuery events" "EVENTLOG"
        } else {
            # Fallback to hardcoded defaults if no config available
            if ($IsServer) {
                $AnalysisDays = 3
                $MaxEventsPerQuery = 500
                Write-LogMessage "INFO" "Server detected - using default: 3 days, max 500 events (no config)" "EVENTLOG"
            } else {
                $AnalysisDays = 7
                $MaxEventsPerQuery = 1000
                Write-LogMessage "INFO" "Workstation detected - using default: 7 days, max 1000 events (no config)" "EVENTLOG"
            }
        }
        
        $AnalysisStartTime = (Get-Date).AddDays(-$AnalysisDays)
        
        $SystemType = if ($IsServer) { "Server" } else { "Workstation" }
        Write-LogMessage "INFO" "$SystemType detected - analyzing last $AnalysisDays days (max $MaxEventsPerQuery events per query)" "EVENTLOG"
        
        # Define critical event IDs to monitor
        $CriticalEvents = @{
            # High-priority security events only
            4625 = @{LogName = "Security"; Description = "Failed Logon"; RiskLevel = "MEDIUM"}
            4720 = @{LogName = "Security"; Description = "User Account Created"; RiskLevel = "MEDIUM"}
            4724 = @{LogName = "Security"; Description = "Password Reset Attempt"; RiskLevel = "MEDIUM"}
            4732 = @{LogName = "Security"; Description = "User Added to Security Group"; RiskLevel = "MEDIUM"}
            4740 = @{LogName = "Security"; Description = "User Account Locked"; RiskLevel = "HIGH"}
            4771 = @{LogName = "Security"; Description = "Kerberos Pre-auth Failed"; RiskLevel = "MEDIUM"}
            
            # Critical system events
            6008 = @{LogName = "System"; Description = "Unexpected System Shutdown"; RiskLevel = "HIGH"}
            7034 = @{LogName = "System"; Description = "Service Crashed"; RiskLevel = "MEDIUM"}
            
            # Application stability events
            1000 = @{LogName = "Application"; Description = "Application Error"; RiskLevel = "MEDIUM"}
        }
        
        # Get event log summary information
        try {
            $EventLogs = Get-EventLog -List
            $SecurityLog = $EventLogs | Where-Object { $_.LogDisplayName -eq "Security" }
            $SystemLog = $EventLogs | Where-Object { $_.LogDisplayName -eq "System" }
            $ApplicationLog = $EventLogs | Where-Object { $_.LogDisplayName -eq "Application" }
            
            if ($SecurityLog) {
                $SecurityLogSize = [math]::Round($SecurityLog.FileSize / 1MB, 2)
                $SecurityMaxSize = [math]::Round($SecurityLog.MaximumKilobytes / 1024, 2)
                $SecurityUsagePercent = [math]::Round(($SecurityLogSize / $SecurityMaxSize) * 100, 1)
                
                $SecurityRisk = if ($SecurityUsagePercent -gt 90) { "HIGH" } elseif ($SecurityUsagePercent -gt 75) { "MEDIUM" } else { "LOW" }
                $SecurityRecommendation = if ($SecurityUsagePercent -gt 85) {
                    "Security event log approaching capacity - consider archiving"
                } else { "" }
                
                $Results += [PSCustomObject]@{
                    Category = "Event Logs"
                    Item = "Security Log Status"
                    Value = "$SecurityUsagePercent% full"
                    Details = "Size: $SecurityLogSize MB / $SecurityMaxSize MB, Entry count available via event queries"
                    RiskLevel = $SecurityRisk
                    Recommendation = $SecurityRecommendation
                }
                
                Write-LogMessage "INFO" "Security log: $SecurityUsagePercent% full ($SecurityLogSize MB / $SecurityMaxSize MB)" "EVENTLOG"
            }
            
            if ($SystemLog) {
                $SystemLogSize = [math]::Round($SystemLog.FileSize / 1MB, 2)
                $SystemMaxSize = [math]::Round($SystemLog.MaximumKilobytes / 1024, 2)
                $SystemUsagePercent = [math]::Round(($SystemLogSize / $SystemMaxSize) * 100, 1)
                
                $Results += [PSCustomObject]@{
                    Category = "Event Logs"
                    Item = "System Log Status"
                    Value = "$SystemUsagePercent% full"
                    Details = "Size: $SystemLogSize MB / $SystemMaxSize MB, Entry count available via event queries"
                    RiskLevel = "INFO"
                    Recommendation = ""
                }
                
                Write-LogMessage "INFO" "System log: $SystemUsagePercent% full ($SystemLogSize MB / $SystemMaxSize MB)" "EVENTLOG"
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve event log summary: $($_.Exception.Message)" "EVENTLOG"
        }
        
        # Analyze critical security events
        foreach ($EventID in $CriticalEvents.Keys) {
            $EventInfo = $CriticalEvents[$EventID]
            $LogName = $EventInfo.LogName
            $Description = $EventInfo.Description
            $BaseRiskLevel = $EventInfo.RiskLevel
            
            try {
                Write-LogMessage "INFO" "Checking for Event ID $EventID ($Description) in $LogName log..." "EVENTLOG"
                
                # Performance-limited event query
                $Events = Get-EventLog -LogName $LogName -After $AnalysisStartTime -InstanceId $EventID -Newest $MaxEventsPerQuery -ErrorAction SilentlyContinue
                
                if ($Events) {
                    $EventCount = $Events.Count
                    $MostRecent = $Events | Sort-Object TimeGenerated -Descending | Select-Object -First 1
                    $MostRecentTime = $MostRecent.TimeGenerated
                    
                    # Determine risk level based on event type and frequency
                    $RiskLevel = $BaseRiskLevel
                    $Recommendation = ""
                    
                    # Special handling for high-frequency events
                    if ($EventID -eq 4625 -and $EventCount -gt 50) {  # Multiple failed logons
                        $RiskLevel = "HIGH"
                        $Recommendation = "Investigate multiple failed logon attempts - possible brute force attack"
                    }
                    elseif ($EventID -eq 4740 -and $EventCount -gt 5) {  # Multiple account lockouts
                        $RiskLevel = "HIGH"
                        $Recommendation = "Multiple account lockouts may indicate attack or policy issues"
                    }
                    elseif ($EventID -eq 6008 -and $EventCount -gt 3) {  # Multiple unexpected shutdowns
                        $RiskLevel = "HIGH"
                        $Recommendation = "Multiple unexpected shutdowns may indicate system instability"
                    }
                    elseif ($EventID -eq 7034 -and $EventCount -gt 10) {  # Multiple service crashes
                        $RiskLevel = "HIGH"
                        $Recommendation = "Multiple service crashes may indicate system problems"
                    }
                    elseif ($EventID -eq 4625) {
                        $Recommendation = "Monitor failed logon attempts for security threats"
                    }
                    elseif ($EventID -eq 4672) {
                        $Recommendation = "Monitor special privilege assignments for unauthorized elevation"
                    }
                    
                    # Dynamic timeframe display using configured values
                    $TimeframeDays = "$AnalysisDays days"
                    $EventCountDisplay = if ($EventCount -eq $MaxEventsPerQuery) { "$EventCount+ events" } else { "$EventCount events" }
                    
                    $Results += [PSCustomObject]@{
                        Category = "Security Events"
                        Item = $Description
                        Value = "$EventCountDisplay ($TimeframeDays)"
                        Details = "Event ID: $EventID, Most recent: $MostRecentTime"
                        RiskLevel = $RiskLevel
                        Recommendation = $Recommendation
                    }
                    
                    Write-LogMessage "INFO" "Event ID $EventID`: $EventCount events found, most recent: $MostRecentTime" "EVENTLOG"
                }
                else {
                    # Only report absence of critical security events, not routine events
                    if ($EventID -in @(4625, 4740)) {
                        Write-LogMessage "INFO" "Event ID $EventID`: No events found (good)" "EVENTLOG"
                    }
                }
            }
            catch {
                Write-LogMessage "WARN" "Could not query Event ID $EventID in $LogName log: $($_.Exception.Message)" "EVENTLOG"
            }
        }
        
        # Check for Windows Defender events (performance limited)
        try {
            $DefenderEvents = Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Windows Defender/Operational"; StartTime=$AnalysisStartTime} -MaxEvents $MaxEventsPerQuery -ErrorAction SilentlyContinue

            if ($DefenderEvents) {
                # Only count actual threat detections, not historical management events
                # 1116 = Malware detected, 1117 = Action taken to protect system
                # Exclude: 1006 (history changed), 1007 (generic action), 1008 (history deleted), 1009 (restored from quarantine)
                $ThreatEvents = $DefenderEvents | Where-Object { $_.Id -in @(1116, 1117) }
                $ScanEvents = $DefenderEvents | Where-Object { $_.Id -in @(1000, 1001, 1002) }
                
                # Use dynamic timeframe for display
                $TimeframeDays = "$AnalysisDays days"
                
                if ($ThreatEvents) {
                    $ThreatCount = $ThreatEvents.Count
                    $Results += [PSCustomObject]@{
                        Category = "Security Events"
                        Item = "Windows Defender Threats"
                        Value = "$ThreatCount threats detected"
                        Details = "Threat detection events in last $TimeframeDays"
                        RiskLevel = "HIGH"
                        Recommendation = "Investigate and remediate detected security threats"
                    }
                    Write-LogMessage "WARN" "Windows Defender: $ThreatCount threats detected in last $TimeframeDays" "EVENTLOG"
                } else {
                    $Results += [PSCustomObject]@{
                        Category = "Security Events"
                        Item = "Windows Defender Threats"
                        Value = "0 threats detected"
                        Details = "No threat detection events in last $TimeframeDays"
                        RiskLevel = "LOW"
                        Recommendation = ""
                    }
                }
                
                if ($ScanEvents) {
                    $ScanCount = $ScanEvents.Count
                    $Results += [PSCustomObject]@{
                        Category = "Security Events"
                        Item = "Windows Defender Scans"
                        Value = "$ScanCount scans performed"
                        Details = "Antivirus scan events in last $TimeframeDays"
                        RiskLevel = "INFO"
                        Recommendation = ""
                    }
                    Write-LogMessage "INFO" "Windows Defender: $ScanCount scans performed in last $TimeframeDays" "EVENTLOG"
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve Windows Defender events: $($_.Exception.Message)" "EVENTLOG"
        }
        
        # Check for PowerShell execution events (potential security concern)
        try {
            $PowerShellEvents = Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-PowerShell/Operational"; StartTime=$AnalysisStartTime; Id=4103,4104} -ErrorAction SilentlyContinue
            
            if ($PowerShellEvents) {
                $PSEventCount = $PowerShellEvents.Count
                $SuspiciousPS = $PowerShellEvents | Where-Object { 
                    $_.Message -match "Invoke-|Download|WebClient|System.Net|Base64|Encode|Hidden|Bypass|ExecutionPolicy" 
                }
                
                $PSRisk = if ($SuspiciousPS.Count -gt 0) { "HIGH" } elseif ($PSEventCount -gt 100) { "MEDIUM" } else { "LOW" }
                $PSRecommendation = if ($SuspiciousPS.Count -gt 0) {
                    "Investigate suspicious PowerShell execution patterns"
                } elseif ($PSEventCount -gt 100) {
                    "High PowerShell usage - review for legitimate business needs"
                } else { "" }
                
                # Build detailed suspicious patterns description
                $SuspiciousPatterns = @()
                if ($SuspiciousPS.Count -gt 0) {
                    $PatternCounts = @{}
                    foreach ($Event in $SuspiciousPS) {
                        if ($Event.Message -match "Invoke-") { $PatternCounts["Invoke Commands"]++ }
                        if ($Event.Message -match "Download|WebClient|System.Net") { $PatternCounts["Network Downloads"]++ }
                        if ($Event.Message -match "Base64|Encode") { $PatternCounts["Encoding/Obfuscation"]++ }
                        if ($Event.Message -match "Hidden|Bypass|ExecutionPolicy") { $PatternCounts["Policy Bypass"]++ }
                    }
                    
                    foreach ($Pattern in $PatternCounts.Keys) {
                        $SuspiciousPatterns += "$Pattern ($($PatternCounts[$Pattern]))"
                    }
                }
                
                $PatternDetails = if ($SuspiciousPatterns.Count -gt 0) {
                    "Suspicious patterns detected: " + ($SuspiciousPatterns -join ", ")
                } else {
                    "No suspicious patterns detected in PowerShell executions"
                }
                
                $Results += [PSCustomObject]@{
                    Category = "Security Events"
                    Item = "PowerShell Execution"
                    Value = "$PSEventCount executions (7 days)"
                    Details = "$PatternDetails. Total suspicious events: $($SuspiciousPS.Count)"
                    RiskLevel = $PSRisk
                    Recommendation = $PSRecommendation
                }
                
                # Add raw PowerShell events to data collection for detailed analysis
                if ($SuspiciousPS.Count -gt 0) {
                    $PSEventDetails = @()
                    foreach ($Event in ($SuspiciousPS | Select-Object -First 10)) {
                        $PSEventDetails += [PSCustomObject]@{
                            TimeGenerated = $Event.TimeCreated
                            EventId = $Event.Id
                            Message = $Event.Message.Substring(0, [Math]::Min(500, $Event.Message.Length))
                            ProcessId = $Event.ProcessId
                            UserId = $Event.UserId
                        }
                    }
                    Add-RawDataCollection -CollectionName "SuspiciousPowerShellEvents" -Data $PSEventDetails
                }
                
                Write-LogMessage "INFO" "PowerShell events: $PSEventCount total, $($SuspiciousPS.Count) suspicious" "EVENTLOG"
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve PowerShell events: $($_.Exception.Message)" "EVENTLOG"
        }
        
        # Check for USB device insertion events
        try {
            $USBEvents = Get-WinEvent -FilterHashtable @{LogName="System"; StartTime=$AnalysisStartTime; Id=20001,20003} -ErrorAction SilentlyContinue
            
            if ($USBEvents) {
                $USBCount = $USBEvents.Count
                $USBRisk = if ($USBCount -gt 20) { "MEDIUM" } else { "LOW" }
                $USBRecommendation = if ($USBCount -gt 10) {
                    "Monitor USB device usage for data loss prevention"
                } else { "" }
                
                $Results += [PSCustomObject]@{
                    Category = "Security Events"
                    Item = "USB Device Activity"
                    Value = "$USBCount USB events (7 days)"
                    Details = "USB device insertion/removal events"
                    RiskLevel = $USBRisk
                    Recommendation = $USBRecommendation
                }
                
                Write-LogMessage "INFO" "USB events: $USBCount device events in last 7 days" "EVENTLOG"
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve USB device events: $($_.Exception.Message)" "EVENTLOG"
        }
        
        Write-LogMessage "SUCCESS" "Event log analysis completed - $($Results.Count) items analyzed" "EVENTLOG"
        return $Results
    }
    catch {
        Write-LogMessage "ERROR" "Failed to analyze event logs: $($_.Exception.Message)" "EVENTLOG"
        return @()
    }
}