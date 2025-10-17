# WindowsServerAuditor - Self-Contained Web Version
# Version 2.0.0 - Server Audit Script (Manifest-Based Build)
# Platform: Windows 10/11, Windows Server 2008-2022+
# Requires: PowerShell 5.0+
# Usage: [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; iex (irm https://your-url/WindowsServerAuditor-Web.ps1)
# Built: 2025-10-17 10:40:56
# Modules: 27 embedded modules in dependency order

param(
    [string]$OutputPath = "$env:USERPROFILE\WindowsAudit",
    [switch]$Verbose
)

# Embedded Configuration
$Script:EmbeddedConfig = @'
{
  "version": "1.3.0",
  "modules": {
    "system": {
      "enabled": true,
      "timeout": 30,
      "description": "System information and server role detection"
    },
    "memory": {
      "enabled": true,
      "timeout": 15,
      "description": "Memory usage and configuration analysis"
    },
    "disk": {
      "enabled": true,
      "timeout": 20,
      "description": "Disk space and storage analysis"
    },
    "network": {
      "enabled": true,
      "timeout": 30,
      "description": "Network configuration and security analysis"
    },
    "process": {
      "enabled": true,
      "timeout": 30,
      "description": "Running processes and services analysis"
    },
    "patches": {
      "enabled": true,
      "timeout": 60,
      "description": "Windows Update and patch status"
    },
    "software": {
      "enabled": true,
      "timeout": 45,
      "description": "Installed software inventory with server focus"
    },
    "security": {
      "enabled": true,
      "timeout": 20,
      "description": "Security settings and antivirus detection"
    },
    "eventlog": {
      "enabled": true,
      "timeout": 45,
      "description": "Event log analysis for server events"
    },
    "users": {
      "enabled": true,
      "timeout": 20,
      "description": "User accounts with server/service account focus"
    },
    "serverroles": {
      "enabled": true,
      "timeout": 30,
      "description": "Windows Server roles and features detection"
    },
    "dhcp": {
      "enabled": true,
      "timeout": 20,
      "description": "DHCP server configuration and scope analysis"
    },
    "dns": {
      "enabled": true,
      "timeout": 20,
      "description": "DNS server zones and configuration analysis"
    },
    "fileshares": {
      "enabled": true,
      "timeout": 15,
      "description": "File shares and permissions analysis"
    },
    "activedirectory": {
      "enabled": true,
      "timeout": 45,
      "description": "Active Directory users, groups, and configuration"
    },
    "iis": {
      "enabled": true,
      "timeout": 20,
      "description": "IIS web server configuration and sites"
    },
    "services": {
      "enabled": true,
      "timeout": 15,
      "description": "Windows services analysis with server focus"
    }
  },
  "output": {
    "formats": [
      "markdown",
      "rawjson"
    ],
    "path": "./output",
    "timestamp": true,
    "filename_prefix": "server_audit"
  },
  "settings": {
    "collect_ad_details": true,
    "collect_dhcp_reservations": true,
    "collect_dns_records": false,
    "collect_iis_bindings": true,
    "max_ad_users": 1000,
    "max_ad_groups": 500,
    "eventlog": {
      "analysis_days": 3,
      "max_events_per_query": 500,
      "workstation_analysis_days": 7,
      "workstation_max_events": 1000,
      "domain_controller_analysis_days": 30,
      "domain_controller_max_events": 500
    },
    "antivirus_signatures": {
      "SentinelOne": [
        "SentinelAgent",
        "SentinelRemediation",
        "SentinelCtl"
      ],
      "CrowdStrike": [
        "CSAgent",
        "CSFalconService",
        "CSFalconContainer"
      ],
      "CarbonBlack": [
        "cb",
        "CarbonBlack",
        "RepMgr",
        "RepUtils",
        "RepUx"
      ],
      "Cortex XDR": [
        "cytool",
        "cyserver",
        "CyveraService"
      ],
      "McAfee": [
        "mcshield",
        "mfemms",
        "mfevtps",
        "McCSPServiceHost",
        "masvc"
      ],
      "Symantec": [
        "ccSvcHst",
        "NortonSecurity",
        "navapsvc",
        "rtvscan",
        "savroam"
      ],
      "Trend Micro": [
        "tmbmsrv",
        "tmproxy",
        "tmlisten",
        "PccNTMon",
        "TmListen"
      ],
      "Kaspersky": [
        "avp",
        "avpui",
        "klnagent",
        "ksde",
        "kavfs"
      ],
      "Bitdefender": [
        "bdagent",
        "vsservppl",
        "vsserv",
        "updatesrv",
        "bdredline"
      ],
      "ESET": [
        "epag",
        "epwd",
        "ekrn",
        "egui",
        "efsw"
      ],
      "Sophos": [
        "SophosAgent",
        "savservice",
        "SophosFS",
        "SophosHealth"
      ],
      "F-Secure": [
        "fsm32",
        "fsgk32",
        "fsav32",
        "fshoster",
        "FSMA"
      ],
      "Avast": [
        "avastui",
        "avastsvc",
        "avastbrowser",
        "wsc_proxy"
      ],
      "AVG": [
        "avguard",
        "avgui",
        "avgrsa",
        "avgfws",
        "avgcsrvx"
      ],
      "Webroot": [
        "WRSA",
        "WRData",
        "WRCore",
        "WRConsumerService"
      ],
      "Malwarebytes": [
        "mbamservice",
        "mbamtray",
        "MBAMProtector",
        "mbae64"
      ],
      "Windows Defender": [
        "MsMpEng",
        "NisSrv",
        "SecurityHealthService"
      ]
    }
  }
}
'@

# Global variables
if (-not $OutputPath -or [string]::IsNullOrWhiteSpace($OutputPath)) {
    $Script:OutputPath = "$env:USERPROFILE\WindowsAudit"
} else {
    $Script:OutputPath = $OutputPath
}
$Script:LogFile = ""
$Script:StartTime = Get-Date
$Script:ComputerName = $env:COMPUTERNAME
$Script:BaseFileName = "${ComputerName}_$($StartTime.ToString('yyyyMMdd_HHmmss'))"

# Ensure output directory exists
if (-not (Test-Path $Script:OutputPath)) {
    New-Item -ItemType Directory -Path $Script:OutputPath -Force | Out-Null
}

# === EMBEDDED MODULES (DEPENDENCY ORDER) ===

# [FOUNDATION] Initialize-Logging - Logging system initialization
# Dependencies: 
# Order: 1
# WindowsWorkstationAuditor - Logging Initialization Module
# Version 1.3.0

function Initialize-Logging {
    <#
    .SYNOPSIS
        Initializes the logging system for the audit tool
        
    .DESCRIPTION
        Creates log directory structure and sets up the main log file path.
        Can work with parameters or global script variables.
        
    .PARAMETER LogDirectory
        Directory to create log files in (optional, uses $OutputPath/logs if not specified)
        
    .PARAMETER LogFileName
        Name of the log file (optional, uses ${Script:BaseFileName}_audit.log if not specified)
        
    .NOTES
        Requires: $OutputPath, $Script:BaseFileName, $ComputerName global variables (if parameters not provided)
    #>
    param(
        [string]$LogDirectory,
        [string]$LogFileName
    )
    
    try {
        # Use parameters if provided, otherwise fall back to global variables
        if (-not $LogDirectory) {
            $LogDirectory = Join-Path $OutputPath "logs"
        }
        
        if (-not $LogFileName) {
            $LogFileName = "${Script:BaseFileName}_audit.log"
        }
        
        if (-not (Test-Path $LogDirectory)) {
            New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
        }
        
        $Script:LogFile = Join-Path $LogDirectory $LogFileName
        
        # Determine if this is workstation or server based on the filename
        $AuditorType = if ($LogFileName -like "*server*") { "WindowsServerAuditor" } else { "WindowsWorkstationAuditor" }
        
        Write-LogMessage "INFO" "$AuditorType v1.3.0 Started"
        Write-LogMessage "INFO" "Computer: $($Script:ComputerName)"
        Write-LogMessage "INFO" "User: $env:USERNAME"
        Write-LogMessage "INFO" "Base filename: $Script:BaseFileName"
        Write-LogMessage "INFO" "Log file: $Script:LogFile"
        
        return $true
    }
    catch {
        Write-Host "ERROR: Failed to initialize logging: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# [FOUNDATION] Write-LogMessage - Core logging functionality
# Dependencies: Initialize-Logging
# Order: 2
# WindowsWorkstationAuditor - Centralized Logging Module
# Version 1.3.0

function Write-LogMessage {
    <#
    .SYNOPSIS
        Centralized logging function with console and file output
        
    .DESCRIPTION
        Writes log messages with timestamp, level, and category formatting.
        Provides colored console output and file logging capabilities.
        
    .PARAMETER Level
        Log level: ERROR, WARN, SUCCESS, INFO
        
    .PARAMETER Message
        The log message content
        
    .PARAMETER Category
        Optional category for message organization (default: GENERAL)
        
    .NOTES
        Requires: $Script:LogFile global variable for file output
    #>
    param(
        [string]$Level,
        [string]$Message,
        [string]$Category = "GENERAL"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] [$Category] $Message"
    
    # Console output with color coding
    switch ($Level) {
        "ERROR" { Write-Host $LogEntry -ForegroundColor Red }
        "WARN"  { Write-Host $LogEntry -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $LogEntry -ForegroundColor Green }
        default { Write-Host $LogEntry }
    }
    
    # File output
    if ($Script:LogFile) {
        Add-Content -Path $Script:LogFile -Value $LogEntry
    }
}

# [DATA] Import-AuditData - JSON audit data import and consolidation
# Dependencies: Write-LogMessage
# Order: 10
# NetworkAuditAggregator - JSON Import Module
# Version 1.0.0

function Import-AuditData {
    <#
    .SYNOPSIS
        Imports and consolidates JSON audit files from multiple systems
        
    .DESCRIPTION
        Scans the import directory for audit JSON files, validates their format,
        and consolidates findings into a unified data structure for reporting.
        
    .PARAMETER ImportPath
        Directory containing JSON audit files
        
    .OUTPUTS
        PSCustomObject with SystemCount, FindingCount, Systems, and AllFindings
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [string]$ImportPath
    )
    
    Write-Verbose "Scanning for audit files in: $ImportPath"
    
    # Initialize result structure
    $Result = [PSCustomObject]@{
        SystemCount = 0
        FindingCount = 0
        Systems = @()
        AllFindings = @()
        ImportedFiles = @()
        Errors = @()
    }
    
    # Ensure import directory exists
    if (-not (Test-Path $ImportPath)) {
        Write-Warning "Import directory does not exist: $ImportPath"
        return $Result
    }
    
    # Find JSON audit files (system audits and dark web checks)
    $SystemFiles = Get-ChildItem -Path $ImportPath -Filter "*_raw_data.json" -File
    $DarkWebFiles = Get-ChildItem -Path $ImportPath -Filter "darkweb-check-*.json" -File
    $JsonFiles = @($SystemFiles) + @($DarkWebFiles)
    Write-Verbose "Found $($JsonFiles.Count) audit files ($($SystemFiles.Count) system, $($DarkWebFiles.Count) dark web)"
    
    foreach ($JsonFile in $JsonFiles) {
        try {
            Write-Verbose "Processing: $($JsonFile.Name)"
            
            # Read and parse JSON (handle BOM characters and empty category names)
            $JsonContent = Get-Content $JsonFile.FullName -Raw -Encoding UTF8
            # Remove BOM if present
            if ($JsonContent.Length -gt 0 -and $JsonContent[0] -eq [char]0xFEFF) {
                $JsonContent = $JsonContent.Substring(1)
            }
            # Remove empty string category (audit tool bug) using multiline regex
            $JsonContent = $JsonContent -replace '(?s)"":\s*\{.*?"findings":\s*\[.*?\]\s*\},?\s*', ''
            # Clean up trailing commas before closing braces
            $JsonContent = $JsonContent -replace ',(\s*[\]}])', '$1'
            $AuditData = $JsonContent | ConvertFrom-Json
            
            # Determine file type and validate structure
            $IsDarkWebFile = $JsonFile.Name -like "darkweb-check-*"

            if ($IsDarkWebFile) {
                # Validate dark web file structure
                if (-not $AuditData.Results -or -not $AuditData.Summary) {
                    Write-Warning "Invalid dark web file format: $($JsonFile.Name) - Missing Results or Summary"
                    $Result.Errors += "Invalid format: $($JsonFile.Name)"
                    continue
                }
            } else {
                # Validate system audit file structure - support all formats
                # Old format: compliance_framework.findings (pre-Sept 12)
                # Current format: categories + recommendation_framework (Sept 12+)
                $HasOldFormat = $AuditData.metadata -and $AuditData.compliance_framework.findings
                $HasCurrentFormat = $AuditData.metadata -and $AuditData.categories

                if (-not $HasOldFormat -and -not $HasCurrentFormat) {
                    Write-Warning "Invalid audit file format: $($JsonFile.Name) - Missing metadata or findings structure"
                    $Result.Errors += "Invalid format: $($JsonFile.Name)"
                    continue
                }
            }
            
            # Extract system information based on file type
            if ($IsDarkWebFile) {
                $SystemInfo = [PSCustomObject]@{
                    ComputerName = "Dark Web Check"
                    AuditTimestamp = $AuditData.CheckDate
                    ToolVersion = "DarkWebChecker v1.0"
                    FileName = $JsonFile.Name
                    FileSize = [math]::Round($JsonFile.Length / 1KB, 1)
                    FindingCount = $AuditData.Summary.BreachesFound
                    OperatingSystem = "Dark Web Analysis"
                    SystemType = "Breach Monitor"
                    Domain = ""
                    LastBootTime = ""
                }
            } else {
                # Count findings based on format
                $TotalFindings = 0
                if ($AuditData.compliance_framework.findings) {
                    $TotalFindings = $AuditData.compliance_framework.findings.Count
                } elseif ($AuditData.categories) {
                    # Count findings across all categories
                    try {
                        $AuditData.categories.PSObject.Properties | ForEach-Object {
                            if ($_.Value -and $_.Value.findings -and $_.Value.findings.Count) {
                                $TotalFindings += $_.Value.findings.Count
                            }
                        }
                    } catch {
                        Write-Verbose "Error counting findings: $($_.Exception.Message)"
                        $TotalFindings = 0
                    }
                }

                # Safely convert metadata values to strings
                $ComputerName = if ($AuditData.metadata.computer_name) { $AuditData.metadata.computer_name.ToString() } else { "Unknown" }
                $AuditTimestamp = if ($AuditData.metadata.audit_timestamp) { $AuditData.metadata.audit_timestamp.ToString() } else { "Unknown" }
                $ToolVersion = if ($AuditData.metadata.tool_version) { $AuditData.metadata.tool_version.ToString() } else { "Unknown" }

                $SystemInfo = [PSCustomObject]@{
                    ComputerName = $ComputerName
                    AuditTimestamp = $AuditTimestamp
                    ToolVersion = $ToolVersion
                    FileName = $JsonFile.Name
                    FileSize = [math]::Round($JsonFile.Length / 1KB, 1)
                    FindingCount = $TotalFindings
                    OperatingSystem = ""
                    SystemType = "Unknown"
                    Domain = ""
                    LastBootTime = ""
                }
            }
            
            # Extract additional system details (only for system audit files)
            if (-not $IsDarkWebFile) {
                if ($AuditData.system_context -and $AuditData.system_context.os_info) {
                    $SystemInfo.OperatingSystem = $AuditData.system_context.os_info.caption
                    $SystemInfo.Domain = $AuditData.system_context.domain
                    $SystemInfo.LastBootTime = $AuditData.system_context.os_info.last_boot_time
                }

                # Determine system type from server roles or OS
                if ($AuditData.system_context.os_info.caption -like "*Server*") {
                    $SystemInfo.SystemType = "Server"
                } else {
                    $SystemInfo.SystemType = "Workstation"
                }
            }
            
            # Add system to collection
            $Result.Systems += $SystemInfo
            $Result.SystemCount++
            
            # Process findings based on file type
            if ($IsDarkWebFile) {
                # Process dark web results (limit to max 10 results as requested)
                $DarkWebFindings = $AuditData.Results | Where-Object { $_.Item -like "*Domain Breach*" } | Select-Object -First 10

                foreach ($Finding in $DarkWebFindings) {
                    $EnrichedFinding = [PSCustomObject]@{
                        Category = $Finding.Category
                        Item = $Finding.Item
                        Value = $Finding.Value
                        Details = $Finding.Details
                        RiskLevel = $Finding.RiskLevel
                        Recommendation = $Finding.Recommendation
                        SystemName = "Dark Web Check"
                        SystemType = "Breach Monitor"
                        AuditDate = $SystemInfo.AuditTimestamp
                        FindingId = "DW-$(Get-Random)"
                        Framework = "Dark Web"
                    }

                    $Result.AllFindings += $EnrichedFinding
                    $Result.FindingCount++
                }
            } else {
                # Process system audit findings - handle both old and new formats
                if ($AuditData.compliance_framework.findings) {
                    # Old format: compliance_framework.findings array
                    foreach ($Finding in $AuditData.compliance_framework.findings) {
                        if (-not $Finding.category -or -not $Finding.item) {
                            Write-Verbose "Skipping finding with missing category or item in $($JsonFile.Name)"
                            continue
                        }

                        $EnrichedFinding = [PSCustomObject]@{
                            Category = if ($Finding.category) { [string]$Finding.category } else { "Unknown" }
                            Item = if ($Finding.item) { [string]$Finding.item } else { "Unknown" }
                            Value = ""
                            Details = if ($Finding.requirement) { [string]$Finding.requirement } else { "No details available" }
                            RiskLevel = if ($Finding.risk_level) { [string]$Finding.risk_level } else { "INFO" }
                            Recommendation = if ($Finding.requirement) { [string]$Finding.requirement } else { "No recommendation available" }
                            SystemName = if ($SystemInfo.ComputerName) { [string]$SystemInfo.ComputerName } else { "Unknown" }
                            SystemType = if ($SystemInfo.SystemType) { [string]$SystemInfo.SystemType } else { "Unknown" }
                            AuditDate = if ($SystemInfo.AuditTimestamp) { [string]$SystemInfo.AuditTimestamp } else { "Unknown" }
                            FindingId = if ($Finding.finding_id) { [string]$Finding.finding_id } else { "UNKNOWN-$(Get-Random)" }
                            Framework = if ($Finding.framework) { [string]$Finding.framework } else { "Unknown" }
                        }

                        $Result.AllFindings += $EnrichedFinding
                        $Result.FindingCount++
                    }
                } elseif ($AuditData.categories) {
                    # New format: categories with nested findings
                    $AuditData.categories.PSObject.Properties | ForEach-Object {
                        $CategoryName = $_.Name
                        $CategoryData = $_.Value

                        # Skip empty category names (audit tool bug)
                        if ([string]::IsNullOrWhiteSpace($CategoryName)) {
                            Write-Verbose "Skipping empty category name in $($JsonFile.Name)"
                            return
                        }

                        if ($CategoryData.findings) {
                            foreach ($Finding in $CategoryData.findings) {
                                # Skip findings with all null fields (corrupted data)
                                if ($null -eq $Finding.item_name -or
                                    [string]::IsNullOrWhiteSpace($Finding.item_name) -or
                                    ($null -eq $Finding.category -and $null -eq $Finding.details)) {
                                    Write-Verbose "Skipping finding with null/empty data in $($JsonFile.Name)"
                                    continue
                                }

                                try {
                                    # Convert value to string safely, handling integers and nulls
                                    $ValueString = ""
                                    if ($null -ne $Finding.value) {
                                        $ValueString = $Finding.value.ToString()
                                    }

                                    $EnrichedFinding = [PSCustomObject]@{
                                        Category = if ($Finding.category) { $Finding.category.ToString() } else { $CategoryName }
                                        Item = $Finding.item_name.ToString()
                                        Value = $ValueString
                                        Details = if ($Finding.details) { $Finding.details.ToString() } else { "No details available" }
                                        RiskLevel = if ($Finding.risk_level) { $Finding.risk_level.ToString() } else { "INFO" }
                                        Recommendation = if ($Finding.recommendation_note) { $Finding.recommendation_note.ToString() } else { "" }
                                        SystemName = if ($SystemInfo.ComputerName) { $SystemInfo.ComputerName.ToString() } else { "Unknown" }
                                        SystemType = if ($SystemInfo.SystemType) { $SystemInfo.SystemType.ToString() } else { "Unknown" }
                                        AuditDate = if ($SystemInfo.AuditTimestamp) { $SystemInfo.AuditTimestamp.ToString() } else { "Unknown" }
                                        FindingId = if ($Finding.id) { $Finding.id.ToString() } else { "UNKNOWN-$(Get-Random)" }
                                        Framework = "WindowsAudit"
                                    }

                                    $Result.AllFindings += $EnrichedFinding
                                    $Result.FindingCount++
                                } catch {
                                    Write-Verbose "Skipping finding due to property error in $($JsonFile.Name): $($_.Exception.Message)"
                                    continue
                                }
                            }
                        }
                    }
                }
            }
            
            $Result.ImportedFiles += $JsonFile.Name
            if ($IsDarkWebFile) {
                Write-Verbose "  > Imported $($DarkWebFindings.Count) dark web findings"
            } else {
                Write-Verbose "  > Imported $($SystemInfo.FindingCount) findings from $($SystemInfo.ComputerName)"
            }
            
        }
        catch {
            Write-Warning "Failed to process $($JsonFile.Name): $($_.Exception.Message)"
            Write-Verbose "Error details: $($_.ScriptStackTrace)"
            $Result.Errors += "Processing error: $($JsonFile.Name) - $($_.Exception.Message)"
        }
    }
    
    # Generate summary statistics
    if ($Result.SystemCount -gt 0) {
        $Result | Add-Member -NotePropertyName "RiskSummary" -NotePropertyValue @{
            HighRisk = ($Result.AllFindings | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
            MediumRisk = ($Result.AllFindings | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count  
            LowRisk = ($Result.AllFindings | Where-Object { $_.RiskLevel -eq "LOW" }).Count
            Info = ($Result.AllFindings | Where-Object { $_.RiskLevel -eq "INFO" }).Count
        }
        
        $Result | Add-Member -NotePropertyName "CategoryBreakdown" -NotePropertyValue (
            $Result.AllFindings | Group-Object Category | 
            ForEach-Object { [PSCustomObject]@{ Category = $_.Name; Count = $_.Count } }
        )
        
        Write-Verbose "Risk Summary: HIGH=$($Result.RiskSummary.HighRisk), MEDIUM=$($Result.RiskSummary.MediumRisk), LOW=$($Result.RiskSummary.LowRisk), INFO=$($Result.RiskSummary.Info)"
    }
    
    return $Result
}

# [ANALYSIS] Generate-RiskAnalysis - Risk assessment and scoring
# Dependencies: Import-AuditData
# Order: 20
# NetworkAuditAggregator - Risk Analysis Generator
# Version 1.0.0

function Generate-RiskAnalysis {
    <#
    .SYNOPSIS
        Generates color-coded risk analysis matching client report format
        
    .DESCRIPTION
        Analyzes consolidated findings to create risk-based sections with
        specific recommendations, similar to the "High Risk" and "Low Risk" 
        sections in professional client reports.
        
    .PARAMETER ImportedData
        Consolidated audit data from Import-AuditData
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$ImportedData
    )
    
    Write-Verbose "Generating risk analysis from $($ImportedData.FindingCount) findings"
    
    # Initialize risk analysis structure
    $RiskAnalysis = [PSCustomObject]@{
        HighRiskFindings = @()
        MediumRiskFindings = @()
        LowRiskFindings = @()
        SystemsSnapshot = @()
        RiskSummary = @{
            TotalRisks = 0
            CriticalSystems = 0
            ImmediateActions = 0
        }
    }
    
    # Process HIGH risk findings
    $HighRiskItems = $ImportedData.AllFindings | Where-Object { $_.RiskLevel -eq "HIGH" } |
        Group-Object Category, Item | 
        ForEach-Object {
            $Finding = $_.Group[0]
            $AffectedSystems = $_.Group | Select-Object -Unique SystemName
            
            [PSCustomObject]@{
                RiskFactor = $Finding.Item
                Category = $Finding.Category  
                Description = $Finding.Details
                Recommendation = $Finding.Recommendation
                AffectedCount = $AffectedSystems.Count
                AffectedSystems = ($AffectedSystems.SystemName -join ", ")
                Severity = "Critical"
            }
        } | Sort-Object AffectedCount -Descending
    
    $RiskAnalysis.HighRiskFindings = $HighRiskItems
    
    # Process MEDIUM risk findings  
    $MediumRiskItems = $ImportedData.AllFindings | Where-Object { $_.RiskLevel -eq "MEDIUM" } |
        Group-Object Category, Item |
        ForEach-Object {
            $Finding = $_.Group[0]
            $AffectedSystems = $_.Group | Select-Object -Unique SystemName
            
            [PSCustomObject]@{
                RiskFactor = $Finding.Item
                Category = $Finding.Category
                Description = $Finding.Details  
                Recommendation = $Finding.Recommendation
                AffectedCount = $AffectedSystems.Count
                AffectedSystems = ($AffectedSystems.SystemName -join ", ")
                Severity = "Moderate"
            }
        } | Sort-Object AffectedCount -Descending | Select-Object -First 10
    
    $RiskAnalysis.MediumRiskFindings = $MediumRiskItems
    
    # Process LOW risk findings (informational)
    $LowRiskItems = $ImportedData.AllFindings | Where-Object { $_.RiskLevel -eq "LOW" } |
        Group-Object Category, Item |
        ForEach-Object {
            $Finding = $_.Group[0]
            $AffectedSystems = $_.Group | Select-Object -Unique SystemName
            
            [PSCustomObject]@{
                RiskFactor = $Finding.Item
                Category = $Finding.Category
                Description = $Finding.Details
                Recommendation = $Finding.Recommendation  
                AffectedCount = $AffectedSystems.Count
                AffectedSystems = ($AffectedSystems.SystemName -join ", ")
                Severity = "Low"
            }
        } | Sort-Object AffectedCount -Descending | Select-Object -First 5
    
    $RiskAnalysis.LowRiskFindings = $LowRiskItems
    
    # Generate Systems Snapshot (similar to Computer Snapshot table)
    # Exclude dark web checks - only include actual computer systems
    $ActualSystems = $ImportedData.Systems | Where-Object { $_.SystemType -ne "Breach Monitor" }
    foreach ($System in $ActualSystems) {
        $SystemFindings = $ImportedData.AllFindings | Where-Object { $_.SystemName -eq $System.ComputerName }
        
        # Calculate grades for each category
        $Grades = @{
            Security = Get-SystemGrade -Findings ($SystemFindings | Where-Object { $_.Category -eq "Security" })
            Users = Get-SystemGrade -Findings ($SystemFindings | Where-Object { $_.Category -eq "Users" })
            Network = Get-SystemGrade -Findings ($SystemFindings | Where-Object { $_.Category -eq "Network" })
            Patching = Get-SystemGrade -Findings ($SystemFindings | Where-Object { $_.Category -eq "Patching" })
            System = Get-SystemGrade -Findings ($SystemFindings | Where-Object { $_.Category -eq "System" })
        }
        
        # Calculate overall grade
        $OverallGrade = Get-OverallGrade -Grades $Grades
        
        $SystemSnapshot = [PSCustomObject]@{
            ComputerName = $System.ComputerName
            OverallGrade = $OverallGrade
            SecurityGrade = $Grades.Security
            UsersGrade = $Grades.Users  
            NetworkGrade = $Grades.Network
            PatchingGrade = $Grades.Patching
            SystemGrade = $Grades.System
            OperatingSystem = $System.OperatingSystem
            SystemType = $System.SystemType
            HighRiskCount = ($SystemFindings | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
            MediumRiskCount = ($SystemFindings | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
            FindingsCount = $SystemFindings.Count
        }
        
        $RiskAnalysis.SystemsSnapshot += $SystemSnapshot
    }
    
    # Calculate risk summary
    $RiskAnalysis.RiskSummary = @{
        TotalRisks = $RiskAnalysis.HighRiskFindings.Count + $RiskAnalysis.MediumRiskFindings.Count
        CriticalSystems = ($RiskAnalysis.SystemsSnapshot | Where-Object { $_.OverallGrade -in @("C", "D", "F") }).Count
        ImmediateActions = $RiskAnalysis.HighRiskFindings.Count
        SystemsNeedingAttention = ($RiskAnalysis.SystemsSnapshot | Where-Object { $_.HighRiskCount -gt 0 }).Count
    }
    
    Write-Verbose "Risk analysis completed: $($RiskAnalysis.HighRiskFindings.Count) high-risk, $($RiskAnalysis.MediumRiskFindings.Count) medium-risk findings"
    
    return $RiskAnalysis
}

function Get-SystemGrade {
    <#
    .SYNOPSIS
        Calculates letter grade (A-F) for a system category based on risk findings
    #>
    param([array]$Findings)
    
    if (-not $Findings -or $Findings.Count -eq 0) { return "A" }
    
    $HighRisk = ($Findings | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
    $MediumRisk = ($Findings | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
    $TotalFindings = $Findings.Count
    
    # Grading based on risk distribution
    if ($HighRisk -gt 0) {
        if ($HighRisk -ge 3) { return "F" }
        elseif ($HighRisk -eq 2) { return "D" } 
        else { return "C" }
    }
    elseif ($MediumRisk -gt 0) {
        if ($MediumRisk -ge 3) { return "C" }
        elseif ($MediumRisk -eq 2) { return "B" }
        else { return "B" }
    }
    else {
        return "A"
    }
}

function Get-OverallGrade {
    <#
    .SYNOPSIS  
        Calculates overall system grade from category grades
    #>
    param([hashtable]$Grades)
    
    $GradeValues = @{ "A" = 4; "B" = 3; "C" = 2; "D" = 1; "F" = 0 }
    $GradeLetters = @{ 4 = "A"; 3 = "B"; 2 = "C"; 1 = "D"; 0 = "F" }
    
    $TotalValue = 0
    $GradeCount = 0
    
    foreach ($Grade in $Grades.Values) {
        $TotalValue += $GradeValues[$Grade]
        $GradeCount++
    }
    
    if ($GradeCount -eq 0) { return "A" }
    
    $Average = [math]::Round($TotalValue / $GradeCount)
    return $GradeLetters[$Average]
}

# [ANALYSIS] Generate-ScoringMatrix - Scoring matrix generation
# Dependencies: Generate-RiskAnalysis
# Order: 21
# NetworkAuditAggregator - Scoring Matrix Generator  
# Version 1.0.0

function Generate-ScoringMatrix {
    <#
    .SYNOPSIS
        Generates component-based scoring matrix similar to client report format
        
    .DESCRIPTION
        Analyzes audit findings to create scoring matrix with criticality levels
        and adherence ratings (1-5 scale) matching professional report format.
        
    .PARAMETER ImportedData
        Consolidated audit data from Import-AuditData
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$ImportedData
    )
    
    Write-Verbose "Generating scoring matrix for $($ImportedData.SystemCount) systems"
    
    # Initialize scoring components
    $ScoringComponents = @()
    
    # Network Infrastructure Component
    $NetworkFindings = $ImportedData.AllFindings | Where-Object { $_.Category -eq "Network" }
    $NetworkRisks = $NetworkFindings | Where-Object { $_.RiskLevel -in @("HIGH", "MEDIUM") }
    $NetworkAdherence = Get-AdherenceScore -TotalFindings $NetworkFindings.Count -RiskFindings $NetworkRisks.Count
    
    $ScoringComponents += [PSCustomObject]@{
        Component = "Network Infrastructure"
        SectionCriticality = "High"
        ClientAdherence = $NetworkAdherence
        Overview = "Network security, firewall configuration, and infrastructure hardening"
        Details = if ($NetworkRisks.Count -gt 0) { "Issues found: $($NetworkRisks.Count) network risks identified" } else { "$($NetworkFindings.Count) network findings assessed, no high/medium risks" }
    }
    
    # Desktop/User Infrastructure Component  
    $UserFindings = $ImportedData.AllFindings | Where-Object { $_.Category -eq "Users" }
    $UserRisks = $UserFindings | Where-Object { $_.RiskLevel -in @("HIGH", "MEDIUM") }
    $UserAdherence = Get-AdherenceScore -TotalFindings $UserFindings.Count -RiskFindings $UserRisks.Count
    
    $AdminIssues = $UserFindings | Where-Object { $_.Item -like "*Administrator*" -and $_.RiskLevel -in @("HIGH", "MEDIUM") }
    $ScoringComponents += [PSCustomObject]@{
        Component = "Desktop/User Infrastructure" 
        SectionCriticality = "High"
        ClientAdherence = $UserAdherence
        Overview = "User account management, administrative privileges, and access control"
        Details = if ($AdminIssues.Count -gt 0) { "Administrator account issues on $($AdminIssues.Count) systems" }
                  else { "$($UserFindings.Count) user account findings assessed, no high/medium risks" }
    }
    
    # Security Component
    $SecurityFindings = $ImportedData.AllFindings | Where-Object { $_.Category -eq "Security" }  
    $SecurityRisks = $SecurityFindings | Where-Object { $_.RiskLevel -in @("HIGH", "MEDIUM") }
    $SecurityAdherence = Get-AdherenceScore -TotalFindings $SecurityFindings.Count -RiskFindings $SecurityRisks.Count
    
    $AntivirusIssues = $SecurityFindings | Where-Object { $_.Item -like "*Antivirus*" -or $_.Item -like "*Anti-virus*" }
    $ScoringComponents += [PSCustomObject]@{
        Component = "Security Controls"
        SectionCriticality = "High"  
        ClientAdherence = $SecurityAdherence
        Overview = "Antivirus protection, security software, and threat detection capabilities"
        Details = if ($AntivirusIssues.Count -gt 0) { "Antivirus configuration requires attention" }
                  else { "$($SecurityFindings.Count) security findings assessed, no high/medium risks" }
    }
    
    # Patch Management Component
    $PatchFindings = $ImportedData.AllFindings | Where-Object { $_.Category -eq "Patching" }
    $PatchRisks = $PatchFindings | Where-Object { $_.RiskLevel -in @("HIGH", "MEDIUM") }
    $PatchAdherence = Get-AdherenceScore -TotalFindings $PatchFindings.Count -RiskFindings $PatchRisks.Count
    
    $ScoringComponents += [PSCustomObject]@{
        Component = "Patch Management"
        SectionCriticality = "High"
        ClientAdherence = $PatchAdherence  
        Overview = "Operating system updates, security patches, and software currency"
        Details = if ($PatchRisks.Count -gt 0) { "$($PatchRisks.Count) systems need critical updates" }
                  else { "$($PatchFindings.Count) patch findings assessed, no high/medium risks" }
    }
    
    # Management Infrastructure Component
    $SystemFindings = $ImportedData.AllFindings | Where-Object { $_.Category -eq "System" }
    $SystemRisks = $SystemFindings | Where-Object { $_.RiskLevel -in @("HIGH", "MEDIUM") }
    $ManagementAdherence = Get-AdherenceScore -TotalFindings $SystemFindings.Count -RiskFindings $SystemRisks.Count
    
    $ScoringComponents += [PSCustomObject]@{
        Component = "Management Infrastructure"
        SectionCriticality = "High"
        ClientAdherence = $ManagementAdherence
        Overview = "System monitoring, centralized management, and operational oversight"  
        Details = "Centralized management capabilities assessed across $($ImportedData.SystemCount) systems"
    }
    
    # Applications Component
    $SoftwareFindings = $ImportedData.AllFindings | Where-Object { $_.Category -eq "Software" }
    $SoftwareRisks = $SoftwareFindings | Where-Object { $_.RiskLevel -in @("HIGH", "MEDIUM") }
    $ApplicationAdherence = Get-AdherenceScore -TotalFindings $SoftwareFindings.Count -RiskFindings $SoftwareRisks.Count
    
    $RemoteAccessTools = $SoftwareFindings | Where-Object { $_.Details -like "*remote access*" -or $_.Item -like "*TeamViewer*" -or $_.Item -like "*AnyDesk*" }
    $ScoringComponents += [PSCustomObject]@{
        Component = "Applications"
        SectionCriticality = "Medium"
        ClientAdherence = $ApplicationAdherence
        Overview = "Software inventory, remote access tools, and application management"
        Details = if ($RemoteAccessTools.Count -gt 0) { "Remote access software detected on $($RemoteAccessTools.Count) systems" }
                  else { "Application inventory completed" }
    }
    
    # Calculate overall score
    $OverallScore = [math]::Round(($ScoringComponents | Measure-Object ClientAdherence -Average).Average, 1)
    
    $ScoringMatrix = [PSCustomObject]@{
        OverallScore = $OverallScore
        Components = $ScoringComponents
        ScoreDistribution = @{
            Excellent = ($ScoringComponents | Where-Object { $_.ClientAdherence -eq 5 }).Count
            Good = ($ScoringComponents | Where-Object { $_.ClientAdherence -eq 4 }).Count  
            Fair = ($ScoringComponents | Where-Object { $_.ClientAdherence -eq 3 }).Count
            Poor = ($ScoringComponents | Where-Object { $_.ClientAdherence -eq 2 }).Count
            Critical = ($ScoringComponents | Where-Object { $_.ClientAdherence -eq 1 }).Count
        }
    }
    
    Write-Verbose "Scoring matrix completed: Overall score $OverallScore/5.0"
    
    return $ScoringMatrix
}

function Get-AdherenceScore {
    <#
    .SYNOPSIS
        Calculates adherence score (1-5) based on risk findings ratio
    #>
    param(
        [int]$TotalFindings,
        [int]$RiskFindings
    )
    
    if ($TotalFindings -eq 0) { return 5 }
    
    $RiskRatio = $RiskFindings / $TotalFindings
    
    switch ($true) {
        ($RiskRatio -eq 0) { return 5 }      # No risks - Excellent
        ($RiskRatio -le 0.1) { return 4 }    # ≤10% risks - Good  
        ($RiskRatio -le 0.3) { return 3 }    # ≤30% risks - Fair
        ($RiskRatio -le 0.6) { return 2 }    # ≤60% risks - Poor
        default { return 1 }                  # >60% risks - Critical
    }
}

# [REPORTING] Generate-ExecutiveSummary - Executive-level summary generation
# Dependencies: Import-AuditData
# Order: 30
# NetworkAuditAggregator - Executive Summary Generator
# Version 1.0.0

function Generate-ExecutiveSummary {
    <#
    .SYNOPSIS
        Generates executive-level summary of IT assessment findings
        
    .DESCRIPTION
        Analyzes consolidated audit data to produce high-level metrics, 
        key findings, and priority recommendations suitable for executive reporting.
        
    .PARAMETER ImportedData
        Consolidated audit data from Import-AuditData
        
    .PARAMETER ClientName
        Client name for report customization
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$ImportedData,
        
        [Parameter(Mandatory = $true)]
        [string]$ClientName
    )
    
    Write-Verbose "Generating executive summary for $($ImportedData.SystemCount) systems"
    
    # Environment Overview Analysis (separate computers from dark web checks)
    $WorkstationCount = ($ImportedData.Systems | Where-Object { $_.SystemType -like "*Workstation*" }).Count
    $ServerCount = ($ImportedData.Systems | Where-Object { $_.SystemType -like "*Server*" }).Count
    $DarkWebChecks = ($ImportedData.Systems | Where-Object { $_.SystemType -eq "Breach Monitor" }).Count
    $DomainControllers = ($ImportedData.AllFindings | Where-Object { $_.Category -eq "System" -and $_.Item -eq "Server Roles" -and $_.Value -like "*Domain Controller*" }).Count

    # Systems assessed = computers only (exclude dark web checks)
    $ComputerCount = $WorkstationCount + $ServerCount

    # Initialize summary object
    $Summary = [PSCustomObject]@{
        ClientName = $ClientName
        AssessmentDate = (Get-Date).ToString("MMMM yyyy")
        SystemsAssessed = $ComputerCount
        TotalFindings = $ImportedData.FindingCount
        RiskDistribution = $ImportedData.RiskSummary
        KeyFindings = @()
        PriorityRecommendations = @()
        EnvironmentOverview = @{}
        TechnicalHighlights = @{}
        SecurityStrengths = @()
        PositiveFindings = @{}
    }

    $Summary.EnvironmentOverview = @{
        TotalSystems = $ImportedData.SystemCount
        Workstations = $WorkstationCount
        Servers = $ServerCount
        DarkWebChecks = $DarkWebChecks
        DomainControllers = $DomainControllers
        AssessmentScope = "$ComputerCount computers ($WorkstationCount workstations, $ServerCount servers)" + $(if ($DarkWebChecks -gt 0) { " + $DarkWebChecks dark web check(s)" } else { "" })
    }
    
    # Key Findings Analysis (HIGH and MEDIUM risk items)
    $CriticalFindings = $ImportedData.AllFindings | Where-Object { $_.RiskLevel -in @("HIGH", "MEDIUM") } | 
        Group-Object Category, Item | 
        ForEach-Object {
            [PSCustomObject]@{
                Category = $_.Group[0].Category
                Issue = $_.Group[0].Item
                AffectedSystems = $_.Count
                RiskLevel = $_.Group[0].RiskLevel
                Description = $_.Group[0].Details
                Recommendation = $_.Group[0].Recommendation
            }
        } | Sort-Object { if ($_.RiskLevel -eq "HIGH") { 1 } else { 2 } }, AffectedSystems -Descending
    
    $Summary.KeyFindings = $CriticalFindings | Select-Object -First 10
    
    # Technical Highlights
    $SecurityFindings = $ImportedData.AllFindings | Where-Object { $_.Category -in @("Security", "Users", "Network") }
    $PatchFindings = $ImportedData.AllFindings | Where-Object { $_.Category -eq "Patching" -and $_.RiskLevel -eq "HIGH" }
    $SoftwareFindings = $ImportedData.AllFindings | Where-Object { $_.Category -eq "Software" }
    $DarkWebFindings = $ImportedData.AllFindings | Where-Object { $_.Category -eq "Dark Web Analysis" -and $_.Item -like "*Domain Breach*" }
    
    $Summary.TechnicalHighlights = @{
        SecurityIssues = $SecurityFindings.Count
        CriticalPatches = $PatchFindings.Count
        SoftwareInventory = $SoftwareFindings.Count
        DarkWebBreaches = $DarkWebFindings.Count
        SystemsWithAdminIssues = ($ImportedData.AllFindings | Where-Object {
            $_.Category -eq "Users" -and $_.Item -like "*Administrator*" -and $_.RiskLevel -in @("HIGH", "MEDIUM")
        } | Select-Object -Unique SystemName).Count
        NetworkRisks = ($ImportedData.AllFindings | Where-Object {
            $_.Category -eq "Network" -and $_.RiskLevel -eq "HIGH"
        }).Count
    }

    # Security Strengths Analysis - ONLY REAL FINDINGS, NO FABRICATION
    $PositiveFindings = $ImportedData.AllFindings | Where-Object { $_.RiskLevel -in @("LOW", "INFO") }

    # CRITICAL: Only show findings that actually exist in the audit data
    # NO pattern matching, NO inference, NO fabrication
    $SecurityStrengths = @()

    # Convert positive findings directly to security strengths with exact details from audit
    foreach ($Finding in $PositiveFindings) {
        # Only include findings that represent positive security configurations
        $IsSecurityStrength = $false
        $StrengthCategory = ""

        switch ($Finding.Category) {
            "Security" {
                if ($Finding.Item -match "FileVault|XProtect|Gatekeeper|Firewall|System Integrity Protection|Find My") {
                    $IsSecurityStrength = $true
                    $StrengthCategory = "Security Controls"
                }
            }
            "Patching" {
                if ($Finding.Item -match "Automatic Updates|Available Updates" -and $Finding.Details -notmatch "disabled|failed|error") {
                    $IsSecurityStrength = $true
                    $StrengthCategory = "Update Management"
                }
            }
            "Management" {
                if ($Finding.Item -match "MDM Enrollment" -and $Finding.Details -notmatch "not enrolled|disabled") {
                    $IsSecurityStrength = $true
                    $StrengthCategory = "Device Management"
                }
            }
            "Dark Web Analysis" {
                if ($Finding.Item -match "No.*breach|Clean" -or ($Finding.RiskLevel -eq "INFO" -and $Finding.Details -notmatch "breach.*found")) {
                    $IsSecurityStrength = $true
                    $StrengthCategory = "Threat Intelligence"
                }
            }
        }

        if ($IsSecurityStrength) {
            $SecurityStrengths += [PSCustomObject]@{
                Category = $StrengthCategory
                Strength = $Finding.Item
                Details = $Finding.Details  # EXACT details from audit, no modification
                SystemCount = 1
                OriginalFinding = $Finding  # Keep reference to source
            }
        }
    }

    # Remove duplicates and limit to top 10
    $Summary.SecurityStrengths = $SecurityStrengths | Sort-Object Category, Strength | Select-Object -First 10

    $Summary.PositiveFindings = @{
        TotalPositiveFindings = $PositiveFindings.Count
        SecurityStrengthsFound = $SecurityStrengths.Count
        StrengthCategories = ($SecurityStrengths | Group-Object Category).Count
    }

    # Priority Recommendations (based on risk level and system impact)
    $RecommendationPriorities = @()
    
    # High-impact recommendations based on findings
    if ($Summary.RiskDistribution.HighRisk -gt 0) {
        $RecommendationPriorities += [PSCustomObject]@{
            Priority = 1
            Category = "Critical Security"
            Recommendation = "Address $($Summary.RiskDistribution.HighRisk) high-risk security findings immediately"
            Timeframe = "1-2 weeks"
            Impact = "High"
            AffectedSystems = ($ImportedData.AllFindings | Where-Object { $_.RiskLevel -eq "HIGH" } | Select-Object -Unique SystemName).Count
        }
    }
    
    if ($PatchFindings.Count -gt 0) {
        $RecommendationPriorities += [PSCustomObject]@{
            Priority = 2  
            Category = "Patch Management"
            Recommendation = "Deploy critical security updates to $($PatchFindings.Count) systems"
            Timeframe = "2-4 weeks"
            Impact = "High"
            AffectedSystems = ($PatchFindings | Select-Object -Unique SystemName).Count
        }
    }
    
    if ($Summary.TechnicalHighlights.SystemsWithAdminIssues -gt 0) {
        $RecommendationPriorities += [PSCustomObject]@{
            Priority = 3
            Category = "Access Management"  
            Recommendation = "Review administrator account configurations on $($Summary.TechnicalHighlights.SystemsWithAdminIssues) systems"
            Timeframe = "1-3 weeks"
            Impact = "Medium"
            AffectedSystems = $Summary.TechnicalHighlights.SystemsWithAdminIssues
        }
    }
    
    if ($Summary.RiskDistribution.MediumRisk -gt 10) {
        $RecommendationPriorities += [PSCustomObject]@{
            Priority = 4
            Category = "IT Hygiene"
            Recommendation = "Address $($Summary.RiskDistribution.MediumRisk) medium-risk findings for improved security posture"
            Timeframe = "1-2 months"
            Impact = "Medium"
            AffectedSystems = ($ImportedData.AllFindings | Where-Object { $_.RiskLevel -eq "MEDIUM" } | Select-Object -Unique SystemName).Count
        }
    }
    
    $Summary.PriorityRecommendations = $RecommendationPriorities
    
    Write-Verbose "Executive summary generated: $($Summary.KeyFindings.Count) key findings, $($Summary.SecurityStrengths.Count) security strengths, $($Summary.PriorityRecommendations.Count) priority recommendations"
    
    return $Summary
}

# [EXPORT] Export-RawDataJSON - Raw JSON data export
# Dependencies: Import-AuditData
# Order: 40
# WindowsWorkstationAuditor - Raw Data JSON Export Module
# Version 1.3.0

function Export-RawDataJSON {
    <#
    .SYNOPSIS
        Exports comprehensive audit data to structured JSON for aggregation tools
        
    .DESCRIPTION
        Creates a detailed JSON export with complete data structures, raw collections,
        metadata, and standardized schema for use by aggregation and analysis tools.
        
    .PARAMETER Results
        Array of audit results from modules
        
    .PARAMETER RawData
        Hashtable of raw data collections from modules (optional)
        
    .PARAMETER OutputPath
        Directory path for the JSON output
        
    .PARAMETER BaseFileName
        Base filename for the export (without extension)
    #>
    param(
        [array]$Results,
        [hashtable]$RawData = @{},
        [string]$OutputPath,
        [string]$BaseFileName
    )
    
    if (-not $Results -or $Results.Count -eq 0) {
        Write-LogMessage "WARN" "No results to export to raw JSON" "EXPORT"
        return
    }
    
    $JSONPath = Join-Path $OutputPath "${BaseFileName}_raw_data.json"
    
    try {
        # Build comprehensive data structure
        $AuditData = [ordered]@{
            metadata = [ordered]@{
                tool_name = "WindowsWorkstationAuditor"
                tool_version = "1.3.0"
                schema_version = "1.0"
                computer_name = $env:COMPUTERNAME
                audit_timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                audit_duration_seconds = if ($Script:StartTime) { ((Get-Date) - $Script:StartTime).TotalSeconds } else { 0 }
                total_findings = $Results.Count
            }
            
            risk_summary = [ordered]@{
                high_risk_count = ($Results | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
                medium_risk_count = ($Results | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
                low_risk_count = ($Results | Where-Object { $_.RiskLevel -eq "LOW" }).Count
                info_count = ($Results | Where-Object { $_.RiskLevel -eq "INFO" }).Count
                recommendation_findings = ($Results | Where-Object { $_.Recommendation -and $_.Recommendation.Trim() -ne "" }).Count
            }
            
            categories = [ordered]@{}
            
            raw_collections = [ordered]@{}
            
            recommendation_framework = [ordered]@{
                primary = "NIST"
                findings = @()
            }
        }
        
        # Process results by category
        $Categories = $Results | Group-Object Category
        
        foreach ($Category in $Categories) {
            $CategoryName = $Category.Name
            $CategoryItems = $Category.Group
            
            $AuditData.categories[$CategoryName] = [ordered]@{
                total_items = $CategoryItems.Count
                risk_breakdown = [ordered]@{
                    high = ($CategoryItems | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
                    medium = ($CategoryItems | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
                    low = ($CategoryItems | Where-Object { $_.RiskLevel -eq "LOW" }).Count
                    info = ($CategoryItems | Where-Object { $_.RiskLevel -eq "INFO" }).Count
                }
                findings = @()
            }
            
            # Add each finding with enhanced structure
            foreach ($Item in $CategoryItems) {
                $Finding = [ordered]@{
                    id = [System.Guid]::NewGuid().ToString()
                    item_name = $Item.Item
                    value = $Item.Value
                    details = $Item.Details
                    risk_level = $Item.RiskLevel
                    recommendation_note = $Item.Recommendation
                    category = $Item.Category
                    timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                }
                
                $AuditData.categories[$CategoryName].findings += $Finding
                
                # Add to recommendation findings if applicable
                if ($Item.Recommendation -and $Item.Recommendation.Trim() -ne "") {
                    $RecommendationFinding = [ordered]@{
                        finding_id = $Finding.id
                        framework = "NIST"
                        recommendation = $Item.Recommendation
                        category = $CategoryName
                        item = $Item.Item
                        risk_level = $Item.RiskLevel
                    }
                    $AuditData.recommendation_framework.findings += $RecommendationFinding
                }
            }
        }
        
        # Add raw data collections if provided
        foreach ($DataType in $RawData.Keys) {
            $AuditData.raw_collections[$DataType] = $RawData[$DataType]
        }
        
        # Add system context data
        $AuditData.system_context = [ordered]@{
            powershell_version = $PSVersionTable.PSVersion.ToString()
            execution_policy = (Get-ExecutionPolicy).ToString()
            current_user = $env:USERNAME
            domain = $env:USERDOMAIN
            os_info = [ordered]@{}
        }
        
        # Try to get OS information
        try {
            $OS = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
            if ($OS) {
                $AuditData.system_context.os_info = [ordered]@{
                    caption = $OS.Caption
                    version = $OS.Version
                    build_number = $OS.BuildNumber
                    architecture = $OS.OSArchitecture
                    install_date = if ($OS.InstallDate) { $OS.InstallDate.ToString("yyyy-MM-ddTHH:mm:ss.fffZ") } else { $null }
                    last_boot_time = if ($OS.LastBootUpTime) { $OS.LastBootUpTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ") } else { $null }
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve OS information for JSON export: $($_.Exception.Message)" "EXPORT"
        }
        
        # Export with proper formatting
        $JSONContent = $AuditData | ConvertTo-Json -Depth 10 -Compress:$false
        $JSONContent | Set-Content -Path $JSONPath -Encoding UTF8
        
        Write-LogMessage "SUCCESS" "Raw data JSON exported: $JSONPath" "EXPORT"
        return $JSONPath
    }
    catch {
        Write-LogMessage "ERROR" "Failed to export raw JSON: $($_.Exception.Message)" "EXPORT"
        return $null
    }
}

function Add-RawDataCollection {
    <#
    .SYNOPSIS
        Helper function for modules to register raw data collections
        
    .DESCRIPTION
        Allows audit modules to register detailed data collections that should
        be included in the raw JSON export for aggregation tools.
        
    .PARAMETER CollectionName
        Name of the data collection
        
    .PARAMETER Data
        Raw data to be included in export
        
    .PARAMETER Global:RawDataCollections
        Global hashtable to store collections (created if doesn't exist)
    #>
    param(
        [string]$CollectionName,
        [object]$Data
    )
    
    if (-not (Get-Variable -Name "RawDataCollections" -Scope Global -ErrorAction SilentlyContinue)) {
        $Global:RawDataCollections = @{}
    }
    
    $Global:RawDataCollections[$CollectionName] = $Data
    Write-LogMessage "INFO" "Added raw data collection: $CollectionName ($($Data.Count) items)" "EXPORT"
}

# [EXPORT] Export-MarkdownReport - Markdown report generation
# Dependencies: Generate-ExecutiveSummary
# Order: 41
# WindowsWorkstationAuditor - Markdown Report Export Module
# Version 1.3.0

function Export-MarkdownReport {
    <#
    .SYNOPSIS
        Exports audit results to a technician-friendly markdown report
        
    .DESCRIPTION
        Creates a comprehensive markdown report with executive summary,
        detailed findings, action items, and full data visibility for technicians.
        
    .PARAMETER Results
        Array of audit results to include in the report
        
    .PARAMETER OutputPath
        Directory path for the markdown report output
        
    .PARAMETER BaseFileName
        Base filename for the report (without extension)
    #>
    param(
        [array]$Results,
        [string]$OutputPath,
        [string]$BaseFileName
    )

    if (-not $Results -or $Results.Count -eq 0) {
        Write-LogMessage "WARN" "No results to export to markdown report" "EXPORT"
        return
    }

    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        Write-LogMessage "ERROR" "OutputPath is null or empty - cannot create report" "EXPORT"
        throw "OutputPath parameter is required but was null or empty"
    }

    $ReportPath = Join-Path $OutputPath "${BaseFileName}_technician_report.md"
    
    try {
        # Build report content
        $ReportContent = @()
        
        # Header
        #region Report Header Generation
        # Auto-detect if this is a server audit based on results content or OS type
        $IsServerAudit = $false
        
        # Method 1: Check if server-specific results are present
        $ServerIndicators = @("Server Roles", "DHCP", "DNS", "Active Directory")
        $HasServerResults = $Results | Where-Object { $_.Category -in $ServerIndicators }
        
        # Method 2: Check OS type via WMI
        try {
            $OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
            $IsWindowsServer = $OSInfo.ProductType -ne 1  # ProductType: 1=Workstation, 2=DC, 3=Server
        }
        catch {
            $IsWindowsServer = $false
        }
        
        # Determine audit type
        $IsServerAudit = ($HasServerResults.Count -gt 0) -or $IsWindowsServer
        
        # Generate appropriate header
        if ($IsServerAudit) {
            $ReportContent += "# Windows Server IT Assessment Report"
            $ReportTitle = "WindowsServerAuditor v1.3.0"
        } else {
            $ReportContent += "# Windows Workstation Security Audit Report" 
            $ReportTitle = "WindowsWorkstationAuditor v1.3.0"
        }
        
        $ReportContent += ""
        $ReportContent += "**Computer:** $env:COMPUTERNAME"
        $ReportContent += "**Generated:** $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        $ReportContent += "**Tool Version:** $ReportTitle"
        #endregion
        $ReportContent += ""
        
        # Executive Summary
        $HighRisk = $Results | Where-Object { $_.RiskLevel -eq "HIGH" }
        $MediumRisk = $Results | Where-Object { $_.RiskLevel -eq "MEDIUM" }
        $LowRisk = $Results | Where-Object { $_.RiskLevel -eq "LOW" }
        $InfoItems = $Results | Where-Object { $_.RiskLevel -eq "INFO" }
        
        $ReportContent += "## Executive Summary"
        $ReportContent += ""
        $ReportContent += "| Risk Level | Count | Priority |"
        $ReportContent += "|------------|--------|----------|"
        $ReportContent += "| HIGH | $($HighRisk.Count) | Immediate Action Required |"
        $ReportContent += "| MEDIUM | $($MediumRisk.Count) | Review and Plan Remediation |"
        $ReportContent += "| LOW | $($LowRisk.Count) | Monitor and Maintain |"
        $ReportContent += "| INFO | $($InfoItems.Count) | Informational |"
        $ReportContent += ""

        # Security Strengths Section (GREEN indicators for positive findings)
        if ($LowRisk.Count -gt 0 -or $InfoItems.Count -gt 0) {
            $ReportContent += "## Security Strengths"
            $ReportContent += ""
            $ReportContent += "> **Positive security findings and properly configured systems**"
            $ReportContent += ""

            # Group positive findings by category
            $PositiveFindings = $LowRisk + $InfoItems
            $StrengthsByCategory = $PositiveFindings | Group-Object Category | Sort-Object Name

            foreach ($CategoryGroup in $StrengthsByCategory) {
                $CategoryName = $CategoryGroup.Name
                $CategoryCount = $CategoryGroup.Count

                $ReportContent += "### $CategoryName ($CategoryCount findings)"
                $ReportContent += ""

                # Show actual system findings from audit data only
                if ($CategoryName -eq "System") {
                    $TopFindings = $CategoryGroup.Group | Select-Object -First 3
                    foreach ($Finding in $TopFindings) {
                        $ReportContent += "- **$($Finding.Item)**: $($Finding.Details)"
                    }
                }
                elseif ($CategoryName -eq "Patching") {
                    # Show actual patching findings from audit data only
                    $TopFindings = $CategoryGroup.Group | Select-Object -First 3
                    foreach ($Finding in $TopFindings) {
                        $ReportContent += "- **$($Finding.Item)**: $($Finding.Details)"
                    }
                }
                elseif ($CategoryName -eq "Dark Web Analysis") {
                    # Show actual dark web findings from audit data only
                    $TopFindings = $CategoryGroup.Group | Select-Object -First 3
                    foreach ($Finding in $TopFindings) {
                        $ReportContent += "- **$($Finding.Item)**: $($Finding.Details)"
                    }
                }
                else {
                    # Show top 3 positive findings for other categories
                    $TopFindings = $CategoryGroup.Group | Select-Object -First 3
                    foreach ($Finding in $TopFindings) {
                        $ReportContent += "- **$($Finding.Item)**: $($Finding.Details)"
                    }
                }
                $ReportContent += ""
            }

            $ReportContent += "---"
            $ReportContent += ""
        }
        
        # Critical Action Items
        if ($HighRisk.Count -gt 0 -or $MediumRisk.Count -gt 0) {
            $ReportContent += "## Critical Action Items"
            $ReportContent += ""
            
            if ($HighRisk.Count -gt 0) {
                $ReportContent += "### HIGH PRIORITY (Immediate Action Required)"
                $ReportContent += ""
                foreach ($Item in $HighRisk) {
                    $ReportContent += "- **$($Item.Category) - $($Item.Item):** $($Item.Value)"
                    $ReportContent += "  - Details: $($Item.Details)"
                    if ($Item.Recommendation) {
                        $ReportContent += "  - Recommendation: $($Item.Recommendation)"
                    }
                    $ReportContent += ""
                }
            }
            
            if ($MediumRisk.Count -gt 0) {
                $ReportContent += "### MEDIUM PRIORITY (Review and Plan)"
                $ReportContent += ""
                foreach ($Item in $MediumRisk) {
                    $ReportContent += "- **$($Item.Category) - $($Item.Item):** $($Item.Value)"
                    $ReportContent += "  - Details: $($Item.Details)"
                    if ($Item.Recommendation) {
                        $ReportContent += "  - Recommendation: $($Item.Recommendation)"
                    }
                    $ReportContent += ""
                }
            }
        }
        
        # Additional Information (LOW and INFO items only, excluding Security Events to avoid repetition)
        $AdditionalItems = $Results | Where-Object { $_.RiskLevel -in @("LOW", "INFO") -and $_.Category -ne "Security Events" }
        $AdditionalCategories = $AdditionalItems | Group-Object Category | Sort-Object Name
        
        if ($AdditionalCategories.Count -gt 0) {
            $ReportContent += "## Additional Information"
            $ReportContent += ""
            
            foreach ($Category in $AdditionalCategories) {
                $CategoryName = $Category.Name
                $CategoryItems = $Category.Group
                
                $ReportContent += "### $CategoryName"
                $ReportContent += ""
                
                foreach ($Item in $CategoryItems) {
                    $RiskIcon = switch ($Item.RiskLevel) {
                        "LOW" { "[LOW]" }
                        default { "[INFO]" }
                    }
                    
                    $ReportContent += "**$RiskIcon $($Item.Item):** $($Item.Value)"
                    $ReportContent += ""
                    $ReportContent += "- **Details:** $($Item.Details)"
                    if ($Item.Recommendation) {
                        $ReportContent += "- **Recommendation:** $($Item.Recommendation)"
                    }
                    $ReportContent += ""
                }
            }
        }
        
        # System Information Section with Enhanced Details
        $SystemInfo = $Results | Where-Object { $_.Category -eq "System" }
        if ($SystemInfo) {
            $ReportContent += "## System Configuration Details"
            $ReportContent += ""
            foreach ($Item in $SystemInfo) {
                $ReportContent += "- **$($Item.Item):** $($Item.Value) - $($Item.Details)"
            }
            $ReportContent += ""
        }
        
        # Recommendation Summary
        $RecommendationItems = $Results | Where-Object { $_.Recommendation -and $_.Recommendation.Trim() -ne "" }
        if ($RecommendationItems.Count -gt 0) {
            $ReportContent += "## Recommendations"
            $ReportContent += ""
            $RecommendationItems | Group-Object Recommendation | ForEach-Object {
                $ReportContent += "- **$($_.Name)**"
                $ReportContent += "  - Affected Items: $($_.Count)"
                $ReportContent += ""
            }
        }
        
        # Footer
        $ReportContent += "---"
        $ReportContent += ""
        $ReportContent += "*This report was generated by WindowsWorkstationAuditor v1.3.0*"
        $ReportContent += ""
        $ReportContent += "*For detailed data analysis and aggregation, refer to the corresponding JSON export.*"
        
        # Write report to file
        $ReportContent | Set-Content -Path $ReportPath -Encoding UTF8
        
        Write-LogMessage "SUCCESS" "Markdown report exported: $ReportPath" "EXPORT"
        return $ReportPath
    }
    catch {
        Write-LogMessage "ERROR" "Failed to export markdown report: $($_.Exception.Message)" "EXPORT"
        return $null
    }
}

# [EXPORT] Export-ClientReport - Client-ready report export
# Dependencies: Generate-ExecutiveSummary, Export-MarkdownReport
# Order: 42
# NetworkAuditAggregator - Client Report Export
# Version 1.0.0

function Export-ClientReport {
    <#
    .SYNOPSIS
        Exports consolidated analysis to professional HTML report
        
    .DESCRIPTION
        Generates client-ready HTML report with executive summary, scoring matrix,
        and risk analysis sections matching professional consulting format.
        
    .PARAMETER ExecutiveSummary
        Executive summary data from Generate-ExecutiveSummary
        
    .PARAMETER ScoringMatrix
        Scoring matrix data from Generate-ScoringMatrix
        
    .PARAMETER RiskAnalysis
        Risk analysis data from Generate-RiskAnalysis
        
    .PARAMETER OutputPath
        Directory for generated report
        
    .PARAMETER ClientName
        Client name for report customization
    #>
    
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$ExecutiveSummary,
        
        [Parameter(Mandatory = $true)] 
        [PSCustomObject]$ScoringMatrix,
        
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$RiskAnalysis,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $true)]
        [string]$ClientName
    )
    
    # Ensure output directory exists
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    # Generate report filename
    $ReportDate = Get-Date -Format "yyyy-MM-dd"
    $SafeClientName = $ClientName -replace '[^\w\s-]', '' -replace '\s+', '-'
    $ReportFileName = "$SafeClientName-IT-Assessment-Report-$ReportDate.html"
    $ReportPath = Join-Path $OutputPath $ReportFileName
    
    Write-Verbose "Generating client report: $ReportFileName"
    
    # Generate HTML content
    $HtmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$ClientName - IT Assessment Report</title>
    <style>
        $(Get-ReportStyles)
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>$ClientName</h1>
            <h2>IT Assessment & Recommendations</h2>
            <p class="report-date">$($ExecutiveSummary.AssessmentDate)</p>
        </div>
        
        <!-- Executive Summary -->
        <div class="section">
            <h2 class="section-header">Executive Summary</h2>
            
            <div class="summary-metrics">
                <div class="metric-box">
                    <div class="metric-value">$($ExecutiveSummary.SystemsAssessed)</div>
                    <div class="metric-label">Systems Assessed</div>
                </div>
                <div class="metric-box high-risk">
                    <div class="metric-value">$($ExecutiveSummary.RiskDistribution.HighRisk)</div>
                    <div class="metric-label">High Risk</div>
                </div>
                <div class="metric-box medium-risk">
                    <div class="metric-value">$($ExecutiveSummary.RiskDistribution.MediumRisk)</div>
                    <div class="metric-label">Medium Risk</div>
                </div>
                <div class="metric-box low-risk">
                    <div class="metric-value">$($ExecutiveSummary.RiskDistribution.LowRisk)</div>
                    <div class="metric-label">Low Risk</div>
                </div>
            </div>
            
            <div class="environment-overview">
                <h3>Environment Overview</h3>
                $(
                    $ScopeDetails = @()
                    if ($ExecutiveSummary.EnvironmentOverview.Workstations -gt 0) { $ScopeDetails += "$($ExecutiveSummary.EnvironmentOverview.Workstations) workstations" }
                    if ($ExecutiveSummary.EnvironmentOverview.Servers -gt 0) { $ScopeDetails += "$($ExecutiveSummary.EnvironmentOverview.Servers) servers" }
                    if ($ExecutiveSummary.EnvironmentOverview.DarkWebChecks -gt 0) { $ScopeDetails += "dark web analysis" }
                    $ScopeText = if ($ScopeDetails.Count -gt 0) { $ScopeDetails -join ', ' } else { "systems" }
                    "<p><strong>Assessment Scope:</strong> $ScopeText</p>"
                )
                <p><strong>Total Findings:</strong> $($ExecutiveSummary.TotalFindings) items identified across all systems</p>
                <p><strong>Priority Actions:</strong> $($ExecutiveSummary.PriorityRecommendations.Count) immediate recommendations</p>
            </div>

            <!-- Security Strengths Section -->
            $(if ($ExecutiveSummary.SecurityStrengths -and $ExecutiveSummary.SecurityStrengths.Count -gt 0) { @"
            <div class="security-strengths">
                <h3 style="color: #28a745; display: flex; align-items: center;">
                    Security Strengths
                </h3>
                <div style="background: linear-gradient(135deg, #e8f5e8 0%, #f0f9f0 100%); border-left: 4px solid #28a745; padding: 15px; border-radius: 8px; margin: 10px 0;">
                    <p style="margin-bottom: 15px; color: #155724;"><strong>Positive security findings and properly configured systems</strong></p>
                    $(
                        # Group security strengths by category for scalability
                        $StrengthGroups = $ExecutiveSummary.SecurityStrengths | Group-Object Category
                        ($StrengthGroups | ForEach-Object {
                            $CategoryName = $_.Name
                            $Items = $_.Group
                            $ItemCount = $Items.Count

                            "<div style='margin-bottom: 15px; padding: 10px; background: rgba(40, 167, 69, 0.1); border-radius: 4px;'>" +
                            "<strong style='color: #28a745;'>$CategoryName ($ItemCount items):</strong><br>" +
                            "<ul style='margin: 5px 0; padding-left: 20px; color: #155724;'>" +
                            (($Items | Select-Object -First 5 | ForEach-Object { "<li>$($_.Strength)</li>" }) -join "") +
                            $(if ($ItemCount -gt 5) { "<li style='color: #6c757d;'><em>... and $($ItemCount - 5) more</em></li>" } else { "" }) +
                            "</ul>" +
                            "</div>"
                        }) -join ""
                    )
                    <p style="margin-top: 15px; margin-bottom: 0; color: #28a745; font-weight: bold;">
                        $($ExecutiveSummary.PositiveFindings.TotalPositiveFindings) total positive findings identified
                    </p>
                </div>
            </div>
"@ })
        </div>
        
        <!-- Scoring Summary -->
        <div class="section">
            <h2 class="section-header">Scoring Summary</h2>
            <div class="scoring-note">
                <p><strong>Client Adherence Rating Scale:</strong></p>
                <ul>
                    <li>5 - Adhere to the best practice</li>
                    <li>4 - Strong adherence, minimal gaps identified</li>
                    <li>3 - Adhere in some areas, but not all</li>
                    <li>2 - Limited adherence to the best practice(s), several gaps identified</li>
                    <li>1 - No adherence to the best practice(s)</li>
                </ul>
            </div>
            
            <table class="scoring-table">
                <thead>
                    <tr>
                        <th>Component</th>
                        <th>Section Criticality</th>
                        <th>Client Adherence</th>
                        <th>Overview</th>
                    </tr>
                </thead>
                <tbody>
                    $(Generate-ScoringTableRows -Components $ScoringMatrix.Components)
                </tbody>
            </table>
        </div>
        
        <!-- Risk Analysis -->
        <div class="section">
            <h2 class="section-header">Risk Analysis</h2>
            
            $(Generate-RiskSection -Title "High Risk" -Color "high-risk" -Findings $RiskAnalysis.HighRiskFindings)
            
            $(Generate-RiskSection -Title "Medium Risk" -Color "medium-risk" -Findings $RiskAnalysis.MediumRiskFindings)
            
            $(Generate-RiskSection -Title "Low Risk" -Color "low-risk" -Findings $RiskAnalysis.LowRiskFindings)
        </div>
        
        <!-- Systems Snapshot -->
        <div class="section">
            <h2 class="section-header">Systems Overview</h2>
            <table class="systems-table">
                <thead>
                    <tr>
                        <th>Computer</th>
                        <th>Overall Grade</th>
                        <th>Security</th>
                        <th>Users</th>
                        <th>Network</th>
                        <th>Patching</th>
                        <th>System</th>
                        <th>High Risk Items</th>
                    </tr>
                </thead>
                <tbody>
                    $(Generate-SystemsTableRows -Systems $RiskAnalysis.SystemsSnapshot)
                </tbody>
            </table>
        </div>
        
        <!-- Priority Recommendations -->
        <div class="section">
            <h2 class="section-header">Priority Recommendations</h2>
            <table class="recommendations-table">
                <thead>
                    <tr>
                        <th>Priority</th>
                        <th>Category</th>
                        <th>Recommendation</th>
                        <th>Timeframe</th>
                        <th>Impact</th>
                    </tr>
                </thead>
                <tbody>
                    $(Generate-RecommendationsTableRows -Recommendations $ExecutiveSummary.PriorityRecommendations)
                </tbody>
            </table>
        </div>
        
        <div class="footer">
            <p>Report generated on $(Get-Date -Format 'MMMM dd, yyyy') by BusinessNetworkAggregator v1.0.0</p>
        </div>
    </div>
</body>
</html>
"@
    
    # Write HTML file
    $HtmlContent | Set-Content -Path $ReportPath -Encoding UTF8
    
    Write-Verbose "Report exported to: $ReportPath"
    return $ReportPath
}

function Get-ReportStyles {
    return @"
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        .header { text-align: center; padding: 40px 20px; background: #2c3e50; color: white; }
        .header h1 { margin: 0; font-size: 2.5em; font-weight: 300; }
        .header h2 { margin: 10px 0; font-size: 1.4em; font-weight: 300; opacity: 0.9; }
        .report-date { margin: 20px 0 0 0; font-size: 1.1em; opacity: 0.8; }
        
        .section { padding: 30px; border-bottom: 1px solid #eee; }
        .section-header { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; margin-bottom: 20px; }
        
        .summary-metrics { display: flex; gap: 20px; margin: 20px 0; flex-wrap: wrap; }
        .metric-box { flex: 1; text-align: center; padding: 20px; border-radius: 8px; min-width: 120px; }
        .metric-box { background: #ecf0f1; }
        .metric-box.high-risk { background: #e74c3c; color: white; }
        .metric-box.medium-risk { background: #f39c12; color: white; }
        .metric-box.low-risk { background: #f1c40f; }
        .metric-value { font-size: 2.5em; font-weight: bold; margin-bottom: 5px; }
        .metric-label { font-size: 0.9em; opacity: 0.8; }
        
        .environment-overview { background: #f8f9fa; padding: 20px; border-radius: 8px; margin-top: 20px; }
        .environment-overview h3 { margin-top: 0; color: #2c3e50; }
        
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border: 1px solid #ddd; }
        th { background: #34495e; color: white; font-weight: 600; }
        tr:nth-child(even) { background: #f8f9fa; }
        
        .risk-section { margin: 30px 0; }
        .risk-header { padding: 15px; border-radius: 8px 8px 0 0; color: white; font-weight: bold; font-size: 1.2em; }
        .risk-header.high-risk { background: #e74c3c; }
        .risk-header.medium-risk { background: #f39c12; }
        .risk-header.low-risk { background: #f1c40f; color: #2c3e50; }
        .risk-content { border: 1px solid #ddd; border-top: none; padding: 20px; background: white; }
        .risk-item { margin-bottom: 20px; padding-bottom: 15px; border-bottom: 1px solid #eee; }
        .risk-item:last-child { border-bottom: none; }
        .risk-title { font-weight: bold; color: #2c3e50; margin-bottom: 5px; }
        .risk-description { margin-bottom: 10px; color: #666; }
        .risk-recommendation { background: #e8f4f8; padding: 10px; border-radius: 4px; font-style: italic; }
        
        .systems-table th, .systems-table td { text-align: center; padding: 8px; }
        .grade-A { background: #2ecc71; color: white; font-weight: bold; }
        .grade-B { background: #3498db; color: white; font-weight: bold; }
        .grade-C { background: #f39c12; color: white; font-weight: bold; }
        .grade-D { background: #e67e22; color: white; font-weight: bold; }
        .grade-F { background: #e74c3c; color: white; font-weight: bold; }
        
        .footer { text-align: center; padding: 20px; background: #ecf0f1; color: #7f8c8d; font-size: 0.9em; }
        
        @media print {
            .container { box-shadow: none; }
            .section { page-break-inside: avoid; }
        }
"@
}

function Generate-ScoringTableRows {
    param([array]$Components)
    
    $rows = ""
    foreach ($component in $Components) {
        $adherenceClass = "adherence-$($component.ClientAdherence)"
        $rows += @"
        <tr>
            <td><strong>$($component.Component)</strong></td>
            <td>$($component.SectionCriticality)</td>
            <td class="$adherenceClass"><strong>$($component.ClientAdherence)</strong></td>
            <td>$($component.Overview)<br><small style="color: #666;">$($component.Details)</small></td>
        </tr>
"@
    }
    return $rows
}

function Generate-RiskSection {
    param([string]$Title, [string]$Color, [array]$Findings)
    
    if ($Findings.Count -eq 0) { return "" }
    
    $content = @"
    <div class="risk-section">
        <div class="risk-header $Color">$Title</div>
        <div class="risk-content">
"@
    
    foreach ($finding in $Findings) {
        $content += @"
            <div class="risk-item">
                <div class="risk-title">$($finding.RiskFactor)</div>
                <div class="risk-description">$($finding.Description)</div>
                <div class="risk-recommendation"><strong>Recommendation:</strong> $($finding.Recommendation)</div>
                <small><strong>Affected Systems ($($finding.AffectedCount)):</strong> $($finding.AffectedSystems)</small>
            </div>
"@
    }
    
    $content += @"
        </div>
    </div>
"@
    
    return $content
}

function Generate-SystemsTableRows {
    param([array]$Systems)
    
    $rows = ""
    foreach ($system in $Systems) {
        $rows += @"
        <tr>
            <td><strong>$($system.ComputerName)</strong><br><small>$($system.OperatingSystem)</small></td>
            <td class="grade-$($system.OverallGrade)">$($system.OverallGrade)</td>
            <td class="grade-$($system.SecurityGrade)">$($system.SecurityGrade)</td>
            <td class="grade-$($system.UsersGrade)">$($system.UsersGrade)</td>
            <td class="grade-$($system.NetworkGrade)">$($system.NetworkGrade)</td>
            <td class="grade-$($system.PatchingGrade)">$($system.PatchingGrade)</td>
            <td class="grade-$($system.SystemGrade)">$($system.SystemGrade)</td>
            <td>$($system.HighRiskCount)</td>
        </tr>
"@
    }
    return $rows
}

function Generate-RecommendationsTableRows {
    param([array]$Recommendations)
    
    $rows = ""
    foreach ($rec in $Recommendations) {
        $priorityClass = if ($rec.Priority -eq 1) { "high-risk" } elseif ($rec.Priority -le 2) { "medium-risk" } else { "low-risk" }
        $rows += @"
        <tr>
            <td class="$priorityClass" style="text-align: center; font-weight: bold; color: white;">$($rec.Priority)</td>
            <td><strong>$($rec.Category)</strong></td>
            <td>$($rec.Recommendation)</td>
            <td>$($rec.Timeframe)</td>
            <td>$($rec.Impact)</td>
        </tr>
"@
    }
    return $rows
}

# [SYSTEM] Get-SystemInformation - System hardware and OS information
# Dependencies: Write-LogMessage
# Order: 100
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

# [SYSTEM] Get-DiskSpaceAnalysis - Disk space utilization analysis
# Dependencies: Write-LogMessage
# Order: 101
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

# [SYSTEM] Get-MemoryAnalysis - Memory utilization analysis
# Dependencies: Write-LogMessage
# Order: 102
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

# [SYSTEM] Get-ProcessAnalysis - Running process analysis
# Dependencies: Write-LogMessage
# Order: 103
# WindowsWorkstationAuditor - Process Analysis Module
# Version 1.3.0

function Get-ProcessAnalysis {
    <#
    .SYNOPSIS
        Analyzes running processes, services, and startup programs
        
    .DESCRIPTION
        Collects comprehensive process information including running processes,
        system services, startup programs, and identifies potential security risks
        based on process characteristics and known threat indicators.
        
    .OUTPUTS
        Array of PSCustomObjects with Category, Item, Value, Details, RiskLevel, Recommendation
        
    .NOTES
        Requires: Write-LogMessage function
        Permissions: Local user (process enumeration, service access)
    #>
    
    Write-LogMessage "INFO" "Analyzing processes, services, and startup programs..." "PROCESS"
    
    try {
        $Results = @()
        
        # Get running processes with detailed information
        try {
            $Processes = Get-Process | Sort-Object CPU -Descending
            $ProcessCount = $Processes.Count
            $SystemProcesses = $Processes | Where-Object { $_.ProcessName -match "^(System|Registry|smss|csrss|wininit|winlogon|services|lsass|lsm|svchost|dwm|explorer)$" }
            $UserProcesses = $Processes | Where-Object { $_.ProcessName -notmatch "^(System|Registry|smss|csrss|wininit|winlogon|services|lsass|lsm|svchost|dwm|explorer)$" }
            
            $Results += [PSCustomObject]@{
                Category = "Processes"
                Item = "Process Summary"
                Value = "$ProcessCount total processes"
                Details = "System processes: $($SystemProcesses.Count), User processes: $($UserProcesses.Count)"
                RiskLevel = "INFO"
                Recommendation = ""
            }
            
            Write-LogMessage "INFO" "Process analysis: $ProcessCount total processes" "PROCESS"
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve process information: $($_.Exception.Message)" "PROCESS"
        }
        
        # Analyze system services
        try {
            $Services = Get-Service
            $RunningServices = $Services | Where-Object { $_.Status -eq "Running" }
            $StoppedServices = $Services | Where-Object { $_.Status -eq "Stopped" }
            $StartupServices = $Services | Where-Object { $_.StartType -eq "Automatic" }
            
            $Results += [PSCustomObject]@{
                Category = "Services"
                Item = "Service Summary"
                Value = "$($Services.Count) total services"
                Details = "Running: $($RunningServices.Count), Stopped: $($StoppedServices.Count), Auto-start: $($StartupServices.Count)"
                RiskLevel = "INFO"
                Recommendation = ""
            }
            
            # Check for critical security services
            $SecurityServices = @(
                @{Name = "Windows Defender Antivirus Service"; ServiceName = "WinDefend"},
                @{Name = "Windows Security Center"; ServiceName = "wscsvc"},
                @{Name = "Windows Firewall"; ServiceName = "MpsSvc"},
                @{Name = "Base Filtering Engine"; ServiceName = "BFE"},
                @{Name = "DNS Client"; ServiceName = "Dnscache"}
            )
            
            foreach ($SecurityService in $SecurityServices) {
                $ServiceName = $SecurityService.ServiceName
                $DisplayName = $SecurityService.Name
                $Service = $Services | Where-Object { $_.Name -eq $ServiceName }
                
                if ($Service) {
                    $ServiceStatus = $Service.Status
                    $ServiceRisk = if ($ServiceStatus -ne "Running") { "HIGH" } else { "LOW" }
                    $ServiceRecommendation = if ($ServiceStatus -ne "Running") {
                        "Critical security service should be running"
                    } else { "" }
                    
                    $Results += [PSCustomObject]@{
                        Category = "Services"
                        Item = "$DisplayName"
                        Value = $ServiceStatus
                        Details = "Critical security service ($ServiceName)"
                        RiskLevel = $ServiceRisk
                        Recommendation = ""
                    }
                    
                    Write-LogMessage "INFO" "Security service $DisplayName`: $ServiceStatus" "PROCESS"
                } else {
                    $Results += [PSCustomObject]@{
                        Category = "Services"
                        Item = "$DisplayName"
                        Value = "Not Found"
                        Details = "Critical security service ($ServiceName) not found"
                        RiskLevel = "MEDIUM"
                        Recommendation = "Security service not found - may indicate system compromise"
                    }
                    
                    Write-LogMessage "WARN" "Security service not found: $DisplayName" "PROCESS"
                }
            }
            
            Write-LogMessage "INFO" "Service analysis: $($Services.Count) total, $($RunningServices.Count) running" "PROCESS"
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve service information: $($_.Exception.Message)" "PROCESS"
        }
        
        # Analyze startup programs
        try {
            # Check registry startup locations - system-wide and user-specific
            $StartupLocations = @(
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
            )
            
            # Add user-specific entries only if not running as SYSTEM
            if ($env:USERNAME -ne "SYSTEM") {
                $StartupLocations += @(
                    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
                )
            } else {
                Write-LogMessage "INFO" "Running as SYSTEM - checking system-wide startup entries only" "PROCESS"
            }
            
            $StartupPrograms = @()
            foreach ($Location in $StartupLocations) {
                try {
                    $RegItems = Get-ItemProperty -Path $Location -ErrorAction SilentlyContinue
                    if ($RegItems) {
                        $RegItems.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
                            $StartupPrograms += [PSCustomObject]@{
                                Name = $_.Name
                                Command = $_.Value
                                Location = $Location
                            }
                        }
                    }
                }
                catch {
                    Write-LogMessage "WARN" "Could not access startup location: $Location" "PROCESS"
                }
            }
            
            # Check startup folder (may be empty in system context)
            try {
                $StartupFolder = [System.Environment]::GetFolderPath("Startup")
                $CommonStartupFolder = [System.Environment]::GetFolderPath("CommonStartup")
                
                $StartupFiles = @()
                if ($StartupFolder -and (Test-Path $StartupFolder)) {
                    $StartupFiles += Get-ChildItem -Path $StartupFolder -File -ErrorAction SilentlyContinue
                }
                if ($CommonStartupFolder -and (Test-Path $CommonStartupFolder)) {
                    $StartupFiles += Get-ChildItem -Path $CommonStartupFolder -File -ErrorAction SilentlyContinue
                }
                
                foreach ($File in $StartupFiles) {
                    $StartupPrograms += [PSCustomObject]@{
                        Name = $File.Name
                        Command = $File.FullName
                        Location = "Startup Folder"
                    }
                }
            }
            catch {
                Write-LogMessage "WARN" "Could not access startup folders: $($_.Exception.Message)" "PROCESS"
            }
            
            $StartupCount = $StartupPrograms.Count
            $StartupRisk = if ($StartupCount -gt 20) { "MEDIUM" } elseif ($StartupCount -gt 30) { "HIGH" } else { "LOW" }
            $StartupRecommendation = if ($StartupCount -gt 25) {
                "Large number of startup programs may impact boot time and security"
            } else { "" }
            
            $Results += [PSCustomObject]@{
                Category = "Startup"
                Item = "Startup Programs"
                Value = "$StartupCount programs configured"
                Details = "Registry entries and startup folder items"
                RiskLevel = $StartupRisk
                Recommendation = ""
            }
            
            # Check for startup entries from unusual locations
            $UnusualLocationStartup = $StartupPrograms | Where-Object {
                $_.Command -match "\\temp\\|\\tmp\\|\\appdata\\local\\temp\\|\\users\\public\\|\\downloads\\"
            }
            
            if ($UnusualLocationStartup.Count -gt 0) {
                foreach ($Unusual in ($UnusualLocationStartup | Select-Object -First 5)) {
                    $Results += [PSCustomObject]@{
                        Category = "Startup"
                        Item = "Startup from Unusual Location"
                        Value = $Unusual.Name
                        Details = "Running from: $($Unusual.Command). Programs should typically run from Program Files or system directories."
                        RiskLevel = "HIGH"
                        Recommendation = "Investigate startup programs from temporary or unusual locations"
                    }
                    
                    Write-LogMessage "WARN" "Startup from unusual location: $($Unusual.Name) - $($Unusual.Command)" "PROCESS"
                }
            }
            
            Write-LogMessage "INFO" "Startup analysis: $StartupCount programs, $($UnusualLocationStartup.Count) from unusual locations" "PROCESS"
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve startup program information: $($_.Exception.Message)" "PROCESS"
        }
        
        # System hardware information (factual, not performance snapshot)
        try {
            $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
            $TotalMemoryGB = [math]::Round($ComputerSystem.TotalPhysicalMemory / 1GB, 2)
            $ProcessorCount = $ComputerSystem.NumberOfLogicalProcessors

            $Results += [PSCustomObject]@{
                Category = "Performance"
                Item = "System Hardware"
                Value = "$TotalMemoryGB GB RAM"
                Details = "Total RAM: $TotalMemoryGB GB, Processors: $ProcessorCount, Active processes: $ProcessCount"
                RiskLevel = "INFO"
                Recommendation = ""
            }

            Write-LogMessage "INFO" "System hardware: $TotalMemoryGB GB RAM, $ProcessorCount processors" "PROCESS"
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve system hardware information: $($_.Exception.Message)" "PROCESS"
        }
        
        Write-LogMessage "SUCCESS" "Process analysis completed - $($Results.Count) items analyzed" "PROCESS"
        return $Results
    }
    catch {
        Write-LogMessage "ERROR" "Failed to analyze processes: $($_.Exception.Message)" "PROCESS"
        return @()
    }
}

# [INVENTORY] Get-SoftwareInventory - Installed software inventory
# Dependencies: Write-LogMessage
# Order: 110
# WindowsWorkstationAuditor - Software Inventory Module
# Version 1.3.0

function Get-SoftwareInventory {
    <#
    .SYNOPSIS
        Collects comprehensive software inventory from Windows registry

    .DESCRIPTION
        Performs detailed software inventory analysis including:
        - Installed program enumeration from both 32-bit and 64-bit registry locations
        - Critical software version checking (browsers, office suites, runtimes)
        - Software age analysis for update compliance
        - Installation date tracking for security assessment

    .OUTPUTS
        Array of PSCustomObjects with Category, Item, Value, Details, RiskLevel, Recommendation

    .NOTES
        Requires: Write-LogMessage function
        Permissions: Standard user rights sufficient for registry reading
        Coverage: Both 32-bit and 64-bit installed applications
    #>

    Write-LogMessage "INFO" "Collecting software inventory..." "SOFTWARE"

    try {
        $Software64 = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
                     Where-Object { $_.DisplayName -and $_.DisplayName -notlike "KB*" }

        $Software32 = Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
                     Where-Object { $_.DisplayName -and $_.DisplayName -notlike "KB*" }

        $AllSoftware = $Software64 + $Software32 | Sort-Object DisplayName -Unique

        $Results = @()

        # Software count summary
        $Results += [PSCustomObject]@{
            Category = "Software"
            Item = "Total Installed Programs"
            Value = $AllSoftware.Count
            Details = "Unique installed applications"
            RiskLevel = "INFO"
            Recommendation = ""
        }


        # Remote access software detection - simple prefix matching
        $RemoteAccessPrefixes = @(
            "TeamViewer",
            "AnyDesk",
            "Chrome Remote Desktop",
            "VNC Viewer",
            "RealVNC",
            "UltraVNC",
            "TightVNC",
            "LogMeIn Pro",
            "LogMeIn Client",
            "GoToMyPC",
            "Splashtop Streamer",
            "Splashtop Business",
            "Parsec",
            "Ammyy Admin",
            "SupRemo",
            "Radmin Viewer",
            "ScreenConnect Client",
            "BeyondTrust",
            "Bomgar",
            "Jump Desktop",
            "NoMachine",
            "DameWare",
            "pcAnywhere",
            "GoToAssist",
            "RemotePC",
            "Zoho Assist",
            "LiteManager"
        )

        $DetectedRemoteAccess = @()
        foreach ($Prefix in $RemoteAccessPrefixes) {
            $Found = $AllSoftware | Where-Object { $_.DisplayName -like "$Prefix*" }
            foreach ($App in $Found) {
                $InstallDate = if ($App.InstallDate) {
                    try { [datetime]::ParseExact($App.InstallDate, "yyyyMMdd", $null) } catch { $null }
                } else { $null }

                $DetectedRemoteAccess += [PSCustomObject]@{
                    DisplayName = $App.DisplayName
                    Version = $App.DisplayVersion
                    InstallDate = $InstallDate
                }

                $Results += [PSCustomObject]@{
                    Category = "Software"
                    Item = "Remote Access Software"
                    Value = "$($App.DisplayName) - $($App.DisplayVersion)"
                    Details = "Remote access software detected. Install date: $(if ($InstallDate) { $InstallDate.ToString('yyyy-MM-dd') } else { 'Unknown' }). Review business justification and security controls."
                    RiskLevel = "MEDIUM"
                    Recommendation = "Document and secure remote access tools"
                }
            }
        }

        if ($DetectedRemoteAccess.Count -gt 0) {
            Write-LogMessage "WARN" "Remote access software detected: $(($DetectedRemoteAccess | Select-Object -ExpandProperty DisplayName) -join ', ')" "SOFTWARE"
            Add-RawDataCollection -CollectionName "RemoteAccessSoftware" -Data $DetectedRemoteAccess
        } else {
            Write-LogMessage "INFO" "No remote access software detected" "SOFTWARE"
        }

        # RMM/Monitoring software detection - simple prefix matching
        $RMMPrefixes = @(
            "ConnectWise Automate",
            "ConnectWise Continuum",
            "NinjaOne",
            "NinjaRMM",
            "Kaseya",
            "Datto RMM",
            "CentraStage",
            "Atera Agent",
            "Syncro Agent",
            "Pulseway",
            "N-able",
            "N-central",
            "SolarWinds RMM",
            "ManageEngine",
            "Desktop Central",
            "Auvik",
            "PRTG",
            "WhatsUp Gold",
            "CrowdStrike",
            "Falcon Sensor",
            "SentinelOne",
            "Huntress",
            "Bitdefender GravityZone",
            "LogMeIn Central",
            "GoToAssist Corporate"
        )

        $DetectedRMM = @()
        foreach ($Prefix in $RMMPrefixes) {
            $Found = $AllSoftware | Where-Object { $_.DisplayName -like "$Prefix*" }
            foreach ($App in $Found) {
                $InstallDate = if ($App.InstallDate) {
                    try { [datetime]::ParseExact($App.InstallDate, "yyyyMMdd", $null) } catch { $null }
                } else { $null }

                $DetectedRMM += [PSCustomObject]@{
                    DisplayName = $App.DisplayName
                    Version = $App.DisplayVersion
                    InstallDate = $InstallDate
                }

                $Results += [PSCustomObject]@{
                    Category = "Software"
                    Item = "RMM/Monitoring Software"
                    Value = "$($App.DisplayName) - $($App.DisplayVersion)"
                    Details = "RMM/monitoring software detected. Install date: $(if ($InstallDate) { $InstallDate.ToString('yyyy-MM-dd') } else { 'Unknown' }). Review management authorization and security controls."
                    RiskLevel = "MEDIUM"
                    Recommendation = "Document and authorize remote monitoring tools"
                }
            }
        }

        if ($DetectedRMM.Count -gt 0) {
            Write-LogMessage "WARN" "RMM/monitoring software detected: $(($DetectedRMM | Select-Object -ExpandProperty DisplayName) -join ', ')" "SOFTWARE"
            Add-RawDataCollection -CollectionName "RMMSoftware" -Data $DetectedRMM
        } else {
            Write-LogMessage "INFO" "No RMM/monitoring software detected" "SOFTWARE"
        }

        # Add all software to raw data collection for detailed export
        $SoftwareList = @()
        foreach ($App in $AllSoftware) {
            $InstallDate = if ($App.InstallDate) {
                try { [datetime]::ParseExact($App.InstallDate, "yyyyMMdd", $null) } catch { $null }
            } else { $null }

            $SoftwareList += [PSCustomObject]@{
                Name = $App.DisplayName
                Version = $App.DisplayVersion
                Publisher = $App.Publisher
                InstallDate = if ($InstallDate) { $InstallDate.ToString('yyyy-MM-dd') } else { 'Unknown' }
                InstallLocation = $App.InstallLocation
                UninstallString = $App.UninstallString
                EstimatedSize = $App.EstimatedSize
            }
        }

        Add-RawDataCollection -CollectionName "InstalledSoftware" -Data $SoftwareList

        # Add a summary finding with software categories
        $Browsers = $AllSoftware | Where-Object { $_.DisplayName -match "Chrome|Firefox|Edge|Safari" }
        $DevTools = $AllSoftware | Where-Object { $_.DisplayName -match "Visual Studio|Git|Docker|Node" }
        $Office = $AllSoftware | Where-Object { $_.DisplayName -match "Office|Word|Excel|PowerPoint" }
        $Security = $AllSoftware | Where-Object { $_.DisplayName -match "Antivirus|McAfee|Norton|Symantec|Defender" }

        $Results += [PSCustomObject]@{
            Category = "Software"
            Item = "Software Categories"
            Value = "Full inventory available in raw data"
            Details = "Browsers: $($Browsers.Count), Dev Tools: $($DevTools.Count), Office: $($Office.Count), Security: $($Security.Count), Total: $($AllSoftware.Count)"
            RiskLevel = "INFO"
            Recommendation = ""
        }

        Write-LogMessage "SUCCESS" "Software inventory completed - $($AllSoftware.Count) programs found" "SOFTWARE"
        return $Results
    }
    catch {
        Write-LogMessage "ERROR" "Failed to collect software inventory: $($_.Exception.Message)" "SOFTWARE"
        return @()
    }
}


# [SECURITY] Get-PatchStatus - Windows Update and patch status
# Dependencies: Write-LogMessage
# Order: 120
# WindowsWorkstationAuditor - Patch Status Analysis Module
# Version 1.3.0

function Get-PatchStatus {
    <#
    .SYNOPSIS
        Analyzes Windows patch status with InProgress update detection
        
    .DESCRIPTION
        Performs comprehensive patch management analysis including:
        - Available Windows updates scanning via PSWindowsUpdate module
        - InProgress update detection (downloaded but requiring reboot)
        - Critical security update identification
        - System uptime analysis for restart requirements
        - Windows Update service configuration verification
        - Automatic update policy assessment
        - Recent hotfix installation history
        
    .OUTPUTS
        Array of PSCustomObjects with Category, Item, Value, Details, RiskLevel, Recommendation
        
    .NOTES
        Requires: Write-LogMessage function, PSWindowsUpdate module (auto-installed)
        Permissions: Local admin rights for complete patch analysis
        Dependencies: Windows Update service, PSWindowsUpdate PowerShell module
    #>
    
    Write-LogMessage "INFO" "Analyzing patch status with InProgress detection..." "PATCHES"
    
    try {
        $Results = @()
        
        # Install PSWindowsUpdate if needed - handle NuGet prompts automatically
        $PSWUAvailable = $false
        try {
            # SYSTEM/Service account fix: Add system profile module path if not already present
            # This applies to SYSTEM account and computer accounts (ending with $)
            if ($env:USERNAME -eq "SYSTEM" -or $env:USERNAME -like "*$") {
                $SystemModulePath = "$env:SystemRoot\system32\config\systemprofile\Documents\WindowsPowerShell\Modules"
                if ($env:PSModulePath -notlike "*$SystemModulePath*") {
                    $env:PSModulePath = "$env:PSModulePath;$SystemModulePath"
                    Write-LogMessage "INFO" "Added system profile module path to PSModulePath for account: $env:USERNAME" "PATCHES"
                }
            }

            if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
                Write-LogMessage "INFO" "Installing PSWindowsUpdate module..." "PATCHES"
                Set-ExecutionPolicy Bypass -Scope Process -Force
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

                # Install NuGet provider automatically to avoid prompts
                # Use AllUsers scope if running as SYSTEM or computer account, CurrentUser otherwise
                $InstallScope = if ($env:USERNAME -eq "SYSTEM" -or $env:USERNAME -like "*$") { "AllUsers" } else { "CurrentUser" }
                Write-LogMessage "INFO" "Installing NuGet and PSWindowsUpdate with scope: $InstallScope" "PATCHES"

                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope $InstallScope
                Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

                Install-Module PSWindowsUpdate -Force -Scope $InstallScope -SkipPublisherCheck
            }
            Import-Module PSWindowsUpdate -Force
            $PSWUAvailable = $true
            Write-LogMessage "SUCCESS" "PSWindowsUpdate module available" "PATCHES"
        }
        catch {
            Write-LogMessage "ERROR" "PSWindowsUpdate installation failed: $($_.Exception.Message)" "PATCHES"
        }
        
        if ($PSWUAvailable) {
            try {
                # Check for new available updates
                Write-LogMessage "INFO" "Scanning for available updates..." "PATCHES"
                $AvailableUpdates = @(Get-WindowsUpdate -MicrosoftUpdate -Verbose:$false -ErrorAction SilentlyContinue)
                Write-LogMessage "INFO" "Available updates to install: $($AvailableUpdates.Count)" "PATCHES"
                
                # Check update history for InProgress updates (downloaded but need reboot)
                Write-LogMessage "INFO" "Checking update history for InProgress updates..." "PATCHES"
                $UpdateHistory = Get-WUHistory -Last 30 -ErrorAction SilentlyContinue
                $InProgressUpdates = @($UpdateHistory | Where-Object { 
                    $_.Result -eq "InProgress" -and $_.Date -gt (Get-Date).AddDays(-30)
                })
                
                Write-LogMessage "INFO" "InProgress updates found: $($InProgressUpdates.Count)" "PATCHES"
                
                # Log the specific InProgress updates
                if ($InProgressUpdates.Count -gt 0) {
                    Write-LogMessage "WARN" "UPDATES REQUIRING REBOOT DETECTED:" "PATCHES"
                    foreach ($Update in $InProgressUpdates) {
                        Write-LogMessage "WARN" "  - NEEDS REBOOT: $($Update.Title)" "PATCHES"
                    }
                }
                
                # Analyze InProgress updates for criticality
                $CriticalInProgress = @($InProgressUpdates | Where-Object { 
                    $_.Title -match "Cumulative Update|Critical|Security Update"
                })
                
                # Check reboot status
                $RebootRequired = $false
                try {
                    $SystemInfo = New-Object -ComObject Microsoft.Update.SystemInfo
                    $RebootRequired = $SystemInfo.RebootRequired
                    Write-LogMessage "INFO" "System reboot required: $RebootRequired" "PATCHES"
                }
                catch {
                    $RebootRequired = $InProgressUpdates.Count -gt 0
                    Write-LogMessage "INFO" "Reboot required based on InProgress updates: $RebootRequired" "PATCHES"
                }
                
                # Main patch status report
                $TotalPending = $AvailableUpdates.Count + $InProgressUpdates.Count
                $StatusDetails = "Available: $($AvailableUpdates.Count), Downloaded/Pending Reboot: $($InProgressUpdates.Count)"
                
                $Results += [PSCustomObject]@{
                    Category = "Patches"
                    Item = "Update Status"
                    Value = "$TotalPending total"
                    Details = $StatusDetails
                    RiskLevel = if ($CriticalInProgress.Count -gt 0) { "HIGH" } elseif ($InProgressUpdates.Count -gt 0) { "HIGH" } elseif ($AvailableUpdates.Count -gt 0) { "MEDIUM" } else { "LOW" }
                    Recommendation = if ($CriticalInProgress.Count -gt 0) { "CRITICAL: Restart required for critical updates" } elseif ($InProgressUpdates.Count -gt 0) { "Restart required to complete updates" } else { "" }
                }
                
                # Critical updates requiring reboot
                if ($CriticalInProgress.Count -gt 0) {
                    $CriticalTitles = ($CriticalInProgress | Select-Object -First 2).Title -join "; "
                    $Results += [PSCustomObject]@{
                        Category = "Patches"
                        Item = "Critical Updates Awaiting Reboot"
                        Value = $CriticalInProgress.Count
                        Details = $CriticalTitles
                        RiskLevel = "HIGH"
                        Recommendation = "IMMEDIATE: Restart to complete critical security updates"
                    }
                }
                
                # Reboot required alert
                if ($RebootRequired -or $InProgressUpdates.Count -gt 0) {
                    $Results += [PSCustomObject]@{
                        Category = "Patches"
                        Item = "Reboot Required"
                        Value = "Yes"
                        Details = "System restart needed to complete $($InProgressUpdates.Count) updates"
                        RiskLevel = "HIGH"
                        Recommendation = "Restart system to complete update installation"
                    }
                }
                
                # Available updates (not yet downloaded)
                if ($AvailableUpdates.Count -gt 0) {
                    $Results += [PSCustomObject]@{
                        Category = "Patches"
                        Item = "Available Updates"
                        Value = "$($AvailableUpdates.Count) updates"
                        Details = "Updates available for download and installation"
                        RiskLevel = "MEDIUM"
                        Recommendation = "Install available updates within 30 days"
                    }
                }
                
                Write-LogMessage "SUCCESS" "Patch analysis complete - Available: $($AvailableUpdates.Count), InProgress: $($InProgressUpdates.Count), Critical InProgress: $($CriticalInProgress.Count)" "PATCHES"
                
            }
            catch {
                Write-LogMessage "ERROR" "PSWindowsUpdate patch analysis failed: $($_.Exception.Message)" "PATCHES"
            }
        } else {
            # Simple fallback when PSWindowsUpdate fails
            $Results += [PSCustomObject]@{
                Category = "Patches"
                Item = "Update Status"
                Value = "Module Failed"
                Details = "PSWindowsUpdate module could not be loaded - manual verification required"
                RiskLevel = "MEDIUM"
                Recommendation = "Manually verify patch status"
            }
        }
        
        # Get recent hotfixes (last 90 days)
        try {
            $RecentDate = (Get-Date).AddDays(-90)
            $RecentHotfixes = Get-HotFix | Where-Object { 
                $_.InstalledOn -and $_.InstalledOn -gt $RecentDate 
            } | Measure-Object
            
            $Results += [PSCustomObject]@{
                Category = "Patches"
                Item = "Recent Patches (90 days)"
                Value = $RecentHotfixes.Count
                Details = "Hotfixes installed in last 90 days"
                RiskLevel = if ($RecentHotfixes.Count -eq 0) { "HIGH" } elseif ($RecentHotfixes.Count -lt 5) { "MEDIUM" } else { "LOW" }
                Recommendation = if ($RecentHotfixes.Count -eq 0) { "No recent patches detected - verify update process" } else { "" }
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve recent hotfix information: $($_.Exception.Message)" "PATCHES"
            $Results += [PSCustomObject]@{
                Category = "Patches"
                Item = "Recent Patches (90 days)"
                Value = "Unknown"
                Details = "Could not retrieve hotfix history"
                RiskLevel = "MEDIUM"
                Recommendation = "Verify patch installation history"
            }
        }
        
        # Get last boot time (indicates recent patching activity)
        try {
            $OS = Get-CimInstance -ClassName Win32_OperatingSystem
            $LastBootTime = $OS.LastBootUpTime
            $UptimeDays = [math]::Round((New-TimeSpan -Start $LastBootTime -End (Get-Date)).TotalDays, 1)
            
            $Results += [PSCustomObject]@{
                Category = "Patches"
                Item = "System Uptime"
                Value = "$UptimeDays days"
                Details = "Last boot: $($LastBootTime.ToString('yyyy-MM-dd HH:mm:ss'))"
                RiskLevel = if ($UptimeDays -gt 30) { "MEDIUM" } elseif ($UptimeDays -gt 60) { "HIGH" } else { "LOW" }
                Recommendation = if ($UptimeDays -gt 30) { "Consider regular restarts for patch application" } else { "" }
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve system uptime: $($_.Exception.Message)" "PATCHES"
        }
        
        # Windows Update service status
        try {
            $UpdateService = Get-Service -Name "wuauserv" -ErrorAction Stop
            $Results += [PSCustomObject]@{
                Category = "Patches"
                Item = "Windows Update Service"
                Value = $UpdateService.Status
                Details = "Service startup type: $($UpdateService.StartType)"
                RiskLevel = if ($UpdateService.Status -eq "Running") { "LOW" } elseif ($UpdateService.Status -eq "Stopped" -and $UpdateService.StartType -eq "Manual") { "LOW" } else { "HIGH" }
                Recommendation = if ($UpdateService.Status -ne "Running" -and $UpdateService.StartType -eq "Disabled") { "Windows Update service should not be permanently disabled" } else { "" }
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not check Windows Update service status: $($_.Exception.Message)" "PATCHES"
            $Results += [PSCustomObject]@{
                Category = "Patches"
                Item = "Windows Update Service"
                Value = "Unknown"
                Details = "Could not retrieve service status"
                RiskLevel = "MEDIUM"
                Recommendation = "Verify Windows Update service configuration"
            }
        }
        
        # Comprehensive Windows Update configuration detection (effective settings)
        try {
            Write-LogMessage "INFO" "Detecting effective Windows Update configuration..." "PATCHES"
            
            # Check for WSUS configuration (Group Policy takes precedence)
            $WSUSServerGP = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer" -ErrorAction SilentlyContinue
            $UseWSUSGP = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" -ErrorAction SilentlyContinue
            $NoInternetGP = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DoNotConnectToWindowsUpdateInternetLocations" -ErrorAction SilentlyContinue
            $AUOptionsGP = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -ErrorAction SilentlyContinue
            $NoAutoUpdateGP = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -ErrorAction SilentlyContinue
            
            # Check for SCCM/ConfigMgr client
            $SCCMClient = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client" -ErrorAction SilentlyContinue
            $SCCMVersion = if ($SCCMClient -and $SCCMClient.SmsClientVersion) { $SCCMClient.SmsClientVersion } else { $null }
            
            # Check for Windows Update for Business (WUfB/Intune)
            $WUfBPolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\Current\Device\Update" -ErrorAction SilentlyContinue
            
            # Determine effective configuration (in order of precedence)
            $UpdateConfig = ""
            $UpdateDetails = ""
            $RiskLevel = "INFO"
            $Recommendation = ""
            
            # 1. SCCM/ConfigMgr (highest precedence for enterprise)
            if ($SCCMClient) {
                $UpdateConfig = "SCCM/ConfigMgr Managed"
                $UpdateDetails = "ConfigMgr client detected"
                if ($SCCMVersion) { $UpdateDetails += " (version: $SCCMVersion)" }
                $RiskLevel = "LOW"
                Write-LogMessage "SUCCESS" "SCCM ConfigMgr client detected: $SCCMVersion" "PATCHES"
            }
            
            # 2. WSUS Configuration (Group Policy managed)
            elseif ($WSUSServerGP -and $WSUSServerGP.WUServer -and $UseWSUSGP -and $UseWSUSGP.UseWUServer -eq 1) {
                $UpdateConfig = "WSUS Server"
                $UpdateDetails = "WSUS Server: $($WSUSServerGP.WUServer)"
                if ($NoInternetGP -and $NoInternetGP.DoNotConnectToWindowsUpdateInternetLocations -eq 1) {
                    $UpdateDetails += " (Internet blocked)"
                }
                $RiskLevel = "LOW"
                Write-LogMessage "SUCCESS" "WSUS configuration detected: $($WSUSServerGP.WUServer)" "PATCHES"
            }
            
            # 3. Windows Update for Business (WUfB/Intune)
            elseif ($WUfBPolicy) {
                $UpdateConfig = "Windows Update for Business"
                $UpdateDetails = "Managed by Intune/WUfB policies"
                $RiskLevel = "LOW"
                Write-LogMessage "SUCCESS" "Windows Update for Business detected" "PATCHES"
            }
            
            # 4. Group Policy Automatic Updates (without WSUS)
            elseif ($AUOptionsGP -or $NoAutoUpdateGP) {
                if ($NoAutoUpdateGP -and $NoAutoUpdateGP.NoAutoUpdate -eq 1) {
                    $UpdateConfig = "Automatic Updates Disabled"
                    $UpdateDetails = "Disabled by Group Policy (NoAutoUpdate=1)"
                    $RiskLevel = "HIGH"
                    $Recommendation = "Automatic updates should be enabled or managed by WSUS/SCCM"
                } elseif ($AUOptionsGP -and $AUOptionsGP.AUOptions) {
                    $AUValue = $AUOptionsGP.AUOptions
                    $UpdateConfig = switch ($AUValue) {
                        2 { "Notify before downloading" }
                        3 { "Download but notify before installing" }
                        4 { "Install automatically" }
                        5 { "Allow users to choose setting" }
                        default { "Custom configuration (AUOptions: $AUValue)" }
                    }
                    $UpdateDetails = "Group Policy managed (AUOptions: $AUValue)"
                    $RiskLevel = if ($AUValue -in @(3,4)) { "LOW" } elseif ($AUValue -eq 2) { "MEDIUM" } else { "HIGH" }
                }
                Write-LogMessage "SUCCESS" "Group Policy automatic updates: AUOptions=$($AUOptionsGP.AUOptions)" "PATCHES"
            }
            
            # 5. Local Registry Configuration
            else {
                $LocalAUConfig = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -ErrorAction SilentlyContinue
                if ($LocalAUConfig -and $LocalAUConfig.AUOptions) {
                    $AUValue = $LocalAUConfig.AUOptions
                    $UpdateConfig = switch ($AUValue) {
                        1 { "Automatic updates disabled" }
                        2 { "Notify before downloading" }
                        3 { "Download but notify before installing" }
                        4 { "Install automatically" }
                        5 { "Allow users to choose setting" }
                        default { "Custom configuration (AUOptions: $AUValue)" }
                    }
                    $UpdateDetails = "Local registry setting (AUOptions: $AUValue)"
                    $RiskLevel = if ($AUValue -in @(3,4)) { "LOW" } elseif ($AUValue -eq 2) { "MEDIUM" } else { "HIGH" }
                    Write-LogMessage "SUCCESS" "Local automatic updates: AUOptions=$AUValue" "PATCHES"
                } else {
                    # No explicit configuration found - Windows default behavior
                    $UpdateConfig = "Windows Default Behavior"
                    $UpdateDetails = "No explicit update configuration detected - using Windows default automatic update behavior"
                    $RiskLevel = "MEDIUM"
                    $Recommendation = "Consider implementing managed Windows Update strategy (WSUS, SCCM, or WUfB)"
                    Write-LogMessage "WARN" "No Windows Update configuration detected" "PATCHES"
                }
            }
            
            $Results += [PSCustomObject]@{
                Category = "Patches"
                Item = "Windows Update Configuration"
                Value = $UpdateConfig
                Details = $UpdateDetails
                RiskLevel = $RiskLevel
                Recommendation = ""
            }
        }
        catch {
            Write-LogMessage "ERROR" "Failed to detect Windows Update configuration: $($_.Exception.Message)" "PATCHES"
            $Results += [PSCustomObject]@{
                Category = "Patches"
                Item = "Windows Update Configuration"
                Value = "Detection Failed"
                Details = "Error detecting update configuration: $($_.Exception.Message)"
                RiskLevel = "ERROR"
                Recommendation = "Investigate Windows Update configuration detection issue"
            }
        }
        
        Write-LogMessage "SUCCESS" "Patch status analysis completed" "PATCHES"
        return $Results
    }
    catch {
        Write-LogMessage "ERROR" "Failed to analyze patch status: $($_.Exception.Message)" "PATCHES"
        return @()
    }
}

# [SECURITY] Get-SecuritySettings - Windows security configuration analysis
# Dependencies: Write-LogMessage
# Order: 121
# WindowsWorkstationAuditor - Security Settings Analysis Module
# Version 1.3.0

function Get-SecuritySettings {
    <#
    .SYNOPSIS
        Analyzes critical Windows security settings and configurations

    .DESCRIPTION
        Performs comprehensive security settings analysis including:
        - Antivirus detection via process signature matching (config-driven)
        - Windows Defender status and configuration details
        - Windows Firewall profile status (Domain, Private, Public)
        - User Account Control (UAC) configuration
        - BitLocker encryption status and key escrow

    .OUTPUTS
        Array of PSCustomObjects with Category, Item, Value, Details, RiskLevel, Recommendation

    .NOTES
        Requires: Write-LogMessage function, antivirus_signatures in config
        Permissions: Standard user rights for most checks, admin rights for comprehensive analysis
        Dependencies: Config file with antivirus process signatures
    #>
    
    Write-LogMessage "INFO" "Analyzing security settings..." "SECURITY"

    try {
        $Results = @()

        # Antivirus Detection System
        $DetectedAV = @()

        # Windows Defender - Use direct PowerShell query (built into Windows 10/11)
        try {
            $DefenderStatus = Get-MpComputerStatus -ErrorAction Stop
            if ($DefenderStatus.AntivirusEnabled) {
                Write-LogMessage "INFO" "Windows Defender detected: RealTime=$($DefenderStatus.RealTimeProtectionEnabled), Signatures=$($DefenderStatus.AntivirusSignatureAge) days old" "SECURITY"

                $DetectedAV += [PSCustomObject]@{
                    Name = "Windows Defender"
                    DetectionMethod = "Get-MpComputerStatus"
                    RealTimeProtection = $DefenderStatus.RealTimeProtectionEnabled
                    SignatureAge = $DefenderStatus.AntivirusSignatureAge
                    LastUpdate = $DefenderStatus.AntivirusSignatureLastUpdated
                }
            }
        }
        catch {
            Write-LogMessage "DEBUG" "Get-MpComputerStatus not available or Defender not installed: $($_.Exception.Message)" "SECURITY"
        }

        # Third-party AV detection via process matching from config
        if (Get-Variable -Name "Config" -Scope Global -ErrorAction SilentlyContinue) {
            $ConfigSigs = $null

            # Try inline signatures first (web version), then fall back to file
            if ($Global:Config.settings -and $Global:Config.settings.antivirus_signatures) {
                $ConfigSigs = $Global:Config.settings.antivirus_signatures
                Write-LogMessage "INFO" "Using inline AV signatures from config" "SECURITY"
            }
            elseif ($Global:Config.settings -and $Global:Config.settings.antivirus_signatures_file) {
                $AVSigFile = $Global:Config.settings.antivirus_signatures_file
                if (Test-Path $AVSigFile) {
                    try {
                        $AVSigConfig = Get-Content $AVSigFile | ConvertFrom-Json
                        $ConfigSigs = $AVSigConfig.antivirus_signatures
                        Write-LogMessage "INFO" "Loaded AV signatures from $AVSigFile" "SECURITY"
                    }
                    catch {
                        Write-LogMessage "WARN" "Failed to load AV signatures from $AVSigFile" "SECURITY"
                    }
                }
            }

            if ($ConfigSigs) {
                # Get running processes once for matching
                $RunningProcesses = Get-Process | Select-Object ProcessName

                # Count signatures for logging
                $SigCount = ($ConfigSigs.PSObject.Properties | Measure-Object).Count
                Write-LogMessage "INFO" "Checking $SigCount AV signatures from config..." "SECURITY"

                # Iterate through PSCustomObject properties directly (no conversion needed)
                foreach ($Property in $ConfigSigs.PSObject.Properties) {
                    $AVName = $Property.Name
                    $ProcessSignatures = $Property.Value

                    # Skip Windows Defender since we detect it directly
                    if ($AVName -eq "Windows Defender") {
                        continue
                    }

                    $Found = $false
                    foreach ($ProcessPattern in $ProcessSignatures) {
                        $MatchedProcesses = $RunningProcesses | Where-Object { $_.ProcessName -like "*$ProcessPattern*" }
                        if ($MatchedProcesses) {
                            Write-LogMessage "INFO" "Matched process pattern '$ProcessPattern' for $AVName" "SECURITY"
                            $Found = $true
                            break
                        }
                    }

                    if ($Found) {
                        $DetectedAV += [PSCustomObject]@{
                            Name = $AVName
                            DetectionMethod = "Process Signature"
                            ProcessSignature = $ProcessSignatures -join ", "
                        }

                        Write-LogMessage "INFO" "Detected third-party AV: $AVName" "SECURITY"
                    }
                }
            }
        }

        # Generate results from detected AV products
        if ($DetectedAV.Count -gt 0) {
            foreach ($AV in $DetectedAV) {
                $Details = "Detected via $($AV.DetectionMethod)"
                $RiskLevel = "LOW"

                # Windows Defender specific details
                if ($AV.Name -eq "Windows Defender") {
                    if ($AV.RealTimeProtection -ne $null) {
                        $Details += ", Real-time protection: $($AV.RealTimeProtection)"
                        if (-not $AV.RealTimeProtection) {
                            $RiskLevel = "HIGH"
                        }
                    }
                    if ($AV.SignatureAge -ne $null) {
                        $Details += ", Signature age: $($AV.SignatureAge) days"
                        if ($AV.SignatureAge -gt 7) {
                            $RiskLevel = "MEDIUM"
                        }
                    }
                    if ($AV.LastUpdate) {
                        $Details += ", Last update: $($AV.LastUpdate)"
                    }
                }

                $Results += [PSCustomObject]@{
                    Category = "Security"
                    Item = "Antivirus Product"
                    Value = "$($AV.Name) - Active"
                    Details = $Details
                    RiskLevel = $RiskLevel
                    Recommendation = ""
                }
            }

            # Summary
            $DetectedNames = ($DetectedAV | Select-Object -ExpandProperty Name) -join ', '
            $SummaryRisk = if ($DetectedAV.Count -gt 1) { "MEDIUM" } else { "LOW" }
            $SummaryRecommendation = if ($DetectedAV.Count -gt 1) { "Multiple AV products may cause conflicts - review configuration" } else { "" }

            $Results += [PSCustomObject]@{
                Category = "Security"
                Item = "Antivirus Protection Summary"
                Value = "$($DetectedAV.Count) product(s) detected"
                Details = "Active products: $DetectedNames"
                RiskLevel = $SummaryRisk
                Recommendation = $SummaryRecommendation
            }

            Write-LogMessage "SUCCESS" "AV detection: $($DetectedAV.Count) product(s) - $DetectedNames" "SECURITY"
        } else {
            $Results += [PSCustomObject]@{
                Category = "Security"
                Item = "Antivirus Protection"
                Value = "None detected"
                Details = "No antivirus processes detected. Either no AV is installed or signatures need updating."
                RiskLevel = "HIGH"
                Recommendation = "Install and configure antivirus protection"
            }

            Write-LogMessage "WARN" "No antivirus products detected" "SECURITY"
        }

        # Add detected AV products to raw data collection
        Add-RawDataCollection -CollectionName "AntivirusProducts" -Data $DetectedAV
        
        # Windows Firewall Status
        $FirewallProfiles = Get-NetFirewallProfile
        foreach ($Profile in $FirewallProfiles) {
            $Results += [PSCustomObject]@{
                Category = "Security"
                Item = "Firewall - $($Profile.Name)"
                Value = if ($Profile.Enabled) { "Enabled" } else { "Disabled" }
                Details = "Default action: Inbound=$($Profile.DefaultInboundAction), Outbound=$($Profile.DefaultOutboundAction)"
                RiskLevel = if ($Profile.Enabled) { "LOW" } else { "HIGH" }
                Recommendation = if (-not $Profile.Enabled) { "Enable firewall protection" } else { "" }
            }
        }
        
        # UAC Status
        $UACKey = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue
        $Results += [PSCustomObject]@{
            Category = "Security"
            Item = "User Account Control (UAC)"
            Value = if ($UACKey.EnableLUA) { "Enabled" } else { "Disabled" }
            Details = "UAC elevation prompts"
            RiskLevel = if ($UACKey.EnableLUA) { "LOW" } else { "HIGH" }
            Recommendation = if (-not $UACKey.EnableLUA) { "Enable UAC for privilege escalation control" } else { "" }
        }
        
        # BitLocker Encryption Analysis
        try {
            Write-LogMessage "INFO" "Analyzing BitLocker encryption status..." "SECURITY"
            
            # Check if BitLocker is available
            $BitLockerFeature = Get-WindowsOptionalFeature -Online -FeatureName "BitLocker" -ErrorAction SilentlyContinue
            if ($BitLockerFeature -and $BitLockerFeature.State -eq "Enabled") {
                
                # Get all BitLocker volumes
                $BitLockerVolumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
                if ($BitLockerVolumes) {
                    $EncryptedVolumes = @()
                    $UnencryptedVolumes = @()
                    
                    foreach ($Volume in $BitLockerVolumes) {
                        $VolumeInfo = @{
                            MountPoint = $Volume.MountPoint
                            EncryptionPercentage = $Volume.EncryptionPercentage
                            VolumeStatus = $Volume.VolumeStatus
                            ProtectionStatus = $Volume.ProtectionStatus
                            EncryptionMethod = $Volume.EncryptionMethod
                            KeyProtectors = $Volume.KeyProtector
                        }
                        
                        if ($Volume.VolumeStatus -eq "FullyEncrypted") {
                            $EncryptedVolumes += $VolumeInfo
                        } else {
                            $UnencryptedVolumes += $VolumeInfo
                        }
                        
                        # Analyze key protectors and escrow status
                        $KeyProtectorDetails = @()
                        $RecoveryKeyEscrowed = $false
                        $EscrowLocation = "None"
                        
                        foreach ($Protector in $Volume.KeyProtector) {
                            $KeyProtectorDetails += "$($Protector.KeyProtectorType)"
                            
                            # Check for recovery password protector
                            if ($Protector.KeyProtectorType -eq "RecoveryPassword") {
                                # Try to determine escrow status via manage-bde
                                try {
                                    $MbdeOutput = & manage-bde -protectors -get $Volume.MountPoint 2>$null
                                    if ($LASTEXITCODE -eq 0) {
                                        # Check for Azure AD or AD escrow indicators
                                        if ($MbdeOutput -match "Backed up to Azure Active Directory|Backed up to Microsoft Entra") {
                                            $RecoveryKeyEscrowed = $true
                                            $EscrowLocation = "Azure AD"
                                        }
                                        elseif ($MbdeOutput -match "Backed up to Active Directory") {
                                            $RecoveryKeyEscrowed = $true
                                            $EscrowLocation = "Active Directory"
                                        }
                                    }
                                }
                                catch {
                                    Write-LogMessage "WARN" "Could not determine recovery key escrow status for volume $($Volume.MountPoint)" "SECURITY"
                                }
                            }
                        }
                        
                        # Report individual volume status
                        $VolumeRisk = switch ($Volume.VolumeStatus) {
                            "FullyEncrypted" { "LOW" }
                            "EncryptionInProgress" { "MEDIUM" }
                            "DecryptionInProgress" { "HIGH" }
                            "FullyDecrypted" { "HIGH" }
                            default { "HIGH" }
                        }
                        
                        $VolumeRecommendation = switch ($Volume.VolumeStatus) {
                            "FullyDecrypted" { "Enable BitLocker encryption for data protection" }
                            "DecryptionInProgress" { "Complete BitLocker decryption or re-enable encryption" }
                            "EncryptionInProgress" { "Allow BitLocker encryption to complete" }
                            default { "" }
                        }
                        
                        # Add recovery key escrow compliance
                        if ($Volume.VolumeStatus -eq "FullyEncrypted" -and -not $RecoveryKeyEscrowed) {
                            $VolumeRecommendation = "Backup BitLocker recovery key to Azure AD or Active Directory"
                            $VolumeRisk = "MEDIUM"
                        }
                        
                        $Results += [PSCustomObject]@{
                            Category = "Security"
                            Item = "BitLocker Volume"
                            Value = "$($Volume.MountPoint) - $($Volume.VolumeStatus)"
                            Details = "Encryption: $($Volume.EncryptionPercentage)%, Protection: $($Volume.ProtectionStatus), Method: $($Volume.EncryptionMethod), Key Escrow: $EscrowLocation"
                            RiskLevel = $VolumeRisk
                            Recommendation = ""
                        }
                        
                        Write-LogMessage "INFO" "BitLocker volume $($Volume.MountPoint): $($Volume.VolumeStatus), Escrow: $EscrowLocation" "SECURITY"
                    }
                    
                    # Summary report
                    $TotalVolumes = $BitLockerVolumes.Count
                    $EncryptedCount = $EncryptedVolumes.Count
                    $Results += [PSCustomObject]@{
                        Category = "Security"
                        Item = "BitLocker Encryption Summary"
                        Value = "$EncryptedCount of $TotalVolumes volumes encrypted"
                        Details = "BitLocker disk encryption status across all volumes"
                        RiskLevel = if ($EncryptedCount -eq $TotalVolumes) { "LOW" } elseif ($EncryptedCount -gt 0) { "MEDIUM" } else { "HIGH" }
                        Recommendation = if ($EncryptedCount -lt $TotalVolumes) { "Encrypt all system and data volumes with BitLocker" } else { "" }
                    }
                    
                } else {
                    $Results += [PSCustomObject]@{
                        Category = "Security"
                        Item = "BitLocker Encryption"
                        Value = "No volumes detected"
                        Details = "Unable to retrieve BitLocker volume information"
                        RiskLevel = "MEDIUM"
                        Recommendation = "Verify BitLocker configuration and permissions"
                    }
                }
            } else {
                $Results += [PSCustomObject]@{
                    Category = "Security"
                    Item = "BitLocker Encryption"
                    Value = "Not Available"
                    Details = "BitLocker feature not enabled or not supported"
                    RiskLevel = "HIGH"
                    Recommendation = "Enable BitLocker feature for disk encryption"
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not analyze BitLocker encryption: $($_.Exception.Message)" "SECURITY"
            $Results += [PSCustomObject]@{
                Category = "Security"
                Item = "BitLocker Encryption"
                Value = "Analysis Failed"
                Details = "Unable to analyze BitLocker status - may require elevated privileges"
                RiskLevel = "MEDIUM"
                Recommendation = "Manual verification required"
            }
        }
        
        Write-LogMessage "SUCCESS" "Security settings analysis completed" "SECURITY"
        return $Results
    }
    catch {
        Write-LogMessage "ERROR" "Failed to analyze security settings: $($_.Exception.Message)" "SECURITY"
        return @()
    }
}

# [SECURITY] Get-UserAccountAnalysis - User account and privilege analysis
# Dependencies: Write-LogMessage
# Order: 122
# WindowsWorkstationAuditor - User Account Analysis Module
# Version 1.3.0

function Get-UserAccountAnalysis {
    <#
    .SYNOPSIS
        Analyzes user accounts and administrative privileges with Azure AD support
        
    .DESCRIPTION
        Performs comprehensive analysis of local and Azure AD user accounts including:
        - Local administrator account enumeration
        - Current user privilege assessment
        - Guest account status verification
        - Azure AD joined system detection
        - Administrative privilege distribution analysis
        
    .OUTPUTS
        Array of PSCustomObjects with Category, Item, Value, Details, RiskLevel, Recommendation
        
    .NOTES
        Requires: Write-LogMessage function
        Permissions: Local admin rights recommended for complete analysis
        Supports: Traditional domain, Azure AD joined, and workgroup systems
    #>
    
    Write-LogMessage "INFO" "Analyzing user accounts..." "USERS"
    
    try {
        $LocalAdmins = @()
        
        # Determine execution context
        $CurrentUser = if ($env:USERNAME -eq "SYSTEM") { "SYSTEM" } else { $env:USERNAME }
        Write-LogMessage "INFO" "Current user: $CurrentUser" "USERS"
        
        # Check if current user is admin
        $IsCurrentUserAdmin = $false
        try {
            $CurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
            $Principal = New-Object Security.Principal.WindowsPrincipal($CurrentIdentity)
            $IsCurrentUserAdmin = $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            Write-LogMessage "INFO" "Current user is admin: $IsCurrentUserAdmin" "USERS"
        }
        catch {
            Write-LogMessage "WARN" "Could not check current user admin status: $($_.Exception.Message)" "USERS"
        }
        
        # Detect if we're on a Domain Controller
        $IsDomainController = $false
        try {
            $OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
            $IsDomainController = $OSInfo.ProductType -eq 2  # ProductType: 1=Workstation, 2=DC, 3=Server
            Write-LogMessage "INFO" "Domain Controller detected: $IsDomainController" "USERS"
        }
        catch {
            Write-LogMessage "WARN" "Could not determine system type for DC detection" "USERS"
        }
        
        # Use different methods based on whether we're on a Domain Controller
        if ($IsDomainController) {
            Write-LogMessage "INFO" "Using Active Directory methods for Domain Controller..." "USERS"
            try {
                # Try to import AD module
                Import-Module ActiveDirectory -ErrorAction SilentlyContinue
                
                # Get Domain Admins and Enterprise Admins
                $DomainAdmins = @()
                $EnterpriseAdmins = @()
                
                try {
                    $DomainAdmins = Get-ADGroupMember "Domain Admins" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
                } catch {
                    Write-LogMessage "WARN" "Could not get Domain Admins: $($_.Exception.Message)" "USERS"
                }
                
                try {
                    $EnterpriseAdmins = Get-ADGroupMember "Enterprise Admins" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
                } catch {
                    Write-LogMessage "WARN" "Could not get Enterprise Admins: $($_.Exception.Message)" "USERS"
                }
                
                # Combine and deduplicate
                $LocalAdmins = @($DomainAdmins) + @($EnterpriseAdmins) | Sort-Object -Unique | Where-Object { $_ -ne $null }
                Write-LogMessage "INFO" "Found $($DomainAdmins.Count) Domain Admins, $($EnterpriseAdmins.Count) Enterprise Admins" "USERS"
            }
            catch {
                Write-LogMessage "WARN" "AD module not available, falling back to local group detection: $($_.Exception.Message)" "USERS"
                $IsDomainController = $false  # Fall back to local methods
            }
        }
        
        # Use local methods for non-DCs or if AD methods failed
        if (-not $IsDomainController -or $LocalAdmins.Count -eq 0) {
            Write-LogMessage "INFO" "Using local group detection methods..." "USERS"
        
        # Method 1: Try Get-LocalGroupMember (best for Azure AD)
        try {
            Write-LogMessage "INFO" "Attempting Get-LocalGroupMember..." "USERS"
            $AdminMembers = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
            Write-LogMessage "INFO" "Get-LocalGroupMember returned $($AdminMembers.Count) members" "USERS"
            
            $LocalAdmins = foreach ($Member in $AdminMembers) {
                Write-LogMessage "INFO" "Processing member: Name='$($Member.Name)', ObjectClass='$($Member.ObjectClass)'" "USERS"
                
                # Extract just the username part
                if ($Member.Name -match "\\") {
                    $Username = $Member.Name.Split('\')[-1]
                } else {
                    $Username = $Member.Name
                }
                Write-LogMessage "INFO" "Extracted username: '$Username'" "USERS"
                $Username
            }
        }
        catch {
            Write-LogMessage "WARN" "Get-LocalGroupMember failed: $($_.Exception.Message)" "USERS"
        }
        
        # Method 2: Fallback to net localgroup
        if ($LocalAdmins.Count -eq 0) {
            try {
                Write-LogMessage "INFO" "Fallback: Using net localgroup Administrators" "USERS"
                $NetOutput = & net localgroup Administrators 2>&1
                Write-LogMessage "INFO" "Net command output has $($NetOutput.Count) lines" "USERS"
                
                if ($LASTEXITCODE -eq 0) {
                    $InMembersList = $false
                    $LocalAdmins = foreach ($Line in $NetOutput) {
                        # Look for the separator line
                        if ($Line -match "^-+$") {
                            $InMembersList = $true
                            continue
                        }
                        
                        # Process member lines
                        if ($InMembersList -and $Line.Trim() -ne "" -and $Line -notmatch "The command completed successfully") {
                            $CleanName = $Line.Trim()
                            # Handle AzureAD\ prefix
                            if ($CleanName -match "^AzureAD\\(.+)$") {
                                $CleanName = $matches[1]
                            }
                            Write-LogMessage "INFO" "Found admin: '$CleanName'" "USERS"
                            $CleanName
                        }
                    }
                }
            }
            catch {
                Write-LogMessage "ERROR" "Net localgroup method failed: $($_.Exception.Message)" "USERS"
            }
        }
        
            # Method 3: If still no admins but current user is admin, add them
            if ($LocalAdmins.Count -eq 0 -and $IsCurrentUserAdmin) {
                Write-LogMessage "INFO" "Adding current user as admin since detection failed" "USERS"
                $LocalAdmins = @($env:USERNAME)
            }
        }
        
        $Results = @()
        
        # Local Administrator Count (always add this result)
        $AdminCount = $LocalAdmins.Count
        Write-LogMessage "SUCCESS" "Administrator count: $AdminCount" "USERS"
        $Results += [PSCustomObject]@{
            Category = "Users"
            Item = "Local Administrators"
            Value = $AdminCount
            Details = "Users: $($LocalAdmins -join ', ')"
            RiskLevel = if ($AdminCount -gt 3) { "HIGH" } elseif ($AdminCount -gt 1) { "MEDIUM" } else { "LOW" }
            Recommendation = if ($AdminCount -gt 3) { "Limit administrative access" } else { "" }
        }
        
        # Account Security Analysis (different for DCs vs regular systems)
        if ($IsDomainController) {
            # For Domain Controllers: Check for disabled domain accounts
            try {
                if (Get-Module -Name ActiveDirectory -ListAvailable) {
                    $DisabledUsers = Get-ADUser -Filter {Enabled -eq $false} -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count
                    $Results += [PSCustomObject]@{
                        Category = "Users"
                        Item = "Disabled Domain Accounts"
                        Value = $DisabledUsers
                        Details = "Disabled user accounts in Active Directory"
                        RiskLevel = if ($DisabledUsers -gt 10) { "MEDIUM" } else { "LOW" }
                        Recommendation = if ($DisabledUsers -gt 10) { "Review and clean up disabled accounts" } else { "" }
                    }
                    Write-LogMessage "INFO" "Found $DisabledUsers disabled domain accounts" "USERS"
                } else {
                    Write-LogMessage "INFO" "Active Directory module not available for disabled account analysis" "USERS"
                }
            }
            catch {
                Write-LogMessage "WARN" "Could not check disabled domain accounts: $($_.Exception.Message)" "USERS"
            }
        } else {
            # For regular systems: Check Guest Account Status
            try {
                $LocalUsers = Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction SilentlyContinue
                if ($LocalUsers) {
                    $GuestAccount = $LocalUsers | Where-Object { $_.Name -eq "Guest" }
                    if ($GuestAccount) {
                        $Results += [PSCustomObject]@{
                            Category = "Users"
                            Item = "Guest Account"
                            Value = if ($GuestAccount.Disabled) { "Disabled" } else { "Enabled" }
                            Details = "Guest account status"
                            RiskLevel = if ($GuestAccount.Disabled) { "LOW" } else { "HIGH" }
                            Recommendation = if (-not $GuestAccount.Disabled) { "Disable guest account" } else { "" }
                        }
                    } else {
                        Write-LogMessage "INFO" "No Guest account found in local users" "USERS"
                    }
                } else {
                    Write-LogMessage "WARN" "Unable to enumerate local users" "USERS"
                }
            }
            catch {
                Write-LogMessage "WARN" "Could not check local users for Guest account: $($_.Exception.Message)" "USERS"
            }
        }
        
        Write-LogMessage "SUCCESS" "User account analysis completed - Found $AdminCount administrators" "USERS"
        Write-LogMessage "INFO" "Returning $($Results.Count) user account results" "USERS"
        return $Results
    }
    catch {
        Write-LogMessage "ERROR" "Failed to analyze user accounts: $($_.Exception.Message)" "USERS"
        return @()
    }
}

# [SECURITY] Get-PolicyAnalysis - Group Policy and security policy analysis
# Dependencies: Write-LogMessage
# Order: 123
# WindowsWorkstationAuditor - Policy Analysis Module
# Version 1.3.0

function Get-PolicyAnalysis {
    <#
    .SYNOPSIS
        Analyzes security policies, Group Policy, and audit configurations
        
    .DESCRIPTION
        Performs comprehensive policy analysis including:
        - Group Policy Object (GPO) detection and enumeration
        - Local security policy analysis via secedit export
        - Password policy configuration (length, complexity, history)
        - Account lockout policy settings
        - Screen lock/screen saver policy verification
        - Audit policy configuration for security logging
        - User rights assignment analysis for privilege escalation risks
        - Windows Defender policy restrictions
        
    .OUTPUTS
        Array of PSCustomObjects with Category, Item, Value, Details, RiskLevel, Recommendation
        
    .NOTES
        Requires: Write-LogMessage function
        Permissions: Admin rights for comprehensive policy analysis
        Dependencies: secedit.exe, auditpol.exe, gpresult.exe
        Coverage: Local policies, Group Policy, audit settings
    #>
    
    Write-LogMessage "INFO" "Analyzing security policies and settings..." "POLICY"
    
    try {
        $Results = @()
        
        # Policy Management Detection - distinguish between Group Policy, MDM, and Local Security Policy
        Write-LogMessage "INFO" "Checking Group Policy configuration..." "POLICY"
        
        # 1. Check for traditional Group Policy (domain-joined)
        try {
            $GPResult = & gpresult /r /scope:computer 2>$null
            if ($LASTEXITCODE -eq 0) {
                # Parse GP result for applied policies
                $AppliedGPOs = @()
                $InGPOSection = $false
                $IsLocalPolicyOnly = $true
                
                foreach ($Line in $GPResult) {
                    if ($Line -match "Applied Group Policy Objects") {
                        $InGPOSection = $true
                        continue
                    }
                    if ($Line -match "The following GPOs were not applied" -or $Line -match "The computer is a part of the following security groups") {
                        $InGPOSection = $false
                        continue
                    }
                    if ($InGPOSection -and $Line.Trim() -ne "" -and $Line -notmatch "^-+$" -and $Line -notmatch "^\s*$") {
                        $CleanedGPOName = $Line.Trim()
                        if ($CleanedGPOName -notmatch "^-+$" -and $CleanedGPOName -ne "Applied Group Policy Objects") {
                            $AppliedGPOs += $CleanedGPOName
                            # Check if it's real Group Policy or just Local Security Policy
                            if ($CleanedGPOName -ne "Local Group Policy") {
                                $IsLocalPolicyOnly = $false
                            }
                            Write-LogMessage "INFO" "Found policy: $CleanedGPOName" "POLICY"
                        }
                    }
                }
                
                # Categorize the results properly
                if ($AppliedGPOs.Count -gt 0 -and -not $IsLocalPolicyOnly) {
                    # Real Group Policy Objects found
                    $Results += [PSCustomObject]@{
                        Category = "Policy"
                        Item = "Domain Group Policy"
                        Value = "$($AppliedGPOs.Count) GPOs Applied"
                        Details = "Traditional Active Directory Group Policy Objects"
                        RiskLevel = "LOW"
                        Recommendation = ""
                    }
                    
                    foreach ($GPO in $AppliedGPOs) {
                        if ($GPO -and $GPO.Trim() -ne "" -and $GPO -ne "Local Group Policy") {
                            $Results += [PSCustomObject]@{
                                Category = "Policy"
                                Item = "Domain GPO"
                                Value = $GPO
                                Details = "Active Directory Group Policy Object"
                                RiskLevel = "INFO"
                                Recommendation = ""
                            }
                        }
                    }
                } else {
                    # No real GPOs - expected for Azure AD joined devices
                    $Results += [PSCustomObject]@{
                        Category = "Policy"
                        Item = "Domain Group Policy"
                        Value = "Not Applied"
                        Details = "No traditional AD Group Policy Objects (normal for Azure AD joined devices)"
                        RiskLevel = "INFO"
                        Recommendation = ""
                    }
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not check Group Policy status: $($_.Exception.Message)" "POLICY"
        }
        
        # 2. Check for MDM/Intune Policy (for Azure AD joined devices)
        try {
            # Check MDM enrollment status
            $MDMEnrolled = $false
            $MDMDetails = "Not enrolled"
            $AppliedPolicies = @()
            
            # Check registry for MDM enrollment
            $MDMKey = "HKLM:\SOFTWARE\Microsoft\Enrollments"
            if (Test-Path $MDMKey) {
                $Enrollments = Get-ChildItem $MDMKey -ErrorAction SilentlyContinue
                foreach ($Enrollment in $Enrollments) {
                    $EnrollmentInfo = Get-ItemProperty $Enrollment.PSPath -ErrorAction SilentlyContinue
                    if ($EnrollmentInfo -and ($EnrollmentInfo.ProviderID -eq "MS DM Server" -or $EnrollmentInfo.EnrollmentType -eq 6)) {
                        $MDMEnrolled = $true
                        $MDMDetails = "Enrolled via Microsoft Intune/MDM"
                        Write-LogMessage "INFO" "MDM enrollment detected: $($EnrollmentInfo.ProviderID)" "POLICY"
                        break
                    }
                }
            }
            
            # If MDM enrolled, try to detect applied policies
            if ($MDMEnrolled) {
                # Method 1: Check PolicyManager registry for applied policies (correct path)
                $PolicyManagerKey = "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device"
                if (Test-Path $PolicyManagerKey) {
                    $PolicyCategories = Get-ChildItem $PolicyManagerKey -ErrorAction SilentlyContinue
                    foreach ($Category in $PolicyCategories) {
                        if ($Category.Name -notmatch "Status|Reporting") {
                            $CategoryName = $Category.PSChildName
                            $PolicyValues = Get-ItemProperty $Category.PSPath -ErrorAction SilentlyContinue
                            if ($PolicyValues) {
                                $ValueCount = ($PolicyValues.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" }).Count
                                if ($ValueCount -gt 0) {
                                    $AppliedPolicies += "$CategoryName ($ValueCount settings)"
                                }
                            }
                        }
                    }
                    Write-LogMessage "INFO" "MDM applied policies detected: $($AppliedPolicies.Count) categories" "POLICY"
                }
                
                # Method 1b: Check specific common Intune CSPs
                $CommonCSPs = @(
                    @{Name = "DeviceLock"; Description = "Device lock and password policies"},
                    @{Name = "Bitlocker"; Description = "BitLocker encryption policies"},
                    @{Name = "Update"; Description = "Windows Update policies"},
                    @{Name = "Firewall"; Description = "Windows Firewall policies"},
                    @{Name = "ApplicationControl"; Description = "Application control policies"},
                    @{Name = "VPNv2"; Description = "VPN configuration policies"},
                    @{Name = "WiFi"; Description = "WiFi configuration policies"}
                )
                
                $CSPDetailsMap = @{}
                foreach ($CSP in $CommonCSPs) {
                    $CSPKey = "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\$($CSP.Name)"
                    if (Test-Path $CSPKey) {
                        $CSPSettings = Get-ItemProperty $CSPKey -ErrorAction SilentlyContinue
                        if ($CSPSettings) {
                            $SettingNames = ($CSPSettings.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" }).Name
                            if ($SettingNames.Count -gt 0) {
                                $AppliedPolicies += "$($CSP.Name) ($($SettingNames.Count) settings)"
                                
                                # Filter out technical metadata and capture meaningful settings
                                $FilteredSettingNames = $SettingNames | Where-Object { 
                                    $_ -notmatch "_ProviderSet$|_WinningProvider$|_LastWrite$|_Version$" 
                                }
                                
                                $SettingDetails = @()
                                foreach ($SettingName in ($FilteredSettingNames | Select-Object -First 8)) {
                                    $SettingValue = $CSPSettings.$SettingName
                                    if ($SettingValue -ne $null -and $SettingValue -ne "") {
                                        # Format boolean values more clearly
                                        if ($SettingValue -eq "1") {
                                            $SettingDetails += "$SettingName=Enabled"
                                        } elseif ($SettingValue -eq "0") {
                                            $SettingDetails += "$SettingName=Disabled"
                                        } else {
                                            $SettingDetails += "$SettingName=$SettingValue"
                                        }
                                    } else {
                                        $SettingDetails += "$SettingName"
                                    }
                                }
                                $CSPDetailsMap[$CSP.Name] = @{
                                    Description = $CSP.Description
                                    Settings = $SettingDetails
                                    Count = $FilteredSettingNames.Count
                                    TotalCount = $SettingNames.Count
                                }
                                
                                Write-LogMessage "INFO" "$($CSP.Name) CSP policies found: $($SettingNames.Count) settings" "POLICY"
                            }
                        }
                    }
                }
                
                # Method 2: Try WMI Bridge Provider (requires elevated privileges)
                try {
                    $WMIClasses = Get-CimClass -Namespace "root\cimv2\mdm\dmmap" -ClassName "*Policy_Result*" -ErrorAction SilentlyContinue
                    if ($WMIClasses) {
                        Write-LogMessage "INFO" "MDM WMI Bridge Provider accessible - $($WMIClasses.Count) policy classes" "POLICY"
                    }
                }
                catch {
                    Write-LogMessage "INFO" "MDM WMI Bridge Provider not accessible (normal for non-SYSTEM context)" "POLICY"
                }
            }
            
            # Results
            $Results += [PSCustomObject]@{
                Category = "Policy"
                Item = "MDM Policy Management"
                Value = if ($MDMEnrolled) { "Active" } else { "Not Detected" }
                Details = if ($MDMEnrolled -and $AppliedPolicies.Count -gt 0) { 
                    "Intune/MDM enrolled with policies applied: $($AppliedPolicies -join ', ')" 
                } elseif ($MDMEnrolled) { 
                    "Intune/MDM enrolled - policy details require elevated access" 
                } else { 
                    "Not enrolled in MDM management" 
                }
                RiskLevel = if ($MDMEnrolled) { "LOW" } else { "MEDIUM" }
                Recommendation = if (-not $MDMEnrolled) { "Consider MDM enrollment for centralized management" } else { "" }
            }
            
            # Individual policy categories with detailed settings if detected
            if ($CSPDetailsMap.Count -gt 0) {
                foreach ($CSPName in $CSPDetailsMap.Keys) {
                    $CSPInfo = $CSPDetailsMap[$CSPName]
                    $SettingsPreview = if ($CSPInfo.Settings.Count -gt 0) {
                        $FirstFewSettings = $CSPInfo.Settings | Select-Object -First 3
                        "Settings: $($FirstFewSettings -join ', ')"
                        if ($CSPInfo.Settings.Count -gt 3) {
                            $SettingsPreview += " (+$($CSPInfo.Count - 3) more)"
                        }
                    } else {
                        "$($CSPInfo.Count) configured settings"
                    }
                    
                    $Results += [PSCustomObject]@{
                        Category = "Policy"
                        Item = "$CSPName Policy"
                        Value = "$($CSPInfo.Count) settings configured"
                        Details = "$($CSPInfo.Description): $SettingsPreview"
                        RiskLevel = "INFO"
                        Recommendation = ""
                    }
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not check MDM status: $($_.Exception.Message)" "POLICY"
        }
        
        # Local Security Policy Analysis using secedit
        Write-LogMessage "INFO" "Analyzing local security policies..." "POLICY"
        try {
            $TempSecPol = "$env:TEMP\secpol.cfg"
            $SecEditResult = & secedit /export /cfg $TempSecPol /quiet 2>$null
            
            if (Test-Path $TempSecPol) {
                $SecPolContent = Get-Content $TempSecPol
                
                # Password Policy Analysis with null checking
                $MinPasswordLengthLine = $SecPolContent | Where-Object { $_ -match "MinimumPasswordLength" } | Select-Object -First 1
                $MinPasswordLength = if ($MinPasswordLengthLine) { $MinPasswordLengthLine.Split('=')[1].Trim() } else { $null }
                
                $PasswordComplexityLine = $SecPolContent | Where-Object { $_ -match "PasswordComplexity" } | Select-Object -First 1
                $PasswordComplexity = if ($PasswordComplexityLine) { $PasswordComplexityLine.Split('=')[1].Trim() } else { $null }
                
                $MaxPasswordAgeLine = $SecPolContent | Where-Object { $_ -match "MaximumPasswordAge" } | Select-Object -First 1
                $MaxPasswordAge = if ($MaxPasswordAgeLine) { $MaxPasswordAgeLine.Split('=')[1].Trim() } else { $null }
                
                $MinPasswordAgeLine = $SecPolContent | Where-Object { $_ -match "MinimumPasswordAge" } | Select-Object -First 1
                $MinPasswordAge = if ($MinPasswordAgeLine) { $MinPasswordAgeLine.Split('=')[1].Trim() } else { $null }
                
                $PasswordHistorySizeLine = $SecPolContent | Where-Object { $_ -match "PasswordHistorySize" } | Select-Object -First 1
                $PasswordHistorySize = if ($PasswordHistorySizeLine) { $PasswordHistorySizeLine.Split('=')[1].Trim() } else { $null }
                
                # Account Lockout Policy with null checking
                $LockoutThresholdLine = $SecPolContent | Where-Object { $_ -match "LockoutBadCount" } | Select-Object -First 1
                $LockoutThreshold = if ($LockoutThresholdLine) { $LockoutThresholdLine.Split('=')[1].Trim() } else { $null }
                
                $LockoutDurationLine = $SecPolContent | Where-Object { $_ -match "LockoutDuration" } | Select-Object -First 1
                $LockoutDuration = if ($LockoutDurationLine) { $LockoutDurationLine.Split('=')[1].Trim() } else { $null }
                
                $ResetLockoutCounterLine = $SecPolContent | Where-Object { $_ -match "ResetLockoutCount" } | Select-Object -First 1
                $ResetLockoutCounter = if ($ResetLockoutCounterLine) { $ResetLockoutCounterLine.Split('=')[1].Trim() } else { $null }
                
                # Password Policy Results
                $Results += [PSCustomObject]@{
                    Category = "Policy"
                    Item = "Password Length Requirement"
                    Value = if ($MinPasswordLength) { "$MinPasswordLength characters" } else { "Not configured" }
                    Details = "Minimum password length policy"
                    RiskLevel = if ([int]$MinPasswordLength -ge 12) { "LOW" } elseif ([int]$MinPasswordLength -ge 8) { "MEDIUM" } else { "HIGH" }
                    Recommendation = if ([int]$MinPasswordLength -lt 8) { "Minimum 8 characters required" } elseif ([int]$MinPasswordLength -lt 12) { "Consider 12+ characters for enhanced security" } else { "" }
                }
                
                $Results += [PSCustomObject]@{
                    Category = "Policy"
                    Item = "Password Complexity"
                    Value = if ($PasswordComplexity -eq "1") { "Enabled" } else { "Disabled" }
                    Details = "Requires uppercase, lowercase, numbers, and symbols"
                    RiskLevel = if ($PasswordComplexity -eq "1") { "LOW" } else { "HIGH" }
                    Recommendation = if ($PasswordComplexity -ne "1") { "Enable password complexity requirements" } else { "" }
                }
                
                $Results += [PSCustomObject]@{
                    Category = "Policy"
                    Item = "Password History"
                    Value = if ($PasswordHistorySize) { "$PasswordHistorySize passwords remembered" } else { "Not configured" }
                    Details = "Prevents password reuse"
                    RiskLevel = if ([int]$PasswordHistorySize -ge 12) { "LOW" } elseif ([int]$PasswordHistorySize -ge 5) { "MEDIUM" } else { "HIGH" }
                    Recommendation = if ([int]$PasswordHistorySize -lt 12) { "Remember last 12 passwords minimum" } else { "" }
                }
                
                # Account Lockout Policy Results
                $Results += [PSCustomObject]@{
                    Category = "Policy"
                    Item = "Account Lockout Threshold"
                    Value = if ($LockoutThreshold -and $LockoutThreshold -ne "0") { "$LockoutThreshold invalid attempts" } else { "No lockout policy" }
                    Details = "Failed logon attempts before lockout"
                    RiskLevel = if ($LockoutThreshold -and [int]$LockoutThreshold -le 10 -and [int]$LockoutThreshold -gt 0) { "LOW" } elseif ($LockoutThreshold -eq "0") { "HIGH" } else { "MEDIUM" }
                    Recommendation = if ($LockoutThreshold -eq "0") { "Configure account lockout policy" } else { "" }
                }
                
                if ($LockoutThreshold -and $LockoutThreshold -ne "0") {
                    $LockoutDurationMinutes = if ($LockoutDuration) { [math]::Round([int]$LockoutDuration / 60) } else { 0 }
                    $Results += [PSCustomObject]@{
                        Category = "Policy"
                        Item = "Account Lockout Duration"
                        Value = if ($LockoutDuration -eq "-1") { "Until admin unlocks" } else { "$LockoutDurationMinutes minutes" }
                        Details = "How long accounts remain locked"
                        RiskLevel = if ($LockoutDuration -eq "-1" -or $LockoutDurationMinutes -ge 15) { "LOW" } else { "MEDIUM" }
                        Recommendation = ""
                    }
                }
                
                # Clean up temp file
                Remove-Item $TempSecPol -Force -ErrorAction SilentlyContinue
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not analyze local security policies: $($_.Exception.Message)" "POLICY"
        }
        
        # Screen Lock / Screen Saver Policy
        Write-LogMessage "INFO" "Checking screen lock policies..." "POLICY"
        try {
            # Check screen saver settings (skip HKCU if running as SYSTEM)
            $ScreenSaveActive = $null
            $ScreenSaveTimeOut = $null  
            $ScreenSaverIsSecure = $null
            
            if ($env:USERNAME -ne "SYSTEM") {
                $ScreenSaveActive = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveActive" -ErrorAction SilentlyContinue
                $ScreenSaveTimeOut = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -ErrorAction SilentlyContinue
                $ScreenSaverIsSecure = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -ErrorAction SilentlyContinue
            } else {
                Write-LogMessage "INFO" "Running as SYSTEM - skipping user-specific screen saver settings" "POLICY"
            }
            
            # Check machine-wide policy settings
            $MachineScreenSaver = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" -ErrorAction SilentlyContinue
            
            if ($ScreenSaveActive -and $ScreenSaveActive.ScreenSaveActive -eq "1") {
                $TimeoutMinutes = if ($ScreenSaveTimeOut) { [math]::Round([int]$ScreenSaveTimeOut.ScreenSaveTimeOut / 60) } else { 0 }
                $IsSecure = $ScreenSaverIsSecure -and $ScreenSaverIsSecure.ScreenSaverIsSecure -eq "1"
                
                $Results += [PSCustomObject]@{
                    Category = "Policy"
                    Item = "Screen Lock Policy"
                    Value = "Enabled - $TimeoutMinutes minutes"
                    Details = "Secure: $IsSecure, Timeout: $TimeoutMinutes minutes"
                    RiskLevel = if ($IsSecure -and $TimeoutMinutes -le 15 -and $TimeoutMinutes -gt 0) { "LOW" } elseif ($IsSecure -and $TimeoutMinutes -le 30) { "MEDIUM" } else { "HIGH" }
                    Recommendation = if (-not $IsSecure) { "Enable secure screen saver" } elseif ($TimeoutMinutes -gt 15) { "Screen lock timeout should be 15 minutes or less" } else { "" }
                }
            } else {
                # Handle case where no user context exists (SYSTEM) or screen saver is disabled
                $PolicyStatus = if ($env:USERNAME -eq "SYSTEM") { "Cannot Check (System Context)" } else { "Disabled" }
                $PolicyRisk = if ($env:USERNAME -eq "SYSTEM") { "MEDIUM" } else { "HIGH" }
                $PolicyRecommendation = if ($env:USERNAME -eq "SYSTEM") { "Screen lock policy should be enforced via Group Policy" } else { "Configure automatic screen lock" }
                
                $Results += [PSCustomObject]@{
                    Category = "Policy"
                    Item = "Screen Lock Policy"
                    Value = $PolicyStatus
                    Details = if ($env:USERNAME -eq "SYSTEM") { "Running as SYSTEM - user-specific settings not accessible" } else { "No automatic screen lock configured" }
                    RiskLevel = $PolicyRisk
                    Recommendation = ""
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not check screen lock policies: $($_.Exception.Message)" "POLICY"
        }
        
        # Audit Policy Analysis
        Write-LogMessage "INFO" "Analyzing audit policies..." "POLICY"
        try {
            $AuditPolResult = & auditpol /get /category:* 2>$null
            if ($LASTEXITCODE -eq 0) {
                # Parse audit policy results
                $CriticalAuditEvents = @(
                    @{Name="Logon/Logoff"; Pattern="Logon"}
                    @{Name="Account Logon"; Pattern="Credential Validation"}
                    @{Name="Account Management"; Pattern="User Account Management"}
                    @{Name="Policy Change"; Pattern="Audit Policy Change"}
                    @{Name="Privilege Use"; Pattern="Sensitive Privilege Use"}
                )
                
                $AuditResults = @()
                foreach ($AuditEvent in $CriticalAuditEvents) {
                    $EventLine = $AuditPolResult | Where-Object { $_ -match $AuditEvent.Pattern }
                    if ($EventLine) {
                        $AuditStatus = if ($EventLine -match "Success and Failure|Success|Failure") { 
                            $matches[0] 
                        } else { 
                            "No Auditing" 
                        }
                        $AuditResults += "$($AuditEvent.Name): $AuditStatus"
                    }
                }
                
                $EnabledAudits = ($AuditResults | Where-Object { $_ -notmatch "No Auditing" }).Count
                $TotalAudits = $AuditResults.Count
                
                $Results += [PSCustomObject]@{
                    Category = "Policy"
                    Item = "Audit Policy Configuration"
                    Value = "$EnabledAudits of $TotalAudits critical audits enabled"
                    Details = $AuditResults -join "; "
                    RiskLevel = if ($EnabledAudits -eq $TotalAudits) { "LOW" } elseif ($EnabledAudits -ge 3) { "MEDIUM" } else { "HIGH" }
                    Recommendation = if ($EnabledAudits -lt $TotalAudits) { "Enable comprehensive audit logging" } else { "" }
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not analyze audit policies: $($_.Exception.Message)" "POLICY"
        }
        
        # User Rights Assignment (Critical Rights)
        Write-LogMessage "INFO" "Checking critical user rights assignments..." "POLICY"
        try {
            $TempUserRights = "$env:TEMP\userrights.txt"
            $SecEditResult = & secedit /export /areas USER_RIGHTS /cfg $TempUserRights /quiet 2>$null
            
            if (Test-Path $TempUserRights) {
                $UserRightsContent = Get-Content $TempUserRights
                
                # Check critical rights with detailed analysis
                $CriticalRights = @{
                    "SeServiceLogonRight" = @{ Name = "Log on as a service"; Pattern = "SeServiceLogonRight"; Risk = "HIGH" }
                    "SeInteractiveLogonRight" = @{ Name = "Log on locally"; Pattern = "SeInteractiveLogonRight"; Risk = "MEDIUM" }
                    "SeShutdownPrivilege" = @{ Name = "Shut down the system"; Pattern = "SeShutdownPrivilege"; Risk = "MEDIUM" }
                    "SeBackupPrivilege" = @{ Name = "Back up files and directories"; Pattern = "SeBackupPrivilege"; Risk = "HIGH" }
                    "SeRestorePrivilege" = @{ Name = "Restore files and directories"; Pattern = "SeRestorePrivilege"; Risk = "HIGH" }
                    "SeDebugPrivilege" = @{ Name = "Debug programs"; Pattern = "SeDebugPrivilege"; Risk = "HIGH" }
                    "SeTakeOwnershipPrivilege" = @{ Name = "Take ownership"; Pattern = "SeTakeOwnershipPrivilege"; Risk = "HIGH" }
                }
                
                $DangerousRights = @()
                $CheckedRights = @()
                
                foreach ($Right in $CriticalRights.Keys) {
                    $RightInfo = $CriticalRights[$Right]
                    $RightLine = $UserRightsContent | Where-Object { $_ -match $Right } | Select-Object -First 1
                    
                    if ($RightLine) {
                        $AssignedUsers = $RightLine.Split('=')[1]
                        $CheckedRights += "$($RightInfo.Name): Configured"
                        
                        # Check for overly permissive assignments
                        if ($AssignedUsers -and $AssignedUsers -match "Everyone") {
                            $DangerousRights += "$($RightInfo.Name) assigned to Everyone"
                        }
                        elseif ($AssignedUsers -and $AssignedUsers -match "Users" -and $RightInfo.Risk -eq "HIGH") {
                            $DangerousRights += "$($RightInfo.Name) assigned to Users group"
                        }
                    } else {
                        $CheckedRights += "$($RightInfo.Name): Not configured"
                    }
                }
                
                # Summary entry
                $Results += [PSCustomObject]@{
                    Category = "Policy"
                    Item = "Local Security Policy"
                    Value = "Active"
                    Details = "Local computer security settings managed independently"
                    RiskLevel = "INFO"
                    Recommendation = ""
                }
                
                if ($DangerousRights.Count -gt 0) {
                    $Results += [PSCustomObject]@{
                        Category = "Policy"
                        Item = "User Rights Assignment"
                        Value = "Issues Found"
                        Details = $DangerousRights -join "; "
                        RiskLevel = "MEDIUM"
                        Recommendation = "Review user rights assignments for least privilege"
                    }
                } else {
                    $Results += [PSCustomObject]@{
                        Category = "Policy"
                        Item = "User Rights Assignment"
                        Value = "Secure Configuration"
                        Details = "Critical rights: $($CheckedRights -join ', ')"
                        RiskLevel = "LOW"
                        Recommendation = ""
                    }
                }
                
                Remove-Item $TempUserRights -Force -ErrorAction SilentlyContinue
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not check user rights assignments: $($_.Exception.Message)" "POLICY"
        }
        
        # Windows Defender Policy Settings
        Write-LogMessage "INFO" "Checking Windows Defender policy settings..." "POLICY"
        try {
            $DefenderPolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -ErrorAction SilentlyContinue
            $DefenderRealTime = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -ErrorAction SilentlyContinue
            
            if ($DefenderPolicy -and $DefenderPolicy.DisableAntiSpyware -eq 1) {
                $Results += [PSCustomObject]@{
                    Category = "Policy"
                    Item = "Windows Defender Policy"
                    Value = "Disabled by Policy"
                    Details = "Windows Defender disabled through Group Policy"
                    RiskLevel = "HIGH"
                    Recommendation = "Ensure antivirus protection is enabled unless replaced by third-party solution"
                }
            } elseif ($DefenderRealTime -and $DefenderRealTime.DisableRealtimeMonitoring -eq 1) {
                $Results += [PSCustomObject]@{
                    Category = "Policy"
                    Item = "Windows Defender Policy"
                    Value = "Real-time Protection Disabled"
                    Details = "Real-time protection disabled by policy"
                    RiskLevel = "HIGH"
                    Recommendation = "Enable real-time antivirus protection"
                }
            } else {
                $Results += [PSCustomObject]@{
                    Category = "Policy"
                    Item = "Windows Defender Policy"
                    Value = "Not Restricted"
                    Details = "No policy restrictions on Windows Defender"
                    RiskLevel = "LOW"
                    Recommendation = ""
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not check Windows Defender policies: $($_.Exception.Message)" "POLICY"
        }
        
        Write-LogMessage "SUCCESS" "Policy analysis completed" "POLICY"
        return $Results
    }
    catch {
        Write-LogMessage "ERROR" "Failed to analyze policies: $($_.Exception.Message)" "POLICY"
        return @()
    }
}

# [NETWORK] Get-NetworkAnalysis - Network configuration and connectivity analysis
# Dependencies: Write-LogMessage
# Order: 130
# WindowsWorkstationAuditor - Network Analysis Module
# Version 1.3.0

function Get-NetworkAnalysis {
    <#
    .SYNOPSIS
        Analyzes network adapters, IP configuration, open ports, and network shares
        
    .DESCRIPTION
        Collects comprehensive network information including network adapter status,
        IP configuration (static vs DHCP), open ports and listening services,
        network shares, and network security settings.
        
    .OUTPUTS
        Array of PSCustomObjects with Category, Item, Value, Details, RiskLevel, Recommendation
        
    .NOTES
        Requires: Write-LogMessage function
        Permissions: Local user (WMI access and network configuration access)
    #>
    
    Write-LogMessage "INFO" "Analyzing network configuration and security..." "NETWORK"
    
    try {
        $Results = @()
        
        # Get network adapters
        try {
            $NetworkAdapters = @(Get-CimInstance -ClassName Win32_NetworkAdapter | Where-Object { $_.NetConnectionStatus -ne $null })
            $ActiveAdapters = @($NetworkAdapters | Where-Object { $_.NetConnectionStatus -eq 2 })
            $DisconnectedAdapters = @($NetworkAdapters | Where-Object { $_.NetConnectionStatus -eq 7 })

            $ActiveCount = $ActiveAdapters.Count
            $DisconnectedCount = $DisconnectedAdapters.Count
            $TotalCount = $NetworkAdapters.Count

            $Results += [PSCustomObject]@{
                Category = "Network"
                Item = "Network Adapters"
                Value = "$ActiveCount active, $DisconnectedCount disconnected"
                Details = "Total adapters: $TotalCount"
                RiskLevel = "INFO"
                Recommendation = ""
            }
            
            foreach ($Adapter in $ActiveAdapters) {
                $AdapterName = $Adapter.Name
                $ConnectionName = $Adapter.NetConnectionID
                $Speed = if ($Adapter.Speed) { "$([math]::Round($Adapter.Speed / 1MB, 0)) Mbps" } else { "Unknown" }
                $MACAddress = $Adapter.MACAddress
                
                $Results += [PSCustomObject]@{
                    Category = "Network"
                    Item = "Active Network Adapter"
                    Value = "Connected"
                    Details = "$ConnectionName ($AdapterName), Speed: $Speed, MAC: $MACAddress"
                    RiskLevel = "INFO"
                    Recommendation = ""
                }
                
                Write-LogMessage "INFO" "Active adapter: $ConnectionName - $Speed" "NETWORK"
            }

            Write-LogMessage "INFO" "Network adapters: $ActiveCount active, $TotalCount total" "NETWORK"
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve network adapter information: $($_.Exception.Message)" "NETWORK"
        }
        
        # Get IP configuration
        try {
            $IPConfigs = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
            
            foreach ($IPConfig in $IPConfigs) {
                $InterfaceIndex = $IPConfig.InterfaceIndex
                $IPAddresses = $IPConfig.IPAddress
                $SubnetMasks = $IPConfig.IPSubnet
                $DefaultGateways = $IPConfig.DefaultIPGateway
                $DHCPEnabled = $IPConfig.DHCPEnabled
                $DNSServers = $IPConfig.DNSServerSearchOrder
                $Description = $IPConfig.Description
                
                if ($IPAddresses) {
                    foreach ($i in 0..($IPAddresses.Count - 1)) {
                        $IPAddress = $IPAddresses[$i]
                        $SubnetMask = if ($SubnetMasks -and $i -lt $SubnetMasks.Count) { $SubnetMasks[$i] } else { "N/A" }
                        
                        # Skip IPv6 link-local addresses for cleaner output
                        if ($IPAddress -match "^fe80:" -or $IPAddress -match "^169\.254\.") {
                            continue
                        }
                        
                        $ConfigType = if ($DHCPEnabled) { "DHCP" } else { "Static" }
                        $IPType = if ($IPAddress -match ":") { "IPv6" } else { "IPv4" }
                        
                        $IPRisk = if (-not $DHCPEnabled -and $IPAddress -match "^192\.168\.|^10\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.") {
                            "LOW"
                        } elseif (-not $DHCPEnabled) {
                            "MEDIUM"
                        } else {
                            "LOW"
                        }
                        
                        $IPRecommendation = if (-not $DHCPEnabled -and $IPType -eq "IPv4") {
                            "Static IP configuration should be documented and managed"
                        } else { "" }
                        
                        $GatewayInfo = if ($DefaultGateways) { "Gateway: $($DefaultGateways[0])" } else { "No gateway" }
                        
                        $Results += [PSCustomObject]@{
                            Category = "Network"
                            Item = "IP Configuration ($IPType)"
                            Value = "$IPAddress ($ConfigType)"
                            Details = "$Description, Subnet: $SubnetMask, $GatewayInfo"
                            RiskLevel = $IPRisk
                            Recommendation = ""
                        }
                        
                        Write-LogMessage "INFO" "IP Config: $IPAddress ($ConfigType) on $Description" "NETWORK"
                    }
                }
                
                # DNS Configuration
                if ($DNSServers) {
                    $DNSList = $DNSServers -join ", "
                    $DNSRisk = "LOW"
                    $DNSRecommendation = ""
                    
                    # Check for potentially insecure DNS servers
                    $PublicDNS = @("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "208.67.222.222", "208.67.220.220")
                    $HasPublicDNS = $DNSServers | Where-Object { $_ -in $PublicDNS }
                    
                    if ($HasPublicDNS) {
                        $DNSRisk = "MEDIUM"
                        $DNSRecommendation = "Consider using internal DNS servers for better security control"
                    }
                    
                    $Results += [PSCustomObject]@{
                        Category = "Network"
                        Item = "DNS Configuration"
                        Value = $DNSServers.Count.ToString() + " servers configured"
                        Details = "DNS Servers: $DNSList"
                        RiskLevel = $DNSRisk
                        Recommendation = ""
                    }
                    
                    Write-LogMessage "INFO" "DNS servers: $DNSList" "NETWORK"
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve IP configuration: $($_.Exception.Message)" "NETWORK"
        }
        
        # Get open ports and listening services
        try {
            $ListeningPorts = Get-NetTCPConnection | Where-Object { $_.State -eq "Listen" } | Sort-Object LocalPort
            $UDPPorts = Get-NetUDPEndpoint | Sort-Object LocalPort
            
            $TCPPortCount = $ListeningPorts.Count
            $UDPPortCount = $UDPPorts.Count
            
            # Check for common risky ports
            $RiskyTCPPorts = @(21, 23, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900)
            $OpenRiskyPorts = $ListeningPorts | Where-Object { $_.LocalPort -in $RiskyTCPPorts }
            
            $PortRisk = if ($OpenRiskyPorts.Count -gt 0) { "HIGH" } 
                       elseif ($TCPPortCount -gt 50) { "MEDIUM" } 
                       else { "LOW" }
            
            $PortRecommendation = if ($OpenRiskyPorts.Count -gt 0) {
                "Review open ports for security risks - found potentially risky ports"
            } elseif ($TCPPortCount -gt 50) {
                "Large number of open ports may increase attack surface"
            } else { "" }
            
            $Results += [PSCustomObject]@{
                Category = "Network"
                Item = "Open Ports"
                Value = "$TCPPortCount TCP, $UDPPortCount UDP"
                Details = "Risky TCP ports open: $($OpenRiskyPorts.Count)"
                RiskLevel = $PortRisk
                Recommendation = ""
            }
            
            # Detail risky ports if found - header + detail format
            $UniqueRiskyPorts = $OpenRiskyPorts | Group-Object LocalPort | ForEach-Object { $_.Group[0] }
            if ($UniqueRiskyPorts.Count -gt 0) {
                # Header entry with compliance message
                $Results += [PSCustomObject]@{
                    Category = "Network"
                    Item = "Risky Open Ports"
                    Value = "$($UniqueRiskyPorts.Count) high-risk ports detected"
                    Details = "Network services that may present security risks"
                    RiskLevel = "HIGH"
                    Recommendation = "Secure or disable unnecessary network services"
                }
                
                # Individual detail entries without compliance duplication
                foreach ($RiskyPort in $UniqueRiskyPorts) {
                    $PortNumber = $RiskyPort.LocalPort
                    $ProcessId = $RiskyPort.OwningProcess
                    $ProcessName = if ($ProcessId) {
                        try { (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue).ProcessName }
                        catch { "Unknown" }
                    } else { "Unknown" }
                    
                    $ServiceName = switch ($PortNumber) {
                        21 { "FTP" }
                        23 { "Telnet" }
                        135 { "RPC Endpoint Mapper" }
                        139 { "NetBIOS Session Service" }
                        445 { "SMB/CIFS" }
                        1433 { "SQL Server" }
                        1521 { "Oracle Database" }
                        3306 { "MySQL" }
                        3389 { "Remote Desktop" }
                        5432 { "PostgreSQL" }
                        5900 { "VNC" }
                        default { "Unknown Service" }
                    }
                    
                    $Results += [PSCustomObject]@{
                        Category = "Network"
                        Item = "Port $PortNumber"
                        Value = "$ServiceName"
                        Details = "Process: $ProcessName (PID: $ProcessId)"
                        RiskLevel = "INFO"
                        Recommendation = ""
                    }
                    
                    Write-LogMessage "WARN" "Risky port open: $PortNumber ($ServiceName) - Process: $ProcessName" "NETWORK"
                }
            }
            
            $UniqueRiskyCount = ($UniqueRiskyPorts | Measure-Object).Count
            Write-LogMessage "INFO" "Open ports: $TCPPortCount TCP, $UDPPortCount UDP ($UniqueRiskyCount risky)" "NETWORK"
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve open port information: $($_.Exception.Message)" "NETWORK"
        }
        
        # Check Remote Desktop (RDP) Configuration - High Risk if enabled
        try {
            # Check if RDP is enabled via registry
            $RDPEnabled = $false
            $RDPPort = 3389  # Default RDP port
            
            try {
                $RDPRegistry = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
                $RDPEnabled = ($RDPRegistry.fDenyTSConnections -eq 0)
            } catch {
                Write-LogMessage "WARN" "Could not check RDP registry settings: $($_.Exception.Message)" "NETWORK"
            }
            
            # Check if RDP port is open/listening
            $RDPListening = $false
            if ($TCPConnections) {
                $RDPListening = $TCPConnections | Where-Object { $_.LocalPort -eq $RDPPort -and $_.State -eq "Listen" }
            }
            
            # Check for custom RDP port
            try {
                $CustomPortRegistry = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "PortNumber" -ErrorAction SilentlyContinue
                if ($CustomPortRegistry -and $CustomPortRegistry.PortNumber -ne 3389) {
                    $RDPPort = $CustomPortRegistry.PortNumber
                    $RDPListening = $TCPConnections | Where-Object { $_.LocalPort -eq $RDPPort -and $_.State -eq "Listen" }
                }
            } catch {
                # Ignore errors checking for custom port
            }
            
            if ($RDPEnabled -or $RDPListening) {
                $RDPStatus = if ($RDPEnabled -and $RDPListening) { "Enabled and Listening" }
                            elseif ($RDPEnabled) { "Enabled (Not Listening)" }
                            else { "Listening (Unknown Config)" }
                
                $PortText = if ($RDPPort -ne 3389) { " on custom port $RDPPort" } else { "" }
                
                $Results += [PSCustomObject]@{
                    Category = "Network"
                    Item = "Remote Desktop (RDP)"
                    Value = $RDPStatus
                    Details = "RDP is accessible$PortText. This provides remote access to the system and should be secured with strong authentication, network restrictions, and monitoring."
                    RiskLevel = "HIGH"
                    Recommendation = "Secure remote access - use VPN, strong auth, restrict source IPs, enable logging"
                }
                
                Write-LogMessage "WARN" "RDP detected: $RDPStatus on port $RDPPort" "NETWORK"
            } else {
                $Results += [PSCustomObject]@{
                    Category = "Network"
                    Item = "Remote Desktop (RDP)"
                    Value = "Disabled"
                    Details = "RDP is properly disabled"
                    RiskLevel = "LOW"
                    Recommendation = ""
                }
                
                Write-LogMessage "INFO" "RDP is disabled - good security posture" "NETWORK"
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not analyze RDP configuration: $($_.Exception.Message)" "NETWORK"
        }
        
        # Get network shares
        try {
            $NetworkShares = Get-CimInstance -ClassName Win32_Share | Where-Object { $_.Type -eq 0 }  # Disk shares only
            $AdminShares = $NetworkShares | Where-Object { $_.Name -match '\$$' }
            $UserShares = $NetworkShares | Where-Object { $_.Name -notmatch '\$$' }
            
            $ShareRisk = if ($UserShares.Count -gt 0) { "MEDIUM" } 
                        elseif ($AdminShares.Count -gt 3) { "MEDIUM" } 
                        else { "LOW" }
            
            $ShareRecommendation = if ($UserShares.Count -gt 0) {
                "Review network share permissions and access controls"
            } else { "" }
            
            $Results += [PSCustomObject]@{
                Category = "Network"
                Item = "Network Shares"
                Value = "$($NetworkShares.Count) total shares"
                Details = "User shares: $($UserShares.Count), Admin shares: $($AdminShares.Count)"
                RiskLevel = $ShareRisk
                Recommendation = ""
            }
            
            foreach ($Share in $UserShares) {
                $ShareName = $Share.Name
                $SharePath = $Share.Path
                $ShareDescription = $Share.Description
                
                $Results += [PSCustomObject]@{
                    Category = "Network"
                    Item = "Network Share"
                    Value = $ShareName
                    Details = "Path: $SharePath, Description: $ShareDescription"
                    RiskLevel = "MEDIUM"
                    Recommendation = "Ensure proper access controls and monitoring for network shares"
                }
                
                Write-LogMessage "INFO" "Network share: $ShareName -> $SharePath" "NETWORK"
            }
            
            Write-LogMessage "INFO" "Network shares: $($NetworkShares.Count) total ($($UserShares.Count) user, $($AdminShares.Count) admin)" "NETWORK"
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve network share information: $($_.Exception.Message)" "NETWORK"
        }
        
        # Get network discovery and file sharing settings
        try {
            $NetworkProfile = Get-NetFirewallProfile | Where-Object { $_.Enabled -eq $true }
            $NetworkDiscovery = Get-NetFirewallRule -DisplayGroup "Network Discovery" | Where-Object { $_.Enabled -eq $true }
            $FileSharing = Get-NetFirewallRule -DisplayGroup "File and Printer Sharing" | Where-Object { $_.Enabled -eq $true }
            
            $DiscoveryEnabled = $NetworkDiscovery.Count -gt 0
            $FileSharingEnabled = $FileSharing.Count -gt 0
            
            $DiscoveryRisk = if ($DiscoveryEnabled) { "MEDIUM" } else { "LOW" }
            $DiscoveryRecommendation = if ($DiscoveryEnabled) {
                "Network discovery should be disabled on untrusted networks"
            } else { "" }
            
            $Results += [PSCustomObject]@{
                Category = "Network"
                Item = "Network Discovery"
                Value = if ($DiscoveryEnabled) { "Enabled" } else { "Disabled" }
                Details = "Network discovery firewall rules: $($NetworkDiscovery.Count) enabled"
                RiskLevel = $DiscoveryRisk
                Recommendation = ""
            }
            
            $SharingRisk = if ($FileSharingEnabled) { "MEDIUM" } else { "LOW" }
            $SharingRecommendation = if ($FileSharingEnabled) {
                "File sharing should be carefully controlled and monitored"
            } else { "" }
            
            $Results += [PSCustomObject]@{
                Category = "Network"
                Item = "File and Printer Sharing"
                Value = if ($FileSharingEnabled) { "Enabled" } else { "Disabled" }
                Details = "File sharing firewall rules: $($FileSharing.Count) enabled"
                RiskLevel = $SharingRisk
                Recommendation = ""
            }
            
            Write-LogMessage "INFO" "Network Discovery: $(if ($DiscoveryEnabled) {'Enabled'} else {'Disabled'}), File Sharing: $(if ($FileSharingEnabled) {'Enabled'} else {'Disabled'})" "NETWORK"
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve network security settings: $($_.Exception.Message)" "NETWORK"
        }
        
        # Get wireless network information if available
        try {
            $WirelessProfiles = netsh wlan show profiles 2>$null | Select-String "All User Profile"
            if ($WirelessProfiles) {
                $ProfileCount = $WirelessProfiles.Count
                
                $Results += [PSCustomObject]@{
                    Category = "Network"
                    Item = "Wireless Profiles"
                    Value = "$ProfileCount saved profiles"
                    Details = "Saved wireless network configurations"
                    RiskLevel = "MEDIUM"
                    Recommendation = "Review wireless network profiles and remove unused ones"
                }
                
                Write-LogMessage "INFO" "Wireless profiles: $ProfileCount saved" "NETWORK"
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve wireless profile information: $($_.Exception.Message)" "NETWORK"
        }
        
        Write-LogMessage "SUCCESS" "Network analysis completed - $($Results.Count) items analyzed" "NETWORK"
        return $Results
    }
    catch {
        Write-LogMessage "ERROR" "Failed to analyze network configuration: $($_.Exception.Message)" "NETWORK"
        return @()
    }
}

# [NETWORK] Get-DNSAnalysis - DNS configuration analysis
# Dependencies: Write-LogMessage
# Order: 131
# WindowsServerAuditor - DNS Analysis Module
# Version 1.3.0

function Get-DNSAnalysis {
    <#
    .SYNOPSIS
        Analyzes DNS server configuration and zone information (read-only)
        
    .DESCRIPTION
        Performs DNS server discovery and analysis including:
        - DNS service status and configuration
        - DNS zones and record counts
        - Forwarder configuration
        - DNS security settings (read-only queries only)
        
    .OUTPUTS
        Array of PSCustomObjects with Category, Item, Value, Details, RiskLevel, Recommendation
        
    .NOTES
        Version: 1.3.0
        Dependencies: Write-LogMessage, Add-RawDataCollection
        Permissions: DNS Admin rights recommended for complete analysis
        Safety: READ-ONLY - No configuration changes made
    #>
    
    Write-LogMessage "INFO" "Analyzing DNS server configuration..." "DNS"
    
    try {
        $Results = @()
        
        # Check if DNS Server role is installed
        try {
            $DNSFeature = Get-WindowsFeature -Name "DNS" -ErrorAction SilentlyContinue
            if (-not $DNSFeature -or $DNSFeature.InstallState -ne "Installed") {
                Write-LogMessage "INFO" "DNS Server role not installed - skipping DNS analysis" "DNS"
                return @([PSCustomObject]@{
                    Category = "DNS"
                    Item = "DNS Server Status"
                    Value = "Not Installed"
                    Details = "DNS Server role is not installed on this system"
                    RiskLevel = "INFO"
                    Recommendation = ""
                })
            }
        }
        catch {
            Write-LogMessage "WARN" "Unable to check DNS feature status: $($_.Exception.Message)" "DNS"
        }
        
        # Check if DnsServer module is available
        if (-not (Get-Module -ListAvailable -Name DnsServer)) {
            Write-LogMessage "WARN" "DnsServer PowerShell module not available - limited analysis" "DNS"
            
            # Check DNS service status only
            $DNSService = Get-Service -Name "DNS" -ErrorAction SilentlyContinue
            if ($DNSService) {
                $Results += [PSCustomObject]@{
                    Category = "DNS"
                    Item = "DNS Service"
                    Value = $DNSService.Status
                    Details = "DNS Server service detected but PowerShell module unavailable for detailed analysis"
                    RiskLevel = if ($DNSService.Status -eq "Running") { "INFO" } else { "HIGH" }
                    Recommendation = "Install DnsServer PowerShell module for complete DNS analysis"
                }
            }
            return $Results
        }
        
        # Import DNS Server module (read-only)
        try {
            Import-Module DnsServer -Force -ErrorAction Stop
            Write-LogMessage "SUCCESS" "DnsServer module loaded" "DNS"
        }
        catch {
            Write-LogMessage "ERROR" "Failed to import DnsServer module: $($_.Exception.Message)" "DNS"
            return @([PSCustomObject]@{
                Category = "DNS"
                Item = "Module Error"
                Value = "Failed to load DnsServer module"
                Details = $_.Exception.Message
                RiskLevel = "ERROR"
                Recommendation = "Resolve DNS module loading issue"
            })
        }
        
        # Get DNS server configuration (read-only)
        Write-LogMessage "INFO" "Retrieving DNS server configuration..." "DNS"
        
        try {
            # DNS server settings
            $DNSServerSettings = Get-DnsServerSetting -ErrorAction SilentlyContinue
            
            if ($DNSServerSettings) {
                $Results += [PSCustomObject]@{
                    Category = "DNS"
                    Item = "DNS Server Status"
                    Value = "Active"
                    Details = "DNS Server is configured and accessible"
                    RiskLevel = "INFO"
                    Recommendation = ""
                }
                
                # Check recursion settings
                $RecursionStatus = if ($DNSServerSettings.EnableRecursion) { "Enabled" } else { "Disabled" }
                $RecursionRisk = if ($DNSServerSettings.EnableRecursion) { "MEDIUM" } else { "LOW" }
                
                $Results += [PSCustomObject]@{
                    Category = "DNS"
                    Item = "DNS Recursion"
                    Value = $RecursionStatus
                    Details = "DNS recursion allows the server to perform lookups for clients"
                    RiskLevel = $RecursionRisk
                    Recommendation = if ($DNSServerSettings.EnableRecursion) { "Consider disabling recursion on public-facing DNS servers" } else { "" }
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Unable to retrieve DNS server settings: $($_.Exception.Message)" "DNS"
        }
        
        # Get DNS zones (read-only enumeration)
        Write-LogMessage "INFO" "Analyzing DNS zones..." "DNS"
        
        try {
            $DNSZones = Get-DnsServerZone -ErrorAction SilentlyContinue
            
            if ($DNSZones) {
                $ZoneData = @()
                
                # Count zones by type
                $PrimaryZones = $DNSZones | Where-Object { $_.ZoneType -eq "Primary" }
                $SecondaryZones = $DNSZones | Where-Object { $_.ZoneType -eq "Secondary" }
                $ForwardZones = $DNSZones | Where-Object { $_.IsReverseLookupZone -eq $false }
                $ReverseZones = $DNSZones | Where-Object { $_.IsReverseLookupZone -eq $true }
                
                $Results += [PSCustomObject]@{
                    Category = "DNS"
                    Item = "DNS Zone Summary"
                    Value = "$($DNSZones.Count) total zones"
                    Details = "Primary: $($PrimaryZones.Count), Secondary: $($SecondaryZones.Count), Forward: $($ForwardZones.Count), Reverse: $($ReverseZones.Count)"
                    RiskLevel = "INFO"
                    Recommendation = ""
                }
                
                # Analyze each zone (limited to first 10 for performance)
                $ZonesToAnalyze = $DNSZones | Select-Object -First 10
                
                foreach ($Zone in $ZonesToAnalyze) {
                    Write-LogMessage "INFO" "Analyzing zone: $($Zone.ZoneName)" "DNS"
                    
                    try {
                        # Get record count (read-only query)
                        $ResourceRecords = Get-DnsServerResourceRecord -ZoneName $Zone.ZoneName -ErrorAction SilentlyContinue
                        $RecordCount = if ($ResourceRecords) { $ResourceRecords.Count } else { 0 }
                        
                        # Determine zone risk level
                        $ZoneRisk = switch ($Zone.ZoneType) {
                            "Primary" { "INFO" }
                            "Secondary" { "LOW" }
                            "Stub" { "LOW" }
                            default { "INFO" }
                        }
                        
                        $Results += [PSCustomObject]@{
                            Category = "DNS"
                            Item = "DNS Zone"
                            Value = "$($Zone.ZoneName) ($($Zone.ZoneType))"
                            Details = "Records: $RecordCount, Reverse lookup: $($Zone.IsReverseLookupZone), Dynamic updates: $($Zone.DynamicUpdate)"
                            RiskLevel = $ZoneRisk
                            Recommendation = ""
                        }
                        
                        # Store zone data for raw export
                        $ZoneData += @{
                            ZoneName = $Zone.ZoneName
                            ZoneType = $Zone.ZoneType
                            IsReverseLookupZone = $Zone.IsReverseLookupZone
                            DynamicUpdate = $Zone.DynamicUpdate
                            RecordCount = $RecordCount
                            ZoneFile = $Zone.ZoneFile
                            IsDsIntegrated = $Zone.IsDsIntegrated
                        }
                        
                        # Check for potentially risky configurations
                        if ($Zone.DynamicUpdate -eq "NonsecureAndSecure") {
                            $Results += [PSCustomObject]@{
                                Category = "DNS"
                                Item = "Dynamic Update Risk"
                                Value = "$($Zone.ZoneName) - Nonsecure updates allowed"
                                Details = "Zone allows both secure and nonsecure dynamic updates"
                                RiskLevel = "MEDIUM"
                                Recommendation = "Consider restricting to secure dynamic updates only"
                            }
                        }
                    }
                    catch {
                        Write-LogMessage "WARN" "Unable to analyze zone $($Zone.ZoneName): $($_.Exception.Message)" "DNS"
                    }
                }
                
                # Add zone data to raw collection
                Add-RawDataCollection -CollectionName "DNSZones" -Data $ZoneData
            } else {
                $Results += [PSCustomObject]@{
                    Category = "DNS"
                    Item = "DNS Zones"
                    Value = "No zones configured"
                    Details = "DNS Server role is installed but no zones are configured"
                    RiskLevel = "MEDIUM"
                    Recommendation = "Configure DNS zones if this server should provide DNS services"
                }
            }
        }
        catch {
            Write-LogMessage "ERROR" "Failed to analyze DNS zones: $($_.Exception.Message)" "DNS"
            $Results += [PSCustomObject]@{
                Category = "DNS"
                Item = "Zone Analysis Error"
                Value = "Failed"
                Details = "Unable to retrieve DNS zone information: $($_.Exception.Message)"
                RiskLevel = "ERROR"
                Recommendation = "Investigate DNS zone access permissions"
            }
        }
        
        # Check DNS forwarders (read-only)
        try {
            $DNSForwarders = Get-DnsServerForwarder -ErrorAction SilentlyContinue
            
            if ($DNSForwarders -and $DNSForwarders.IPAddress -and $DNSForwarders.IPAddress.Count -gt 0) {
                $ForwarderList = $DNSForwarders.IPAddress -join ", "
                $ForwarderTimeout = $DNSForwarders.Timeout
                
                $Results += [PSCustomObject]@{
                    Category = "DNS"
                    Item = "DNS Forwarders"
                    Value = "$($DNSForwarders.IPAddress.Count) forwarders configured"
                    Details = "Forwarders: $ForwarderList, Timeout: $ForwarderTimeout seconds"
                    RiskLevel = "INFO"
                    Recommendation = ""
                }
                
                # Check for public DNS forwarders
                $PublicDNS = @("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "4.2.2.2", "208.67.222.222")
                $PublicForwarders = $DNSForwarders.IPAddress | Where-Object { $_ -in $PublicDNS }
                
                if ($PublicForwarders) {
                    $Results += [PSCustomObject]@{
                        Category = "DNS"
                        Item = "Public DNS Forwarders"
                        Value = "$($PublicForwarders.Count) public forwarders detected"
                        Details = "Public DNS servers: $($PublicForwarders -join ', ')"
                        RiskLevel = "MEDIUM"
                        Recommendation = "Consider using internal or ISP DNS forwarders for better control"
                    }
                }
            } else {
                $Results += [PSCustomObject]@{
                    Category = "DNS"
                    Item = "DNS Forwarders"
                    Value = "No forwarders configured"
                    Details = "DNS server is not configured to forward queries"
                    RiskLevel = "LOW"
                    Recommendation = ""
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Unable to retrieve DNS forwarder configuration: $($_.Exception.Message)" "DNS"
        }
        
        Write-LogMessage "SUCCESS" "DNS analysis completed" "DNS"
        return $Results
        
    }
    catch {
        Write-LogMessage "ERROR" "Failed to analyze DNS configuration: $($_.Exception.Message)" "DNS"
        return @([PSCustomObject]@{
            Category = "DNS"
            Item = "Analysis Error"
            Value = "Failed"
            Details = "Error during DNS analysis: $($_.Exception.Message)"
            RiskLevel = "ERROR"
            Recommendation = "Investigate DNS analysis failure"
        })
    }
}

# [NETWORK] Get-DHCPAnalysis - DHCP configuration analysis
# Dependencies: Write-LogMessage
# Order: 132
# WindowsServerAuditor - DHCP Analysis Module
# Version 1.3.0

function Get-DHCPAnalysis {
    <#
    .SYNOPSIS
        Analyzes DHCP server configuration and scope information
        
    .DESCRIPTION
        Performs comprehensive DHCP server analysis including:
        - DHCP service status and configuration
        - DHCP scopes and utilization
        - Reservations and exclusions
        - DHCP options and security settings
        - Lease duration and renewal settings
        
    .OUTPUTS
        Array of PSCustomObjects with Category, Item, Value, Details, RiskLevel, Recommendation
        
    .NOTES
        Requires: Write-LogMessage function, Add-RawDataCollection function
        Permissions: Local Administrator rights and DHCP Admin rights
        Coverage: Windows Server DHCP role
    #>
    
    Write-LogMessage "INFO" "Analyzing DHCP server configuration..." "DHCP"
    
    try {
        $Results = @()
        
        # Check if DHCP role is installed
        try {
            $DHCPFeature = Get-WindowsFeature -Name "DHCP" -ErrorAction SilentlyContinue
            if (-not $DHCPFeature -or $DHCPFeature.InstallState -ne "Installed") {
                Write-LogMessage "INFO" "DHCP Server role not installed - skipping DHCP analysis" "DHCP"
                return @([PSCustomObject]@{
                    Category = "DHCP"
                    Item = "DHCP Server Status"
                    Value = "Not Installed"
                    Details = "DHCP Server role is not installed on this system"
                    RiskLevel = "INFO"
                    Recommendation = ""
                })
            }
        }
        catch {
            Write-LogMessage "WARN" "Unable to check DHCP feature status: $($_.Exception.Message)" "DHCP"
        }
        
        # Check if DhcpServer module is available
        if (-not (Get-Module -ListAvailable -Name DhcpServer)) {
            Write-LogMessage "WARN" "DhcpServer PowerShell module not available - limited analysis" "DHCP"
            
            # Fall back to service-based detection
            $DHCPService = Get-Service -Name "DHCPServer" -ErrorAction SilentlyContinue
            if ($DHCPService) {
                $Results += [PSCustomObject]@{
                    Category = "DHCP"
                    Item = "DHCP Service"
                    Value = $DHCPService.Status
                    Details = "DHCP Server service detected but PowerShell module unavailable for detailed analysis"
                    RiskLevel = if ($DHCPService.Status -eq "Running") { "INFO" } else { "HIGH" }
                    Recommendation = "Install DhcpServer PowerShell module for complete DHCP analysis"
                }
            }
            return $Results
        }
        
        # Import DHCP Server module
        try {
            Import-Module DhcpServer -Force -ErrorAction Stop
            Write-LogMessage "SUCCESS" "DhcpServer module loaded" "DHCP"
        }
        catch {
            Write-LogMessage "ERROR" "Failed to import DhcpServer module: $($_.Exception.Message)" "DHCP"
            return @([PSCustomObject]@{
                Category = "DHCP"
                Item = "Module Error"
                Value = "Failed to load DhcpServer module"
                Details = $_.Exception.Message
                RiskLevel = "ERROR"
                Recommendation = "Resolve DHCP module loading issue"
            })
        }
        
        # Get DHCP server settings
        Write-LogMessage "INFO" "Retrieving DHCP server configuration..." "DHCP"
        
        try {
            $DHCPServerSettings = Get-DhcpServerSetting -ErrorAction SilentlyContinue
            $DHCPServer = $env:COMPUTERNAME
            
            if ($DHCPServerSettings) {
                $Results += [PSCustomObject]@{
                    Category = "DHCP"
                    Item = "DHCP Server Status"
                    Value = "Active"
                    Details = "DHCP Server is configured and accessible"
                    RiskLevel = "INFO"
                    Recommendation = ""
                }
                
                # DHCP Server Settings
                $Results += [PSCustomObject]@{
                    Category = "DHCP"
                    Item = "Conflict Detection"
                    Value = if ($DHCPServerSettings.ConflictDetectionAttempts -gt 0) { "Enabled ($($DHCPServerSettings.ConflictDetectionAttempts) attempts)" } else { "Disabled" }
                    Details = "Number of ping attempts to detect IP address conflicts before lease assignment"
                    RiskLevel = if ($DHCPServerSettings.ConflictDetectionAttempts -eq 0) { "MEDIUM" } else { "LOW" }
                    Recommendation = if ($DHCPServerSettings.ConflictDetectionAttempts -eq 0) { "Enable conflict detection for network stability" } else { "" }
                }
                
                $Results += [PSCustomObject]@{
                    Category = "DHCP"
                    Item = "DHCP Audit Logging"
                    Value = if ($DHCPServerSettings.AuditLogEnable) { "Enabled" } else { "Disabled" }
                    Details = "DHCP audit logging status for tracking lease assignments and renewals"
                    RiskLevel = if (-not $DHCPServerSettings.AuditLogEnable) { "MEDIUM" } else { "LOW" }
                    Recommendation = if (-not $DHCPServerSettings.AuditLogEnable) { "Enable DHCP audit logging for security monitoring" } else { "" }
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Unable to retrieve DHCP server settings: $($_.Exception.Message)" "DHCP"
        }
        
        # Get DHCP Scopes
        Write-LogMessage "INFO" "Analyzing DHCP scopes..." "DHCP"
        
        try {
            $DHCPScopes = Get-DhcpServerv4Scope -ErrorAction SilentlyContinue
            
            if ($DHCPScopes) {
                $ScopeData = @()
                
                foreach ($Scope in $DHCPScopes) {
                    Write-LogMessage "INFO" "Analyzing scope: $($Scope.Name) ($($Scope.ScopeId))" "DHCP"
                    
                    # Get scope statistics
                    try {
                        $ScopeStats = Get-DhcpServerv4ScopeStatistics -ScopeId $Scope.ScopeId -ErrorAction SilentlyContinue
                        $UtilizationPercent = if ($ScopeStats.InUse -and $ScopeStats.Free) {
                            [math]::Round(($ScopeStats.InUse / ($ScopeStats.InUse + $ScopeStats.Free)) * 100, 2)
                        } else { 0 }
                        
                        # Determine risk level based on utilization
                        $UtilizationRisk = switch ($UtilizationPercent) {
                            {$_ -ge 90} { "HIGH" }
                            {$_ -ge 80} { "MEDIUM" }
                            {$_ -ge 70} { "LOW" }
                            default { "INFO" }
                        }
                        
                        $Results += [PSCustomObject]@{
                            Category = "DHCP"
                            Item = "Scope Utilization"
                            Value = "$($Scope.Name) - $UtilizationPercent%"
                            Details = "Scope: $($Scope.ScopeId), Range: $($Scope.StartRange) - $($Scope.EndRange), In Use: $($ScopeStats.InUse), Available: $($ScopeStats.Free)"
                            RiskLevel = $UtilizationRisk
                            Recommendation = if ($UtilizationPercent -ge 80) { "Consider expanding DHCP scope or reviewing lease duration" } else { "" }
                        }
                        
                        # Get reservations for this scope
                        try {
                            $Reservations = Get-DhcpServerv4Reservation -ScopeId $Scope.ScopeId -ErrorAction SilentlyContinue
                            $ReservationCount = if ($Reservations) { $Reservations.Count } else { 0 }
                            
                            $Results += [PSCustomObject]@{
                                Category = "DHCP"
                                Item = "Scope Reservations"
                                Value = "$($Scope.Name) - $ReservationCount reservations"
                                Details = "Static IP reservations in scope $($Scope.ScopeId)"
                                RiskLevel = "INFO"
                                Recommendation = ""
                            }
                        }
                        catch {
                            Write-LogMessage "WARN" "Unable to get reservations for scope $($Scope.ScopeId): $($_.Exception.Message)" "DHCP"
                        }
                        
                        # Get exclusions for this scope
                        try {
                            $Exclusions = Get-DhcpServerv4ExclusionRange -ScopeId $Scope.ScopeId -ErrorAction SilentlyContinue
                            $ExclusionCount = if ($Exclusions) { $Exclusions.Count } else { 0 }
                            
                            if ($ExclusionCount -gt 0) {
                                $ExclusionRanges = ($Exclusions | ForEach-Object { "$($_.StartRange)-$($_.EndRange)" }) -join ", "
                                $Results += [PSCustomObject]@{
                                    Category = "DHCP"
                                    Item = "Scope Exclusions"
                                    Value = "$($Scope.Name) - $ExclusionCount ranges"
                                    Details = "Excluded ranges: $ExclusionRanges"
                                    RiskLevel = "INFO"
                                    Recommendation = ""
                                }
                            }
                        }
                        catch {
                            Write-LogMessage "WARN" "Unable to get exclusions for scope $($Scope.ScopeId): $($_.Exception.Message)" "DHCP"
                        }
                        
                        # Check lease duration
                        $LeaseDurationDays = $Scope.LeaseDuration.TotalDays
                        $LeaseDurationRisk = if ($LeaseDurationDays -gt 30) { "MEDIUM" } elseif ($LeaseDurationDays -lt 1) { "MEDIUM" } else { "LOW" }
                        
                        $Results += [PSCustomObject]@{
                            Category = "DHCP"
                            Item = "Lease Duration"
                            Value = "$($Scope.Name) - $([math]::Round($LeaseDurationDays, 1)) days"
                            Details = "DHCP lease duration for scope $($Scope.ScopeId)"
                            RiskLevel = $LeaseDurationRisk
                            Recommendation = if ($LeaseDurationDays -gt 30) { "Consider shorter lease duration for better IP management" } elseif ($LeaseDurationDays -lt 1) { "Very short lease duration may cause frequent renewals" } else { "" }
                        }
                        
                        # Store scope data for raw export
                        $ScopeData += @{
                            ScopeId = $Scope.ScopeId
                            Name = $Scope.Name
                            Description = $Scope.Description
                            StartRange = $Scope.StartRange
                            EndRange = $Scope.EndRange
                            SubnetMask = $Scope.SubnetMask
                            LeaseDuration = $Scope.LeaseDuration
                            State = $Scope.State
                            Type = $Scope.Type
                            Statistics = @{
                                InUse = $ScopeStats.InUse
                                Available = $ScopeStats.Free
                                Reserved = $ScopeStats.Reserved
                                Pending = $ScopeStats.Pending
                                UtilizationPercent = $UtilizationPercent
                            }
                            Reservations = $Reservations | ForEach-Object {
                                @{
                                    IPAddress = $_.IPAddress
                                    ClientId = $_.ClientId
                                    Name = $_.Name
                                    Description = $_.Description
                                    Type = $_.Type
                                }
                            }
                            Exclusions = $Exclusions | ForEach-Object {
                                @{
                                    StartRange = $_.StartRange
                                    EndRange = $_.EndRange
                                }
                            }
                        }
                    }
                    catch {
                        Write-LogMessage "WARN" "Unable to get statistics for scope $($Scope.ScopeId): $($_.Exception.Message)" "DHCP"
                        
                        $Results += [PSCustomObject]@{
                            Category = "DHCP"
                            Item = "Scope Configuration"
                            Value = "$($Scope.Name)"
                            Details = "Range: $($Scope.StartRange) - $($Scope.EndRange), Status: $($Scope.State) (Statistics unavailable)"
                            RiskLevel = "INFO"
                            Recommendation = ""
                        }
                    }
                }
                
                # Add raw data collection
                Add-RawDataCollection -CollectionName "DHCPScopes" -Data $ScopeData
                
                # Summary
                $TotalScopes = $DHCPScopes.Count
                $ActiveScopes = ($DHCPScopes | Where-Object { $_.State -eq "Active" }).Count
                
                $Results += [PSCustomObject]@{
                    Category = "DHCP"
                    Item = "DHCP Scope Summary"
                    Value = "$TotalScopes total scopes ($ActiveScopes active)"
                    Details = "Total configured DHCP scopes on this server"
                    RiskLevel = "INFO"
                    Recommendation = ""
                }
            } else {
                $Results += [PSCustomObject]@{
                    Category = "DHCP"
                    Item = "DHCP Scopes"
                    Value = "No scopes configured"
                    Details = "DHCP Server role is installed but no scopes are configured"
                    RiskLevel = "MEDIUM"
                    Recommendation = "Configure DHCP scopes if this server should provide DHCP services"
                }
            }
        }
        catch {
            Write-LogMessage "ERROR" "Failed to analyze DHCP scopes: $($_.Exception.Message)" "DHCP"
            $Results += [PSCustomObject]@{
                Category = "DHCP"
                Item = "Scope Analysis Error"
                Value = "Failed"
                Details = "Unable to retrieve DHCP scope information: $($_.Exception.Message)"
                RiskLevel = "ERROR"
                Recommendation = "Investigate DHCP scope access permissions"
            }
        }
        
        # Check DHCP Options (Server-level)
        try {
            $ServerOptions = Get-DhcpServerv4OptionValue -All -ErrorAction SilentlyContinue
            if ($ServerOptions) {
                $ImportantOptions = @{
                    3 = "Router (Default Gateway)"
                    6 = "DNS Servers"
                    15 = "Domain Name"
                    44 = "WINS Servers"
                    46 = "WINS Node Type"
                }
                
                foreach ($Option in $ServerOptions) {
                    if ($ImportantOptions.ContainsKey($Option.OptionId)) {
                        $OptionName = $ImportantOptions[$Option.OptionId]
                        $OptionValue = $Option.Value -join ", "
                        
                        $Results += [PSCustomObject]@{
                            Category = "DHCP"
                            Item = "Server DHCP Option"
                            Value = "$OptionName"
                            Details = "Option $($Option.OptionId): $OptionValue"
                            RiskLevel = "INFO"
                            Recommendation = ""
                        }
                    }
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Unable to retrieve DHCP server options: $($_.Exception.Message)" "DHCP"
        }
        
        Write-LogMessage "SUCCESS" "DHCP analysis completed" "DHCP"
        return $Results
        
    }
    catch {
        Write-LogMessage "ERROR" "Failed to analyze DHCP configuration: $($_.Exception.Message)" "DHCP"
        return @([PSCustomObject]@{
            Category = "DHCP"
            Item = "Analysis Error"
            Value = "Failed"
            Details = "Error during DHCP analysis: $($_.Exception.Message)"
            RiskLevel = "ERROR"
            Recommendation = "Investigate DHCP analysis failure"
        })
    }
}

# [NETWORK] Get-FileShareAnalysis - File share configuration analysis
# Dependencies: Write-LogMessage
# Order: 133
# WindowsServerAuditor - File Share Analysis Module
# Version 1.3.0

function Get-FileShareAnalysis {
    <#
    .SYNOPSIS
        Analyzes file shares and permissions (read-only discovery)
        
    .DESCRIPTION
        Performs file share discovery and analysis including:
        - SMB/CIFS share enumeration
        - Share permissions and access controls
        - Hidden and administrative shares
        - Share usage patterns and security risks
        
    .OUTPUTS
        Array of PSCustomObjects with Category, Item, Value, Details, RiskLevel, Recommendation
        
    .NOTES
        Version: 1.3.0
        Dependencies: Write-LogMessage, Add-RawDataCollection
        Permissions: Local Admin recommended for complete share analysis
        Safety: READ-ONLY - No share modifications or access changes made
    #>
    
    Write-LogMessage "INFO" "Analyzing file shares..." "FILESHARE"
    
    try {
        $Results = @()
        
        # Check if File Services role is installed
        try {
            $FileServicesFeature = Get-WindowsFeature -Name "File-Services" -ErrorAction SilentlyContinue
            $FileServerFeature = Get-WindowsFeature -Name "FS-FileServer" -ErrorAction SilentlyContinue
            
            $HasFileServices = ($FileServicesFeature -and $FileServicesFeature.InstallState -eq "Installed") -or 
                             ($FileServerFeature -and $FileServerFeature.InstallState -eq "Installed")
            
            if (-not $HasFileServices) {
                Write-LogMessage "INFO" "File Services role not installed - basic share analysis only" "FILESHARE"
            }
        }
        catch {
            Write-LogMessage "WARN" "Unable to check File Services feature: $($_.Exception.Message)" "FILESHARE"
        }
        
        # Get SMB shares using Get-SmbShare (read-only)
        Write-LogMessage "INFO" "Enumerating SMB shares..." "FILESHARE"
        
        try {
            $SMBShares = Get-SmbShare -ErrorAction SilentlyContinue
            
            if ($SMBShares) {
                $ShareData = @()
                
                # Categorize shares
                $UserShares = $SMBShares | Where-Object { $_.Name -notlike "*$" -and $_.ShareType -eq "FileSystemDirectory" }
                $AdminShares = $SMBShares | Where-Object { $_.Name -like "*$" }
                $SpecialShares = $SMBShares | Where-Object { $_.ShareType -ne "FileSystemDirectory" }
                
                $Results += [PSCustomObject]@{
                    Category = "File Shares"
                    Item = "Share Summary"
                    Value = "$($SMBShares.Count) total shares"
                    Details = "User shares: $($UserShares.Count), Admin shares: $($AdminShares.Count), Special: $($SpecialShares.Count)"
                    RiskLevel = "INFO"
                    Recommendation = ""
                }
                
                # Analyze each user share
                foreach ($Share in $UserShares) {
                    Write-LogMessage "INFO" "Analyzing share: $($Share.Name)" "FILESHARE"
                    
                    try {
                        # Get share path and description
                        $SharePath = $Share.Path
                        $ShareDescription = if ($Share.Description) { $Share.Description } else { "No description" }
                        
                        # Determine share risk level based on name and characteristics
                        $ShareRisk = switch -Regex ($Share.Name) {
                            "^(NETLOGON|SYSVOL)$" { "LOW" }  # Domain Controller administrative shares
                            "^(Users?|Home|Profiles?)$" { "LOW" }
                            "^(Public|Everyone|Guest|Temp)$" { "HIGH" }
                            "^(Data|Shared?|Common)$" { "MEDIUM" }
                            "^(Backup|Archive)$" { "MEDIUM" }
                            default { "MEDIUM" }
                        }
                        
                        # Check if share allows anonymous access (basic check)
                        $AnonymousAccess = "Unknown"
                        try {
                            $ShareAccess = Get-SmbShareAccess -Name $Share.Name -ErrorAction SilentlyContinue
                            $EveryoneAccess = $ShareAccess | Where-Object { $_.AccountName -eq "Everyone" }
                            $AnonymousAccess = if ($EveryoneAccess) { "Possible" } else { "Restricted" }
                            
                            # Increase risk if Everyone has access
                            if ($EveryoneAccess) {
                                $ShareRisk = "HIGH"
                            }
                        }
                        catch {
                            Write-LogMessage "WARN" "Unable to check access for share $($Share.Name): $($_.Exception.Message)" "FILESHARE"
                        }
                        
                        $Results += [PSCustomObject]@{
                            Category = "File Shares"
                            Item = "File Share"
                            Value = "$($Share.Name) ($SharePath)"
                            Details = "Description: $ShareDescription, Anonymous access: $AnonymousAccess"
                            RiskLevel = $ShareRisk
                            Recommendation = if ($ShareRisk -eq "HIGH") { "Review share permissions and restrict access" } else { "" }
                        }
                        
                        # Get detailed share access permissions (read-only)
                        try {
                            $ShareAccessList = Get-SmbShareAccess -Name $Share.Name -ErrorAction SilentlyContinue
                            $AccessSummary = @()
                            
                            if ($ShareAccessList) {
                                foreach ($Access in $ShareAccessList) {
                                    $AccessSummary += "$($Access.AccountName):$($Access.AccessRight)"
                                }
                                
                                # Check for risky permissions (exclude Domain Controller administrative shares)
                                $IsDomainControllerShare = $Share.Name -in @("NETLOGON", "SYSVOL")
                                
                                if (-not $IsDomainControllerShare) {
                                    $RiskyAccounts = $ShareAccessList | Where-Object { 
                                        $_.AccountName -in @("Everyone", "Guest", "Anonymous Logon", "Users") -and 
                                        $_.AccessRight -in @("Full", "Change")
                                    }
                                    
                                    if ($RiskyAccounts) {
                                        $Results += [PSCustomObject]@{
                                            Category = "File Shares"
                                            Item = "Share Permission Risk"
                                            Value = "$($Share.Name) - Excessive permissions"
                                            Details = "Risky permissions found: $($RiskyAccounts.AccountName -join ', ') with $($RiskyAccounts.AccessRight -join ', ') access"
                                            RiskLevel = "HIGH"
                                            Recommendation = "Restrict share permissions to specific users or groups"
                                        }
                                    }
                                } else {
                                    # Domain Controller shares - validate they have proper Everyone access
                                    $EveryoneAccess = $ShareAccessList | Where-Object { $_.AccountName -eq "Everyone" }
                                    if ($EveryoneAccess) {
                                        $Results += [PSCustomObject]@{
                                            Category = "File Shares"
                                            Item = "DC Share Configuration"
                                            Value = "$($Share.Name) - Everyone access configured"
                                            Details = "Domain Controller share with required Everyone access for domain functionality"
                                            RiskLevel = "LOW"
                                            Recommendation = ""
                                        }
                                    } else {
                                        $Results += [PSCustomObject]@{
                                            Category = "File Shares"
                                            Item = "DC Share Configuration"
                                            Value = "$($Share.Name) - Missing Everyone access"
                                            Details = "Domain Controller share may be missing required Everyone access for proper domain functionality"
                                            RiskLevel = "HIGH"
                                            Recommendation = "Verify NETLOGON/SYSVOL shares have appropriate Everyone read access"
                                        }
                                    }
                                }
                            }
                            
                            # Store share data for raw export
                            $ShareData += @{
                                Name = $Share.Name
                                Path = $Share.Path
                                Description = $Share.Description
                                ShareType = $Share.ShareType
                                CurrentUsers = $Share.CurrentUsers
                                CachingMode = $Share.CachingMode
                                EncryptData = $Share.EncryptData
                                FolderEnumerationMode = $Share.FolderEnumerationMode
                                Permissions = $AccessSummary
                                RiskLevel = $ShareRisk
                            }
                        }
                        catch {
                            Write-LogMessage "WARN" "Unable to get detailed permissions for share $($Share.Name): $($_.Exception.Message)" "FILESHARE"
                        }
                    }
                    catch {
                        Write-LogMessage "WARN" "Error analyzing share $($Share.Name): $($_.Exception.Message)" "FILESHARE"
                    }
                }
                
                # Check administrative shares
                foreach ($AdminShare in $AdminShares) {
                    $Results += [PSCustomObject]@{
                        Category = "File Shares"
                        Item = "Administrative Share"
                        Value = "$($AdminShare.Name) ($($AdminShare.Path))"
                        Details = "Default administrative share for remote management"
                        RiskLevel = "LOW"
                        Recommendation = ""
                    }
                }
                
                # Add share data to raw collection
                if ($ShareData.Count -gt 0) {
                    Add-RawDataCollection -CollectionName "FileShares" -Data $ShareData
                }
                
            } else {
                $Results += [PSCustomObject]@{
                    Category = "File Shares"
                    Item = "SMB Shares"
                    Value = "No shares found"
                    Details = "No SMB/CIFS shares are currently configured"
                    RiskLevel = "INFO"
                    Recommendation = ""
                }
            }
        }
        catch {
            Write-LogMessage "ERROR" "Failed to enumerate SMB shares: $($_.Exception.Message)" "FILESHARE"
            $Results += [PSCustomObject]@{
                Category = "File Shares"
                Item = "Share Enumeration Error"
                Value = "Failed"
                Details = "Unable to retrieve SMB share information: $($_.Exception.Message)"
                RiskLevel = "ERROR"
                Recommendation = "Investigate file sharing service status"
            }
        }
        
        # Check SMB server settings (read-only)
        try {
            Write-LogMessage "INFO" "Checking SMB server configuration..." "FILESHARE"
            
            $SMBServerConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
            
            if ($SMBServerConfig) {
                # Check SMB version support
                $SMBVersions = @()
                if ($SMBServerConfig.EnableSMB1Protocol) { $SMBVersions += "SMBv1" }
                if ($SMBServerConfig.EnableSMB2Protocol) { $SMBVersions += "SMBv2/3" }
                
                $SMBVersionString = $SMBVersions -join ", "
                
                # SMB1 is a security risk
                $SMBRisk = if ($SMBServerConfig.EnableSMB1Protocol) { "HIGH" } else { "LOW" }
                
                $Results += [PSCustomObject]@{
                    Category = "File Shares"
                    Item = "SMB Protocol Support"
                    Value = $SMBVersionString
                    Details = "SMB signing required: $($SMBServerConfig.RequireSecuritySignature), Encryption supported: $($SMBServerConfig.EncryptData)"
                    RiskLevel = $SMBRisk
                    Recommendation = if ($SMBServerConfig.EnableSMB1Protocol) { "Disable SMBv1 protocol - significant security vulnerability" } else { "SMB configuration is secure" }
                }
                
                # Check SMB signing
                if (-not $SMBServerConfig.RequireSecuritySignature) {
                    $Results += [PSCustomObject]@{
                        Category = "File Shares"
                        Item = "SMB Security Signing"
                        Value = "Not Required"
                        Details = "SMB signing helps prevent man-in-the-middle attacks"
                        RiskLevel = "MEDIUM"
                        Recommendation = "Consider enabling SMB security signing"
                    }
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Unable to check SMB server configuration: $($_.Exception.Message)" "FILESHARE"
        }
        
        # Check Windows file sharing service status (read-only)
        try {
            $LanmanServer = Get-Service -Name "LanmanServer" -ErrorAction SilentlyContinue
            
            if ($LanmanServer) {
                $Results += [PSCustomObject]@{
                    Category = "File Shares"
                    Item = "File Sharing Service"
                    Value = "$($LanmanServer.Status) ($($LanmanServer.StartType))"
                    Details = "Server service (LanmanServer) enables file and print sharing"
                    RiskLevel = if ($LanmanServer.Status -eq "Running") { "INFO" } else { "MEDIUM" }
                    Recommendation = ""
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Unable to check file sharing service: $($_.Exception.Message)" "FILESHARE"
        }
        
        Write-LogMessage "SUCCESS" "File share analysis completed" "FILESHARE"
        return $Results
        
    }
    catch {
        Write-LogMessage "ERROR" "Failed to analyze file shares: $($_.Exception.Message)" "FILESHARE"
        return @([PSCustomObject]@{
            Category = "File Shares"
            Item = "Analysis Error"
            Value = "Failed"
            Details = "Error during file share analysis: $($_.Exception.Message)"
            RiskLevel = "ERROR"
            Recommendation = "Investigate file share analysis failure"
        })
    }
}

# [ENTERPRISE] Get-ActiveDirectoryAnalysis - Active Directory integration analysis
# Dependencies: Write-LogMessage
# Order: 140
# WindowsServerAuditor - Active Directory Analysis Module
# Version 1.3.0

function Get-ActiveDirectoryAnalysis {
    <#
    .SYNOPSIS
        Analyzes Active Directory configuration and objects (read-only discovery)
        
    .DESCRIPTION
        Performs AD discovery and analysis including:
        - Domain Controller role detection
        - User and group counts
        - Domain functional level
        - Forest and domain configuration
        - Password policy settings (read-only queries only)
        
    .OUTPUTS
        Array of PSCustomObjects with Category, Item, Value, Details, RiskLevel, Recommendation
        
    .NOTES
        Version: 1.3.0
        Dependencies: Write-LogMessage, Add-RawDataCollection
        Permissions: Domain User minimum, Domain Admin recommended
        Safety: READ-ONLY - No AD objects created, modified, or deleted
    #>
    
    Write-LogMessage "INFO" "Analyzing Active Directory configuration..." "ACTIVEDIRECTORY"
    
    try {
        $Results = @()
        
        # Check if AD DS role is installed
        try {
            $ADDSFeature = Get-WindowsFeature -Name "AD-Domain-Services" -ErrorAction SilentlyContinue
            if (-not $ADDSFeature -or $ADDSFeature.InstallState -ne "Installed") {
                Write-LogMessage "INFO" "AD DS role not installed - skipping Active Directory analysis" "ACTIVEDIRECTORY"
                return @([PSCustomObject]@{
                    Category = "Active Directory"
                    Item = "AD DS Status"
                    Value = "Not Installed"
                    Details = "Active Directory Domain Services role is not installed on this system"
                    RiskLevel = "INFO"
                    Recommendation = ""
                })
            }
        }
        catch {
            Write-LogMessage "WARN" "Unable to check AD DS feature status: $($_.Exception.Message)" "ACTIVEDIRECTORY"
        }
        
        # Check if ActiveDirectory module is available
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            Write-LogMessage "WARN" "ActiveDirectory PowerShell module not available - limited analysis" "ACTIVEDIRECTORY"
            
            # Check AD services status only
            $ADServices = @("NTDS", "DNS", "Kdc", "W32Time")
            foreach ($ServiceName in $ADServices) {
                $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
                if ($Service) {
                    $Results += [PSCustomObject]@{
                        Category = "Active Directory"
                        Item = "AD Service"
                        Value = "$ServiceName - $($Service.Status)"
                        Details = "Active Directory service status"
                        RiskLevel = if ($Service.Status -eq "Running") { "INFO" } else { "HIGH" }
                        Recommendation = ""
                    }
                }
            }
            
            $Results += [PSCustomObject]@{
                Category = "Active Directory"
                Item = "Module Limitation"
                Value = "ActiveDirectory module unavailable"
                Details = "Install RSAT-AD-PowerShell for complete AD analysis"
                RiskLevel = "MEDIUM"
                Recommendation = "Install ActiveDirectory PowerShell module for detailed analysis"
            }
            
            return $Results
        }
        
        # Import Active Directory module (read-only)
        try {
            Import-Module ActiveDirectory -Force -ErrorAction Stop
            Write-LogMessage "SUCCESS" "ActiveDirectory module loaded" "ACTIVEDIRECTORY"
        }
        catch {
            Write-LogMessage "ERROR" "Failed to import ActiveDirectory module: $($_.Exception.Message)" "ACTIVEDIRECTORY"
            return @([PSCustomObject]@{
                Category = "Active Directory"
                Item = "Module Error"
                Value = "Failed to load ActiveDirectory module"
                Details = $_.Exception.Message
                RiskLevel = "ERROR"
                Recommendation = "Resolve Active Directory module loading issue"
            })
        }
        
        # Get domain information (read-only)
        Write-LogMessage "INFO" "Retrieving domain information..." "ACTIVEDIRECTORY"
        
        try {
            $Domain = Get-ADDomain -ErrorAction SilentlyContinue
            
            if ($Domain) {
                $Results += [PSCustomObject]@{
                    Category = "Active Directory"
                    Item = "Domain Information"
                    Value = $Domain.DNSRoot
                    Details = "NetBIOS: $($Domain.NetBIOSName), Functional Level: $($Domain.DomainMode), PDC: $($Domain.PDCEmulator)"
                    RiskLevel = "INFO"
                    Recommendation = ""
                }
                
                # Check domain functional level
                $DomainLevel = $Domain.DomainMode
                $LevelRisk = switch -Regex ($DomainLevel) {
                    "2003|2008" { "HIGH" }
                    "2012" { "MEDIUM" }
                    "2016|2019|2022" { "LOW" }
                    default { "MEDIUM" }
                }
                
                $Results += [PSCustomObject]@{
                    Category = "Active Directory"
                    Item = "Domain Functional Level"
                    Value = $DomainLevel
                    Details = "Domain functional level determines available AD features"
                    RiskLevel = $LevelRisk
                    Recommendation = if ($LevelRisk -eq "HIGH") { "Consider upgrading domain functional level for security improvements" } else { "" }
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Unable to retrieve domain information: $($_.Exception.Message)" "ACTIVEDIRECTORY"
        }
        
        # Get forest information (read-only)
        try {
            $Forest = Get-ADForest -ErrorAction SilentlyContinue
            
            if ($Forest) {
                $Results += [PSCustomObject]@{
                    Category = "Active Directory"
                    Item = "Forest Information"
                    Value = $Forest.Name
                    Details = "Functional Level: $($Forest.ForestMode), Domains: $($Forest.Domains.Count), Schema Master: $($Forest.SchemaMaster)"
                    RiskLevel = "INFO"
                    Recommendation = ""
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Unable to retrieve forest information: $($_.Exception.Message)" "ACTIVEDIRECTORY"
        }
        
        # Get user counts (read-only, limited query for performance)
        Write-LogMessage "INFO" "Analyzing AD users..." "ACTIVEDIRECTORY"
        
        try {
            # Get user count summary (limited query)
            $AllUsers = Get-ADUser -Filter * -Properties Enabled, PasswordLastSet, LastLogonDate -ResultSetSize 1000 -ErrorAction SilentlyContinue
            
            if ($AllUsers) {
                $EnabledUsers = $AllUsers | Where-Object { $_.Enabled -eq $true }
                $DisabledUsers = $AllUsers | Where-Object { $_.Enabled -eq $false }
                $NeverLoggedOn = $AllUsers | Where-Object { -not $_.LastLogonDate }
                
                # Enhanced stale account analysis (multiple thresholds)
                $StaleDate90 = (Get-Date).AddDays(-90)
                $StaleDate180 = (Get-Date).AddDays(-180)
                $StaleUsers90 = $AllUsers | Where-Object { $_.LastLogonDate -lt $StaleDate90 -and $_.Enabled -eq $true }
                $StaleUsers180 = $AllUsers | Where-Object { $_.LastLogonDate -lt $StaleDate180 -and $_.Enabled -eq $true }
                
                $Results += [PSCustomObject]@{
                    Category = "Active Directory" 
                    Item = "User Account Summary"
                    Value = "$($AllUsers.Count) total users"
                    Details = "Enabled: $($EnabledUsers.Count), Disabled: $($DisabledUsers.Count), Stale 90+ days: $($StaleUsers90.Count), Stale 180+ days: $($StaleUsers180.Count)"
                    RiskLevel = if ($StaleUsers180.Count -gt 5) { "HIGH" } elseif ($StaleUsers90.Count -gt 10) { "MEDIUM" } else { "INFO" }
                    Recommendation = if ($StaleUsers90.Count -gt 0) { "Review and disable stale user accounts - prioritize 180+ day inactive users" } else { "" }
                }
                
                # Separate detailed stale user finding
                if ($StaleUsers90.Count -gt 0) {
                    $Results += [PSCustomObject]@{
                        Category = "Active Directory"
                        Item = "Stale User Accounts"
                        Value = "$($StaleUsers90.Count) users inactive 90+ days ($($StaleUsers180.Count) inactive 180+ days)"
                        Details = "Enabled user accounts with no recent logon activity require cleanup review"
                        RiskLevel = if ($StaleUsers180.Count -gt 5) { "HIGH" } elseif ($StaleUsers90.Count -gt 15) { "MEDIUM" } else { "LOW" }
                        Recommendation = "Disable or remove stale user accounts per company retention policy"
                    }
                }
                
                # Check for users with old passwords
                $OldPasswordDate = (Get-Date).AddDays(-180)
                $OldPasswords = $AllUsers | Where-Object { $_.PasswordLastSet -lt $OldPasswordDate -and $_.Enabled -eq $true }
                
                if ($OldPasswords.Count -gt 0) {
                    $Results += [PSCustomObject]@{
                        Category = "Active Directory"
                        Item = "Password Age Analysis"
                        Value = "$($OldPasswords.Count) users with old passwords"
                        Details = "Users with passwords older than 180 days"
                        RiskLevel = "MEDIUM"
                        Recommendation = "Review password policy and encourage regular password changes"
                    }
                }
                
                # Store limited user data for raw export (no sensitive info)
                $UserSummaryData = @{
                    TotalUsers = $AllUsers.Count
                    EnabledUsers = $EnabledUsers.Count
                    DisabledUsers = $DisabledUsers.Count
                    StaleUsers90Days = $StaleUsers90.Count
                    StaleUsers180Days = $StaleUsers180.Count
                    OldPasswordUsers = $OldPasswords.Count
                    NeverLoggedOnUsers = $NeverLoggedOn.Count
                }
                
                Add-RawDataCollection -CollectionName "ADUserSummary" -Data $UserSummaryData
            }
        }
        catch {
            Write-LogMessage "WARN" "Unable to analyze AD users: $($_.Exception.Message)" "ACTIVEDIRECTORY"
        }
        
        # Get computer accounts for stale analysis (read-only, limited query for performance)
        Write-LogMessage "INFO" "Analyzing AD computers..." "ACTIVEDIRECTORY"
        
        try {
            # Get computer account summary (limited query)
            $AllComputers = Get-ADComputer -Filter * -Properties Enabled, LastLogonDate, OperatingSystem, OperatingSystemVersion -ResultSetSize 500 -ErrorAction SilentlyContinue
            
            if ($AllComputers) {
                $EnabledComputers = $AllComputers | Where-Object { $_.Enabled -eq $true }
                $DisabledComputers = $AllComputers | Where-Object { $_.Enabled -eq $false }
                $NeverLoggedOnComputers = $AllComputers | Where-Object { -not $_.LastLogonDate }
                
                # Enhanced stale computer analysis (multiple thresholds) 
                $StaleDate90 = (Get-Date).AddDays(-90)
                $StaleDate180 = (Get-Date).AddDays(-180)
                $StaleComputers90 = $AllComputers | Where-Object { $_.LastLogonDate -lt $StaleDate90 -and $_.Enabled -eq $true }
                $StaleComputers180 = $AllComputers | Where-Object { $_.LastLogonDate -lt $StaleDate180 -and $_.Enabled -eq $true }
                
                $Results += [PSCustomObject]@{
                    Category = "Active Directory"
                    Item = "Computer Account Summary"
                    Value = "$($AllComputers.Count) total computers"
                    Details = "Enabled: $($EnabledComputers.Count), Disabled: $($DisabledComputers.Count), Stale 90+ days: $($StaleComputers90.Count), Stale 180+ days: $($StaleComputers180.Count)"
                    RiskLevel = if ($StaleComputers180.Count -gt 3) { "HIGH" } elseif ($StaleComputers90.Count -gt 5) { "MEDIUM" } else { "INFO" }
                    Recommendation = if ($StaleComputers90.Count -gt 0) { "Review and remove stale computer accounts - prioritize 180+ day inactive computers" } else { "" }
                }
                
                # Separate detailed stale computer finding
                if ($StaleComputers90.Count -gt 0) {
                    $Results += [PSCustomObject]@{
                        Category = "Active Directory"
                        Item = "Stale Computer Accounts"
                        Value = "$($StaleComputers90.Count) computers inactive 90+ days ($($StaleComputers180.Count) inactive 180+ days)"
                        Details = "Enabled computer accounts with no recent domain logon activity require cleanup review"
                        RiskLevel = if ($StaleComputers180.Count -gt 3) { "HIGH" } elseif ($StaleComputers90.Count -gt 10) { "MEDIUM" } else { "LOW" }
                        Recommendation = "Remove stale computer accounts to maintain AD hygiene and security"
                    }
                }
                
                # Operating system analysis
                $OSCounts = $AllComputers | Where-Object { $_.OperatingSystem } | Group-Object OperatingSystem | Sort-Object Count -Descending
                if ($OSCounts) {
                    $OSBreakdown = ($OSCounts | Select-Object -First 5 | ForEach-Object { "$($_.Name): $($_.Count)" }) -join ", "
                    $Results += [PSCustomObject]@{
                        Category = "Active Directory"
                        Item = "Computer Operating Systems"
                        Value = "$($OSCounts.Count) different OS types"
                        Details = "Top OS types: $OSBreakdown"
                        RiskLevel = "INFO"
                        Recommendation = ""
                    }
                }
                
                # Store computer data for raw export (no sensitive info)
                $ComputerSummaryData = @{
                    TotalComputers = $AllComputers.Count
                    EnabledComputers = $EnabledComputers.Count
                    DisabledComputers = $DisabledComputers.Count
                    StaleComputers90Days = $StaleComputers90.Count
                    StaleComputers180Days = $StaleComputers180.Count
                    NeverLoggedOnComputers = $NeverLoggedOnComputers.Count
                    OperatingSystemBreakdown = $OSCounts | Select-Object Name, Count | ForEach-Object { @{ OS = $_.Name; Count = $_.Count } }
                }
                
                Add-RawDataCollection -CollectionName "ADComputerSummary" -Data $ComputerSummaryData
            }
        }
        catch {
            Write-LogMessage "WARN" "Unable to analyze AD computers: $($_.Exception.Message)" "ACTIVEDIRECTORY"
        }
        
        # Get group information (read-only, limited query)
        try {
            Write-LogMessage "INFO" "Analyzing AD groups..." "ACTIVEDIRECTORY"
            
            $AllGroups = Get-ADGroup -Filter * -Properties Members -ResultSetSize 500 -ErrorAction SilentlyContinue
            
            if ($AllGroups) {
                # Check privileged groups
                $PrivilegedGroups = @(
                    "Domain Admins", "Enterprise Admins", "Schema Admins", 
                    "Administrators", "Account Operators", "Backup Operators"
                )
                
                $PrivGroupData = @()
                
                foreach ($GroupName in $PrivilegedGroups) {
                    $Group = $AllGroups | Where-Object { $_.Name -eq $GroupName }
                    if ($Group) {
                        $MemberCount = if ($Group.Members) { $Group.Members.Count } else { 0 }
                        $GroupRisk = switch ($GroupName) {
                            "Domain Admins" { if ($MemberCount -gt 5) { "HIGH" } else { "MEDIUM" } }
                            "Enterprise Admins" { if ($MemberCount -gt 2) { "HIGH" } else { "MEDIUM" } }
                            "Schema Admins" { if ($MemberCount -gt 1) { "HIGH" } else { "LOW" } }
                            default { if ($MemberCount -gt 10) { "MEDIUM" } else { "LOW" } }
                        }
                        
                        $Results += [PSCustomObject]@{
                            Category = "Active Directory"
                            Item = "Privileged Group"
                            Value = "$GroupName - $MemberCount members"
                            Details = "High-privilege group membership count"
                            RiskLevel = $GroupRisk
                            Recommendation = if ($GroupRisk -eq "HIGH") { "Review and minimize privileged group membership" } else { "" }
                        }
                        
                        $PrivGroupData += @{
                            GroupName = $GroupName
                            MemberCount = $MemberCount
                            RiskLevel = $GroupRisk
                        }
                    }
                }
                
                Add-RawDataCollection -CollectionName "ADPrivilegedGroups" -Data $PrivGroupData
                
                $Results += [PSCustomObject]@{
                    Category = "Active Directory"
                    Item = "Group Summary"
                    Value = "$($AllGroups.Count) total groups"
                    Details = "Security groups, distribution lists, and built-in groups"
                    RiskLevel = "INFO"
                    Recommendation = ""
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Unable to analyze AD groups: $($_.Exception.Message)" "ACTIVEDIRECTORY"
        }
        
        # AD Health Monitoring - DC Diagnostics
        Write-LogMessage "INFO" "Performing AD health diagnostics..." "ACTIVEDIRECTORY"
        
        try {
            # Check if this is a Domain Controller
            $IsDC = $false
            try {
                $DCInfo = Get-ADDomainController -Identity $env:COMPUTERNAME -ErrorAction SilentlyContinue
                $IsDC = $DCInfo -ne $null
            }
            catch {
                # Not a DC or no permissions
            }
            
            if ($IsDC) {
                Write-LogMessage "INFO" "Domain Controller detected - running DC health checks..." "ACTIVEDIRECTORY"
                
                # Run dcdiag tests (read-only diagnostic)
                try {
                    $DCDiagOutput = & dcdiag.exe /q /c 2>&1
                    $DCDiagExitCode = $LASTEXITCODE
                    
                    if ($DCDiagExitCode -eq 0) {
                        $Results += [PSCustomObject]@{
                            Category = "Active Directory"
                            Item = "Domain Controller Health"
                            Value = "All tests passed"
                            Details = "DCDiag completed successfully with no critical errors"
                            RiskLevel = "LOW"
                            Recommendation = ""
                        }
                        Write-LogMessage "SUCCESS" "DCDiag tests passed" "ACTIVEDIRECTORY"
                    } else {
                        # Parse dcdiag output for specific issues
                        $DCDiagLines = $DCDiagOutput -split "`n" | Where-Object { $_ -match "failed|error|warning" } | Select-Object -First 3
                        $DCDiagSummary = if ($DCDiagLines) { $DCDiagLines -join "; " } else { "Unknown dcdiag issues detected" }
                        
                        $Results += [PSCustomObject]@{
                            Category = "Active Directory"
                            Item = "Domain Controller Health"
                            Value = "Issues detected"
                            Details = "DCDiag found problems: $DCDiagSummary"
                            RiskLevel = "HIGH"
                            Recommendation = "Investigate and resolve Domain Controller health issues"
                        }
                        Write-LogMessage "WARN" "DCDiag detected issues: $DCDiagSummary" "ACTIVEDIRECTORY"
                    }
                }
                catch {
                    $Results += [PSCustomObject]@{
                        Category = "Active Directory"
                        Item = "Domain Controller Health"
                        Value = "Cannot run diagnostics"
                        Details = "Unable to execute dcdiag: $($_.Exception.Message)"
                        RiskLevel = "MEDIUM"
                        Recommendation = "Ensure dcdiag.exe is available and accessible"
                    }
                    Write-LogMessage "WARN" "Cannot run dcdiag: $($_.Exception.Message)" "ACTIVEDIRECTORY"
                }
                
                # Check AD replication status
                try {
                    Write-LogMessage "INFO" "Checking AD replication status..." "ACTIVEDIRECTORY"
                    $ReplPartners = Get-ADReplicationPartnerMetadata -Target $env:COMPUTERNAME -ErrorAction SilentlyContinue
                    
                    if ($ReplPartners) {
                        $TotalPartners = $ReplPartners.Count
                        $RecentFailures = $ReplPartners | Where-Object { $_.LastReplicationResult -ne 0 }
                        $OldReplications = $ReplPartners | Where-Object { $_.LastReplicationAttempt -lt (Get-Date).AddHours(-24) }
                        
                        if ($RecentFailures.Count -gt 0) {
                            $FailureDetails = ($RecentFailures | Select-Object -First 3 | ForEach-Object { "$($_.Partner) (Error: $($_.LastReplicationResult))" }) -join ", "
                            $Results += [PSCustomObject]@{
                                Category = "Active Directory"
                                Item = "AD Replication Status"
                                Value = "$($RecentFailures.Count) of $TotalPartners partners have failures"
                                Details = "Replication failures: $FailureDetails"
                                RiskLevel = "HIGH"
                                Recommendation = "Investigate and resolve Active Directory replication failures immediately"
                            }
                            Write-LogMessage "ERROR" "AD replication failures detected: $($RecentFailures.Count) partners" "ACTIVEDIRECTORY"
                        } elseif ($OldReplications.Count -gt 0) {
                            $Results += [PSCustomObject]@{
                                Category = "Active Directory"
                                Item = "AD Replication Status"
                                Value = "$($OldReplications.Count) of $TotalPartners partners have stale replication"
                                Details = "Some replication partners haven't replicated in 24+ hours"
                                RiskLevel = "MEDIUM"
                                Recommendation = "Monitor replication frequency and investigate delayed replication"
                            }
                            Write-LogMessage "WARN" "Stale AD replication detected: $($OldReplications.Count) partners" "ACTIVEDIRECTORY"
                        } else {
                            $Results += [PSCustomObject]@{
                                Category = "Active Directory"
                                Item = "AD Replication Status"
                                Value = "Healthy ($TotalPartners replication partners)"
                                Details = "All replication partners are functioning normally"
                                RiskLevel = "LOW"
                                Recommendation = ""
                            }
                            Write-LogMessage "SUCCESS" "AD replication healthy: $TotalPartners partners" "ACTIVEDIRECTORY"
                        }
                        
                        # Store replication data for raw export
                        $ReplSummaryData = @{
                            TotalPartners = $TotalPartners
                            FailedPartners = $RecentFailures.Count
                            StalePartners = $OldReplications.Count
                            ReplicationPartners = $ReplPartners | Select-Object Partner, LastReplicationAttempt, LastReplicationResult | ForEach-Object { 
                                @{ 
                                    Partner = $_.Partner; 
                                    LastAttempt = $_.LastReplicationAttempt; 
                                    LastResult = $_.LastReplicationResult 
                                } 
                            }
                        }
                        Add-RawDataCollection -CollectionName "ADReplicationStatus" -Data $ReplSummaryData
                    }
                }
                catch {
                    Write-LogMessage "WARN" "Unable to check AD replication: $($_.Exception.Message)" "ACTIVEDIRECTORY"
                }
                
                # Check FSMO roles if this is a DC
                try {
                    Write-LogMessage "INFO" "Checking FSMO role holders..." "ACTIVEDIRECTORY"
                    $Forest = Get-ADForest -ErrorAction SilentlyContinue
                    $Domain = Get-ADDomain -ErrorAction SilentlyContinue
                    
                    if ($Forest -and $Domain) {
                        $FSMORoles = @()
                        
                        # Forest-level FSMO roles
                        if ($Forest.SchemaMaster) { $FSMORoles += "Schema Master: $($Forest.SchemaMaster)" }
                        if ($Forest.DomainNamingMaster) { $FSMORoles += "Domain Naming Master: $($Forest.DomainNamingMaster)" }
                        
                        # Domain-level FSMO roles
                        if ($Domain.PDCEmulator) { $FSMORoles += "PDC Emulator: $($Domain.PDCEmulator)" }
                        if ($Domain.RIDMaster) { $FSMORoles += "RID Master: $($Domain.RIDMaster)" }
                        if ($Domain.InfrastructureMaster) { $FSMORoles += "Infrastructure Master: $($Domain.InfrastructureMaster)" }
                        
                        $Results += [PSCustomObject]@{
                            Category = "Active Directory"
                            Item = "FSMO Role Status"
                            Value = "$($FSMORoles.Count) roles identified"
                            Details = $FSMORoles -join "; "
                            RiskLevel = "INFO"
                            Recommendation = ""
                        }
                        Write-LogMessage "SUCCESS" "FSMO roles identified: $($FSMORoles.Count)" "ACTIVEDIRECTORY"
                    }
                }
                catch {
                    Write-LogMessage "WARN" "Unable to check FSMO roles: $($_.Exception.Message)" "ACTIVEDIRECTORY"
                }
            } else {
                Write-LogMessage "INFO" "Non-DC system - skipping DC-specific health checks" "ACTIVEDIRECTORY"
                $Results += [PSCustomObject]@{
                    Category = "Active Directory"
                    Item = "AD Health Monitoring"
                    Value = "Not a Domain Controller"
                    Details = "Advanced AD health monitoring requires Domain Controller role"
                    RiskLevel = "INFO"
                    Recommendation = ""
                }
            }
        }
        catch {
            Write-LogMessage "ERROR" "AD health monitoring failed: $($_.Exception.Message)" "ACTIVEDIRECTORY"
        }
        
        # Get password policy (read-only)
        try {
            $PasswordPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue
            
            if ($PasswordPolicy) {
                $PolicyRisk = "LOW"
                $PolicyIssues = @()
                
                # Check password policy settings
                if ($PasswordPolicy.MinPasswordLength -lt 8) {
                    $PolicyRisk = "HIGH"
                    $PolicyIssues += "Minimum length too short"
                }
                
                if ($PasswordPolicy.MaxPasswordAge.Days -gt 90) {
                    $PolicyRisk = "MEDIUM"
                    $PolicyIssues += "Maximum age too long"
                }
                
                if ($PasswordPolicy.ComplexityEnabled -eq $false) {
                    $PolicyRisk = "HIGH"
                    $PolicyIssues += "Complexity not required"
                }
                
                $PolicyDetails = "Min Length: $($PasswordPolicy.MinPasswordLength), Max Age: $($PasswordPolicy.MaxPasswordAge.Days) days, Complexity: $($PasswordPolicy.ComplexityEnabled)"
                
                $Results += [PSCustomObject]@{
                    Category = "Active Directory"
                    Item = "Password Policy"
                    Value = if ($PolicyIssues.Count -gt 0) { "Issues detected" } else { "Compliant" }
                    Details = $PolicyDetails
                    RiskLevel = $PolicyRisk
                    Recommendation = if ($PolicyIssues.Count -gt 0) { "Strengthen password policy: $($PolicyIssues -join ', ')" } else { "" }
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Unable to retrieve password policy: $($_.Exception.Message)" "ACTIVEDIRECTORY"
        }
        
        Write-LogMessage "SUCCESS" "Active Directory analysis completed" "ACTIVEDIRECTORY"
        return $Results
        
    }
    catch {
        Write-LogMessage "ERROR" "Failed to analyze Active Directory: $($_.Exception.Message)" "ACTIVEDIRECTORY"
        return @([PSCustomObject]@{
            Category = "Active Directory"
            Item = "Analysis Error"
            Value = "Failed"
            Details = "Error during Active Directory analysis: $($_.Exception.Message)"
            RiskLevel = "ERROR"
            Recommendation = "Investigate Active Directory analysis failure"
        })
    }
}

# [ENTERPRISE] Get-ServerRoleAnalysis - Windows Server role analysis
# Dependencies: Write-LogMessage
# Order: 141
# WindowsServerAuditor - Server Role Analysis Module
# Version 1.3.0

function Get-ServerRoleAnalysis {
    <#
    .SYNOPSIS
        Analyzes Windows Server roles and features installed on the system
        
    .DESCRIPTION
        Performs comprehensive server role and feature analysis including:
        - Installed Windows Server roles and features
        - Role service details and configuration status
        - Critical service dependencies for each role
        - Common server role security recommendations
        
    .OUTPUTS
        Array of PSCustomObjects with Category, Item, Value, Details, RiskLevel, Recommendation
        
    .NOTES
        Requires: Write-LogMessage function, Add-RawDataCollection function
        Permissions: Local Administrator rights recommended
        Coverage: Windows Server 2016+, PowerShell 5.0+
    #>
    
    Write-LogMessage "INFO" "Analyzing Windows Server roles and features..." "SERVERROLES"
    
    try {
        $Results = @()
        
        # Check if Server Manager module is available
        if (-not (Get-Module -ListAvailable -Name ServerManager)) {
            Write-LogMessage "WARN" "ServerManager module not available - limited role detection" "SERVERROLES"
            
            # Fall back to basic service detection
            $Results += [PSCustomObject]@{
                Category = "Server Roles"
                Item = "Role Detection"
                Value = "Limited - ServerManager module unavailable"
                Details = "Cannot perform comprehensive role analysis. Using service-based detection."
                RiskLevel = "WARN"
                Recommendation = "Install ServerManager PowerShell module for complete analysis"
            }
            
            return $Results
        }
        
        # Get installed Windows Features
        Write-LogMessage "INFO" "Querying Windows Features..." "SERVERROLES"
        $WindowsFeatures = Get-WindowsFeature | Where-Object { $_.InstallState -eq "Installed" }
        
        # Categorize roles by type
        $ServerRoles = @()
        $ServerFeatures = @()
        $RoleServices = @()
        
        foreach ($Feature in $WindowsFeatures) {
            switch ($Feature.FeatureType) {
                "Role" { 
                    $ServerRoles += $Feature
                    Write-LogMessage "INFO" "Found installed role: $($Feature.DisplayName)" "SERVERROLES"
                }
                "Feature" { $ServerFeatures += $Feature }
                "Role Service" { $RoleServices += $Feature }
            }
        }
        
        # Create raw data collection
        $RoleAnalysisData = @{
            InstalledRoles = $ServerRoles | ForEach-Object {
                @{
                    Name = $_.Name
                    DisplayName = $_.DisplayName
                    InstallState = $_.InstallState
                    FeatureType = $_.FeatureType
                    Path = $_.Path
                    Depth = $_.Depth
                    DependsOn = $_.DependsOn
                    Parent = $_.Parent
                    ServerComponentDescriptor = $_.ServerComponentDescriptor
                }
            }
            InstalledFeatures = $ServerFeatures | ForEach-Object {
                @{
                    Name = $_.Name
                    DisplayName = $_.DisplayName
                    InstallState = $_.InstallState
                    FeatureType = $_.FeatureType
                }
            }
            RoleServices = $RoleServices | ForEach-Object {
                @{
                    Name = $_.Name
                    DisplayName = $_.DisplayName
                    InstallState = $_.InstallState
                    Parent = $_.Parent
                }
            }
        }
        
        Add-RawDataCollection -CollectionName "ServerRoleAnalysis" -Data $RoleAnalysisData
        
        # Summary of installed roles
        $Results += [PSCustomObject]@{
            Category = "Server Roles"
            Item = "Installed Roles Count"
            Value = $ServerRoles.Count
            Details = "Windows Server roles currently installed and active"
            RiskLevel = "INFO"
            Recommendation = ""
        }
        
        $Results += [PSCustomObject]@{
            Category = "Server Roles"
            Item = "Installed Features Count"
            Value = $ServerFeatures.Count
            Details = "Windows Server features currently installed"
            RiskLevel = "INFO"
            Recommendation = ""
        }
        
        # Analyze specific critical roles
        $CriticalRoles = @{
            "AD-Domain-Services" = @{
                Name = "Active Directory Domain Services"
                Risk = "HIGH"
                Description = "Domain Controller - Critical infrastructure component"
                Recommendation = "Ensure proper backup, monitoring, and security hardening"
            }
            "DHCP" = @{
                Name = "DHCP Server"
                Risk = "MEDIUM"
                Description = "Network DHCP service"
                Recommendation = "Monitor scope utilization and secure DHCP settings"
            }
            "DNS" = @{
                Name = "DNS Server"
                Risk = "MEDIUM"
                Description = "Domain Name System service"
                Recommendation = "Secure DNS configuration and monitor for unauthorized changes"
            }
            "Web-Server" = @{
                Name = "Internet Information Services (IIS)"
                Risk = "MEDIUM"
                Description = "Web server role"
                Recommendation = "Regular security updates and secure configuration required"
            }
            "File-Services" = @{
                Name = "File and Storage Services"
                Risk = "MEDIUM"
                Description = "File server capabilities"
                Recommendation = "Monitor file share permissions and access logs"
            }
            "Print-Services" = @{
                Name = "Print and Document Services"
                Risk = "LOW"
                Description = "Print server capabilities"
                Recommendation = "Review print server security and driver updates"
            }
            "Remote-Desktop-Services" = @{
                Name = "Remote Desktop Services"
                Risk = "HIGH"
                Description = "Terminal services and remote access"
                Recommendation = "Secure RDS configuration and monitor remote access"
            }
            "Hyper-V" = @{
                Name = "Hyper-V"
                Risk = "HIGH"
                Description = "Virtualization platform"
                Recommendation = "Secure hypervisor and monitor VM security"
            }
            "ADCS-Cert-Authority" = @{
                Name = "Active Directory Certificate Services"
                Risk = "HIGH"
                Description = "Certificate Authority services"
                Recommendation = "Secure CA configuration and certificate management"
            }
            "ADFS-Federation" = @{
                Name = "Active Directory Federation Services"
                Risk = "HIGH"
                Description = "Identity federation services"
                Recommendation = "Secure ADFS configuration and monitor authentication"
            }
            "WDS" = @{
                Name = "Windows Deployment Services"
                Risk = "MEDIUM"
                Description = "Network-based OS deployment"
                Recommendation = "Secure WDS configuration and image management"
            }
            "WSUS" = @{
                Name = "Windows Server Update Services"
                Risk = "MEDIUM"
                Description = "Windows update distribution"
                Recommendation = "Monitor update approval and distribution"
            }
        }
        
        # Check each critical role
        foreach ($RoleName in $CriticalRoles.Keys) {
            $RoleInfo = $CriticalRoles[$RoleName]
            $InstalledRole = $ServerRoles | Where-Object { $_.Name -eq $RoleName }
            
            if ($InstalledRole) {
                # Get related role services
                $RelatedServices = $RoleServices | Where-Object { $_.Parent -eq $RoleName }
                $ServiceDetails = if ($RelatedServices) {
                    "Role services: $($RelatedServices.DisplayName -join ', ')"
                } else {
                    "No additional role services detected"
                }
                
                $Results += [PSCustomObject]@{
                    Category = "Server Roles"
                    Item = "Critical Role Detected"
                    Value = $RoleInfo.Name
                    Details = "$($RoleInfo.Description). $ServiceDetails"
                    RiskLevel = $RoleInfo.Risk
                    Recommendation = $RoleInfo.Recommendation
                }
            }
        }
        
        # Check for potentially risky feature combinations
        $RiskyFeatures = @()
        
        # Web server with AD DS (domain controller serving web content)
        if (($ServerRoles | Where-Object { $_.Name -eq "Web-Server" }) -and 
            ($ServerRoles | Where-Object { $_.Name -eq "AD-Domain-Services" })) {
            $RiskyFeatures += "Web server installed on Domain Controller"
        }
        
        # Multiple critical roles on single server
        $CriticalRoleCount = ($ServerRoles | Where-Object { $_.Name -in $CriticalRoles.Keys }).Count
        if ($CriticalRoleCount -gt 3) {
            $RiskyFeatures += "Multiple critical roles on single server ($CriticalRoleCount roles)"
        }
        
        # Report risky configurations
        foreach ($RiskyConfig in $RiskyFeatures) {
            $Results += [PSCustomObject]@{
                Category = "Server Roles"
                Item = "Configuration Risk"
                Value = $RiskyConfig
                Details = "Review server role separation and security implications"
                RiskLevel = "HIGH"
                Recommendation = "Consider role separation for security and performance"
            }
        }
        
        # List all installed roles for reference
        if ($ServerRoles.Count -gt 0) {
            $RoleList = ($ServerRoles | ForEach-Object { $_.DisplayName }) -join ", "
            $Results += [PSCustomObject]@{
                Category = "Server Roles"
                Item = "Complete Role List"
                Value = "See Details"
                Details = "Installed roles: $RoleList"
                RiskLevel = "INFO"
                Recommendation = ""
            }
        }
        
        # Check for common optional features that might be security relevant
        $SecurityRelevantFeatures = @{
            "Telnet-Client" = "Telnet Client - Insecure protocol"
            "TFTP-Client" = "TFTP Client - Insecure file transfer"
            "SMB1Protocol" = "SMB v1.0/CIFS File Sharing Support - Deprecated protocol"
            "PowerShell-V2" = "Windows PowerShell 2.0 Engine - Legacy version"
            "Internet-Explorer-Optional-amd64" = "Internet Explorer 11 - Legacy browser"
        }
        
        foreach ($FeatureName in $SecurityRelevantFeatures.Keys) {
            $Feature = $ServerFeatures | Where-Object { $_.Name -eq $FeatureName }
            if ($Feature) {
                $Results += [PSCustomObject]@{
                    Category = "Server Roles"
                    Item = "Security-Relevant Feature"
                    Value = $Feature.DisplayName
                    Details = $SecurityRelevantFeatures[$FeatureName]
                    RiskLevel = "MEDIUM"
                    Recommendation = "Review necessity and consider removal if unused"
                }
            }
        }
        
        Write-LogMessage "SUCCESS" "Server role analysis completed - $($ServerRoles.Count) roles, $($ServerFeatures.Count) features detected" "SERVERROLES"
        return $Results
        
    }
    catch {
        Write-LogMessage "ERROR" "Failed to analyze server roles: $($_.Exception.Message)" "SERVERROLES"
        return @([PSCustomObject]@{
            Category = "Server Roles"
            Item = "Analysis Error"
            Value = "Failed"
            Details = "Error during server role analysis: $($_.Exception.Message)"
            RiskLevel = "ERROR"
            Recommendation = "Investigate server role analysis failure"
        })
    }
}

# [PERIPHERALS] Get-PrinterAnalysis - Printer configuration analysis
# Dependencies: Write-LogMessage
# Order: 150
# WindowsWorkstationAuditor - Printer Analysis Module
# Version 1.3.0

function Get-PrinterAnalysis {
    <#
    .SYNOPSIS
        Analyzes installed printers, drivers, and network printer configurations
        
    .DESCRIPTION
        Collects comprehensive printer information including local and network printers,
        driver versions and status, print spooler service health, and default printer settings.
        
    .OUTPUTS
        Array of PSCustomObjects with Category, Item, Value, Details, RiskLevel, Recommendation
        
    .NOTES
        Requires: Write-LogMessage function
        Permissions: Local user (WMI access and print spooler service access)
    #>
    
    Write-LogMessage "INFO" "Analyzing printer configurations and drivers..." "PRINTER"
    
    try {
        $Results = @()
        
        # Check Print Spooler service status
        try {
            $SpoolerService = Get-Service -Name "Spooler" -ErrorAction SilentlyContinue
            if ($SpoolerService) {
                $SpoolerRisk = if ($SpoolerService.Status -ne "Running") { "HIGH" } else { "LOW" }
                $SpoolerRecommendation = if ($SpoolerService.Status -ne "Running") {
                    "Print Spooler service should be running for proper printer functionality"
                } else { "" }
                
                $Results += [PSCustomObject]@{
                    Category = "Printing"
                    Item = "Print Spooler Service"
                    Value = $SpoolerService.Status
                    Details = "Service startup type: $($SpoolerService.StartType)"
                    RiskLevel = $SpoolerRisk
                    Recommendation = ""
                }
                
                Write-LogMessage "INFO" "Print Spooler Service: $($SpoolerService.Status)" "PRINTER"
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve Print Spooler service status: $($_.Exception.Message)" "PRINTER"
        }
        
        # Get installed printers
        try {
            $Printers = @(Get-CimInstance -ClassName Win32_Printer -ErrorAction SilentlyContinue)
            $PrinterCount = $Printers.Count
            
            if ($PrinterCount -eq 0) {
                $Results += [PSCustomObject]@{
                    Category = "Printing"
                    Item = "Installed Printers"
                    Value = "No printers found"
                    Details = "System has no configured printers"
                    RiskLevel = "INFO"
                    Recommendation = ""
                }
                Write-LogMessage "INFO" "No printers configured on system" "PRINTER"
            } else {
                $LocalPrinters = 0
                $NetworkPrinters = 0
                $DefaultPrinter = ""
                
                foreach ($Printer in $Printers) {
                    $PrinterName = $Printer.Name
                    $PrinterStatus = $Printer.PrinterStatus
                    $IsNetworkPrinter = $Printer.Network
                    $IsDefaultPrinter = $Printer.Default
                    $DriverName = $Printer.DriverName
                    $PortName = $Printer.PortName
                    
                    if ($IsNetworkPrinter) {
                        $NetworkPrinters++
                    } else {
                        $LocalPrinters++
                    }
                    
                    if ($IsDefaultPrinter) {
                        $DefaultPrinter = $PrinterName
                    }
                    
                    # Determine printer risk level based on status
                    $PrinterRisk = switch ($PrinterStatus) {
                        1 { "INFO" }    # Other
                        2 { "INFO" }    # Unknown
                        3 { "LOW" }     # Idle
                        4 { "LOW" }     # Printing
                        5 { "LOW" }     # Warmup
                        6 { "MEDIUM" }  # Stopped Printing
                        7 { "HIGH" }    # Offline
                        default { "MEDIUM" }
                    }
                    
                    $StatusText = switch ($PrinterStatus) {
                        1 { "Other" }
                        2 { "Unknown" }
                        3 { "Idle" }
                        4 { "Printing" }
                        5 { "Warmup" }
                        6 { "Stopped Printing" }
                        7 { "Offline" }
                        default { "Status Code: $PrinterStatus" }
                    }
                    
                    $PrinterRecommendation = if ($PrinterStatus -eq 7) {
                        "Offline printers should be investigated and restored"
                    } elseif ($PrinterStatus -eq 6) {
                        "Stopped printers may indicate driver or connectivity issues"
                    } else { "" }
                    
                    $PrinterType = if ($IsNetworkPrinter) { "Network" } else { "Local" }
                    $DefaultIndicator = if ($IsDefaultPrinter) { " (Default)" } else { "" }
                    
                    $Results += [PSCustomObject]@{
                        Category = "Printing"
                        Item = "Printer$DefaultIndicator"
                        Value = "$PrinterName"
                        Details = "Type: $PrinterType, Status: $StatusText, Driver: $DriverName"
                        RiskLevel = $PrinterRisk
                        Recommendation = ""
                    }
                    
                    Write-LogMessage "INFO" "$PrinterType printer '$PrinterName': $StatusText" "PRINTER"
                }
                
                # Summary of printer configuration
                $Results += [PSCustomObject]@{
                    Category = "Printing"
                    Item = "Printer Summary"
                    Value = "$PrinterCount total printers"
                    Details = "Local: $LocalPrinters, Network: $NetworkPrinters, Default: $DefaultPrinter"
                    RiskLevel = "INFO"
                    Recommendation = ""
                }
                
                Write-LogMessage "INFO" "Printer Summary: $PrinterCount total ($LocalPrinters local, $NetworkPrinters network)" "PRINTER"
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve printer information: $($_.Exception.Message)" "PRINTER"
        }
        
        # Get printer drivers
        try {
            $PrinterDrivers = Get-CimInstance -ClassName Win32_PrinterDriver -ErrorAction SilentlyContinue
            $DriverCount = $PrinterDrivers.Count
            
            if ($DriverCount -gt 0) {
                $UniqueDrivers = $PrinterDrivers | Group-Object -Property Name | Measure-Object | Select-Object -ExpandProperty Count
                
                $Results += [PSCustomObject]@{
                    Category = "Printing"
                    Item = "Printer Drivers"
                    Value = "$UniqueDrivers unique drivers installed"
                    Details = "Total driver installations: $DriverCount"
                    RiskLevel = "INFO"
                    Recommendation = ""
                }
                
                Write-LogMessage "INFO" "Printer Drivers: $UniqueDrivers unique drivers, $DriverCount total installations" "PRINTER"
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve printer driver information: $($_.Exception.Message)" "PRINTER"
        }
        
        # Get printer ports (network connections)
        try {
            $PrinterPorts = Get-CimInstance -ClassName Win32_TCPIPPrinterPort -ErrorAction SilentlyContinue
            if ($PrinterPorts) {
                $NetworkPortCount = $PrinterPorts.Count
                
                foreach ($Port in $PrinterPorts) {
                    $PortName = $Port.Name
                    $HostAddress = $Port.HostAddress
                    $PortNumber = $Port.PortNumber
                    $SNMPEnabled = $Port.SNMPEnabled
                    
                    $PortRisk = if (-not $SNMPEnabled -and $Port.Protocol -eq 1) { "MEDIUM" } else { "LOW" }
                    $PortRecommendation = if (-not $SNMPEnabled -and $Port.Protocol -eq 1) {
                        "Consider enabling SNMP for better printer monitoring"
                    } else { "" }
                    
                    $Results += [PSCustomObject]@{
                        Category = "Printing"
                        Item = "Network Printer Port"
                        Value = "${HostAddress}:${PortNumber}"
                        Details = "Port: $PortName, SNMP Enabled: $SNMPEnabled"
                        RiskLevel = $PortRisk
                        Recommendation = ""
                    }
                    
                    Write-LogMessage "INFO" "Network printer port: $PortName -> ${HostAddress}:${PortNumber}" "PRINTER"
                }
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve printer port information: $($_.Exception.Message)" "PRINTER"
        }
        
        # Check print job queue
        try {
            $PrintJobs = Get-CimInstance -ClassName Win32_PrintJob -ErrorAction SilentlyContinue
            $JobCount = $PrintJobs.Count
            
            if ($JobCount -gt 0) {
                $StuckJobs = $PrintJobs | Where-Object { $_.Status -like "*Error*" -or $_.Status -like "*Paused*" } | Measure-Object | Select-Object -ExpandProperty Count
                
                $QueueRisk = if ($StuckJobs -gt 0) { "MEDIUM" } elseif ($JobCount -gt 10) { "MEDIUM" } else { "LOW" }
                $QueueRecommendation = if ($StuckJobs -gt 0) {
                    "Clear stuck print jobs to maintain system performance"
                } elseif ($JobCount -gt 10) {
                    "Large print queue may indicate printer or network issues"
                } else { "" }
                
                $Results += [PSCustomObject]@{
                    Category = "Printing"
                    Item = "Print Queue"
                    Value = "$JobCount jobs queued"
                    Details = "Active jobs: $JobCount, Stuck/Error jobs: $StuckJobs"
                    RiskLevel = $QueueRisk
                    Recommendation = ""
                }
                
                Write-LogMessage "INFO" "Print queue: $JobCount jobs ($StuckJobs stuck/error)" "PRINTER"
            } else {
                $Results += [PSCustomObject]@{
                    Category = "Printing"
                    Item = "Print Queue"
                    Value = "Empty"
                    Details = "No print jobs currently queued"
                    RiskLevel = "INFO"
                    Recommendation = ""
                }
                
                Write-LogMessage "INFO" "Print queue is empty" "PRINTER"
            }
        }
        catch {
            Write-LogMessage "WARN" "Could not retrieve print job information: $($_.Exception.Message)" "PRINTER"
        }
        
        Write-LogMessage "SUCCESS" "Printer analysis completed - $($Results.Count) items analyzed" "PRINTER"
        return $Results
    }
    catch {
        Write-LogMessage "ERROR" "Failed to analyze printers: $($_.Exception.Message)" "PRINTER"
        return @()
    }
}

# [MONITORING] Get-EventLogAnalysis - Windows Event Log analysis
# Dependencies: Write-LogMessage
# Order: 160
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

# [THREAT-INTEL] Get-DarkWebAnalysis - Dark web breach analysis using HIBP API
# Dependencies: Write-LogMessage
# Order: 170
# WindowsWorkstationAuditor - Dark Web Analysis Module
# Version 1.0.0 - Breach Database Integration

function Get-DarkWebAnalysis {
    <#
    .SYNOPSIS
        Analyzes email domains for exposed credentials using breach database API

    .DESCRIPTION
        Scans specified email domains for compromised accounts using breach database API.
        Identifies breached accounts, breach sources, and dates to assess organizational exposure.

    .PARAMETER Domains
        Comma-separated list of email domains to check (e.g., "company.com,subsidiary.org")


    .PARAMETER ConfigPath
        Path to breach database API configuration file (default: .\config\hibp-api-config.json)

    .OUTPUTS
        Array of PSCustomObjects with Category, Item, Value, Details, RiskLevel, Recommendation

    .NOTES
        Requires: Write-LogMessage function, valid breach database API key
        Dependencies: Internet connectivity, breach database API access
        Rate Limits: Respects API rate limiting with automatic retry
    #>

    param(
        [string]$Domains,
        [string]$ConfigPath = ".\config\hibp-api-config.json",
        [switch]$DemoMode
    )

    Write-LogMessage "INFO" "Starting dark web analysis..." "DARKWEB"

    try {
        $Results = @()

        # Validate input parameters
        if (-not $Domains) {
            $Results += [PSCustomObject]@{
                Category = "Dark Web Analysis"
                Item = "Parameter Validation"
                Value = "ERROR"
                Details = "No domains specified. Use -Domains parameter."
                RiskLevel = "INFO"
                Recommendation = "Specify email domains to check for breaches"
            }
            return $Results
        }

        # Skip configuration check in demo mode
        if ($DemoMode) {
            Write-LogMessage "INFO" "Demo mode enabled - using simulated data" "DARKWEB"
        } else {
            # Load configuration or create minimal config for subscription-free mode
            if (-not (Test-Path $ConfigPath)) {
                Write-LogMessage "WARN" "No configuration file found - will attempt subscription-free mode" "DARKWEB"
                # Create minimal config for subscription-free access
                $Config = @{
                    hibp = @{
                        base_url = "https://haveibeenpwned.com/api/v3"
                        recent_breach_threshold_days = 365
                        rate_limit_delay_ms = 2000
                        subscription_free_mode = $true
                    }
                }
            }
        }

        if ($DemoMode) {
            # Create dummy config for demo mode
            $Config = @{
                hibp = @{
                    recent_breach_threshold_days = 365
                    rate_limit_delay_ms = 100
                    base_url = "https://haveibeenpwned.com/api/v3"
                }
            }
        } elseif (Test-Path $ConfigPath) {
            try {
                $Config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
                Write-LogMessage "SUCCESS" "Loaded breach database configuration" "DARKWEB"

                # Check API key - if not configured, use subscription-free mode
                if (-not $Config.hibp.api_key -or $Config.hibp.api_key -eq "YOUR_32_CHARACTER_HIBP_API_KEY_HERE") {
                    Write-LogMessage "WARN" "No API key configured - using subscription-free breach data (limited)" "DARKWEB"
                    $Config.hibp | Add-Member -MemberType NoteProperty -Name "subscription_free_mode" -Value $true -Force
                } else {
                    $Config.hibp | Add-Member -MemberType NoteProperty -Name "subscription_free_mode" -Value $false -Force
                }
            }
            catch {
                $Results += [PSCustomObject]@{
                    Category = "Dark Web Analysis"
                    Item = "Configuration"
                    Value = "ERROR"
                    Details = "Failed to parse configuration file: $($_.Exception.Message)"
                    RiskLevel = "INFO"
                    Recommendation = "Verify JSON syntax in configuration file"
                }
                return $Results
            }
        }

        # Parse domains from parameter
        $DomainsToCheck = @()

        if ($Domains) {
            $DomainsToCheck += $Domains -split "," | ForEach-Object { $_.Trim() }
        }

        if ($DomainsToCheck.Count -eq 0) {
            $Results += [PSCustomObject]@{
                Category = "Dark Web Analysis"
                Item = "Domain List"
                Value = "ERROR"
                Details = "No valid domains found to check"
                RiskLevel = "INFO"
                Recommendation = "Verify domain list contains valid email domains"
            }
            return $Results
        }

        Write-LogMessage "INFO" "Checking $($DomainsToCheck.Count) domain(s) for breaches" "DARKWEB"

        # Process each domain
        foreach ($Domain in $DomainsToCheck) {
            Write-LogMessage "INFO" "Analyzing domain: $Domain" "DARKWEB"

            try {
                # Check domain breaches using breach database API or generate demo data
                if ($DemoMode) {
                    $BreachData = Get-DemoBreachData -Domain $Domain
                } elseif ($Config.hibp.subscription_free_mode) {
                    $BreachData = Invoke-SubscriptionFreeCheck -Domain $Domain -Config $Config
                } else {
                    $BreachData = Invoke-HIBPDomainCheck -Domain $Domain -Config $Config
                }

                if ($BreachData.Success) {
                    # Process subscription-free breaches with full details
                    if ($BreachData.Breaches.Count -gt 0) {
                        foreach ($Breach in $BreachData.Breaches) {
                            $RiskLevel = Get-BreachRiskLevel -BreachDate $Breach.BreachDate -RecentThresholdDays $Config.hibp.recent_breach_threshold_days

                            $Results += [PSCustomObject]@{
                                Category = "Dark Web Analysis"
                                Item = "Domain Breach (Full Details)"
                                Value = "$Domain - $($Breach.Name)"
                                Details = "Breach Date: $($Breach.BreachDate), Accounts: $($Breach.PwnCount), Data: $($Breach.DataClasses -join ', ')"
                                RiskLevel = $RiskLevel
                                Recommendation = if ($RiskLevel -eq "HIGH") { "Recent breach detected - immediate password reset required for all domain accounts" } else { "Historical breach detected - verify users have updated passwords since breach date" }
                            }
                        }
                    }

                    # Process limited breaches (metadata only)
                    if ($BreachData.LimitedBreaches -and $BreachData.LimitedBreaches.Count -gt 0) {
                        foreach ($Breach in $BreachData.LimitedBreaches) {
                            $RiskLevel = Get-BreachRiskLevel -BreachDate $Breach.BreachDate -RecentThresholdDays $Config.hibp.recent_breach_threshold_days

                            $Results += [PSCustomObject]@{
                                Category = "Dark Web Analysis"
                                Item = "Domain Breach (Limited Info)"
                                Value = "$Domain - $($Breach.Name)"
                                Details = "Breach Date: $($Breach.BreachDate), Accounts: $($Breach.PwnCount), Data: $($Breach.DataClasses -join ', ') [Account details require paid API]"
                                RiskLevel = $RiskLevel
                                Recommendation = if ($RiskLevel -eq "HIGH") { "Recent breach detected - configure paid API key for detailed account analysis" } else { "Historical breach detected - configure paid API key for detailed account analysis" }
                            }
                        }
                    }

                    # If no breaches found at all
                    if ($BreachData.Breaches.Count -eq 0 -and ($BreachData.LimitedBreaches.Count -eq 0 -or -not $BreachData.LimitedBreaches)) {
                        $Results += [PSCustomObject]@{
                            Category = "Dark Web Analysis"
                            Item = "Domain Status"
                            Value = "$Domain - Clean"
                            Details = "No known breaches found for this domain"
                            RiskLevel = "INFO"
                            Recommendation = "Continue monitoring domain for future breaches"
                        }
                    }
                } else {
                    $Results += [PSCustomObject]@{
                        Category = "Dark Web Analysis"
                        Item = "Domain Check"
                        Value = "$Domain - Error"
                        Details = $BreachData.Error
                        RiskLevel = "INFO"
                        Recommendation = "Verify domain name and API connectivity"
                    }
                }

                # Add a note if using subscription-free mode
                if ($Config.hibp.subscription_free_mode -and $BreachData.Note) {
                    $Results += [PSCustomObject]@{
                        Category = "Dark Web Analysis"
                        Item = "Data Source"
                        Value = "Subscription-Free Mode"
                        Details = $BreachData.Note
                        RiskLevel = "INFO"
                        Recommendation = "For comprehensive domain-specific breach data, configure a paid API key"
                    }
                }

                # Rate limiting delay
                if ($Config.hibp.rate_limit_delay_ms -gt 0) {
                    Start-Sleep -Milliseconds $Config.hibp.rate_limit_delay_ms
                }
            }
            catch {
                Write-LogMessage "ERROR" "Failed to check domain $Domain`: $($_.Exception.Message)" "DARKWEB"
                $Results += [PSCustomObject]@{
                    Category = "Dark Web Analysis"
                    Item = "Domain Check"
                    Value = "$Domain - Exception"
                    Details = $_.Exception.Message
                    RiskLevel = "INFO"
                    Recommendation = "Check network connectivity and API configuration"
                }
            }
        }

        Write-LogMessage "SUCCESS" "Completed dark web analysis for $($DomainsToCheck.Count) domain(s)" "DARKWEB"
        return $Results
    }
    catch {
        Write-LogMessage "ERROR" "Dark web analysis failed: $($_.Exception.Message)" "DARKWEB"
        return @([PSCustomObject]@{
            Category = "Dark Web Analysis"
            Item = "Module Error"
            Value = "FAILED"
            Details = $_.Exception.Message
            RiskLevel = "INFO"
            Recommendation = "Check module configuration and dependencies"
        })
    }
}

function Invoke-HIBPDomainCheck {
    <#
    .SYNOPSIS
        Calls breach database API to check for domain breaches
    #>
    param(
        [string]$Domain,
        [object]$Config
    )

    try {
        $Headers = @{
            "hibp-api-key" = $Config.hibp.api_key
            "User-Agent" = "BusinessNetworkAuditor/1.0"
        }

        $Uri = "$($Config.hibp.base_url)/breacheddomain/$Domain"
        $QueryParams = @()

        if (-not $Config.settings.include_unverified_breaches) {
            $QueryParams += "includeUnverified=false"
        }

        if (-not $Config.settings.truncate_response) {
            $QueryParams += "truncateResponse=false"
        }

        if ($QueryParams.Count -gt 0) {
            $Uri += "?" + ($QueryParams -join "&")
        }

        $RetryCount = 0
        $MaxRetries = $Config.hibp.max_retries

        do {
            try {
                $Response = Invoke-RestMethod -Uri $Uri -Headers $Headers -Method Get -ErrorAction Stop

                return @{
                    Success = $true
                    Breaches = $Response
                    Error = $null
                }
            }
            catch {
                if ($_.Exception.Response.StatusCode -eq 429) {
                    # Rate limited
                    $RetryAfter = if ($_.Exception.Response.Headers["Retry-After"]) {
                        [int]$_.Exception.Response.Headers["Retry-After"] * 1000
                    } else {
                        $Config.hibp.rate_limit_delay_ms * 2
                    }

                    Write-LogMessage "WARN" "Rate limited, waiting $($RetryAfter)ms before retry" "DARKWEB"
                    Start-Sleep -Milliseconds $RetryAfter
                    $RetryCount++
                }
                elseif ($_.Exception.Response.StatusCode -eq 404) {
                    # No breaches found (this is actually success)
                    return @{
                        Success = $true
                        Breaches = @()
                        Error = $null
                    }
                }
                else {
                    throw
                }
            }
        } while ($RetryCount -lt $MaxRetries)

        # Max retries exceeded
        return @{
            Success = $false
            Breaches = @()
            Error = "Rate limit exceeded after $MaxRetries retries"
        }
    }
    catch {
        return @{
            Success = $false
            Breaches = @()
            Error = "API call failed: $($_.Exception.Message)"
        }
    }
}

function Get-BreachRiskLevel {
    <#
    .SYNOPSIS
        Determines risk level based on breach date
    #>
    param(
        [string]$BreachDate,
        [int]$RecentThresholdDays = 365
    )

    try {
        $BreachDateTime = [DateTime]::Parse($BreachDate)
        $DaysSinceBreach = (Get-Date) - $BreachDateTime | Select-Object -ExpandProperty Days

        if ($DaysSinceBreach -le $RecentThresholdDays) {
            return "HIGH"
        }
        elseif ($DaysSinceBreach -le ($RecentThresholdDays * 2)) {
            return "MEDIUM"
        }
        else {
            return "LOW"
        }
    }
    catch {
        # If we can't parse the date, default to medium risk
        return "MEDIUM"
    }
}

function Get-DemoBreachData {
    <#
    .SYNOPSIS
        Generates simulated breach data for demo/testing purposes
    #>
    param(
        [string]$Domain
    )

    # Simulate some processing delay
    Start-Sleep -Milliseconds 500

    # Generate different demo scenarios based on domain name
    switch -Wildcard ($Domain.ToLower()) {
        "test.com" {
            # Clean domain - no breaches
            return @{
                Success = $true
                Breaches = @()
                Error = $null
            }
        }
        "example.com" {
            # Single recent breach
            return @{
                Success = $true
                Breaches = @(
                    @{
                        Name = "ExampleBreach"
                        BreachDate = (Get-Date).AddDays(-30).ToString("yyyy-MM-dd")
                        PwnCount = 15420
                        DataClasses = @("Email addresses", "Passwords", "Usernames")
                    }
                )
                Error = $null
            }
        }
        "demo.com" {
            # Multiple breaches with different ages
            return @{
                Success = $true
                Breaches = @(
                    @{
                        Name = "OldBreach2019"
                        BreachDate = "2019-03-15"
                        PwnCount = 250000
                        DataClasses = @("Email addresses", "Passwords")
                    },
                    @{
                        Name = "RecentBreach"
                        BreachDate = (Get-Date).AddDays(-45).ToString("yyyy-MM-dd")
                        PwnCount = 5200
                        DataClasses = @("Email addresses", "Names", "Phone numbers")
                    }
                )
                Error = $null
            }
        }
        default {
            # Random scenario for other domains
            $Random = Get-Random -Minimum 1 -Maximum 4

            if ($Random -eq 1) {
                # Clean domain
                return @{
                    Success = $true
                    Breaches = @()
                    Error = $null
                }
            } else {
                # Generate 1-2 random breaches
                $BreachCount = Get-Random -Minimum 1 -Maximum 3
                $Breaches = @()

                for ($i = 1; $i -le $BreachCount; $i++) {
                    $DaysAgo = Get-Random -Minimum 30 -Maximum 1200
                    $AccountCount = Get-Random -Minimum 1000 -Maximum 500000

                    $Breaches += @{
                        Name = "DemoBreach$i"
                        BreachDate = (Get-Date).AddDays(-$DaysAgo).ToString("yyyy-MM-dd")
                        PwnCount = $AccountCount
                        DataClasses = @("Email addresses", "Passwords", "Usernames")
                    }
                }

                return @{
                    Success = $true
                    Breaches = $Breaches
                    Error = $null
                }
            }
        }
    }
}

function Invoke-SubscriptionFreeCheck {
    <#
    .SYNOPSIS
        Calls public HIBP API endpoints that don't require authentication
    #>
    param(
        [string]$Domain,
        [object]$Config
    )

    try {
        # Get all subscription-free breaches
        $Uri = "$($Config.hibp.base_url)/breaches?includeUnverified=false"

        Write-LogMessage "INFO" "Fetching subscription-free breach data..." "DARKWEB"

        $RetryCount = 0
        $MaxRetries = 3

        do {
            try {
                $Response = Invoke-RestMethod -Uri $Uri -Method Get -ErrorAction Stop

                Write-LogMessage "INFO" "Retrieved $($Response.Count) total breaches from API" "DARKWEB"

                # Count subscription-free breaches for logging
                $SubscriptionFreeCount = ($Response | Where-Object { $_.IsSubscriptionFree }).Count
                Write-LogMessage "INFO" "Found $SubscriptionFreeCount subscription-free breaches" "DARKWEB"

                # Search all breaches for domain matches (even non-subscription-free)
                $SubscriptionFreeBreaches = @()
                $AllRelatedBreaches = @()
                $DomainKeyword = $Domain.Split('.')[0]  # Get company name part

                foreach ($Breach in $Response) {
                    # Check for domain matches in any breach
                    $IsMatch = $false

                    # Direct domain match
                    if ($Breach.Domain -eq $Domain) {
                        $IsMatch = $true
                        Write-LogMessage "INFO" "Direct domain match: $($Breach.Name)" "DARKWEB"
                    }
                    # Company name in breach name
                    elseif ($Breach.Name -like "*$DomainKeyword*") {
                        $IsMatch = $true
                        Write-LogMessage "INFO" "Name match: $($Breach.Name)" "DARKWEB"
                    }
                    # Company name in title
                    elseif ($Breach.Title -like "*$DomainKeyword*") {
                        $IsMatch = $true
                        Write-LogMessage "INFO" "Title match: $($Breach.Name)" "DARKWEB"
                    }
                    # Description contains domain
                    elseif ($Breach.Description -like "*$Domain*") {
                        $IsMatch = $true
                        Write-LogMessage "INFO" "Description match: $($Breach.Name)" "DARKWEB"
                    }

                    if ($IsMatch) {
                        $AllRelatedBreaches += $Breach
                        if ($Breach.IsSubscriptionFree) {
                            $SubscriptionFreeBreaches += $Breach
                        }
                    }
                }

                Write-LogMessage "INFO" "Found $($AllRelatedBreaches.Count) total related breaches ($($SubscriptionFreeBreaches.Count) subscription-free) for $Domain" "DARKWEB"

                # Return subscription-free breaches with full detail, and limited info for others
                $RelevantBreaches = $SubscriptionFreeBreaches
                $LimitedBreaches = $AllRelatedBreaches | Where-Object { -not $_.IsSubscriptionFree }

                return @{
                    Success = $true
                    Breaches = $RelevantBreaches
                    LimitedBreaches = $LimitedBreaches
                    Error = $null
                    Note = "Subscription-free data - limited to public breaches only"
                }
            }
            catch {
                if ($_.Exception.Response.StatusCode -eq 429) {
                    # Rate limited
                    $RetryAfter = 2000  # Default 2 second delay for public endpoint
                    Write-LogMessage "WARN" "Rate limited, waiting $($RetryAfter)ms before retry" "DARKWEB"
                    Start-Sleep -Milliseconds $RetryAfter
                    $RetryCount++
                }
                else {
                    throw
                }
            }
        } while ($RetryCount -lt $MaxRetries)

        # Max retries exceeded
        return @{
            Success = $false
            Breaches = @()
            Error = "Rate limit exceeded after $MaxRetries retries"
        }
    }
    catch {
        # If subscription-free fails, provide helpful message
        return @{
            Success = $true
            Breaches = @()
            Error = $null
            Note = "Unable to fetch subscription-free data: $($_.Exception.Message)"
        }
    }
}

# === MAIN SCRIPT LOGIC ===

# Parse embedded configuration
try {
    $Config = $Script:EmbeddedConfig | ConvertFrom-Json
    Write-Host "Loaded embedded configuration (version: $($Config.version))" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Failed to parse embedded configuration: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}


# Global variables
$Script:LogFile = ""
$Script:StartTime = Get-Date
$Script:ComputerName = $env:COMPUTERNAME
$Script:BaseFileName = "${ComputerName}_$($StartTime.ToString('yyyyMMdd_HHmmss'))"

# Module loading system
function Import-AuditModule {
    <#
    .SYNOPSIS
        Dynamically imports audit modules with dependency management

    .DESCRIPTION
        Loads PowerShell audit modules from the modules directory,
        handling dependencies and providing error handling.

    .PARAMETER ModuleName
        Name of the module to import (without .ps1 extension)

    .PARAMETER ModulePath
        Path to the modules directory
    #>
    param(
        [string]$ModuleName,
        [string]$ModulePath = ".\src\modules"
    )

    try {
        $ModuleFile = Join-Path $ModulePath "$ModuleName.ps1"
        if (Test-Path $ModuleFile) {
            # Dot-source the module file to load functions
            . $ModuleFile
            Write-LogMessage "SUCCESS" "Loaded module: $ModuleName" "MODULE"
            return $true
        } else {
            Write-LogMessage "ERROR" "Module file not found: $ModuleFile" "MODULE"
            return $false
        }
    }
    catch {
        Write-LogMessage "ERROR" "Failed to load module ${ModuleName}: $($_.Exception.Message)" "MODULE"
        return $false
    }
}

function Import-CoreModules {
    <#
    .SYNOPSIS
        Imports core logging and utility modules

    .DESCRIPTION
        Loads essential core modules required for the audit system to function.
    #>

    $CorePath = ".\src\core"
    $CoreModules = @("Write-LogMessage", "Initialize-Logging", "Export-MarkdownReport", "Export-RawDataJSON")
    $LoadedModules = 0

    foreach ($Module in $CoreModules) {
        if (Import-AuditModule -ModuleName $Module -ModulePath $CorePath) {
            $LoadedModules++
        }
    }

    Write-Host "[INFO] Core modules loaded: $LoadedModules/$($CoreModules.Count)" -ForegroundColor Cyan
    return $LoadedModules -eq $CoreModules.Count
}

function Import-AuditModules {
    <#
    .SYNOPSIS
        Imports all audit modules based on configuration

    .DESCRIPTION
        Loads audit modules dynamically based on the configuration file,
        allowing for selective module execution.
    #>

    # Load configuration
    $ConfigFile = Join-Path $ConfigPath "server-audit-config.json"
    if (Test-Path $ConfigFile) {
        try {
            $Config = Get-Content $ConfigFile | ConvertFrom-Json
            Write-LogMessage "SUCCESS" "Loaded configuration from: $ConfigFile" "CONFIG"
        }
        catch {
            Write-LogMessage "WARN" "Failed to load config, using defaults: $($_.Exception.Message)" "CONFIG"
            $Config = $null
        }
    } else {
        Write-LogMessage "WARN" "Config file not found, using defaults: $ConfigFile" "CONFIG"
        $Config = $null
    }

    # Define available audit modules for servers
    $AuditModules = @(
        # Core system analysis (reused from workstation)
        @{ Name = "Get-SystemInformation"; ConfigKey = "system"; Required = $true },
        @{ Name = "Get-MemoryAnalysis"; ConfigKey = "memory"; Required = $true },
        @{ Name = "Get-DiskSpaceAnalysis"; ConfigKey = "disk"; Required = $true },
        @{ Name = "Get-PatchStatus"; ConfigKey = "patches"; Required = $true },
        @{ Name = "Get-ProcessAnalysis"; ConfigKey = "process"; Required = $true },
        @{ Name = "Get-SoftwareInventory"; ConfigKey = "software"; Required = $true },
        @{ Name = "Get-SecuritySettings"; ConfigKey = "security"; Required = $true },
        @{ Name = "Get-NetworkAnalysis"; ConfigKey = "network"; Required = $true },
        @{ Name = "Get-EventLogAnalysis"; ConfigKey = "eventlog"; Required = $true },
        @{ Name = "Get-UserAccountAnalysis"; ConfigKey = "users"; Required = $true },

        # Server-specific modules
        @{ Name = "Get-ServerRoleAnalysis"; ConfigKey = "serverroles"; Required = $true },
        @{ Name = "Get-DHCPAnalysis"; ConfigKey = "dhcp"; Required = $false },
        @{ Name = "Get-DNSAnalysis"; ConfigKey = "dns"; Required = $false },
        @{ Name = "Get-FileShareAnalysis"; ConfigKey = "fileshares"; Required = $true },
        @{ Name = "Get-ActiveDirectoryAnalysis"; ConfigKey = "activedirectory"; Required = $false }
    )

    $LoadedModules = @()
    $FailedModules = @()

    foreach ($Module in $AuditModules) {
        $ModuleName = $Module.Name
        $ConfigKey = $Module.ConfigKey
        $IsRequired = $Module.Required

        # Check if module is enabled in config
        $IsEnabled = $true
        if ($Config -and $Config.modules -and $Config.modules.$ConfigKey) {
            $IsEnabled = $Config.modules.$ConfigKey.enabled
        }

        if ($IsEnabled -or $IsRequired) {
            Write-LogMessage "INFO" "Loading audit module: $ModuleName" "MODULE"

            if (Import-AuditModule -ModuleName $ModuleName) {
                $LoadedModules += $ModuleName
            } else {
                $FailedModules += $ModuleName
                if ($IsRequired) {
                    Write-LogMessage "ERROR" "Required module failed to load: $ModuleName" "MODULE"
                }
            }
        } else {
            Write-LogMessage "INFO" "Module disabled in config: $ModuleName" "MODULE"
        }
    }

    Write-LogMessage "SUCCESS" "Module loading complete - Loaded: $($LoadedModules.Count), Failed: $($FailedModules.Count)" "MODULE"

    return @{
        LoadedModules = $LoadedModules
        FailedModules = $FailedModules
        Config = $Config
    }
}

function Invoke-AuditModule {
    <#
    .SYNOPSIS
        Safely executes an audit module with error handling and timeout

    .DESCRIPTION
        Executes an audit module function with proper error handling,
        timeout protection, and result validation.

    .PARAMETER ModuleName
        Name of the module function to execute

    .PARAMETER TimeoutSeconds
        Maximum execution time before timeout (default: 60)
    #>
    param(
        [string]$ModuleName,
        [int]$TimeoutSeconds = 60
    )

    try {
        Write-LogMessage "INFO" "Executing audit module: $ModuleName" "AUDIT"
        $StartTime = Get-Date

        # Execute the module function
        $Results = & $ModuleName

        $EndTime = Get-Date
        $Duration = ($EndTime - $StartTime).TotalSeconds

        if ($Results -and $Results.Count -gt 0) {
            Write-LogMessage "SUCCESS" "Module $ModuleName completed in $([math]::Round($Duration, 2)) seconds - $($Results.Count) results" "AUDIT"
            return $Results
        } else {
            Write-LogMessage "WARN" "Module $ModuleName returned no results" "AUDIT"
            return @()
        }
    }
    catch {
        Write-LogMessage "ERROR" "Module $ModuleName failed: $($_.Exception.Message)" "AUDIT"
        return @()
    }
}

function Export-AuditResults {
    <#
    .SYNOPSIS
        Exports audit results to various formats including markdown and raw JSON

    .DESCRIPTION
        Exports the collected audit results to multiple formats:
        - markdown: Technician-friendly report with detailed findings
        - rawjson: Comprehensive data for aggregation tools

    .PARAMETER Results
        Array of audit results to export

    .PARAMETER Config
        Configuration object with export settings

    .PARAMETER IsServer
        Flag indicating this is a server audit (affects report generation)

    .PARAMETER OutputPath
        Output directory path for exports
    #>
    param(
        [array]$Results,
        [object]$Config,
        [switch]$IsServer,
        [string]$OutputPath
    )

    if (-not $Results -or $Results.Count -eq 0) {
        Write-LogMessage "WARN" "No results to export" "EXPORT"
        return
    }

    # Validate OutputPath parameter
    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        Write-LogMessage "ERROR" "CRITICAL: OutputPath parameter is null or empty in Export-AuditResults" "EXPORT"
        Write-LogMessage "ERROR" "Script:OutputPath value: '$Script:OutputPath'" "EXPORT"
        # Fallback to script-level OutputPath
        $OutputPath = $Script:OutputPath
        if ([string]::IsNullOrWhiteSpace($OutputPath)) {
            Write-LogMessage "ERROR" "CRITICAL: Script:OutputPath is also null! Using hardcoded fallback." "EXPORT"
            $OutputPath = "C:\WindowsAudit"
        }
        Write-LogMessage "INFO" "Using fallback OutputPath: $OutputPath" "EXPORT"
    }

    # Ensure output directory exists
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        Write-LogMessage "INFO" "Created output directory: $OutputPath" "EXPORT"
    }

    # Default formats: markdown for technicians, rawjson for aggregation
    $ExportFormats = @("markdown", "rawjson")
    if ($Config -and $Config.output -and $Config.output.formats) {
        $ExportFormats = $Config.output.formats
    }

    $ExportResults = @()

    foreach ($Format in $ExportFormats) {
        try {
            switch ($Format.ToLower()) {
                "markdown" {
                    $ReportPath = Export-MarkdownReport -Results $Results -OutputPath $OutputPath -BaseFileName $Script:BaseFileName -IsServer:$IsServer
                    if ($ReportPath) {
                        $ExportResults += "Technician Report: $ReportPath"
                    }
                }
                "rawjson" {
                    # Include raw data collections if available
                    $RawData = @{}
                    if (Get-Variable -Name "RawDataCollections" -Scope Global -ErrorAction SilentlyContinue) {
                        $RawData = $Global:RawDataCollections
                    }

                    $JSONPath = Export-RawDataJSON -Results $Results -RawData $RawData -OutputPath $OutputPath -BaseFileName $Script:BaseFileName -IsServer:$IsServer
                    if ($JSONPath) {
                        $ExportResults += "Raw Data JSON: $JSONPath"
                    }
                }
                default {
                    Write-LogMessage "WARN" "Unsupported export format: $Format" "EXPORT"
                }
            }
        }
        catch {
            Write-LogMessage "ERROR" "Failed to export $Format format: $($_.Exception.Message)" "EXPORT"
        }
    }

    # Summary of exports
    if ($ExportResults.Count -gt 0) {
        Write-LogMessage "SUCCESS" "Export completed - $($ExportResults.Count) files generated" "EXPORT"
        foreach ($Result in $ExportResults) {
            Write-LogMessage "INFO" $Result "EXPORT"
        }
    }
}

function Start-ServerAudit {
    <#
    .SYNOPSIS
        Main server audit orchestration function

    .DESCRIPTION
        Orchestrates the complete server audit execution, result collection, and export.
        Modules are loaded at script level before this function is called.
    #>

    Write-LogMessage "INFO" "Starting Windows Server Audit v1.3.0..." "MAIN"

    # Execute audit modules (modules already loaded at script level)
    $AllResults = @()
    $ServerAuditModules = @(
        "Get-SystemInformation", "Get-MemoryAnalysis", "Get-DiskSpaceAnalysis",
        "Get-PatchStatus", "Get-ProcessAnalysis", "Get-SoftwareInventory",
        "Get-SecuritySettings", "Get-NetworkAnalysis", "Get-EventLogAnalysis",
        "Get-UserAccountAnalysis", "Get-ServerRoleAnalysis", "Get-DHCPAnalysis",
        "Get-DNSAnalysis", "Get-FileShareAnalysis", "Get-ActiveDirectoryAnalysis"
    )

    foreach ($ModuleName in $ServerAuditModules) {
        # Skip if module isn't loaded (Get-Command will return null)
        if (Get-Command $ModuleName -ErrorAction SilentlyContinue) {
            $ModuleResults = Invoke-AuditModule -ModuleName $ModuleName
            if ($ModuleResults -and $ModuleResults.Count -gt 0) {
                $AllResults += $ModuleResults
            }
        } else {
            Write-LogMessage "WARN" "Module not loaded, skipping: $ModuleName" "AUDIT"
        }
    }

    if ($AllResults.Count -eq 0) {
        Write-LogMessage "WARN" "No audit results collected" "MAIN"
    } else {
        Write-LogMessage "SUCCESS" "Collected $($AllResults.Count) audit results" "MAIN"

        # Display risk summary
        $RiskCounts = $AllResults | Group-Object RiskLevel | ForEach-Object { "$($_.Name): $($_.Count)" }
        Write-LogMessage "INFO" "Risk summary - $($RiskCounts -join ', ')" "SUMMARY"

        # Configuration already loaded from embedded config
        
        # Export results
        Export-AuditResults -Results $AllResults -Config $Config -IsServer -OutputPath $Script:OutputPath
    }

    $EndTime = Get-Date
    $Duration = New-TimeSpan -Start $Script:StartTime -End $EndTime
    Write-LogMessage "SUCCESS" "Server audit completed in $([math]::Round($Duration.TotalMinutes, 2)) minutes" "MAIN"

    Write-Host "`nServer Audit Complete!" -ForegroundColor Green
    Write-Host "Results saved to: $OutputPath" -ForegroundColor Cyan
    Write-Host "Log file: $($Script:LogFile)" -ForegroundColor Cyan

    return $AllResults
}

# Script entry point
try {
    # Pre-flight checks
    Write-Host "WindowsServerAuditor v1.3.0 - Windows Server IT Assessment Tool" -ForegroundColor Cyan
    Write-Host "=========================================================" -ForegroundColor Cyan

    # Check if running on Windows Server
    $OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    if ($OSInfo.ProductType -eq 1) {
        Write-Host ""
        Write-Host "WARNING: This system appears to be a WORKSTATION, not a server." -ForegroundColor Yellow
        Write-Host "Consider using WindowsWorkstationAuditor.ps1 instead." -ForegroundColor Yellow
        Write-Host ""

        if (-not $PSBoundParameters.ContainsKey("Force")) {
            Write-Host "Exiting... Use -Force parameter to continue anyway." -ForegroundColor Red
            exit 1
        } else {
            Write-Host "WARNING: Proceeding with server audit on workstation OS (Force parameter used)" -ForegroundColor Red
            Start-Sleep -Seconds 3
        }
    }

    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-Host "ERROR: PowerShell 5.0 or higher is required. Current version: $($PSVersionTable.PSVersion)" -ForegroundColor Red
        exit 1
    }

    # Create output directory structure
    if (-not (Test-Path $OutputPath)) {
        try {
            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
            Write-Host "Created output directory: $OutputPath" -ForegroundColor Green
        }
        catch {
            Write-Host "ERROR: Failed to create output directory: $($_.Exception.Message)" -ForegroundColor Red
            exit 1
        }
    }

    # Initialize logging (basic initialization before core modules load)
    $LogDirectory = Join-Path $Script:OutputPath "logs"
    if (-not (Test-Path $LogDirectory)) {
        New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
    }
    $Script:LogFile = Join-Path $LogDirectory "${Script:BaseFileName}_server_audit.log"

    # Basic logging function for pre-core-module use
    function Write-LogMessage {
        param([string]$Level, [string]$Message, [string]$Category = "GENERAL")
        $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $LogEntry = "[$Timestamp] [$Level] [$Category] $Message"
        switch ($Level) {
            "ERROR" { Write-Host $LogEntry -ForegroundColor Red }
            "WARN"  { Write-Host $LogEntry -ForegroundColor Yellow }
            "SUCCESS" { Write-Host $LogEntry -ForegroundColor Green }
            default { Write-Host $LogEntry }
        }
        if ($Script:LogFile) { Add-Content -Path $Script:LogFile -Value $LogEntry }
    }

    if (-not (Initialize-Logging -LogDirectory $LogDirectory -LogFileName "${Script:BaseFileName}_server_audit.log")) {
        Write-Host "ERROR: Failed to initialize logging system" -ForegroundColor Red
        exit 1
    }

    Write-LogMessage "INFO" "WindowsServerAuditor v1.3.0 starting..." "MAIN"
    Write-LogMessage "INFO" "Server: $($env:COMPUTERNAME)" "MAIN"
    Write-LogMessage "INFO" "OS: $($OSInfo.Caption) $($OSInfo.Version)" "MAIN"
    Write-LogMessage "INFO" "Output directory: $OutputPath" "MAIN"

    # Load configuration as global variable for modules to access
    $ConfigFile = Join-Path $ConfigPath "server-audit-config.json"
    if (Test-Path $ConfigFile) {
        try {
            $Global:Config = Get-Content $ConfigFile | ConvertFrom-Json
            Write-LogMessage "SUCCESS" "Loaded configuration as global: $ConfigFile" "CONFIG"
        }
        catch {
            Write-LogMessage "WARN" "Failed to load config: $($_.Exception.Message)" "CONFIG"
            $Global:Config = $null
        }
    } else {
        Write-LogMessage "WARN" "Config file not found: $ConfigFile" "CONFIG"
        $Global:Config = $null
    }

    # Start the audit
    $AuditResults = Start-ServerAudit
    Write-LogMessage "SUCCESS" "Windows Server Auditor completed successfully" "MAIN"
}
catch {
    Write-Host "FATAL ERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Stack Trace: $($_.ScriptStackTrace)" -ForegroundColor Red
    if ($Script:LogFile) {
        Add-Content -Path $Script:LogFile -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [ERROR] [MAIN] FATAL: $($_.Exception.Message)"
    }
    exit 1
}


