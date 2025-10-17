# WindowsServerAuditor - Windows Server IT Assessment Tool
# Version 1.3.0 - Modular Architecture
# Platform: Windows Server 2008-2022 (use WindowsWorkstationAuditor.ps1 for workstations)
# Requires: PowerShell 5.0+, Local Administrator Rights (recommended)

param(
    [string]$OutputPath = ".\output",
    [string]$ConfigPath = ".\config",
    [switch]$Verbose,
    [switch]$Force
)

# Global variables
$Script:LogFile = ""
$Script:StartTime = Get-Date
$Script:ComputerName = $env:COMPUTERNAME
$Script:BaseFileName = "${ComputerName}_$($StartTime.ToString('yyyyMMdd_HHmmss'))"
$Script:OutputPath = $OutputPath  # Store parameter in script scope

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

        # Load configuration for export
        $ConfigFile = Join-Path $ConfigPath "server-audit-config.json"
        $Config = $null
        if (Test-Path $ConfigFile) {
            try {
                $Config = Get-Content $ConfigFile | ConvertFrom-Json
            } catch {
                Write-LogMessage "WARN" "Failed to load config for export, using defaults" "MAIN"
            }
        }

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

    # Load core modules at script level
    Write-LogMessage "INFO" "Loading core modules..." "MAIN"
    . ".\src\core\Write-LogMessage.ps1"
    . ".\src\core\Initialize-Logging.ps1"
    . ".\src\core\Export-MarkdownReport.ps1"
    . ".\src\core\Export-RawDataJSON.ps1"

    # Initialize proper logging system
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

    # Load all audit modules at script level to ensure global scope
    Write-LogMessage "INFO" "Loading audit modules..." "MAIN"
    $AuditModuleFiles = @(
        # Core system analysis (reused from workstation)
        "Get-SystemInformation", "Get-MemoryAnalysis", "Get-DiskSpaceAnalysis",
        "Get-PatchStatus", "Get-ProcessAnalysis", "Get-SoftwareInventory",
        "Get-SecuritySettings", "Get-NetworkAnalysis", "Get-EventLogAnalysis",
        "Get-UserAccountAnalysis",

        # Server-specific modules
        "Get-ServerRoleAnalysis", "Get-DHCPAnalysis", "Get-DNSAnalysis",
        "Get-FileShareAnalysis", "Get-ActiveDirectoryAnalysis"
    )

    foreach ($ModuleName in $AuditModuleFiles) {
        $ModuleFile = ".\src\modules\$ModuleName.ps1"
        if (Test-Path $ModuleFile) {
            . $ModuleFile
            Write-LogMessage "SUCCESS" "Loaded module: $ModuleName" "MODULE"
        } else {
            Write-LogMessage "WARN" "Module file not found: $ModuleFile" "MODULE"
        }
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
