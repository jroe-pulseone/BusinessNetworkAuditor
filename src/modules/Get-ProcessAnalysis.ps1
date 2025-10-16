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