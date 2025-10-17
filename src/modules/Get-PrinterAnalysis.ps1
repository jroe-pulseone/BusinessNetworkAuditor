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