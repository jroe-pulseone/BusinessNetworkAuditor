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