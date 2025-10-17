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
            # Load AV signatures from separate file if specified
            $ConfigSigs = $null
            if ($Global:Config.settings -and $Global:Config.settings.antivirus_signatures_file) {
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