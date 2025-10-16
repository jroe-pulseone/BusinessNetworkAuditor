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

        # Check for critical software and versions
        $CriticalSoftware = @(
            @{Name="Google Chrome"; Pattern="Chrome"}
            @{Name="Mozilla Firefox"; Pattern="Firefox"}
            @{Name="Adobe Acrobat"; Pattern="Adobe.*Acrobat"}
            @{Name="Microsoft Office"; Pattern="Microsoft Office"}
            @{Name="Java"; Pattern="Java"}
        )

        foreach ($Critical in $CriticalSoftware) {
            $Found = $AllSoftware | Where-Object { $_.DisplayName -match $Critical.Pattern } | Select-Object -First 1
            if ($Found) {
                $InstallDate = if ($Found.InstallDate) {
                    try { [datetime]::ParseExact($Found.InstallDate, "yyyyMMdd", $null) } catch { $null }
                } else { $null }

                $AgeInDays = if ($InstallDate) { (New-TimeSpan -Start $InstallDate -End (Get-Date)).Days } else { $null }

                $RiskLevel = if ($AgeInDays -gt 365) { "HIGH" } elseif ($AgeInDays -gt 180) { "MEDIUM" } else { "LOW" }

                $Results += [PSCustomObject]@{
                    Category = "Software"
                    Item = $Critical.Name
                    Value = $Found.DisplayVersion
                    Details = "Install Date: $(if ($InstallDate) { $InstallDate.ToString('yyyy-MM-dd') } else { 'Unknown' }), Age: $(if ($AgeInDays) { "$AgeInDays days" } else { 'Unknown' })"
                    RiskLevel = $RiskLevel
                    Recommendation = if ($AgeInDays -gt 365) { "Regular software updates required" } else { "" }
                }
            }
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
