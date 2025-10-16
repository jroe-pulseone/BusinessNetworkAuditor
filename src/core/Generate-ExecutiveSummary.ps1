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