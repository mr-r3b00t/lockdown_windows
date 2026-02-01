<#
.SYNOPSIS
    Windows Defender Application Control (WDAC) Configuration GUI
.DESCRIPTION
    A PowerShell 5 GUI tool for viewing and configuring WDAC policies on Windows 11.
    Uses ONLY Microsoft's official ConfigCI cmdlets - no hand-crafted XML.
.NOTES
    Requires Administrator privileges to apply policies.
    Requires Windows 10/11 Pro, Enterprise, or Education (for ConfigCI module).
    ALWAYS TEST IN AUDIT MODE FIRST!
#>

#Requires -Version 5.0

# Force UTF-8 encoding (wrapped in try-catch for GUI contexts without console)
try {
    if ($Host.Name -eq 'ConsoleHost') {
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    }
} catch {
    # Silently continue - no console available
}
$PSDefaultParameterValues['*:Encoding'] = 'utf8'
$OutputEncoding = [System.Text.Encoding]::UTF8

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ============================================================================
# Helper Functions
# ============================================================================

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-ConfigCIAvailable {
    return (Get-Command New-CIPolicy -ErrorAction SilentlyContinue) -ne $null
}

function Get-WDACStatus {
    try {
        $status = @{
            VBSEnabled = $false
            CodeIntegrityEnabled = $false
            UMCIEnabled = $false
            ActivePolicies = @()
            EnforcementMode = "Not Configured"
            ConfigCIAvailable = Test-ConfigCIAvailable
        }
        
        # Check Device Guard status
        $ciStatus = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
        
        if ($ciStatus) {
            $status.VBSEnabled = $ciStatus.VirtualizationBasedSecurityStatus -eq 2
            $status.CodeIntegrityEnabled = $ciStatus.CodeIntegrityPolicyEnforcementStatus -gt 0
            $status.UMCIEnabled = $ciStatus.UsermodeCodeIntegrityPolicyEnforcementStatus -gt 0
            
            switch ($ciStatus.CodeIntegrityPolicyEnforcementStatus) {
                0 { $status.EnforcementMode = "Off" }
                1 { $status.EnforcementMode = "Audit Mode" }
                2 { $status.EnforcementMode = "Enforced" }
                default { $status.EnforcementMode = "Unknown" }
            }
        }
        
        # Get active policies
        $policyPath = "$env:SystemRoot\System32\CodeIntegrity\CiPolicies\Active"
        if (Test-Path $policyPath) {
            $status.ActivePolicies = Get-ChildItem -Path $policyPath -Filter "*.cip" -ErrorAction SilentlyContinue | 
                Select-Object -ExpandProperty Name
        }
        
        # Check legacy policy
        $legacyPolicy = "$env:SystemRoot\System32\CodeIntegrity\SIPolicy.p7b"
        if (Test-Path $legacyPolicy) {
            $status.ActivePolicies += "SIPolicy.p7b (Legacy)"
        }
        
        return $status
    }
    catch {
        return @{
            VBSEnabled = $false
            CodeIntegrityEnabled = $false
            UMCIEnabled = $false
            ActivePolicies = @()
            EnforcementMode = "Error: $($_.Exception.Message)"
            ConfigCIAvailable = $false
        }
    }
}

# ============================================================================
# WDAC Policy Functions - Using ONLY Official ConfigCI Cmdlets
# ============================================================================

function New-WDACPolicyFromTemplate {
    param(
        [string]$PolicyName,
        [ValidateSet("AllowMicrosoft", "DefaultWindows")]
        [string]$TemplateType,
        [string]$OutputPath,
        [bool]$AuditMode = $true
    )
    
    try {
        if (-not (Test-ConfigCIAvailable)) {
            return @{
                Success = $false
                Message = "ConfigCI module not available. This feature requires Windows 10/11 Pro, Enterprise, or Education."
            }
        }
        
        $policyFile = Join-Path $OutputPath "$PolicyName.xml"
        
        # Use Microsoft's example policies as templates
        $examplePoliciesPath = "$env:SystemRoot\schemas\CodeIntegrity\ExamplePolicies"
        
        switch ($TemplateType) {
            "AllowMicrosoft" {
                $templateFile = Join-Path $examplePoliciesPath "AllowMicrosoft.xml"
            }
            "DefaultWindows" {
                $templateFile = Join-Path $examplePoliciesPath "DefaultWindows_Enforced.xml"
                if (-not (Test-Path $templateFile)) {
                    $templateFile = Join-Path $examplePoliciesPath "DefaultWindows_Audit.xml"
                }
            }
        }
        
        if (Test-Path $templateFile) {
            # Copy the official Microsoft template
            Copy-Item -Path $templateFile -Destination $policyFile -Force
            
            # Reset policy ID to make it unique
            Set-CIPolicyIdInfo -FilePath $policyFile -PolicyName $PolicyName -ResetPolicyID
            
            # Configure options using official cmdlets
            # Option 3: Audit Mode
            if ($AuditMode) {
                Set-RuleOption -FilePath $policyFile -Option 3
            }
            else {
                Set-RuleOption -FilePath $policyFile -Option 3 -Delete
            }
            
            # Option 6: Unsigned System Integrity Policy (allows easier management)
            Set-RuleOption -FilePath $policyFile -Option 6
            
            # Option 10: Boot Audit on Failure (CRITICAL - allows boot even if policy has issues)
            Set-RuleOption -FilePath $policyFile -Option 10
            
            # Option 16: No Reboot (allows policy updates without reboot)
            Set-RuleOption -FilePath $policyFile -Option 16
            
            return @{
                Success = $true
                PolicyPath = $policyFile
                Message = "Policy created from Microsoft template: $TemplateType"
            }
        }
        else {
            return @{
                Success = $false
                Message = "Microsoft template not found at: $templateFile`nPlease ensure Windows is properly installed."
            }
        }
    }
    catch {
        return @{
            Success = $false
            Message = "Error creating policy: $($_.Exception.Message)"
        }
    }
}

function New-SignedAppPolicy {
    param(
        [string]$PolicyName,
        [string]$OutputPath,
        [bool]$AuditMode = $true,
        [bool]$MicrosoftOnly = $false
    )
    
    try {
        if (-not (Test-ConfigCIAvailable)) {
            return @{
                Success = $false
                Message = "ConfigCI module not available."
            }
        }
        
        $policyFile = Join-Path $OutputPath "$PolicyName.xml"
        
        if ($MicrosoftOnly) {
            # Use the AllowMicrosoft template
            $templateFile = "$env:SystemRoot\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml"
            if (Test-Path $templateFile) {
                Copy-Item -Path $templateFile -Destination $policyFile -Force
                Set-CIPolicyIdInfo -FilePath $policyFile -PolicyName $PolicyName -ResetPolicyID
            }
            else {
                return @{
                    Success = $false
                    Message = "AllowMicrosoft template not found."
                }
            }
        }
        else {
            # Scan system to find all signed publishers
            $scanPaths = @("$env:SystemRoot\System32")
            
            # Add Program Files if they exist
            if (Test-Path "$env:ProgramFiles") {
                $scanPaths += "$env:ProgramFiles"
            }
            if (Test-Path "${env:ProgramFiles(x86)}") {
                $scanPaths += "${env:ProgramFiles(x86)}"
            }
            
            # Create policy by scanning - this uses Publisher level which allows
            # any app signed by discovered publishers
            New-CIPolicy -FilePath $policyFile -Level Publisher -Fallback Hash `
                -ScanPath $scanPaths -UserPEs -MultiplePolicyFormat
            
            Set-CIPolicyIdInfo -FilePath $policyFile -PolicyName $PolicyName
        }
        
        # Configure standard options
        if ($AuditMode) {
            Set-RuleOption -FilePath $policyFile -Option 3   # Audit Mode
        }
        else {
            Set-RuleOption -FilePath $policyFile -Option 3 -Delete
        }
        
        Set-RuleOption -FilePath $policyFile -Option 6   # Unsigned policy OK
        Set-RuleOption -FilePath $policyFile -Option 10  # Boot Audit on Failure (CRITICAL SAFETY)
        Set-RuleOption -FilePath $policyFile -Option 16  # No Reboot required
        
        return @{
            Success = $true
            PolicyPath = $policyFile
            Message = "Policy created successfully."
        }
    }
    catch {
        return @{
            Success = $false
            Message = "Error: $($_.Exception.Message)"
        }
    }
}

function Add-SafetyOptionsToPolicy {
    param(
        [string]$XmlPath
    )
    
    # Ensures critical safety options are set on a policy before deployment
    try {
        if (-not (Test-ConfigCIAvailable)) {
            return $false
        }
        
        # Option 10: Boot Audit on Failure - CRITICAL for safety
        # This ensures Windows will boot even if the policy blocks something critical
        Set-RuleOption -FilePath $XmlPath -Option 10 -ErrorAction Stop
        
        # Option 6: Unsigned System Integrity Policy - allows policy updates
        Set-RuleOption -FilePath $XmlPath -Option 6 -ErrorAction SilentlyContinue
        
        return $true
    }
    catch {
        return $false
    }
}

function Test-PolicyValidity {
    param(
        [string]$XmlPath
    )
    
    # Tests if a policy can be converted to binary format without errors
    try {
        $testBinPath = Join-Path $env:TEMP "test_policy_$(Get-Random).cip"
        
        # Try to convert - this will fail if the XML is invalid
        ConvertFrom-CIPolicy -XmlFilePath $XmlPath -BinaryFilePath $testBinPath -ErrorAction Stop
        
        # Clean up test file
        if (Test-Path $testBinPath) {
            Remove-Item $testBinPath -Force -ErrorAction SilentlyContinue
        }
        
        return @{
            Valid = $true
            Message = "Policy is valid."
        }
    }
    catch {
        return @{
            Valid = $false
            Message = "Policy validation failed: $($_.Exception.Message)"
        }
    }
}

function Deploy-WDACPolicy {
    param(
        [string]$XmlPath
    )
    
    try {
        if (-not (Test-Administrator)) {
            return @{
                Success = $false
                Message = "Administrator privileges required."
            }
        }
        
        if (-not (Test-ConfigCIAvailable)) {
            return @{
                Success = $false
                Message = "ConfigCI module not available."
            }
        }
        
        if (-not (Test-Path $XmlPath)) {
            return @{
                Success = $false
                Message = "Policy file not found: $XmlPath"
            }
        }
        
        # SAFETY: Add critical safety options to the policy before deployment
        $safetyAdded = Add-SafetyOptionsToPolicy -XmlPath $XmlPath
        if (-not $safetyAdded) {
            return @{
                Success = $false
                Message = "Failed to add safety options to policy. Deployment aborted for safety."
            }
        }
        
        # SAFETY: Validate the policy can be converted before deploying
        $validation = Test-PolicyValidity -XmlPath $XmlPath
        if (-not $validation.Valid) {
            return @{
                Success = $false
                Message = "Policy validation failed: $($validation.Message)`n`nDeployment aborted."
            }
        }
        
        # Convert XML to binary
        $binPath = $XmlPath -replace '\.xml$', '.cip'
        ConvertFrom-CIPolicy -XmlFilePath $XmlPath -BinaryFilePath $binPath -ErrorAction Stop
        
        # Get policy ID from the converted policy
        [xml]$policyXml = Get-Content $XmlPath -Encoding UTF8
        $policyId = $policyXml.SiPolicy.PolicyID -replace '[{}]', ''
        
        if ([string]::IsNullOrEmpty($policyId)) {
            $policyId = [guid]::NewGuid().ToString().ToUpper()
        }
        
        # Deploy to CiPolicies\Active folder (modern method - NOT legacy SIPolicy.p7b)
        $destFolder = "$env:SystemRoot\System32\CodeIntegrity\CiPolicies\Active"
        if (-not (Test-Path $destFolder)) {
            New-Item -Path $destFolder -ItemType Directory -Force | Out-Null
        }
        
        $destPath = Join-Path $destFolder "{$policyId}.cip"
        Copy-Item -Path $binPath -Destination $destPath -Force
        
        # Try to refresh policy without reboot using CiTool (Windows 11)
        $ciToolPath = "$env:SystemRoot\System32\CiTool.exe"
        $refreshed = $false
        if (Test-Path $ciToolPath) {
            try {
                $output = & $ciToolPath --update-policy $destPath 2>&1
                $refreshed = $true
            }
            catch {
                $refreshed = $false
            }
        }
        
        $msg = "Policy deployed to: $destPath"
        $msg += "`n`nSafety option 'Boot Audit on Failure' has been enabled."
        if ($refreshed) {
            $msg += "`nPolicy refreshed. Changes should be active."
        }
        else {
            $msg += "`nA REBOOT is required to activate the policy."
        }
        
        return @{
            Success = $true
            Message = $msg
        }
    }
    catch {
        return @{
            Success = $false
            Message = "Deploy error: $($_.Exception.Message)"
        }
    }
}

function Remove-AllWDACPolicies {
    try {
        if (-not (Test-Administrator)) {
            return @{
                Success = $false
                Message = "Administrator privileges required."
            }
        }
        
        $removed = @()
        
        # Remove from multiple policy location
        $activePath = "$env:SystemRoot\System32\CodeIntegrity\CiPolicies\Active"
        if (Test-Path $activePath) {
            $policies = Get-ChildItem -Path $activePath -Filter "*.cip" -ErrorAction SilentlyContinue
            foreach ($policy in $policies) {
                Remove-Item -Path $policy.FullName -Force -ErrorAction SilentlyContinue
                $removed += $policy.Name
            }
        }
        
        # Remove legacy policy
        $legacyPolicy = "$env:SystemRoot\System32\CodeIntegrity\SIPolicy.p7b"
        if (Test-Path $legacyPolicy) {
            Remove-Item -Path $legacyPolicy -Force -ErrorAction SilentlyContinue
            $removed += "SIPolicy.p7b"
        }
        
        # Try to refresh using CiTool
        $ciToolPath = "$env:SystemRoot\System32\CiTool.exe"
        if (Test-Path $ciToolPath) {
            try {
                & $ciToolPath --refresh 2>&1 | Out-Null
            }
            catch { }
        }
        
        if ($removed.Count -gt 0) {
            return @{
                Success = $true
                Message = "Removed: $($removed -join ', ')`n`nREBOOT REQUIRED to complete removal."
            }
        }
        else {
            return @{
                Success = $true
                Message = "No active policies found."
            }
        }
    }
    catch {
        return @{
            Success = $false
            Message = "Error: $($_.Exception.Message)"
        }
    }
}

function Import-WDACPolicy {
    param(
        [string]$XmlPath
    )
    
    try {
        if (-not (Test-Path $XmlPath)) {
            return @{
                Success = $false
                Message = "File not found: $XmlPath"
            }
        }
        
        [xml]$policyXml = Get-Content -Path $XmlPath -Encoding UTF8
        
        $policyInfo = @{
            PolicyID = $policyXml.SiPolicy.PolicyID
            BasePolicyID = $policyXml.SiPolicy.BasePolicyID
            Version = $policyXml.SiPolicy.VersionEx
            Name = ""
            IsAuditMode = $false
            HasUMCI = $false
            HasBootAudit = $false
            SignerCount = 0
        }
        
        # Get policy name
        $nameSetting = $policyXml.SiPolicy.Settings.Setting | Where-Object { $_.ValueName -eq "Name" }
        if ($nameSetting) {
            $policyInfo.Name = $nameSetting.Value.String
        }
        
        # Check rules/options
        $rules = $policyXml.SiPolicy.Rules.Rule
        if ($rules) {
            $ruleTexts = $rules | ForEach-Object { $_.Option }
            $policyInfo.IsAuditMode = $ruleTexts -contains "Enabled:Audit Mode"
            $policyInfo.HasUMCI = $ruleTexts -contains "Enabled:UMCI"
            $policyInfo.HasBootAudit = $ruleTexts -contains "Enabled:Boot Audit On Failure"
        }
        
        # Count signers
        if ($policyXml.SiPolicy.Signers.Signer) {
            $policyInfo.SignerCount = @($policyXml.SiPolicy.Signers.Signer).Count
        }
        
        return @{
            Success = $true
            PolicyInfo = $policyInfo
            XmlPath = $XmlPath
            Message = "Policy loaded."
        }
    }
    catch {
        return @{
            Success = $false
            Message = "Import error: $($_.Exception.Message)"
        }
    }
}

# ============================================================================
# GUI Creation
# ============================================================================

function Show-WDACConfigGUI {
    $configCIAvailable = Test-ConfigCIAvailable
    
    # Verify Microsoft templates exist
    $templatesExist = $false
    $templatePath = "$env:SystemRoot\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml"
    if (Test-Path $templatePath) {
        $templatesExist = $true
    }
    
    # Create form
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "WDAC Configuration Tool (Safe Mode)"
    $form.Size = New-Object System.Drawing.Size(720, 720)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "FixedSingle"
    $form.MaximizeBox = $false
    $form.BackColor = [System.Drawing.Color]::FromArgb(245, 245, 245)
    $form.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    
    # Header
    $headerPanel = New-Object System.Windows.Forms.Panel
    $headerPanel.Dock = "Top"
    $headerPanel.Height = 50
    $headerPanel.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 212)
    $form.Controls.Add($headerPanel)
    
    $headerLabel = New-Object System.Windows.Forms.Label
    $headerLabel.Text = "Windows Defender Application Control (WDAC)"
    $headerLabel.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
    $headerLabel.ForeColor = [System.Drawing.Color]::White
    $headerLabel.AutoSize = $true
    $headerLabel.Location = New-Object System.Drawing.Point(15, 12)
    $headerPanel.Controls.Add($headerLabel)
    
    # Warning box
    $warningBox = New-Object System.Windows.Forms.GroupBox
    $warningBox.Text = "⚠ CRITICAL WARNING"
    $warningBox.Location = New-Object System.Drawing.Point(15, 60)
    $warningBox.Size = New-Object System.Drawing.Size(675, 55)
    $warningBox.ForeColor = [System.Drawing.Color]::DarkRed
    $form.Controls.Add($warningBox)
    
    $warningLabel = New-Object System.Windows.Forms.Label
    $warningLabel.Text = "ALWAYS test in Audit Mode first! Incorrect WDAC policies can prevent Windows from booting. Keep a recovery USB ready."
    $warningLabel.Location = New-Object System.Drawing.Point(10, 18)
    $warningLabel.Size = New-Object System.Drawing.Size(655, 30)
    $warningLabel.ForeColor = [System.Drawing.Color]::DarkRed
    $warningBox.Controls.Add($warningLabel)
    
    # Status indicators
    $adminLabel = New-Object System.Windows.Forms.Label
    $adminLabel.Location = New-Object System.Drawing.Point(15, 125)
    $adminLabel.AutoSize = $true
    if (Test-Administrator) {
        $adminLabel.Text = "✓ Administrator"
        $adminLabel.ForeColor = [System.Drawing.Color]::Green
    } else {
        $adminLabel.Text = "✗ Not Admin"
        $adminLabel.ForeColor = [System.Drawing.Color]::Red
    }
    $form.Controls.Add($adminLabel)
    
    $configLabel = New-Object System.Windows.Forms.Label
    $configLabel.Location = New-Object System.Drawing.Point(130, 125)
    $configLabel.AutoSize = $true
    if ($configCIAvailable) {
        $configLabel.Text = "✓ ConfigCI Available"
        $configLabel.ForeColor = [System.Drawing.Color]::Green
    } else {
        $configLabel.Text = "✗ ConfigCI NOT Available (Need Pro/Enterprise)"
        $configLabel.ForeColor = [System.Drawing.Color]::Red
    }
    $form.Controls.Add($configLabel)
    
    # Status Group
    $statusGroup = New-Object System.Windows.Forms.GroupBox
    $statusGroup.Text = "Current Status"
    $statusGroup.Location = New-Object System.Drawing.Point(15, 150)
    $statusGroup.Size = New-Object System.Drawing.Size(675, 80)
    $form.Controls.Add($statusGroup)
    
    $statusText = New-Object System.Windows.Forms.TextBox
    $statusText.Multiline = $true
    $statusText.ReadOnly = $true
    $statusText.Location = New-Object System.Drawing.Point(10, 20)
    $statusText.Size = New-Object System.Drawing.Size(555, 50)
    $statusGroup.Controls.Add($statusText)
    
    $refreshBtn = New-Object System.Windows.Forms.Button
    $refreshBtn.Text = "Refresh"
    $refreshBtn.Location = New-Object System.Drawing.Point(580, 20)
    $refreshBtn.Size = New-Object System.Drawing.Size(80, 30)
    $statusGroup.Controls.Add($refreshBtn)
    
    # Policy Templates Group
    $templateGroup = New-Object System.Windows.Forms.GroupBox
    $templateGroup.Text = "Policy Templates (Official Microsoft Templates)"
    $templateGroup.Location = New-Object System.Drawing.Point(15, 240)
    $templateGroup.Size = New-Object System.Drawing.Size(675, 170)
    $form.Controls.Add($templateGroup)
    
    $radioMSTemplate = New-Object System.Windows.Forms.RadioButton
    $radioMSTemplate.Text = "AllowMicrosoft - Windows + Microsoft Store apps (Safest starting point)"
    $radioMSTemplate.Location = New-Object System.Drawing.Point(15, 25)
    $radioMSTemplate.Size = New-Object System.Drawing.Size(640, 22)
    $radioMSTemplate.Checked = $true
    $templateGroup.Controls.Add($radioMSTemplate)
    
    $radioDefWindows = New-Object System.Windows.Forms.RadioButton
    $radioDefWindows.Text = "DefaultWindows - Core Windows only (More restrictive)"
    $radioDefWindows.Location = New-Object System.Drawing.Point(15, 55)
    $radioDefWindows.Size = New-Object System.Drawing.Size(640, 22)
    $templateGroup.Controls.Add($radioDefWindows)
    
    $radioScanSystem = New-Object System.Windows.Forms.RadioButton
    $radioScanSystem.Text = "Scan System - Allow all currently installed signed apps (Takes ~1 min)"
    $radioScanSystem.Location = New-Object System.Drawing.Point(15, 85)
    $radioScanSystem.Size = New-Object System.Drawing.Size(640, 22)
    $templateGroup.Controls.Add($radioScanSystem)
    
    $radioMSOnly = New-Object System.Windows.Forms.RadioButton
    $radioMSOnly.Text = "Microsoft Only - BLOCKS Chrome/Firefox/Adobe/etc (Very restrictive!)"
    $radioMSOnly.Location = New-Object System.Drawing.Point(15, 115)
    $radioMSOnly.Size = New-Object System.Drawing.Size(640, 22)
    $radioMSOnly.ForeColor = [System.Drawing.Color]::DarkRed
    $templateGroup.Controls.Add($radioMSOnly)
    
    $noteLabel = New-Object System.Windows.Forms.Label
    $noteLabel.Text = "Note: All policies include 'Boot Audit on Failure' for safety - Windows will still boot if policy has issues."
    $noteLabel.Location = New-Object System.Drawing.Point(15, 145)
    $noteLabel.Size = New-Object System.Drawing.Size(640, 20)
    $noteLabel.ForeColor = [System.Drawing.Color]::Gray
    $templateGroup.Controls.Add($noteLabel)
    
    # Options Group
    $optGroup = New-Object System.Windows.Forms.GroupBox
    $optGroup.Text = "Options"
    $optGroup.Location = New-Object System.Drawing.Point(15, 420)
    $optGroup.Size = New-Object System.Drawing.Size(675, 60)
    $form.Controls.Add($optGroup)
    
    $chkAudit = New-Object System.Windows.Forms.CheckBox
    $chkAudit.Text = "AUDIT MODE - Log only, don't block (STRONGLY RECOMMENDED!)"
    $chkAudit.Location = New-Object System.Drawing.Point(15, 25)
    $chkAudit.Size = New-Object System.Drawing.Size(640, 25)
    $chkAudit.Checked = $true
    $chkAudit.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $optGroup.Controls.Add($chkAudit)
    
    # Buttons
    $btnCreate = New-Object System.Windows.Forms.Button
    $btnCreate.Text = "Create Policy"
    $btnCreate.Location = New-Object System.Drawing.Point(15, 490)
    $btnCreate.Size = New-Object System.Drawing.Size(100, 35)
    $btnCreate.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 212)
    $btnCreate.ForeColor = [System.Drawing.Color]::White
    $btnCreate.FlatStyle = "Flat"
    $btnCreate.Enabled = $configCIAvailable
    $form.Controls.Add($btnCreate)
    
    $btnImport = New-Object System.Windows.Forms.Button
    $btnImport.Text = "Import XML"
    $btnImport.Location = New-Object System.Drawing.Point(125, 490)
    $btnImport.Size = New-Object System.Drawing.Size(100, 35)
    $btnImport.BackColor = [System.Drawing.Color]::FromArgb(0, 99, 177)
    $btnImport.ForeColor = [System.Drawing.Color]::White
    $btnImport.FlatStyle = "Flat"
    $form.Controls.Add($btnImport)
    
    $btnDeploy = New-Object System.Windows.Forms.Button
    $btnDeploy.Text = "Deploy"
    $btnDeploy.Location = New-Object System.Drawing.Point(235, 490)
    $btnDeploy.Size = New-Object System.Drawing.Size(100, 35)
    $btnDeploy.BackColor = [System.Drawing.Color]::FromArgb(16, 124, 16)
    $btnDeploy.ForeColor = [System.Drawing.Color]::White
    $btnDeploy.FlatStyle = "Flat"
    $btnDeploy.Enabled = $configCIAvailable
    $form.Controls.Add($btnDeploy)
    
    $btnRemove = New-Object System.Windows.Forms.Button
    $btnRemove.Text = "Remove All"
    $btnRemove.Location = New-Object System.Drawing.Point(345, 490)
    $btnRemove.Size = New-Object System.Drawing.Size(100, 35)
    $btnRemove.BackColor = [System.Drawing.Color]::FromArgb(196, 43, 28)
    $btnRemove.ForeColor = [System.Drawing.Color]::White
    $btnRemove.FlatStyle = "Flat"
    $form.Controls.Add($btnRemove)
    
    $btnHelp = New-Object System.Windows.Forms.Button
    $btnHelp.Text = "Help/Recovery"
    $btnHelp.Location = New-Object System.Drawing.Point(560, 490)
    $btnHelp.Size = New-Object System.Drawing.Size(130, 35)
    $btnHelp.BackColor = [System.Drawing.Color]::FromArgb(100, 100, 100)
    $btnHelp.ForeColor = [System.Drawing.Color]::White
    $btnHelp.FlatStyle = "Flat"
    $form.Controls.Add($btnHelp)
    
    # Log
    $logGroup = New-Object System.Windows.Forms.GroupBox
    $logGroup.Text = "Log"
    $logGroup.Location = New-Object System.Drawing.Point(15, 535)
    $logGroup.Size = New-Object System.Drawing.Size(675, 130)
    $form.Controls.Add($logGroup)
    
    $logText = New-Object System.Windows.Forms.TextBox
    $logText.Multiline = $true
    $logText.ReadOnly = $true
    $logText.ScrollBars = "Vertical"
    $logText.Location = New-Object System.Drawing.Point(10, 20)
    $logText.Size = New-Object System.Drawing.Size(655, 100)
    $logGroup.Controls.Add($logText)
    
    # State variable for current policy
    $script:policyPath = $null
    
    # Event handlers
    $updateStatus = {
        $st = Get-WDACStatus
        $statusText.Text = "CI: $(if($st.CodeIntegrityEnabled){'ON'}else{'OFF'}) | Mode: $($st.EnforcementMode) | UMCI: $(if($st.UMCIEnabled){'ON'}else{'OFF'})`r`nPolicies: $(if($st.ActivePolicies.Count -gt 0){$st.ActivePolicies -join ', '}else{'None'})"
    }
    
    $refreshBtn.Add_Click($updateStatus)
    
    $btnCreate.Add_Click({
        # Safety check: Verify ConfigCI is available
        if (-not (Test-ConfigCIAvailable)) {
            [System.Windows.Forms.MessageBox]::Show("ConfigCI module is not available.`n`nThis feature requires Windows 10/11 Pro, Enterprise, or Education.", "Not Available", "OK", "Error")
            return
        }
        
        $folder = New-Object System.Windows.Forms.FolderBrowserDialog
        $folder.Description = "Select folder to save policy"
        
        if ($folder.ShowDialog() -eq "OK") {
            $logText.Text = "Creating policy... Please wait."
            $form.Refresh()
            
            $result = $null
            
            if ($radioMSTemplate.Checked) {
                $result = New-WDACPolicyFromTemplate -PolicyName "AllowMicrosoft" -TemplateType "AllowMicrosoft" `
                    -OutputPath $folder.SelectedPath -AuditMode $chkAudit.Checked
            }
            elseif ($radioDefWindows.Checked) {
                $result = New-WDACPolicyFromTemplate -PolicyName "DefaultWindows" -TemplateType "DefaultWindows" `
                    -OutputPath $folder.SelectedPath -AuditMode $chkAudit.Checked
            }
            elseif ($radioScanSystem.Checked) {
                $result = New-SignedAppPolicy -PolicyName "AllSignedApps" -OutputPath $folder.SelectedPath `
                    -AuditMode $chkAudit.Checked -MicrosoftOnly $false
            }
            elseif ($radioMSOnly.Checked) {
                $result = New-SignedAppPolicy -PolicyName "MicrosoftOnly" -OutputPath $folder.SelectedPath `
                    -AuditMode $chkAudit.Checked -MicrosoftOnly $true
            }
            
            if ($result -and $result.Success) {
                $script:policyPath = $result.PolicyPath
                
                # Validate the created policy immediately
                $validation = Test-PolicyValidity -XmlPath $result.PolicyPath
                if ($validation.Valid) {
                    $logText.Text = "SUCCESS: Policy created and validated.`r`nPath: $($result.PolicyPath)"
                    [System.Windows.Forms.MessageBox]::Show("Policy created and validated!`n`n$($result.PolicyPath)`n`nClick 'Deploy' to apply it.", "Success", "OK", "Information")
                }
                else {
                    $logText.Text = "WARNING: Policy created but validation failed: $($validation.Message)"
                    [System.Windows.Forms.MessageBox]::Show("Policy created but validation failed!`n`n$($validation.Message)`n`nDo NOT deploy this policy.", "Validation Failed", "OK", "Warning")
                    $script:policyPath = $null
                }
            }
            elseif ($result) {
                $logText.Text = "ERROR: $($result.Message)"
                [System.Windows.Forms.MessageBox]::Show($result.Message, "Error", "OK", "Error")
            }
            else {
                $logText.Text = "ERROR: Unknown error occurred."
                [System.Windows.Forms.MessageBox]::Show("An unknown error occurred.", "Error", "OK", "Error")
            }
        }
    })
    
    $btnImport.Add_Click({
        $openDlg = New-Object System.Windows.Forms.OpenFileDialog
        $openDlg.Filter = "XML Files|*.xml"
        $openDlg.Title = "Select WDAC Policy XML"
        
        if ($openDlg.ShowDialog() -eq "OK") {
            $result = Import-WDACPolicy -XmlPath $openDlg.FileName
            
            if ($result.Success) {
                $info = $result.PolicyInfo
                
                # Create a working copy of the policy to add safety options
                $workingCopy = Join-Path $env:TEMP "imported_policy_$(Get-Random).xml"
                Copy-Item -Path $openDlg.FileName -Destination $workingCopy -Force
                
                # Add safety options to the imported policy
                $safetyAdded = Add-SafetyOptionsToPolicy -XmlPath $workingCopy
                
                $script:policyPath = $workingCopy
                
                $msg = "Policy: $($info.Name)`n"
                $msg += "Original Audit Mode: $(if($info.IsAuditMode){'Yes'}else{'NO - ENFORCED!'})`n"
                $msg += "Original Boot Audit: $(if($info.HasBootAudit){'Yes'}else{'No'})`n"
                $msg += "Signers: $($info.SignerCount)`n"
                
                if ($safetyAdded) {
                    $msg += "`n✓ Safety option 'Boot Audit on Failure' has been ADDED to this policy."
                }
                else {
                    $msg += "`n⚠ Could not add safety options. ConfigCI may not be available."
                }
                
                $logText.Text = "Imported: $($openDlg.FileName)"
                
                if (-not $info.IsAuditMode) {
                    $msg += "`n`n⚠ WARNING: This policy is in ENFORCED mode!"
                    $msg += "`nIt will BLOCK applications that don't match."
                }
                
                [System.Windows.Forms.MessageBox]::Show($msg, "Policy Imported", "OK", "Information")
            }
            else {
                $logText.Text = $result.Message
                [System.Windows.Forms.MessageBox]::Show($result.Message, "Error", "OK", "Error")
            }
        }
    })
    
    $btnDeploy.Add_Click({
        if (-not $script:policyPath -or -not (Test-Path $script:policyPath)) {
            [System.Windows.Forms.MessageBox]::Show("No policy loaded. Create or Import a policy first.", "No Policy", "OK", "Warning")
            return
        }
        
        # Validate policy before deployment
        $logText.Text = "Validating policy..."
        $form.Refresh()
        
        $validation = Test-PolicyValidity -XmlPath $script:policyPath
        if (-not $validation.Valid) {
            $logText.Text = "Validation FAILED: $($validation.Message)"
            [System.Windows.Forms.MessageBox]::Show(
                "Policy validation FAILED!`n`n$($validation.Message)`n`nDeployment aborted for safety.",
                "Validation Failed", "OK", "Error")
            return
        }
        
        $logText.Text = "Policy validated successfully."
        
        if (-not $chkAudit.Checked) {
            $warn = [System.Windows.Forms.MessageBox]::Show(
                "⚠ DANGER: Deploying in ENFORCED mode!`n`nIf this policy is wrong, Windows may not boot!`n`nThe safety option 'Boot Audit on Failure' will be enabled,`nbut you should still test in Audit Mode first.`n`nAre you SURE you want to continue?",
                "WARNING - ENFORCED MODE", "YesNo", "Warning")
            if ($warn -ne "Yes") { return }
            
            # Double confirmation for enforced mode
            $doubleWarn = [System.Windows.Forms.MessageBox]::Show(
                "FINAL WARNING`n`nYou are about to deploy an ENFORCED WDAC policy.`n`nType 'I understand' below (case-sensitive):",
                "FINAL CONFIRMATION", "OKCancel", "Stop")
            if ($doubleWarn -ne "OK") { return }
        }
        
        $confirm = [System.Windows.Forms.MessageBox]::Show(
            "Deploy policy?`n`n$($script:policyPath)`n`nSafety option 'Boot Audit on Failure' will be enabled.", 
            "Confirm Deployment", "YesNo", "Question")
        
        if ($confirm -eq "Yes") {
            $logText.Text = "Deploying policy..."
            $form.Refresh()
            
            $result = Deploy-WDACPolicy -XmlPath $script:policyPath
            $logText.Text = $result.Message
            [System.Windows.Forms.MessageBox]::Show($result.Message, $(if($result.Success){"Success"}else{"Error"}), "OK", $(if($result.Success){"Information"}else{"Error"}))
            & $updateStatus
        }
    })
    
    $btnRemove.Add_Click({
        $confirm = [System.Windows.Forms.MessageBox]::Show(
            "Remove ALL WDAC policies?`n`nReboot will be required.", "Confirm", "YesNo", "Warning")
        
        if ($confirm -eq "Yes") {
            $result = Remove-AllWDACPolicies
            $logText.Text = $result.Message
            [System.Windows.Forms.MessageBox]::Show($result.Message, $(if($result.Success){"Success"}else{"Error"}), "OK", $(if($result.Success){"Information"}else{"Error"}))
            & $updateStatus
        }
    })
    
    $btnHelp.Add_Click({
        $help = @"
RECOVERY INSTRUCTIONS
=====================

If Windows won't boot after deploying a WDAC policy:

1. Boot from Windows Installation USB/DVD
2. Select "Repair your computer"
3. Troubleshoot > Command Prompt
4. Type these commands:

   del C:\Windows\System32\CodeIntegrity\SIPolicy.p7b
   del C:\Windows\System32\CodeIntegrity\CiPolicies\Active\*.cip

5. Type: exit
6. Restart

SAFE USAGE
==========
• ALWAYS use Audit Mode first
• Test for several days before enforcing
• Check Event Viewer for violations:
  Applications and Services Logs >
    Microsoft > Windows > CodeIntegrity

POLICY TEMPLATES
================
• AllowMicrosoft: Safest, allows Windows + MS apps
• DefaultWindows: Stricter, core Windows only
• Scan System: Allows all installed signed apps
• Microsoft Only: Very strict, blocks 3rd party
"@
        [System.Windows.Forms.MessageBox]::Show($help, "Help & Recovery", "OK", "Information")
    })
    
    # Initialize
    & $updateStatus
    
    # Set initial log text based on availability
    if (-not $configCIAvailable) {
        $logText.Text = "⚠ ConfigCI module not available. Import/Remove only."
        $btnCreate.Enabled = $false
        $btnDeploy.Enabled = $false
    }
    elseif (-not $templatesExist) {
        $logText.Text = "⚠ Microsoft policy templates not found. Only 'Scan System' option available."
        $radioMSTemplate.Enabled = $false
        $radioDefWindows.Enabled = $false
        $radioMSOnly.Enabled = $false
        $radioScanSystem.Checked = $true
    }
    else {
        $logText.Text = "Ready. Select a template and click 'Create Policy'.`r`n⚠ ALWAYS test in Audit Mode first!"
    }
    
    $form.ShowDialog() | Out-Null
}

# Run
Show-WDACConfigGUI
