<#
.SYNOPSIS
    Windows Defender Application Control (WDAC) Configuration GUI
.DESCRIPTION
    A PowerShell 5 GUI tool for viewing and configuring WDAC policies on Windows 11.
    Provides preset scenarios for common security configurations.
.NOTES
    Requires Administrator privileges to apply policies.
    Windows 11 with WDAC support required.
#>

#Requires -Version 5.0

# Force UTF-8 encoding (wrapped in try-catch for GUI contexts without console)
try {
    if ($Host.Name -ne 'ConsoleHost' -or [Console]::OutputEncoding) {
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    }
} catch {
    # Silently continue - no console available (normal for GUI apps)
}
$PSDefaultParameterValues['*:Encoding'] = 'utf8'
$OutputEncoding = [System.Text.Encoding]::UTF8

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ============================================================================
# WDAC Policy Functions
# ============================================================================

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-WDACStatus {
    try {
        # Check if Code Integrity is enabled
        $ciStatus = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
        
        $status = @{
            VBSEnabled = $false
            CodeIntegrityEnabled = $false
            UMCIEnabled = $false
            ActivePolicies = @()
            EnforcementMode = "Not Configured"
        }
        
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
        
        # Check registry for additional policy info
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
        if (Test-Path $regPath) {
            $regValues = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
            if ($regValues.EnableVirtualizationBasedSecurity -eq 1) {
                $status.VBSEnabled = $true
            }
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
        }
    }
}

function New-WDACPolicyXml {
    param(
        [string]$PolicyName,
        [string]$PolicyType,
        [bool]$BlockDownloadsFolder = $false,
        [bool]$AuditMode = $true
    )
    
    $policyId = [guid]::NewGuid().ToString()
    $basePolicyId = [guid]::NewGuid().ToString()
    
    # Define rule options based on policy type
    $ruleOptions = @()
    
    # Common options
    if ($AuditMode) {
        $ruleOptions += '<Option>Enabled:Audit Mode</Option>'
    }
    $ruleOptions += '<Option>Enabled:UMCI</Option>'
    $ruleOptions += '<Option>Enabled:Inherit Default Policy</Option>'
    $ruleOptions += '<Option>Enabled:Unsigned System Integrity Policy</Option>'
    $ruleOptions += '<Option>Enabled:Update Policy No Reboot</Option>'
    
    # Build signers and rules based on policy type
    $allowedSigners = ""
    $signers = ""
    $fileRules = ""
    $fileRuleRefs = ""
    
    switch ($PolicyType) {
        "AdminAnything_UserSigned" {
            # Administrators can run anything, users only signed apps
            $signers = @"
        <Signer ID="ID_SIGNER_WINDOWS" Name="Microsoft Windows">
            <CertRoot Type="Wellknown" Value="04" />
        </Signer>
        <Signer ID="ID_SIGNER_MSFT" Name="Microsoft Corporation">
            <CertRoot Type="Wellknown" Value="05" />
        </Signer>
        <Signer ID="ID_SIGNER_STORE" Name="Microsoft Store">
            <CertRoot Type="Wellknown" Value="06" />
        </Signer>
        <Signer ID="ID_SIGNER_WHQL" Name="Microsoft WHQL">
            <CertRoot Type="Wellknown" Value="01" />
        </Signer>
        <Signer ID="ID_SIGNER_ELAM" Name="Microsoft ELAM">
            <CertRoot Type="Wellknown" Value="07" />
        </Signer>
        <Signer ID="ID_SIGNER_HAL" Name="Microsoft HAL">
            <CertRoot Type="Wellknown" Value="08" />
        </Signer>
        <Signer ID="ID_SIGNER_THIRD_PARTY" Name="Third Party Signed">
            <CertRoot Type="TBS" Value="*" />
        </Signer>
"@
            $allowedSigners = @"
        <AllowedSigners>
            <AllowedSigner SignerId="ID_SIGNER_WINDOWS" />
            <AllowedSigner SignerId="ID_SIGNER_MSFT" />
            <AllowedSigner SignerId="ID_SIGNER_STORE" />
            <AllowedSigner SignerId="ID_SIGNER_WHQL" />
            <AllowedSigner SignerId="ID_SIGNER_ELAM" />
            <AllowedSigner SignerId="ID_SIGNER_HAL" />
            <AllowedSigner SignerId="ID_SIGNER_THIRD_PARTY" />
        </AllowedSigners>
"@
            $ruleOptions += '<Option>Enabled:Allow Supplemental Policies</Option>'
        }
        
        "AdminAnything_UserMSOnly" {
            # Administrators can run anything, users only Microsoft signed
            $signers = @"
        <Signer ID="ID_SIGNER_WINDOWS" Name="Microsoft Windows">
            <CertRoot Type="Wellknown" Value="04" />
        </Signer>
        <Signer ID="ID_SIGNER_MSFT" Name="Microsoft Corporation">
            <CertRoot Type="Wellknown" Value="05" />
        </Signer>
        <Signer ID="ID_SIGNER_STORE" Name="Microsoft Store">
            <CertRoot Type="Wellknown" Value="06" />
        </Signer>
        <Signer ID="ID_SIGNER_WHQL" Name="Microsoft WHQL">
            <CertRoot Type="Wellknown" Value="01" />
        </Signer>
        <Signer ID="ID_SIGNER_ELAM" Name="Microsoft ELAM">
            <CertRoot Type="Wellknown" Value="07" />
        </Signer>
        <Signer ID="ID_SIGNER_HAL" Name="Microsoft HAL">
            <CertRoot Type="Wellknown" Value="08" />
        </Signer>
"@
            $allowedSigners = @"
        <AllowedSigners>
            <AllowedSigner SignerId="ID_SIGNER_WINDOWS" />
            <AllowedSigner SignerId="ID_SIGNER_MSFT" />
            <AllowedSigner SignerId="ID_SIGNER_STORE" />
            <AllowedSigner SignerId="ID_SIGNER_WHQL" />
            <AllowedSigner SignerId="ID_SIGNER_ELAM" />
            <AllowedSigner SignerId="ID_SIGNER_HAL" />
        </AllowedSigners>
"@
        }
        
        "AllMSOnly" {
            # Everyone only Microsoft signed apps
            $signers = @"
        <Signer ID="ID_SIGNER_WINDOWS" Name="Microsoft Windows">
            <CertRoot Type="Wellknown" Value="04" />
        </Signer>
        <Signer ID="ID_SIGNER_MSFT" Name="Microsoft Corporation">
            <CertRoot Type="Wellknown" Value="05" />
        </Signer>
        <Signer ID="ID_SIGNER_STORE" Name="Microsoft Store">
            <CertRoot Type="Wellknown" Value="06" />
        </Signer>
        <Signer ID="ID_SIGNER_WHQL" Name="Microsoft WHQL">
            <CertRoot Type="Wellknown" Value="01" />
        </Signer>
        <Signer ID="ID_SIGNER_ELAM" Name="Microsoft ELAM">
            <CertRoot Type="Wellknown" Value="07" />
        </Signer>
        <Signer ID="ID_SIGNER_HAL" Name="Microsoft HAL">
            <CertRoot Type="Wellknown" Value="08" />
        </Signer>
"@
            $allowedSigners = @"
        <AllowedSigners>
            <AllowedSigner SignerId="ID_SIGNER_WINDOWS" />
            <AllowedSigner SignerId="ID_SIGNER_MSFT" />
            <AllowedSigner SignerId="ID_SIGNER_STORE" />
            <AllowedSigner SignerId="ID_SIGNER_WHQL" />
            <AllowedSigner SignerId="ID_SIGNER_ELAM" />
            <AllowedSigner SignerId="ID_SIGNER_HAL" />
        </AllowedSigners>
"@
        }
        
        "AllSigned" {
            # Everyone only signed apps (any vendor)
            $signers = @"
        <Signer ID="ID_SIGNER_WINDOWS" Name="Microsoft Windows">
            <CertRoot Type="Wellknown" Value="04" />
        </Signer>
        <Signer ID="ID_SIGNER_MSFT" Name="Microsoft Corporation">
            <CertRoot Type="Wellknown" Value="05" />
        </Signer>
        <Signer ID="ID_SIGNER_STORE" Name="Microsoft Store">
            <CertRoot Type="Wellknown" Value="06" />
        </Signer>
        <Signer ID="ID_SIGNER_WHQL" Name="Microsoft WHQL">
            <CertRoot Type="Wellknown" Value="01" />
        </Signer>
        <Signer ID="ID_SIGNER_ELAM" Name="Microsoft ELAM">
            <CertRoot Type="Wellknown" Value="07" />
        </Signer>
        <Signer ID="ID_SIGNER_HAL" Name="Microsoft HAL">
            <CertRoot Type="Wellknown" Value="08" />
        </Signer>
        <Signer ID="ID_SIGNER_THIRD_PARTY" Name="Third Party Signed">
            <CertRoot Type="TBS" Value="*" />
        </Signer>
"@
            $allowedSigners = @"
        <AllowedSigners>
            <AllowedSigner SignerId="ID_SIGNER_WINDOWS" />
            <AllowedSigner SignerId="ID_SIGNER_MSFT" />
            <AllowedSigner SignerId="ID_SIGNER_STORE" />
            <AllowedSigner SignerId="ID_SIGNER_WHQL" />
            <AllowedSigner SignerId="ID_SIGNER_ELAM" />
            <AllowedSigner SignerId="ID_SIGNER_HAL" />
            <AllowedSigner SignerId="ID_SIGNER_THIRD_PARTY" />
        </AllowedSigners>
"@
        }
    }
    
    # Add Downloads folder blocking rule if requested
    if ($BlockDownloadsFolder) {
        $fileRules = @"
        <Deny ID="ID_DENY_DOWNLOADS_EXE" FriendlyName="Block Downloads EXE" FileName="*" MinimumFileVersion="0.0.0.0" FilePath="%OSDRIVE%\Users\*\Downloads\*.exe" />
        <Deny ID="ID_DENY_DOWNLOADS_DLL" FriendlyName="Block Downloads DLL" FileName="*" MinimumFileVersion="0.0.0.0" FilePath="%OSDRIVE%\Users\*\Downloads\*.dll" />
        <Deny ID="ID_DENY_DOWNLOADS_MSI" FriendlyName="Block Downloads MSI" FileName="*" MinimumFileVersion="0.0.0.0" FilePath="%OSDRIVE%\Users\*\Downloads\*.msi" />
        <Deny ID="ID_DENY_DOWNLOADS_PS1" FriendlyName="Block Downloads PS1" FileName="*" MinimumFileVersion="0.0.0.0" FilePath="%OSDRIVE%\Users\*\Downloads\*.ps1" />
        <Deny ID="ID_DENY_DOWNLOADS_BAT" FriendlyName="Block Downloads BAT" FileName="*" MinimumFileVersion="0.0.0.0" FilePath="%OSDRIVE%\Users\*\Downloads\*.bat" />
        <Deny ID="ID_DENY_DOWNLOADS_CMD" FriendlyName="Block Downloads CMD" FileName="*" MinimumFileVersion="0.0.0.0" FilePath="%OSDRIVE%\Users\*\Downloads\*.cmd" />
        <Deny ID="ID_DENY_DOWNLOADS_VBS" FriendlyName="Block Downloads VBS" FileName="*" MinimumFileVersion="0.0.0.0" FilePath="%OSDRIVE%\Users\*\Downloads\*.vbs" />
        <Deny ID="ID_DENY_DOWNLOADS_JS" FriendlyName="Block Downloads JS" FileName="*" MinimumFileVersion="0.0.0.0" FilePath="%OSDRIVE%\Users\*\Downloads\*.js" />
"@
        $fileRuleRefs = @"
            <FileRuleRef RuleID="ID_DENY_DOWNLOADS_EXE" />
            <FileRuleRef RuleID="ID_DENY_DOWNLOADS_DLL" />
            <FileRuleRef RuleID="ID_DENY_DOWNLOADS_MSI" />
            <FileRuleRef RuleID="ID_DENY_DOWNLOADS_PS1" />
            <FileRuleRef RuleID="ID_DENY_DOWNLOADS_BAT" />
            <FileRuleRef RuleID="ID_DENY_DOWNLOADS_CMD" />
            <FileRuleRef RuleID="ID_DENY_DOWNLOADS_VBS" />
            <FileRuleRef RuleID="ID_DENY_DOWNLOADS_JS" />
"@
    }
    
    $ruleOptionsXml = $ruleOptions -join "`n        "
    
    $policyXml = @"
<?xml version="1.0" encoding="utf-8"?>
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="Base Policy">
    <VersionEx>10.0.0.0</VersionEx>
    <PlatformID>{2E07F7E4-194C-4D20-B7C9-6F44A6C5A234}</PlatformID>
    <PolicyID>{$policyId}</PolicyID>
    <BasePolicyID>{$basePolicyId}</BasePolicyID>
    <Rules>
        $ruleOptionsXml
    </Rules>
    <EKUs />
    <FileRules>
$fileRules
    </FileRules>
    <Signers>
$signers
    </Signers>
    <SigningScenarios>
        <SigningScenario Value="131" ID="ID_SIGNINGSCENARIO_DRIVERS" FriendlyName="Kernel Mode">
            <ProductSigners>
                <AllowedSigners>
                    <AllowedSigner SignerId="ID_SIGNER_WINDOWS" />
                    <AllowedSigner SignerId="ID_SIGNER_WHQL" />
                </AllowedSigners>
            </ProductSigners>
        </SigningScenario>
        <SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_USERMODE" FriendlyName="User Mode">
            <ProductSigners>
$allowedSigners
                <FileRulesRef>
$fileRuleRefs
                </FileRulesRef>
            </ProductSigners>
        </SigningScenario>
    </SigningScenarios>
    <UpdatePolicySigners />
    <CiSigners />
    <HvciOptions>0</HvciOptions>
    <Settings>
        <Setting Provider="PolicyInfo" Key="Information" ValueName="Name">
            <Value>
                <String>$PolicyName</String>
            </Value>
        </Setting>
    </Settings>
</SiPolicy>
"@
    
    return $policyXml
}

function Export-WDACPolicy {
    param(
        [string]$PolicyXml,
        [string]$OutputPath
    )
    
    try {
        # Save XML file
        $xmlPath = Join-Path $OutputPath "WDACPolicy.xml"
        $PolicyXml | Out-File -FilePath $xmlPath -Encoding UTF8 -Force
        
        return @{
            Success = $true
            XmlPath = $xmlPath
            Message = "Policy exported successfully to: $xmlPath"
        }
    }
    catch {
        return @{
            Success = $false
            XmlPath = $null
            Message = "Error exporting policy: $($_.Exception.Message)"
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
                Message = "Administrator privileges required to deploy WDAC policy."
            }
        }
        
        # Convert XML to binary
        $binPath = $XmlPath -replace '\.xml$', '.cip'
        
        # Use ConvertFrom-CIPolicy if available (Windows 10/11)
        if (Get-Command ConvertFrom-CIPolicy -ErrorAction SilentlyContinue) {
            ConvertFrom-CIPolicy -XmlFilePath $XmlPath -BinaryFilePath $binPath
        }
        else {
            return @{
                Success = $false
                Message = "ConvertFrom-CIPolicy cmdlet not available. Ensure you have the ConfigCI module installed."
            }
        }
        
        # Deploy the policy
        $policyDest = "$env:SystemRoot\System32\CodeIntegrity\CiPolicies\Active"
        if (-not (Test-Path $policyDest)) {
            New-Item -Path $policyDest -ItemType Directory -Force | Out-Null
        }
        
        # Get policy ID from XML
        [xml]$policyXmlContent = Get-Content $XmlPath
        $policyId = $policyXmlContent.SiPolicy.PolicyID -replace '[{}]', ''
        
        $destPath = Join-Path $policyDest "{$policyId}.cip"
        Copy-Item -Path $binPath -Destination $destPath -Force
        
        # Refresh policy
        if (Get-Command Invoke-CimMethod -ErrorAction SilentlyContinue) {
            try {
                Invoke-CimMethod -Namespace root\Microsoft\Windows\CI -ClassName PS_UpdateAndCompareCIPolicy -MethodName Update -Arguments @{FilePath = $destPath} -ErrorAction SilentlyContinue
            }
            catch {
                # Policy will be applied on next reboot
            }
        }
        
        return @{
            Success = $true
            Message = "Policy deployed successfully. A reboot may be required for full enforcement."
        }
    }
    catch {
        return @{
            Success = $false
            Message = "Error deploying policy: $($_.Exception.Message)"
        }
    }
}

function Remove-WDACPolicy {
    try {
        if (-not (Test-Administrator)) {
            return @{
                Success = $false
                Message = "Administrator privileges required to remove WDAC policy."
            }
        }
        
        $policyPath = "$env:SystemRoot\System32\CodeIntegrity\CiPolicies\Active"
        if (Test-Path $policyPath) {
            $policies = Get-ChildItem -Path $policyPath -Filter "*.cip" -ErrorAction SilentlyContinue
            foreach ($policy in $policies) {
                Remove-Item -Path $policy.FullName -Force -ErrorAction SilentlyContinue
            }
        }
        
        # Also check legacy location
        $legacyPolicy = "$env:SystemRoot\System32\CodeIntegrity\SIPolicy.p7b"
        if (Test-Path $legacyPolicy) {
            Remove-Item -Path $legacyPolicy -Force -ErrorAction SilentlyContinue
        }
        
        return @{
            Success = $true
            Message = "WDAC policies removed. A reboot is required to complete the removal."
        }
    }
    catch {
        return @{
            Success = $false
            Message = "Error removing policy: $($_.Exception.Message)"
        }
    }
}

# ============================================================================
# GUI Creation
# ============================================================================

function Show-WDACConfigGUI {
    # Create the main form
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Windows 11 WDAC Configuration Tool"
    $form.Size = New-Object System.Drawing.Size(750, 745)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "FixedSingle"
    $form.MaximizeBox = $false
    $form.BackColor = [System.Drawing.Color]::FromArgb(245, 245, 245)
    $form.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    
    # Header Panel
    $headerPanel = New-Object System.Windows.Forms.Panel
    $headerPanel.Location = New-Object System.Drawing.Point(0, 0)
    $headerPanel.Size = New-Object System.Drawing.Size(750, 60)
    $headerPanel.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 212)
    $form.Controls.Add($headerPanel)
    
    $headerLabel = New-Object System.Windows.Forms.Label
    $headerLabel.Text = "Windows Defender Application Control (WDAC)"
    $headerLabel.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
    $headerLabel.ForeColor = [System.Drawing.Color]::White
    $headerLabel.AutoSize = $true
    $headerLabel.Location = New-Object System.Drawing.Point(20, 15)
    $headerPanel.Controls.Add($headerLabel)
    
    # Admin warning label
    $adminLabel = New-Object System.Windows.Forms.Label
    if (Test-Administrator) {
        $adminLabel.Text = "✓ Running as Administrator"
        $adminLabel.ForeColor = [System.Drawing.Color]::Green
    }
    else {
        $adminLabel.Text = "⚠ Not running as Administrator - Deploy functions will be limited"
        $adminLabel.ForeColor = [System.Drawing.Color]::Red
    }
    $adminLabel.AutoSize = $true
    $adminLabel.Location = New-Object System.Drawing.Point(20, 70)
    $form.Controls.Add($adminLabel)
    
    # Status Group Box
    $statusGroup = New-Object System.Windows.Forms.GroupBox
    $statusGroup.Text = "Current WDAC Status"
    $statusGroup.Location = New-Object System.Drawing.Point(20, 95)
    $statusGroup.Size = New-Object System.Drawing.Size(695, 130)
    $form.Controls.Add($statusGroup)
    
    $statusText = New-Object System.Windows.Forms.TextBox
    $statusText.Multiline = $true
    $statusText.ReadOnly = $true
    $statusText.ScrollBars = "Vertical"
    $statusText.Location = New-Object System.Drawing.Point(15, 25)
    $statusText.Size = New-Object System.Drawing.Size(560, 90)
    $statusText.BackColor = [System.Drawing.Color]::White
    $statusGroup.Controls.Add($statusText)
    
    $refreshButton = New-Object System.Windows.Forms.Button
    $refreshButton.Text = "Refresh"
    $refreshButton.Location = New-Object System.Drawing.Point(590, 25)
    $refreshButton.Size = New-Object System.Drawing.Size(90, 30)
    $refreshButton.FlatStyle = "Flat"
    $refreshButton.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 212)
    $refreshButton.ForeColor = [System.Drawing.Color]::White
    $statusGroup.Controls.Add($refreshButton)
    
    # Policy Scenarios Group Box
    $scenarioGroup = New-Object System.Windows.Forms.GroupBox
    $scenarioGroup.Text = "Policy Scenarios"
    $scenarioGroup.Location = New-Object System.Drawing.Point(20, 235)
    $scenarioGroup.Size = New-Object System.Drawing.Size(695, 225)
    $form.Controls.Add($scenarioGroup)
    
    $radioAdminAnythingUserSigned = New-Object System.Windows.Forms.RadioButton
    $radioAdminAnythingUserSigned.Text = "Admin: Run Anything | Users: Signed Apps Only"
    $radioAdminAnythingUserSigned.Location = New-Object System.Drawing.Point(20, 30)
    $radioAdminAnythingUserSigned.Size = New-Object System.Drawing.Size(650, 25)
    $radioAdminAnythingUserSigned.Checked = $true
    $scenarioGroup.Controls.Add($radioAdminAnythingUserSigned)
    
    $descLabel1 = New-Object System.Windows.Forms.Label
    $descLabel1.Text = "    Administrators have no restrictions. Standard users can only run digitally signed applications."
    $descLabel1.ForeColor = [System.Drawing.Color]::Gray
    $descLabel1.Location = New-Object System.Drawing.Point(35, 52)
    $descLabel1.Size = New-Object System.Drawing.Size(640, 20)
    $scenarioGroup.Controls.Add($descLabel1)
    
    $radioAdminAnythingUserMS = New-Object System.Windows.Forms.RadioButton
    $radioAdminAnythingUserMS.Text = "Admin: Run Anything | Users: Microsoft Signed Apps Only"
    $radioAdminAnythingUserMS.Location = New-Object System.Drawing.Point(20, 75)
    $radioAdminAnythingUserMS.Size = New-Object System.Drawing.Size(650, 25)
    $scenarioGroup.Controls.Add($radioAdminAnythingUserMS)
    
    $descLabel2 = New-Object System.Windows.Forms.Label
    $descLabel2.Text = "    Administrators have no restrictions. Standard users can only run Microsoft-signed applications."
    $descLabel2.ForeColor = [System.Drawing.Color]::Gray
    $descLabel2.Location = New-Object System.Drawing.Point(35, 97)
    $descLabel2.Size = New-Object System.Drawing.Size(640, 20)
    $scenarioGroup.Controls.Add($descLabel2)
    
    $radioAllSigned = New-Object System.Windows.Forms.RadioButton
    $radioAllSigned.Text = "Everyone: Signed Apps Only (Any Vendor)"
    $radioAllSigned.Location = New-Object System.Drawing.Point(20, 120)
    $radioAllSigned.Size = New-Object System.Drawing.Size(650, 25)
    $scenarioGroup.Controls.Add($radioAllSigned)
    
    $descLabel3 = New-Object System.Windows.Forms.Label
    $descLabel3.Text = "    Both administrators and standard users can only run digitally signed applications from any vendor."
    $descLabel3.ForeColor = [System.Drawing.Color]::Gray
    $descLabel3.Location = New-Object System.Drawing.Point(35, 142)
    $descLabel3.Size = New-Object System.Drawing.Size(640, 20)
    $scenarioGroup.Controls.Add($descLabel3)
    
    $radioAllMSOnly = New-Object System.Windows.Forms.RadioButton
    $radioAllMSOnly.Text = "Everyone: Microsoft Signed Apps Only"
    $radioAllMSOnly.Location = New-Object System.Drawing.Point(20, 165)
    $radioAllMSOnly.Size = New-Object System.Drawing.Size(650, 25)
    $scenarioGroup.Controls.Add($radioAllMSOnly)
    
    $descLabel4 = New-Object System.Windows.Forms.Label
    $descLabel4.Text = "    Both administrators and standard users can only run Microsoft-signed applications (most restrictive)."
    $descLabel4.ForeColor = [System.Drawing.Color]::Gray
    $descLabel4.Location = New-Object System.Drawing.Point(35, 187)
    $descLabel4.Size = New-Object System.Drawing.Size(640, 20)
    $scenarioGroup.Controls.Add($descLabel4)
    
    # Additional Options Group Box
    $optionsGroup = New-Object System.Windows.Forms.GroupBox
    $optionsGroup.Text = "Additional Options"
    $optionsGroup.Location = New-Object System.Drawing.Point(20, 470)
    $optionsGroup.Size = New-Object System.Drawing.Size(695, 100)
    $form.Controls.Add($optionsGroup)
    
    $chkBlockDownloads = New-Object System.Windows.Forms.CheckBox
    $chkBlockDownloads.Text = "Block executables from Users' Downloads folder"
    $chkBlockDownloads.Location = New-Object System.Drawing.Point(20, 30)
    $chkBlockDownloads.Size = New-Object System.Drawing.Size(650, 25)
    $optionsGroup.Controls.Add($chkBlockDownloads)
    
    $descLabelDownloads = New-Object System.Windows.Forms.Label
    $descLabelDownloads.Text = "    Blocks .exe, .dll, .msi, .ps1, .bat, .cmd, .vbs, .js files from running in any user's Downloads folder."
    $descLabelDownloads.ForeColor = [System.Drawing.Color]::Gray
    $descLabelDownloads.Location = New-Object System.Drawing.Point(35, 52)
    $descLabelDownloads.Size = New-Object System.Drawing.Size(640, 20)
    $optionsGroup.Controls.Add($descLabelDownloads)
    
    $chkAuditMode = New-Object System.Windows.Forms.CheckBox
    $chkAuditMode.Text = "Audit Mode (log violations but don't block)"
    $chkAuditMode.Location = New-Object System.Drawing.Point(20, 72)
    $chkAuditMode.Size = New-Object System.Drawing.Size(650, 25)
    $chkAuditMode.Checked = $true
    $optionsGroup.Controls.Add($chkAuditMode)
    
    # Action Buttons
    $buttonPanel = New-Object System.Windows.Forms.Panel
    $buttonPanel.Location = New-Object System.Drawing.Point(20, 580)
    $buttonPanel.Size = New-Object System.Drawing.Size(695, 50)
    $form.Controls.Add($buttonPanel)
    
    $exportButton = New-Object System.Windows.Forms.Button
    $exportButton.Text = "Export Policy XML"
    $exportButton.Location = New-Object System.Drawing.Point(0, 10)
    $exportButton.Size = New-Object System.Drawing.Size(140, 35)
    $exportButton.FlatStyle = "Flat"
    $exportButton.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 212)
    $exportButton.ForeColor = [System.Drawing.Color]::White
    $buttonPanel.Controls.Add($exportButton)
    
    $deployButton = New-Object System.Windows.Forms.Button
    $deployButton.Text = "Deploy Policy"
    $deployButton.Location = New-Object System.Drawing.Point(150, 10)
    $deployButton.Size = New-Object System.Drawing.Size(140, 35)
    $deployButton.FlatStyle = "Flat"
    $deployButton.BackColor = [System.Drawing.Color]::FromArgb(16, 124, 16)
    $deployButton.ForeColor = [System.Drawing.Color]::White
    $buttonPanel.Controls.Add($deployButton)
    
    $removeButton = New-Object System.Windows.Forms.Button
    $removeButton.Text = "Remove All Policies"
    $removeButton.Location = New-Object System.Drawing.Point(300, 10)
    $removeButton.Size = New-Object System.Drawing.Size(140, 35)
    $removeButton.FlatStyle = "Flat"
    $removeButton.BackColor = [System.Drawing.Color]::FromArgb(196, 43, 28)
    $removeButton.ForeColor = [System.Drawing.Color]::White
    $buttonPanel.Controls.Add($removeButton)
    
    $helpButton = New-Object System.Windows.Forms.Button
    $helpButton.Text = "Help"
    $helpButton.Location = New-Object System.Drawing.Point(555, 10)
    $helpButton.Size = New-Object System.Drawing.Size(140, 35)
    $helpButton.FlatStyle = "Flat"
    $helpButton.BackColor = [System.Drawing.Color]::FromArgb(100, 100, 100)
    $helpButton.ForeColor = [System.Drawing.Color]::White
    $buttonPanel.Controls.Add($helpButton)
    
    # Log Output
    $logGroup = New-Object System.Windows.Forms.GroupBox
    $logGroup.Text = "Activity Log"
    $logGroup.Location = New-Object System.Drawing.Point(20, 635)
    $logGroup.Size = New-Object System.Drawing.Size(695, 60)
    $form.Controls.Add($logGroup)
    
    $logText = New-Object System.Windows.Forms.TextBox
    $logText.Multiline = $true
    $logText.ReadOnly = $true
    $logText.ScrollBars = "Vertical"
    $logText.Location = New-Object System.Drawing.Point(15, 20)
    $logText.Size = New-Object System.Drawing.Size(665, 30)
    $logText.BackColor = [System.Drawing.Color]::White
    $logGroup.Controls.Add($logText)
    
    # ========================================================================
    # Event Handlers
    # ========================================================================
    
    $updateStatus = {
        $status = Get-WDACStatus
        $statusLines = @(
            "Virtualization Based Security: $(if ($status.VBSEnabled) { 'Enabled' } else { 'Disabled' })"
            "Code Integrity: $(if ($status.CodeIntegrityEnabled) { 'Enabled' } else { 'Disabled' })"
            "User Mode Code Integrity (UMCI): $(if ($status.UMCIEnabled) { 'Enabled' } else { 'Disabled' })"
            "Enforcement Mode: $($status.EnforcementMode)"
            "Active Policies: $(if ($status.ActivePolicies.Count -gt 0) { $status.ActivePolicies -join ', ' } else { 'None' })"
        )
        $statusText.Text = $statusLines -join "`r`n"
    }
    
    $refreshButton.Add_Click($updateStatus)
    
    $getSelectedPolicyType = {
        if ($radioAdminAnythingUserSigned.Checked) { return "AdminAnything_UserSigned" }
        if ($radioAdminAnythingUserMS.Checked) { return "AdminAnything_UserMSOnly" }
        if ($radioAllSigned.Checked) { return "AllSigned" }
        if ($radioAllMSOnly.Checked) { return "AllMSOnly" }
        return "AdminAnything_UserSigned"
    }
    
    $getSelectedPolicyName = {
        if ($radioAdminAnythingUserSigned.Checked) { return "Admin-Unrestricted_User-SignedApps" }
        if ($radioAdminAnythingUserMS.Checked) { return "Admin-Unrestricted_User-MSSignedOnly" }
        if ($radioAllSigned.Checked) { return "All-SignedAppsOnly" }
        if ($radioAllMSOnly.Checked) { return "All-MSSignedOnly" }
        return "Custom-WDAC-Policy"
    }
    
    $exportButton.Add_Click({
        $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
        $folderBrowser.Description = "Select folder to export WDAC policy"
        $folderBrowser.RootFolder = "MyComputer"
        
        if ($folderBrowser.ShowDialog() -eq "OK") {
            $policyType = & $getSelectedPolicyType
            $policyName = & $getSelectedPolicyName
            
            $policyXml = New-WDACPolicyXml -PolicyName $policyName -PolicyType $policyType `
                -BlockDownloadsFolder $chkBlockDownloads.Checked -AuditMode $chkAuditMode.Checked
            
            $result = Export-WDACPolicy -PolicyXml $policyXml -OutputPath $folderBrowser.SelectedPath
            
            if ($result.Success) {
                $logText.Text = $result.Message
                [System.Windows.Forms.MessageBox]::Show($result.Message, "Export Successful", "OK", "Information")
            }
            else {
                $logText.Text = $result.Message
                [System.Windows.Forms.MessageBox]::Show($result.Message, "Export Failed", "OK", "Error")
            }
        }
    })
    
    $deployButton.Add_Click({
        $confirmResult = [System.Windows.Forms.MessageBox]::Show(
            "This will deploy a WDAC policy to your system.`n`nAre you sure you want to continue?`n`nNote: A reboot may be required.",
            "Confirm Policy Deployment",
            "YesNo",
            "Warning"
        )
        
        if ($confirmResult -eq "Yes") {
            $policyType = & $getSelectedPolicyType
            $policyName = & $getSelectedPolicyName
            
            $policyXml = New-WDACPolicyXml -PolicyName $policyName -PolicyType $policyType `
                -BlockDownloadsFolder $chkBlockDownloads.Checked -AuditMode $chkAuditMode.Checked
            
            $tempPath = Join-Path $env:TEMP "WDACPolicy_$(Get-Date -Format 'yyyyMMddHHmmss')"
            New-Item -Path $tempPath -ItemType Directory -Force | Out-Null
            
            $exportResult = Export-WDACPolicy -PolicyXml $policyXml -OutputPath $tempPath
            
            if ($exportResult.Success) {
                $deployResult = Deploy-WDACPolicy -XmlPath $exportResult.XmlPath
                
                if ($deployResult.Success) {
                    $logText.Text = $deployResult.Message
                    [System.Windows.Forms.MessageBox]::Show($deployResult.Message, "Deployment Successful", "OK", "Information")
                    & $updateStatus
                }
                else {
                    $logText.Text = $deployResult.Message
                    [System.Windows.Forms.MessageBox]::Show($deployResult.Message, "Deployment Failed", "OK", "Error")
                }
            }
            else {
                $logText.Text = $exportResult.Message
                [System.Windows.Forms.MessageBox]::Show($exportResult.Message, "Export Failed", "OK", "Error")
            }
        }
    })
    
    $removeButton.Add_Click({
        $confirmResult = [System.Windows.Forms.MessageBox]::Show(
            "This will remove all deployed WDAC policies.`n`nAre you sure you want to continue?`n`nNote: A reboot will be required.",
            "Confirm Policy Removal",
            "YesNo",
            "Warning"
        )
        
        if ($confirmResult -eq "Yes") {
            $result = Remove-WDACPolicy
            
            if ($result.Success) {
                $logText.Text = $result.Message
                [System.Windows.Forms.MessageBox]::Show($result.Message, "Removal Successful", "OK", "Information")
                & $updateStatus
            }
            else {
                $logText.Text = $result.Message
                [System.Windows.Forms.MessageBox]::Show($result.Message, "Removal Failed", "OK", "Error")
            }
        }
    })
    
    $helpButton.Add_Click({
        $helpText = @"
WDAC Configuration Tool Help
============================

POLICY SCENARIOS:

1. Admin: Run Anything | Users: Signed Apps Only
   - Administrators can run any application
   - Standard users can only run digitally signed applications
   - Good balance of security and usability

2. Admin: Run Anything | Users: Microsoft Signed Apps Only
   - Administrators can run any application
   - Standard users restricted to Microsoft-signed apps only
   - Higher security, may block third-party applications for users

3. Everyone: Signed Apps Only (Any Vendor)
   - All users (including admins) can only run signed applications
   - Applications must be digitally signed by any trusted vendor
   - Good security while allowing third-party signed software

4. Everyone: Microsoft Signed Apps Only
   - All users (including admins) restricted to Microsoft-signed apps
   - Highest security level
   - May significantly limit application availability

ADDITIONAL OPTIONS:

Block Downloads Folder:
   - Prevents execution of common executable files from Downloads folder
   - Blocks: .exe, .dll, .msi, .ps1, .bat, .cmd, .vbs, .js
   - Helps prevent users from running downloaded malware

Audit Mode:
   - Policy violations are logged but not blocked
   - Recommended for testing before enforcement
   - Check Event Viewer: Applications and Services Logs > Microsoft > Windows > CodeIntegrity

DEPLOYMENT NOTES:

- Requires Administrator privileges
- Reboot may be required for full enforcement
- Always test in Audit Mode first
- Export and backup policies before deployment
"@
        [System.Windows.Forms.MessageBox]::Show($helpText, "Help", "OK", "Information")
    })
    
    # Initial status update
    & $updateStatus
    
    # Show form
    $form.ShowDialog() | Out-Null
}

# ============================================================================
# Main Entry Point
# ============================================================================

Show-WDACConfigGUI
