<#
.SYNOPSIS
    Windows Defender Configuration Manager with GUI
.DESCRIPTION
    A PowerShell 5 GUI tool to view and manage Windows Defender settings on Windows 11.
    Includes hardened baseline configuration with all ASR rules.
.NOTES
    Requires Administrator privileges to modify settings.
    PowerShell 5.1 compatible with UTF-8 encoding.
#>

#Requires -Version 5.1

# Check for Administrator privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Define ASR Rules with their GUIDs and descriptions
$Script:ASRRules = @{
    "56a863a9-875e-4185-98a7-b882c64b5ce5" = "Block abuse of exploited vulnerable signed drivers"
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = "Block Adobe Reader from creating child processes"
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = "Block all Office applications from creating child processes"
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = "Block credential stealing from Windows LSASS"
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = "Block executable content from email client and webmail"
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = "Block execution of potentially obfuscated scripts"
    "d3e037e1-3eb8-44c8-a917-57927947596d" = "Block JavaScript or VBScript from launching downloaded executable content"
    "3b576869-a4ec-4529-8536-b80a7769e899" = "Block Office applications from creating executable content"
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" = "Block Office applications from injecting code into other processes"
    "26190899-1602-49e8-8b27-eb1d0a1ce869" = "Block Office communication application from creating child processes"
    "e6db77e5-3df2-4cf1-b95a-636979351e5b" = "Block persistence through WMI event subscription"
    "d1e49aac-8f56-4280-b9ba-993a6d77406c" = "Block process creations originating from PSExec and WMI commands"
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = "Block untrusted and unsigned processes that run from USB"
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" = "Block Win32 API calls from Office macros"
    "a8f5898e-1dc8-49a9-9878-85004b8a61e6" = "Block Webshell creation for Servers"
    "c1db55ab-c21a-4637-bb3f-a12568109d35" = "Use advanced protection against ransomware"
    "01443614-cd74-433a-b99e-2ecdc07bfc25" = "Block executable files from running unless they meet criteria"
    "33ddedf1-c6e0-47cb-833e-de6133960387" = "Block Office applications from creating exploitable content"
}

# Function to get current Defender status
function Get-DefenderStatus {
    try {
        $mpPreference = Get-MpPreference -ErrorAction Stop
        $mpStatus = Get-MpComputerStatus -ErrorAction Stop
        
        return @{
            RealTimeProtection = -not $mpPreference.DisableRealtimeMonitoring
            CloudProtection = -not $mpPreference.MAPSReporting -eq 0
            AutomaticSampleSubmission = $mpPreference.SubmitSamplesConsent -ne 2
            ControlledFolderAccess = $mpPreference.EnableControlledFolderAccess -eq 1
            NetworkProtection = $mpPreference.EnableNetworkProtection -eq 1
            PUAProtection = $mpPreference.PUAProtection -eq 1
            TamperProtection = $mpStatus.IsTamperProtected
            AntivirusEnabled = $mpStatus.AntivirusEnabled
            AMServiceEnabled = $mpStatus.AMServiceEnabled
            AntispywareEnabled = $mpStatus.AntispywareEnabled
            BehaviorMonitor = -not $mpPreference.DisableBehaviorMonitoring
            IOAVProtection = -not $mpPreference.DisableIOAVProtection
            ScriptScanning = -not $mpPreference.DisableScriptScanning
            ASRRules = $mpPreference.AttackSurfaceReductionRules_Ids
            ASRActions = $mpPreference.AttackSurfaceReductionRules_Actions
            EngineVersion = $mpStatus.AMEngineVersion
            ProductVersion = $mpStatus.AMProductVersion
            SignatureVersion = $mpStatus.AntivirusSignatureVersion
            LastUpdate = $mpStatus.AntivirusSignatureLastUpdated
            Success = $true
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

# Function to get ASR rule action text
function Get-ASRActionText {
    param([int]$Action)
    switch ($Action) {
        0 { return "Disabled" }
        1 { return "Block" }
        2 { return "Audit" }
        6 { return "Warn" }
        default { return "Unknown" }
    }
}

# Create the main form
$form = New-Object System.Windows.Forms.Form
$form.Text = "Windows Defender Configuration Manager"
$form.Size = New-Object System.Drawing.Size(900, 750)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox = $false
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$form.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)

# Create TabControl
$tabControl = New-Object System.Windows.Forms.TabControl
$tabControl.Location = New-Object System.Drawing.Point(10, 10)
$tabControl.Size = New-Object System.Drawing.Size(865, 650)

# Tab 1: Protection Settings
$tabProtection = New-Object System.Windows.Forms.TabPage
$tabProtection.Text = "Protection Settings"
$tabProtection.BackColor = [System.Drawing.Color]::White

# Tab 2: ASR Rules
$tabASR = New-Object System.Windows.Forms.TabPage
$tabASR.Text = "ASR Rules"
$tabASR.BackColor = [System.Drawing.Color]::White

# Tab 3: Status Information
$tabStatus = New-Object System.Windows.Forms.TabPage
$tabStatus.Text = "Status & Info"
$tabStatus.BackColor = [System.Drawing.Color]::White

$tabControl.TabPages.AddRange(@($tabProtection, $tabASR, $tabStatus))

# Admin warning label
$lblAdmin = New-Object System.Windows.Forms.Label
$lblAdmin.Location = New-Object System.Drawing.Point(15, 15)
$lblAdmin.Size = New-Object System.Drawing.Size(820, 25)
if ($isAdmin) {
    $lblAdmin.Text = "✓ Running as Administrator - Changes can be applied"
    $lblAdmin.ForeColor = [System.Drawing.Color]::Green
} else {
    $lblAdmin.Text = "⚠ Not running as Administrator - Changes require elevation"
    $lblAdmin.ForeColor = [System.Drawing.Color]::Red
}
$lblAdmin.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$tabProtection.Controls.Add($lblAdmin)

# Protection Settings GroupBox
$grpProtection = New-Object System.Windows.Forms.GroupBox
$grpProtection.Text = "Core Protection Components"
$grpProtection.Location = New-Object System.Drawing.Point(15, 50)
$grpProtection.Size = New-Object System.Drawing.Size(820, 320)
$tabProtection.Controls.Add($grpProtection)

# Create checkboxes for protection settings
$Script:chkRealTime = New-Object System.Windows.Forms.CheckBox
$chkRealTime.Text = "Real-time Protection"
$chkRealTime.Location = New-Object System.Drawing.Point(20, 30)
$chkRealTime.Size = New-Object System.Drawing.Size(350, 25)
$grpProtection.Controls.Add($chkRealTime)

$Script:chkCloud = New-Object System.Windows.Forms.CheckBox
$chkCloud.Text = "Cloud-delivered Protection (MAPS)"
$chkCloud.Location = New-Object System.Drawing.Point(20, 60)
$chkCloud.Size = New-Object System.Drawing.Size(350, 25)
$grpProtection.Controls.Add($chkCloud)

$Script:chkSampleSubmission = New-Object System.Windows.Forms.CheckBox
$chkSampleSubmission.Text = "Automatic Sample Submission"
$chkSampleSubmission.Location = New-Object System.Drawing.Point(20, 90)
$chkSampleSubmission.Size = New-Object System.Drawing.Size(350, 25)
$grpProtection.Controls.Add($chkSampleSubmission)

$Script:chkControlledFolder = New-Object System.Windows.Forms.CheckBox
$chkControlledFolder.Text = "Controlled Folder Access (Ransomware Protection)"
$chkControlledFolder.Location = New-Object System.Drawing.Point(20, 120)
$chkControlledFolder.Size = New-Object System.Drawing.Size(350, 25)
$grpProtection.Controls.Add($chkControlledFolder)

$Script:chkNetworkProtection = New-Object System.Windows.Forms.CheckBox
$chkNetworkProtection.Text = "Network Protection"
$chkNetworkProtection.Location = New-Object System.Drawing.Point(20, 150)
$chkNetworkProtection.Size = New-Object System.Drawing.Size(350, 25)
$grpProtection.Controls.Add($chkNetworkProtection)

$Script:chkPUA = New-Object System.Windows.Forms.CheckBox
$chkPUA.Text = "Potentially Unwanted Application (PUA) Protection"
$chkPUA.Location = New-Object System.Drawing.Point(20, 180)
$chkPUA.Size = New-Object System.Drawing.Size(350, 25)
$grpProtection.Controls.Add($chkPUA)

$Script:chkBehaviorMonitor = New-Object System.Windows.Forms.CheckBox
$chkBehaviorMonitor.Text = "Behavior Monitoring"
$chkBehaviorMonitor.Location = New-Object System.Drawing.Point(420, 30)
$chkBehaviorMonitor.Size = New-Object System.Drawing.Size(350, 25)
$grpProtection.Controls.Add($chkBehaviorMonitor)

$Script:chkIOAV = New-Object System.Windows.Forms.CheckBox
$chkIOAV.Text = "Scan Downloaded Files and Attachments (IOAV)"
$chkIOAV.Location = New-Object System.Drawing.Point(420, 60)
$chkIOAV.Size = New-Object System.Drawing.Size(350, 25)
$grpProtection.Controls.Add($chkIOAV)

$Script:chkScriptScanning = New-Object System.Windows.Forms.CheckBox
$chkScriptScanning.Text = "Script Scanning"
$chkScriptScanning.Location = New-Object System.Drawing.Point(420, 90)
$chkScriptScanning.Size = New-Object System.Drawing.Size(350, 25)
$grpProtection.Controls.Add($chkScriptScanning)

# Tamper Protection (Read-only)
$Script:chkTamper = New-Object System.Windows.Forms.CheckBox
$chkTamper.Text = "Tamper Protection (Managed via Windows Security)"
$chkTamper.Location = New-Object System.Drawing.Point(420, 120)
$chkTamper.Size = New-Object System.Drawing.Size(380, 25)
$chkTamper.Enabled = $false
$grpProtection.Controls.Add($chkTamper)

# Buttons for Protection tab
$btnApplyProtection = New-Object System.Windows.Forms.Button
$btnApplyProtection.Text = "Apply Protection Settings"
$btnApplyProtection.Location = New-Object System.Drawing.Point(20, 270)
$btnApplyProtection.Size = New-Object System.Drawing.Size(180, 35)
$btnApplyProtection.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
$btnApplyProtection.ForeColor = [System.Drawing.Color]::White
$btnApplyProtection.FlatStyle = "Flat"
$grpProtection.Controls.Add($btnApplyProtection)

$btnRefresh = New-Object System.Windows.Forms.Button
$btnRefresh.Text = "Refresh Status"
$btnRefresh.Location = New-Object System.Drawing.Point(210, 270)
$btnRefresh.Size = New-Object System.Drawing.Size(140, 35)
$btnRefresh.FlatStyle = "Flat"
$grpProtection.Controls.Add($btnRefresh)

# Quick Actions GroupBox
$grpQuickActions = New-Object System.Windows.Forms.GroupBox
$grpQuickActions.Text = "Quick Actions"
$grpQuickActions.Location = New-Object System.Drawing.Point(15, 380)
$grpQuickActions.Size = New-Object System.Drawing.Size(820, 80)
$tabProtection.Controls.Add($grpQuickActions)

$btnEnableAll = New-Object System.Windows.Forms.Button
$btnEnableAll.Text = "Enable All Protection"
$btnEnableAll.Location = New-Object System.Drawing.Point(20, 30)
$btnEnableAll.Size = New-Object System.Drawing.Size(150, 35)
$btnEnableAll.BackColor = [System.Drawing.Color]::FromArgb(0, 150, 0)
$btnEnableAll.ForeColor = [System.Drawing.Color]::White
$btnEnableAll.FlatStyle = "Flat"
$grpQuickActions.Controls.Add($btnEnableAll)

$btnDisableAll = New-Object System.Windows.Forms.Button
$btnDisableAll.Text = "Disable All Protection"
$btnDisableAll.Location = New-Object System.Drawing.Point(180, 30)
$btnDisableAll.Size = New-Object System.Drawing.Size(150, 35)
$btnDisableAll.BackColor = [System.Drawing.Color]::FromArgb(200, 0, 0)
$btnDisableAll.ForeColor = [System.Drawing.Color]::White
$btnDisableAll.FlatStyle = "Flat"
$grpQuickActions.Controls.Add($btnDisableAll)

$btnUpdateSignatures = New-Object System.Windows.Forms.Button
$btnUpdateSignatures.Text = "Update Signatures"
$btnUpdateSignatures.Location = New-Object System.Drawing.Point(340, 30)
$btnUpdateSignatures.Size = New-Object System.Drawing.Size(150, 35)
$btnUpdateSignatures.FlatStyle = "Flat"
$grpQuickActions.Controls.Add($btnUpdateSignatures)

$btnQuickScan = New-Object System.Windows.Forms.Button
$btnQuickScan.Text = "Start Quick Scan"
$btnQuickScan.Location = New-Object System.Drawing.Point(500, 30)
$btnQuickScan.Size = New-Object System.Drawing.Size(150, 35)
$btnQuickScan.FlatStyle = "Flat"
$grpQuickActions.Controls.Add($btnQuickScan)

# ============ ASR Rules Tab ============
$lblASRInfo = New-Object System.Windows.Forms.Label
$lblASRInfo.Text = "Attack Surface Reduction (ASR) rules help prevent actions that malware often abuses."
$lblASRInfo.Location = New-Object System.Drawing.Point(15, 15)
$lblASRInfo.Size = New-Object System.Drawing.Size(820, 20)
$tabASR.Controls.Add($lblASRInfo)

# ASR Rules ListView
$Script:lvASR = New-Object System.Windows.Forms.ListView
$lvASR.Location = New-Object System.Drawing.Point(15, 45)
$lvASR.Size = New-Object System.Drawing.Size(820, 380)
$lvASR.View = "Details"
$lvASR.FullRowSelect = $true
$lvASR.GridLines = $true
$lvASR.CheckBoxes = $false

$lvASR.Columns.Add("Rule Description", 500) | Out-Null
$lvASR.Columns.Add("Current State", 120) | Out-Null
$lvASR.Columns.Add("GUID", 180) | Out-Null

$tabASR.Controls.Add($lvASR)

# ASR Action ComboBox
$lblASRAction = New-Object System.Windows.Forms.Label
$lblASRAction.Text = "Set selected rule to:"
$lblASRAction.Location = New-Object System.Drawing.Point(15, 440)
$lblASRAction.Size = New-Object System.Drawing.Size(120, 25)
$tabASR.Controls.Add($lblASRAction)

$Script:cmbASRAction = New-Object System.Windows.Forms.ComboBox
$cmbASRAction.Location = New-Object System.Drawing.Point(140, 437)
$cmbASRAction.Size = New-Object System.Drawing.Size(120, 25)
$cmbASRAction.DropDownStyle = "DropDownList"
$cmbASRAction.Items.AddRange(@("Disabled", "Block", "Audit", "Warn"))
$cmbASRAction.SelectedIndex = 1
$tabASR.Controls.Add($cmbASRAction)

$btnApplyASRRule = New-Object System.Windows.Forms.Button
$btnApplyASRRule.Text = "Apply to Selected"
$btnApplyASRRule.Location = New-Object System.Drawing.Point(270, 435)
$btnApplyASRRule.Size = New-Object System.Drawing.Size(130, 30)
$btnApplyASRRule.FlatStyle = "Flat"
$tabASR.Controls.Add($btnApplyASRRule)

# ASR Baseline buttons
$grpASRBaseline = New-Object System.Windows.Forms.GroupBox
$grpASRBaseline.Text = "Hardened Baseline Configuration"
$grpASRBaseline.Location = New-Object System.Drawing.Point(15, 480)
$grpASRBaseline.Size = New-Object System.Drawing.Size(820, 120)
$tabASR.Controls.Add($grpASRBaseline)

$lblBaselineInfo = New-Object System.Windows.Forms.Label
$lblBaselineInfo.Text = "Apply a hardened security baseline that enables all ASR rules in Block mode.`nThis is recommended for maximum protection but may require tuning for compatibility."
$lblBaselineInfo.Location = New-Object System.Drawing.Point(20, 25)
$lblBaselineInfo.Size = New-Object System.Drawing.Size(780, 35)
$grpASRBaseline.Controls.Add($lblBaselineInfo)

$btnApplyHardenedBaseline = New-Object System.Windows.Forms.Button
$btnApplyHardenedBaseline.Text = "Apply Hardened Baseline (Block All)"
$btnApplyHardenedBaseline.Location = New-Object System.Drawing.Point(20, 70)
$btnApplyHardenedBaseline.Size = New-Object System.Drawing.Size(220, 35)
$btnApplyHardenedBaseline.BackColor = [System.Drawing.Color]::FromArgb(180, 0, 0)
$btnApplyHardenedBaseline.ForeColor = [System.Drawing.Color]::White
$btnApplyHardenedBaseline.FlatStyle = "Flat"
$grpASRBaseline.Controls.Add($btnApplyHardenedBaseline)

$btnApplyAuditBaseline = New-Object System.Windows.Forms.Button
$btnApplyAuditBaseline.Text = "Apply Audit Baseline (Audit All)"
$btnApplyAuditBaseline.Location = New-Object System.Drawing.Point(250, 70)
$btnApplyAuditBaseline.Size = New-Object System.Drawing.Size(220, 35)
$btnApplyAuditBaseline.BackColor = [System.Drawing.Color]::FromArgb(200, 150, 0)
$btnApplyAuditBaseline.ForeColor = [System.Drawing.Color]::White
$btnApplyAuditBaseline.FlatStyle = "Flat"
$grpASRBaseline.Controls.Add($btnApplyAuditBaseline)

$btnDisableAllASR = New-Object System.Windows.Forms.Button
$btnDisableAllASR.Text = "Disable All ASR Rules"
$btnDisableAllASR.Location = New-Object System.Drawing.Point(480, 70)
$btnDisableAllASR.Size = New-Object System.Drawing.Size(180, 35)
$btnDisableAllASR.FlatStyle = "Flat"
$grpASRBaseline.Controls.Add($btnDisableAllASR)

$btnRefreshASR = New-Object System.Windows.Forms.Button
$btnRefreshASR.Text = "Refresh"
$btnRefreshASR.Location = New-Object System.Drawing.Point(670, 70)
$btnRefreshASR.Size = New-Object System.Drawing.Size(130, 35)
$btnRefreshASR.FlatStyle = "Flat"
$grpASRBaseline.Controls.Add($btnRefreshASR)

# ============ Status Tab ============
$Script:txtStatus = New-Object System.Windows.Forms.TextBox
$txtStatus.Location = New-Object System.Drawing.Point(15, 15)
$txtStatus.Size = New-Object System.Drawing.Size(820, 580)
$txtStatus.Multiline = $true
$txtStatus.ScrollBars = "Vertical"
$txtStatus.ReadOnly = $true
$txtStatus.Font = New-Object System.Drawing.Font("Consolas", 10)
$txtStatus.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$txtStatus.ForeColor = [System.Drawing.Color]::FromArgb(0, 255, 0)
$tabStatus.Controls.Add($txtStatus)

# ============ Functions ============

function Update-ProtectionUI {
    $status = Get-DefenderStatus
    
    if ($status.Success) {
        $chkRealTime.Checked = $status.RealTimeProtection
        $chkCloud.Checked = $status.CloudProtection
        $chkSampleSubmission.Checked = $status.AutomaticSampleSubmission
        $chkControlledFolder.Checked = $status.ControlledFolderAccess
        $chkNetworkProtection.Checked = $status.NetworkProtection
        $chkPUA.Checked = $status.PUAProtection
        $chkTamper.Checked = $status.TamperProtection
        $chkBehaviorMonitor.Checked = $status.BehaviorMonitor
        $chkIOAV.Checked = $status.IOAVProtection
        $chkScriptScanning.Checked = $status.ScriptScanning
        
        # Update status text
        $statusText = @"
═══════════════════════════════════════════════════════════════════════════════
                    WINDOWS DEFENDER STATUS REPORT
═══════════════════════════════════════════════════════════════════════════════
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

PRODUCT INFORMATION
───────────────────────────────────────────────────────────────────────────────
  Engine Version:      $($status.EngineVersion)
  Product Version:     $($status.ProductVersion)
  Signature Version:   $($status.SignatureVersion)
  Last Update:         $($status.LastUpdate)

SERVICE STATUS
───────────────────────────────────────────────────────────────────────────────
  Antivirus Enabled:   $(if($status.AntivirusEnabled){"✓ Yes"}else{"✗ No"})
  AM Service Enabled:  $(if($status.AMServiceEnabled){"✓ Yes"}else{"✗ No"})
  Antispyware Enabled: $(if($status.AntispywareEnabled){"✓ Yes"}else{"✗ No"})

PROTECTION COMPONENTS
───────────────────────────────────────────────────────────────────────────────
  Real-time Protection:     $(if($status.RealTimeProtection){"✓ Enabled"}else{"✗ Disabled"})
  Cloud Protection:         $(if($status.CloudProtection){"✓ Enabled"}else{"✗ Disabled"})
  Sample Submission:        $(if($status.AutomaticSampleSubmission){"✓ Enabled"}else{"✗ Disabled"})
  Controlled Folder Access: $(if($status.ControlledFolderAccess){"✓ Enabled"}else{"✗ Disabled"})
  Network Protection:       $(if($status.NetworkProtection){"✓ Enabled"}else{"✗ Disabled"})
  PUA Protection:           $(if($status.PUAProtection){"✓ Enabled"}else{"✗ Disabled"})
  Tamper Protection:        $(if($status.TamperProtection){"✓ Enabled"}else{"✗ Disabled"})
  Behavior Monitoring:      $(if($status.BehaviorMonitor){"✓ Enabled"}else{"✗ Disabled"})
  IOAV Protection:          $(if($status.IOAVProtection){"✓ Enabled"}else{"✗ Disabled"})
  Script Scanning:          $(if($status.ScriptScanning){"✓ Enabled"}else{"✗ Disabled"})

ASR RULES SUMMARY
───────────────────────────────────────────────────────────────────────────────
"@
        
        if ($status.ASRRules) {
            for ($i = 0; $i -lt $status.ASRRules.Count; $i++) {
                $ruleId = $status.ASRRules[$i]
                $action = if ($status.ASRActions -and $i -lt $status.ASRActions.Count) { $status.ASRActions[$i] } else { 0 }
                $ruleName = if ($ASRRules.ContainsKey($ruleId)) { $ASRRules[$ruleId] } else { "Unknown Rule" }
                $actionText = Get-ASRActionText -Action $action
                $statusText += "  [$actionText] $ruleName`n"
            }
        } else {
            $statusText += "  No ASR rules configured`n"
        }
        
        $txtStatus.Text = $statusText
    } else {
        $txtStatus.Text = "Error retrieving Defender status: $($status.Error)"
    }
}

function Update-ASRListView {
    $lvASR.Items.Clear()
    $status = Get-DefenderStatus
    
    foreach ($rule in $ASRRules.GetEnumerator()) {
        $item = New-Object System.Windows.Forms.ListViewItem($rule.Value)
        
        $currentAction = "Not Configured"
        if ($status.Success -and $status.ASRRules) {
            $index = [Array]::IndexOf($status.ASRRules, $rule.Key)
            if ($index -ge 0 -and $status.ASRActions -and $index -lt $status.ASRActions.Count) {
                $currentAction = Get-ASRActionText -Action $status.ASRActions[$index]
            }
        }
        
        $item.SubItems.Add($currentAction) | Out-Null
        $item.SubItems.Add($rule.Key) | Out-Null
        
        # Color code based on status
        switch ($currentAction) {
            "Block" { $item.BackColor = [System.Drawing.Color]::FromArgb(200, 255, 200) }
            "Audit" { $item.BackColor = [System.Drawing.Color]::FromArgb(255, 255, 200) }
            "Warn"  { $item.BackColor = [System.Drawing.Color]::FromArgb(255, 230, 200) }
            "Disabled" { $item.BackColor = [System.Drawing.Color]::FromArgb(255, 200, 200) }
        }
        
        $lvASR.Items.Add($item) | Out-Null
    }
}

function Apply-ProtectionSettings {
    if (-not $isAdmin) {
        [System.Windows.Forms.MessageBox]::Show(
            "Administrator privileges required to modify settings.`nPlease restart the script as Administrator.",
            "Elevation Required",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        return
    }
    
    try {
        $commands = @()
        
        # Real-time Protection
        $commands += "Set-MpPreference -DisableRealtimeMonitoring `$$(-not $chkRealTime.Checked)"
        
        # Cloud Protection
        $mapsValue = if ($chkCloud.Checked) { 2 } else { 0 }
        $commands += "Set-MpPreference -MAPSReporting $mapsValue"
        
        # Sample Submission
        $sampleValue = if ($chkSampleSubmission.Checked) { 1 } else { 2 }
        $commands += "Set-MpPreference -SubmitSamplesConsent $sampleValue"
        
        # Controlled Folder Access
        $cfaValue = if ($chkControlledFolder.Checked) { 1 } else { 0 }
        $commands += "Set-MpPreference -EnableControlledFolderAccess $cfaValue"
        
        # Network Protection
        $npValue = if ($chkNetworkProtection.Checked) { 1 } else { 0 }
        $commands += "Set-MpPreference -EnableNetworkProtection $npValue"
        
        # PUA Protection
        $puaValue = if ($chkPUA.Checked) { 1 } else { 0 }
        $commands += "Set-MpPreference -PUAProtection $puaValue"
        
        # Behavior Monitoring
        $commands += "Set-MpPreference -DisableBehaviorMonitoring `$$(-not $chkBehaviorMonitor.Checked)"
        
        # IOAV Protection
        $commands += "Set-MpPreference -DisableIOAVProtection `$$(-not $chkIOAV.Checked)"
        
        # Script Scanning
        $commands += "Set-MpPreference -DisableScriptScanning `$$(-not $chkScriptScanning.Checked)"
        
        foreach ($cmd in $commands) {
            Invoke-Expression $cmd
        }
        
        [System.Windows.Forms.MessageBox]::Show(
            "Protection settings have been applied successfully.",
            "Success",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
        
        Update-ProtectionUI
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show(
            "Error applying settings: $($_.Exception.Message)",
            "Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
}

function Apply-ASRBaseline {
    param(
        [int]$Action  # 0=Disabled, 1=Block, 2=Audit, 6=Warn
    )
    
    if (-not $isAdmin) {
        [System.Windows.Forms.MessageBox]::Show(
            "Administrator privileges required to modify ASR rules.`nPlease restart the script as Administrator.",
            "Elevation Required",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        return
    }
    
    $actionText = Get-ASRActionText -Action $Action
    $confirm = [System.Windows.Forms.MessageBox]::Show(
        "This will set ALL ASR rules to '$actionText' mode.`n`nAre you sure you want to continue?",
        "Confirm ASR Baseline",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    )
    
    if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) {
        return
    }
    
    try {
        $ruleIds = @($ASRRules.Keys)
        $actions = @($Action) * $ruleIds.Count
        
        Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleIds -AttackSurfaceReductionRules_Actions $actions
        
        [System.Windows.Forms.MessageBox]::Show(
            "ASR baseline ($actionText) has been applied to all rules.",
            "Success",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
        
        Update-ASRListView
        Update-ProtectionUI
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show(
            "Error applying ASR baseline: $($_.Exception.Message)",
            "Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
}

function Apply-SelectedASRRule {
    if ($lvASR.SelectedItems.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            "Please select an ASR rule from the list.",
            "No Selection",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        return
    }
    
    if (-not $isAdmin) {
        [System.Windows.Forms.MessageBox]::Show(
            "Administrator privileges required.",
            "Elevation Required",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        return
    }
    
    $selectedItem = $lvASR.SelectedItems[0]
    $ruleGuid = $selectedItem.SubItems[2].Text
    
    $actionMap = @{
        "Disabled" = 0
        "Block" = 1
        "Audit" = 2
        "Warn" = 6
    }
    $action = $actionMap[$cmbASRAction.SelectedItem]
    
    try {
        Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleGuid -AttackSurfaceReductionRules_Actions $action
        
        [System.Windows.Forms.MessageBox]::Show(
            "ASR rule updated successfully.",
            "Success",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
        
        Update-ASRListView
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show(
            "Error: $($_.Exception.Message)",
            "Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
}

# ============ Event Handlers ============

$btnApplyProtection.Add_Click({ Apply-ProtectionSettings })

$btnRefresh.Add_Click({
    Update-ProtectionUI
    Update-ASRListView
})

$btnEnableAll.Add_Click({
    $chkRealTime.Checked = $true
    $chkCloud.Checked = $true
    $chkSampleSubmission.Checked = $true
    $chkControlledFolder.Checked = $true
    $chkNetworkProtection.Checked = $true
    $chkPUA.Checked = $true
    $chkBehaviorMonitor.Checked = $true
    $chkIOAV.Checked = $true
    $chkScriptScanning.Checked = $true
    Apply-ProtectionSettings
})

$btnDisableAll.Add_Click({
    $confirm = [System.Windows.Forms.MessageBox]::Show(
        "WARNING: This will disable all protection features.`nYour system will be vulnerable to threats.`n`nAre you sure?",
        "Confirm Disable All",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    )
    
    if ($confirm -eq [System.Windows.Forms.DialogResult]::Yes) {
        $chkRealTime.Checked = $false
        $chkCloud.Checked = $false
        $chkSampleSubmission.Checked = $false
        $chkControlledFolder.Checked = $false
        $chkNetworkProtection.Checked = $false
        $chkPUA.Checked = $false
        $chkBehaviorMonitor.Checked = $false
        $chkIOAV.Checked = $false
        $chkScriptScanning.Checked = $false
        Apply-ProtectionSettings
    }
})

$btnUpdateSignatures.Add_Click({
    try {
        Update-MpSignature
        [System.Windows.Forms.MessageBox]::Show(
            "Signature update initiated.",
            "Update Started",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show(
            "Error: $($_.Exception.Message)",
            "Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
})

$btnQuickScan.Add_Click({
    try {
        Start-MpScan -ScanType QuickScan -AsJob
        [System.Windows.Forms.MessageBox]::Show(
            "Quick scan started in background.",
            "Scan Started",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show(
            "Error: $($_.Exception.Message)",
            "Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
})

$btnApplyHardenedBaseline.Add_Click({ Apply-ASRBaseline -Action 1 })
$btnApplyAuditBaseline.Add_Click({ Apply-ASRBaseline -Action 2 })
$btnDisableAllASR.Add_Click({ Apply-ASRBaseline -Action 0 })
$btnRefreshASR.Add_Click({ Update-ASRListView })
$btnApplyASRRule.Add_Click({ Apply-SelectedASRRule })

# Add TabControl to form
$form.Controls.Add($tabControl)

# Status bar
$statusBar = New-Object System.Windows.Forms.StatusStrip
$statusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
$statusLabel.Text = "Windows Defender Configuration Manager - Ready"
$statusBar.Items.Add($statusLabel) | Out-Null
$form.Controls.Add($statusBar)

# Initialize UI
Update-ProtectionUI
Update-ASRListView

# Show the form
[void]$form.ShowDialog()
