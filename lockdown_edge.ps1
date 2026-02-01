<#
.SYNOPSIS
    Microsoft Edge Customization Tool
.DESCRIPTION
    GUI tool to configure Microsoft Edge settings via registry policies.
    Disables startup wizard, sets blank homepage, and disables privacy-risking features.
.NOTES
    Requires Administrator privileges to modify HKLM policies.
    Compatible with PowerShell 5.1
#>

# Ensure UTF-8 encoding
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'

# Check for Admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Registry paths
$EdgePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
$EdgeUserPath = "HKCU:\SOFTWARE\Policies\Microsoft\Edge"

# Function to ensure registry path exists
function Ensure-RegistryPath {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
}

# Function to set registry value
function Set-EdgePolicy {
    param(
        [string]$Name,
        [object]$Value,
        [string]$Type = "DWord",
        [bool]$UseHKLM = $true
    )
    
    $basePath = if ($UseHKLM -and $isAdmin) { $EdgePolicyPath } else { $EdgeUserPath }
    Ensure-RegistryPath -Path $basePath
    
    try {
        Set-ItemProperty -Path $basePath -Name $Name -Value $Value -Type $Type -Force
        return $true
    } catch {
        return $false
    }
}

# Function to remove registry value
function Remove-EdgePolicy {
    param(
        [string]$Name,
        [bool]$UseHKLM = $true
    )
    
    $basePath = if ($UseHKLM -and $isAdmin) { $EdgePolicyPath } else { $EdgeUserPath }
    
    try {
        if (Test-Path $basePath) {
            Remove-ItemProperty -Path $basePath -Name $Name -ErrorAction SilentlyContinue
        }
        return $true
    } catch {
        return $false
    }
}

# Function to get current registry value
function Get-EdgePolicy {
    param([string]$Name)
    
    # Check HKLM first, then HKCU
    foreach ($path in @($EdgePolicyPath, $EdgeUserPath)) {
        if (Test-Path $path) {
            $value = Get-ItemProperty -Path $path -Name $Name -ErrorAction SilentlyContinue
            if ($null -ne $value.$Name) {
                return $value.$Name
            }
        }
    }
    return $null
}

# Create main form
$form = New-Object System.Windows.Forms.Form
$form.Text = "Microsoft Edge Customization Tool"
$form.Size = New-Object System.Drawing.Size(680, 720)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedSingle"
$form.MaximizeBox = $false
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$form.BackColor = [System.Drawing.Color]::FromArgb(245, 245, 245)

# Title label
$titleLabel = New-Object System.Windows.Forms.Label
$titleLabel.Location = New-Object System.Drawing.Point(20, 15)
$titleLabel.Size = New-Object System.Drawing.Size(640, 30)
$titleLabel.Text = "🛡️ Microsoft Edge Privacy & Customization Settings"
$titleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
$titleLabel.ForeColor = [System.Drawing.Color]::FromArgb(0, 102, 153)
$form.Controls.Add($titleLabel)

# Admin status label
$adminLabel = New-Object System.Windows.Forms.Label
$adminLabel.Location = New-Object System.Drawing.Point(20, 48)
$adminLabel.Size = New-Object System.Drawing.Size(640, 20)
if ($isAdmin) {
    $adminLabel.Text = "✓ Running as Administrator - Machine-wide policies available"
    $adminLabel.ForeColor = [System.Drawing.Color]::FromArgb(0, 128, 0)
} else {
    $adminLabel.Text = "⚠ Running as User - Only user-level policies available (Run as Admin for full control)"
    $adminLabel.ForeColor = [System.Drawing.Color]::FromArgb(200, 100, 0)
}
$form.Controls.Add($adminLabel)

# Create TabControl
$tabControl = New-Object System.Windows.Forms.TabControl
$tabControl.Location = New-Object System.Drawing.Point(20, 75)
$tabControl.Size = New-Object System.Drawing.Size(625, 520)
$form.Controls.Add($tabControl)

# Tab 1: Startup & First Run
$tabStartup = New-Object System.Windows.Forms.TabPage
$tabStartup.Text = "Startup & First Run"
$tabStartup.BackColor = [System.Drawing.Color]::White
$tabControl.Controls.Add($tabStartup)

# Tab 2: Privacy & Telemetry
$tabPrivacy = New-Object System.Windows.Forms.TabPage
$tabPrivacy.Text = "Privacy & Telemetry"
$tabPrivacy.BackColor = [System.Drawing.Color]::White
$tabControl.Controls.Add($tabPrivacy)

# Tab 3: Features & Integrations
$tabFeatures = New-Object System.Windows.Forms.TabPage
$tabFeatures.Text = "Features & Integrations"
$tabFeatures.BackColor = [System.Drawing.Color]::White
$tabControl.Controls.Add($tabFeatures)

# Tab 4: Search & New Tab
$tabSearch = New-Object System.Windows.Forms.TabPage
$tabSearch.Text = "Search & New Tab"
$tabSearch.BackColor = [System.Drawing.Color]::White
$tabControl.Controls.Add($tabSearch)

# Helper function to create checkboxes
function New-SettingCheckbox {
    param(
        [System.Windows.Forms.Control]$Parent,
        [string]$Text,
        [string]$Description,
        [int]$Y,
        [string]$Tag
    )
    
    $cb = New-Object System.Windows.Forms.CheckBox
    $cb.Location = New-Object System.Drawing.Point(15, $Y)
    $cb.Size = New-Object System.Drawing.Size(580, 22)
    $cb.Text = $Text
    $cb.Tag = $Tag
    $cb.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $Parent.Controls.Add($cb)
    
    $descLabel = New-Object System.Windows.Forms.Label
    $descLabel.Location = New-Object System.Drawing.Point(32, ($Y + 22))
    $descLabel.Size = New-Object System.Drawing.Size(565, 18)
    $descLabel.Text = $Description
    $descLabel.ForeColor = [System.Drawing.Color]::FromArgb(100, 100, 100)
    $descLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)
    $Parent.Controls.Add($descLabel)
    
    return $cb
}

# ===== TAB 1: STARTUP & FIRST RUN =====
$y = 15

$chkHideFirstRun = New-SettingCheckbox -Parent $tabStartup -Y $y -Tag "HideFirstRunExperience" `
    -Text "Disable First Run Experience / Welcome Wizard" `
    -Description "Prevents the initial setup wizard and welcome screens from appearing"
$y += 50

$chkDisableImportOnLaunch = New-SettingCheckbox -Parent $tabStartup -Y $y -Tag "ImportOnEachLaunch" `
    -Text "Disable Import Prompt on Each Launch" `
    -Description "Stops Edge from prompting to import data from other browsers"
$y += 50

$chkRestoreOnStartup = New-SettingCheckbox -Parent $tabStartup -Y $y -Tag "RestoreOnStartup" `
    -Text "Open Blank Page on Startup (instead of previous session)" `
    -Description "Starts Edge with a blank page rather than restoring previous tabs"
$y += 50

$chkDisableProfilePicker = New-SettingCheckbox -Parent $tabStartup -Y $y -Tag "BrowserGuestModeEnabled" `
    -Text "Disable Profile Picker on Startup" `
    -Description "Skips the profile selection screen when launching Edge"
$y += 50

$chkDisableSigninPrompt = New-SettingCheckbox -Parent $tabStartup -Y $y -Tag "BrowserSignin" `
    -Text "Disable Sign-in Prompt" `
    -Description "Prevents Edge from prompting you to sign in with a Microsoft account"
$y += 50

$chkDisableDefaultBrowserPrompt = New-SettingCheckbox -Parent $tabStartup -Y $y -Tag "DefaultBrowserSettingEnabled" `
    -Text "Disable 'Set as Default Browser' Prompt" `
    -Description "Stops Edge from asking to be set as the default browser"
$y += 50

$chkDisableAutoImport = New-SettingCheckbox -Parent $tabStartup -Y $y -Tag "AutoImportAtFirstRun" `
    -Text "Disable Automatic Data Import from Other Browsers" `
    -Description "Prevents automatic import of bookmarks, history, etc. from other browsers"

# ===== TAB 2: PRIVACY & TELEMETRY =====
$y = 15

$chkDisableTelemetry = New-SettingCheckbox -Parent $tabPrivacy -Y $y -Tag "MetricsReportingEnabled" `
    -Text "Disable Telemetry & Usage Data Collection" `
    -Description "Prevents Edge from sending usage statistics and crash reports to Microsoft"
$y += 50

$chkDisableDiagnostics = New-SettingCheckbox -Parent $tabPrivacy -Y $y -Tag "DiagnosticData" `
    -Text "Disable Diagnostic Data Collection" `
    -Description "Minimizes diagnostic data sent to Microsoft"
$y += 50

$chkDisablePersonalization = New-SettingCheckbox -Parent $tabPrivacy -Y $y -Tag "PersonalizationReportingEnabled" `
    -Text "Disable Personalization & Ad Tracking" `
    -Description "Prevents browsing data from being used for personalized ads"
$y += 50

$chkEnableTrackingPrevention = New-SettingCheckbox -Parent $tabPrivacy -Y $y -Tag "TrackingPrevention" `
    -Text "Enable Strict Tracking Prevention" `
    -Description "Sets tracking prevention to the strictest level"
$y += 50

$chkEnableDNT = New-SettingCheckbox -Parent $tabPrivacy -Y $y -Tag "ConfigureDoNotTrack" `
    -Text "Enable Do Not Track Requests" `
    -Description "Sends 'Do Not Track' header with browsing requests"
$y += 50

$chkDisableSpellcheckService = New-SettingCheckbox -Parent $tabPrivacy -Y $y -Tag "SpellcheckEnabled" `
    -Text "Disable Microsoft Spellcheck Service (Uses Cloud)" `
    -Description "Disables cloud-based spellchecking that sends typed text to Microsoft"
$y += 50

$chkDisableSendSiteInfo = New-SettingCheckbox -Parent $tabPrivacy -Y $y -Tag "SendSiteInfoToImproveServices" `
    -Text "Disable 'Send Site Info to Improve Services'" `
    -Description "Stops sending browsing data to improve Microsoft services"
$y += 50

$chkDisableNetworkPrediction = New-SettingCheckbox -Parent $tabPrivacy -Y $y -Tag "NetworkPredictionOptions" `
    -Text "Disable Network Prediction / Preloading" `
    -Description "Prevents Edge from pre-fetching pages, which can leak browsing intent"

# ===== TAB 3: FEATURES & INTEGRATIONS =====
$y = 15

$chkDisableCopilot = New-SettingCheckbox -Parent $tabFeatures -Y $y -Tag "CopilotChatEnabled" `
    -Text "Disable Copilot / AI Features" `
    -Description "Disables Microsoft Copilot integration in the sidebar"
$y += 50

$chkDisableSidebar = New-SettingCheckbox -Parent $tabFeatures -Y $y -Tag "HubsSidebarEnabled" `
    -Text "Disable Sidebar / Edge Bar" `
    -Description "Removes the sidebar panel from Edge"
$y += 50

$chkDisableCollections = New-SettingCheckbox -Parent $tabFeatures -Y $y -Tag "EdgeCollectionsEnabled" `
    -Text "Disable Collections Feature" `
    -Description "Disables the Collections feature for saving content"
$y += 50

$chkDisableShopping = New-SettingCheckbox -Parent $tabFeatures -Y $y -Tag "EdgeShoppingAssistantEnabled" `
    -Text "Disable Shopping Assistant" `
    -Description "Disables price comparison and coupon features"
$y += 50

$chkDisableSync = New-SettingCheckbox -Parent $tabFeatures -Y $y -Tag "SyncDisabled" `
    -Text "Disable Sync Functionality" `
    -Description "Prevents syncing of bookmarks, history, and settings across devices"
$y += 50

$chkDisableWallet = New-SettingCheckbox -Parent $tabFeatures -Y $y -Tag "EdgeWalletCheckoutEnabled" `
    -Text "Disable Edge Wallet / Payment Features" `
    -Description "Disables the built-in wallet and payment autofill"
$y += 50

$chkDisableFeedback = New-SettingCheckbox -Parent $tabFeatures -Y $y -Tag "UserFeedbackAllowed" `
    -Text "Disable Feedback Prompts" `
    -Description "Stops Edge from asking for feedback"
$y += 50

$chkDisableMiniMenu = New-SettingCheckbox -Parent $tabFeatures -Y $y -Tag "QuickSearchShowMiniMenu" `
    -Text "Disable Quick Search Mini Menu (on text selection)" `
    -Description "Disables the popup menu when selecting text"

# ===== TAB 4: SEARCH & NEW TAB =====
$y = 15

$chkBlankHomepage = New-SettingCheckbox -Parent $tabSearch -Y $y -Tag "HomepageLocation" `
    -Text "Set Homepage to Blank (about:blank)" `
    -Description "Sets the homepage to a blank page instead of MSN"
$y += 50

$chkBlankNewTab = New-SettingCheckbox -Parent $tabSearch -Y $y -Tag "NewTabPageLocation" `
    -Text "Set New Tab Page to Blank" `
    -Description "Opens a blank page for new tabs instead of the news feed"
$y += 50

$chkDisableNewsFeed = New-SettingCheckbox -Parent $tabSearch -Y $y -Tag "NewTabPageContentEnabled" `
    -Text "Disable News Feed on New Tab Page" `
    -Description "Removes the news content from the new tab page"
$y += 50

$chkDisableQuickLinks = New-SettingCheckbox -Parent $tabSearch -Y $y -Tag "NewTabPageQuickLinksEnabled" `
    -Text "Disable Quick Links on New Tab Page" `
    -Description "Removes suggested sites from the new tab page"
$y += 50

$chkDisableSearchSuggestions = New-SettingCheckbox -Parent $tabSearch -Y $y -Tag "SearchSuggestEnabled" `
    -Text "Disable Search Suggestions" `
    -Description "Prevents sending keystrokes to search engine for suggestions"
$y += 50

$chkDisableAddressBarSuggestions = New-SettingCheckbox -Parent $tabSearch -Y $y -Tag "AddressBarMicrosoftSearchInBingProviderEnabled" `
    -Text "Disable Microsoft Search in Bing Suggestions" `
    -Description "Removes Microsoft Search suggestions from address bar"

# Create custom homepage textbox
$lblCustomHomepage = New-Object System.Windows.Forms.Label
$lblCustomHomepage.Location = New-Object System.Drawing.Point(15, ($y + 60))
$lblCustomHomepage.Size = New-Object System.Drawing.Size(150, 22)
$lblCustomHomepage.Text = "Custom Homepage URL:"
$lblCustomHomepage.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$tabSearch.Controls.Add($lblCustomHomepage)

$txtCustomHomepage = New-Object System.Windows.Forms.TextBox
$txtCustomHomepage.Location = New-Object System.Drawing.Point(170, ($y + 58))
$txtCustomHomepage.Size = New-Object System.Drawing.Size(400, 24)
$txtCustomHomepage.Text = "about:blank"
$tabSearch.Controls.Add($txtCustomHomepage)

# ===== BUTTONS =====
$buttonY = 605

# Apply button
$btnApply = New-Object System.Windows.Forms.Button
$btnApply.Location = New-Object System.Drawing.Point(20, $buttonY)
$btnApply.Size = New-Object System.Drawing.Size(140, 35)
$btnApply.Text = "✓ Apply Settings"
$btnApply.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 212)
$btnApply.ForeColor = [System.Drawing.Color]::White
$btnApply.FlatStyle = "Flat"
$btnApply.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$form.Controls.Add($btnApply)

# Select All button
$btnSelectAll = New-Object System.Windows.Forms.Button
$btnSelectAll.Location = New-Object System.Drawing.Point(170, $buttonY)
$btnSelectAll.Size = New-Object System.Drawing.Size(110, 35)
$btnSelectAll.Text = "Select All"
$btnSelectAll.FlatStyle = "Flat"
$form.Controls.Add($btnSelectAll)

# Deselect All button
$btnDeselectAll = New-Object System.Windows.Forms.Button
$btnDeselectAll.Location = New-Object System.Drawing.Point(290, $buttonY)
$btnDeselectAll.Size = New-Object System.Drawing.Size(110, 35)
$btnDeselectAll.Text = "Deselect All"
$btnDeselectAll.FlatStyle = "Flat"
$form.Controls.Add($btnDeselectAll)

# Reset to Default button
$btnReset = New-Object System.Windows.Forms.Button
$btnReset.Location = New-Object System.Drawing.Point(410, $buttonY)
$btnReset.Size = New-Object System.Drawing.Size(110, 35)
$btnReset.Text = "Reset All"
$btnReset.BackColor = [System.Drawing.Color]::FromArgb(200, 80, 80)
$btnReset.ForeColor = [System.Drawing.Color]::White
$btnReset.FlatStyle = "Flat"
$form.Controls.Add($btnReset)

# Exit button
$btnExit = New-Object System.Windows.Forms.Button
$btnExit.Location = New-Object System.Drawing.Point(530, $buttonY)
$btnExit.Size = New-Object System.Drawing.Size(110, 35)
$btnExit.Text = "Exit"
$btnExit.FlatStyle = "Flat"
$form.Controls.Add($btnExit)

# Status label
$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Location = New-Object System.Drawing.Point(20, 650)
$statusLabel.Size = New-Object System.Drawing.Size(620, 25)
$statusLabel.Text = "Ready. Select options and click 'Apply Settings' to configure Edge."
$statusLabel.ForeColor = [System.Drawing.Color]::FromArgb(80, 80, 80)
$form.Controls.Add($statusLabel)

# ===== EVENT HANDLERS =====

# Get all checkboxes from all tabs
function Get-AllCheckboxes {
    $checkboxes = @()
    foreach ($tab in $tabControl.TabPages) {
        foreach ($control in $tab.Controls) {
            if ($control -is [System.Windows.Forms.CheckBox]) {
                $checkboxes += $control
            }
        }
    }
    return $checkboxes
}

# Select All
$btnSelectAll.Add_Click({
    foreach ($cb in (Get-AllCheckboxes)) {
        $cb.Checked = $true
    }
})

# Deselect All
$btnDeselectAll.Add_Click({
    foreach ($cb in (Get-AllCheckboxes)) {
        $cb.Checked = $false
    }
})

# Apply Settings
$btnApply.Add_Click({
    $successCount = 0
    $errorCount = 0
    
    $statusLabel.Text = "Applying settings..."
    $statusLabel.ForeColor = [System.Drawing.Color]::FromArgb(0, 100, 200)
    $form.Refresh()
    
    # Process each setting
    $settings = @{
        # Startup & First Run
        "HideFirstRunExperience" = @{ Checkbox = $chkHideFirstRun; Value = 1 }
        "ImportOnEachLaunch" = @{ Checkbox = $chkDisableImportOnLaunch; Value = 0 }  # 0 = disabled
        "RestoreOnStartup" = @{ Checkbox = $chkRestoreOnStartup; Value = 5 }  # 5 = open specific page
        "BrowserSignin" = @{ Checkbox = $chkDisableSigninPrompt; Value = 0 }  # 0 = disabled
        "DefaultBrowserSettingEnabled" = @{ Checkbox = $chkDisableDefaultBrowserPrompt; Value = 0 }
        "AutoImportAtFirstRun" = @{ Checkbox = $chkDisableAutoImport; Value = 4 }  # 4 = disable
        "ForceSync" = @{ Checkbox = $chkDisableProfilePicker; Value = 0 }
        
        # Privacy & Telemetry
        "MetricsReportingEnabled" = @{ Checkbox = $chkDisableTelemetry; Value = 0 }
        "DiagnosticData" = @{ Checkbox = $chkDisableDiagnostics; Value = 0 }  # 0 = off
        "PersonalizationReportingEnabled" = @{ Checkbox = $chkDisablePersonalization; Value = 0 }
        "TrackingPrevention" = @{ Checkbox = $chkEnableTrackingPrevention; Value = 3 }  # 3 = strict
        "ConfigureDoNotTrack" = @{ Checkbox = $chkEnableDNT; Value = 1 }
        "SpellcheckEnabled" = @{ Checkbox = $chkDisableSpellcheckService; Value = 0 }
        "SendSiteInfoToImproveServices" = @{ Checkbox = $chkDisableSendSiteInfo; Value = 0 }
        "NetworkPredictionOptions" = @{ Checkbox = $chkDisableNetworkPrediction; Value = 2 }  # 2 = disabled
        
        # Features & Integrations
        "HubsSidebarEnabled" = @{ Checkbox = $chkDisableSidebar; Value = 0 }
        "EdgeCollectionsEnabled" = @{ Checkbox = $chkDisableCollections; Value = 0 }
        "EdgeShoppingAssistantEnabled" = @{ Checkbox = $chkDisableShopping; Value = 0 }
        "SyncDisabled" = @{ Checkbox = $chkDisableSync; Value = 1 }  # 1 = sync disabled
        "EdgeWalletCheckoutEnabled" = @{ Checkbox = $chkDisableWallet; Value = 0 }
        "UserFeedbackAllowed" = @{ Checkbox = $chkDisableFeedback; Value = 0 }
        "QuickSearchShowMiniMenu" = @{ Checkbox = $chkDisableMiniMenu; Value = 0 }
        
        # Search & New Tab
        "NewTabPageContentEnabled" = @{ Checkbox = $chkDisableNewsFeed; Value = 0 }
        "NewTabPageQuickLinksEnabled" = @{ Checkbox = $chkDisableQuickLinks; Value = 0 }
        "SearchSuggestEnabled" = @{ Checkbox = $chkDisableSearchSuggestions; Value = 0 }
        "AddressBarMicrosoftSearchInBingProviderEnabled" = @{ Checkbox = $chkDisableAddressBarSuggestions; Value = 0 }
    }
    
    foreach ($key in $settings.Keys) {
        $setting = $settings[$key]
        if ($setting.Checkbox.Checked) {
            if (Set-EdgePolicy -Name $key -Value $setting.Value) {
                $successCount++
            } else {
                $errorCount++
            }
        }
    }
    
    # Handle Copilot separately (multiple policies)
    if ($chkDisableCopilot.Checked) {
        Set-EdgePolicy -Name "CopilotCDPPageContext" -Value 0 | Out-Null
        Set-EdgePolicy -Name "DiscoverPageContextEnabled" -Value 0 | Out-Null
        if (Set-EdgePolicy -Name "HubsSidebarEnabled" -Value 0) { $successCount++ } else { $errorCount++ }
    }
    
    # Handle Homepage
    if ($chkBlankHomepage.Checked) {
        $homepage = if ($txtCustomHomepage.Text) { $txtCustomHomepage.Text } else { "about:blank" }
        if (Set-EdgePolicy -Name "HomepageLocation" -Value $homepage -Type "String") { $successCount++ } else { $errorCount++ }
        Set-EdgePolicy -Name "HomepageIsNewTabPage" -Value 0 | Out-Null
        Set-EdgePolicy -Name "ShowHomeButton" -Value 1 | Out-Null
    }
    
    # Handle New Tab Page
    if ($chkBlankNewTab.Checked) {
        if (Set-EdgePolicy -Name "NewTabPageLocation" -Value "about:blank" -Type "String") { $successCount++ } else { $errorCount++ }
    }
    
    # Handle RestoreOnStartup with URL
    if ($chkRestoreOnStartup.Checked) {
        $startupPath = if ($isAdmin) { "$EdgePolicyPath\RestoreOnStartupURLs" } else { "$EdgeUserPath\RestoreOnStartupURLs" }
        Ensure-RegistryPath -Path $startupPath
        Set-ItemProperty -Path $startupPath -Name "1" -Value "about:blank" -Type "String" -Force
    }
    
    # Update status
    if ($errorCount -eq 0 -and $successCount -gt 0) {
        $statusLabel.Text = "✓ Successfully applied $successCount settings! Restart Edge to see changes."
        $statusLabel.ForeColor = [System.Drawing.Color]::FromArgb(0, 128, 0)
    } elseif ($successCount -gt 0) {
        $statusLabel.Text = "Applied $successCount settings with $errorCount errors. Run as Admin for full access."
        $statusLabel.ForeColor = [System.Drawing.Color]::FromArgb(200, 100, 0)
    } else {
        $statusLabel.Text = "No settings selected or all operations failed."
        $statusLabel.ForeColor = [System.Drawing.Color]::FromArgb(200, 0, 0)
    }
})

# Reset All Settings
$btnReset.Add_Click({
    $result = [System.Windows.Forms.MessageBox]::Show(
        "This will remove all Edge policy customizations.`n`nAre you sure?",
        "Confirm Reset",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    )
    
    if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
        $statusLabel.Text = "Removing policies..."
        $form.Refresh()
        
        try {
            if ($isAdmin -and (Test-Path $EdgePolicyPath)) {
                Remove-Item -Path $EdgePolicyPath -Recurse -Force -ErrorAction SilentlyContinue
            }
            if (Test-Path $EdgeUserPath) {
                Remove-Item -Path $EdgeUserPath -Recurse -Force -ErrorAction SilentlyContinue
            }
            
            # Deselect all checkboxes
            foreach ($cb in (Get-AllCheckboxes)) {
                $cb.Checked = $false
            }
            
            $statusLabel.Text = "✓ All policies removed. Restart Edge to restore default behavior."
            $statusLabel.ForeColor = [System.Drawing.Color]::FromArgb(0, 128, 0)
        } catch {
            $statusLabel.Text = "Error resetting policies: $_"
            $statusLabel.ForeColor = [System.Drawing.Color]::FromArgb(200, 0, 0)
        }
    }
})

# Exit button
$btnExit.Add_Click({
    $form.Close()
})

# Load current settings on startup
function Load-CurrentSettings {
    # Check and set checkbox states based on current registry values
    $checkStates = @{
        $chkHideFirstRun = (Get-EdgePolicy "HideFirstRunExperience") -eq 1
        $chkDisableTelemetry = (Get-EdgePolicy "MetricsReportingEnabled") -eq 0
        $chkDisablePersonalization = (Get-EdgePolicy "PersonalizationReportingEnabled") -eq 0
        $chkDisableSync = (Get-EdgePolicy "SyncDisabled") -eq 1
        $chkDisableShopping = (Get-EdgePolicy "EdgeShoppingAssistantEnabled") -eq 0
        $chkBlankHomepage = (Get-EdgePolicy "HomepageLocation") -eq "about:blank"
        $chkBlankNewTab = (Get-EdgePolicy "NewTabPageLocation") -eq "about:blank"
    }
    
    foreach ($cb in $checkStates.Keys) {
        if ($checkStates[$cb]) {
            $cb.Checked = $true
        }
    }
}

# Call load function
Load-CurrentSettings

# Show form
[void]$form.ShowDialog()
